"""Langfuse trace export importer — converts traces and observations to AKSI EvaluationResults.

Langfuse (https://langfuse.com) is an open-source LLM observability platform that
exports agent traces as either:
  * a JSON document of the form ``{"traces": [...]}``, or
  * a JSONL stream where each line is a single trace object.

Each trace contains zero or more observations (GENERATION / SPAN / EVENT). This
importer emits one ``EvaluationResult`` per trace, with one ``ControlResult`` per
observation plus optional aggregate records (token usage, prompt-injection
heuristic).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table (relative to this file's package root).
# This file lives at: <repo>/python/src/ancilis/importers/langfuse.py
# So five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "langfuse-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Default fallback control if an observation type is not mapped.
_UNMAPPED_CONTROL = "PR-05"

# Built-in fallback level → result map; overridden by mapping file _metadata if present.
_DEFAULT_LEVEL_TO_RESULT: dict[str, str] = {
    "DEFAULT": "PASS",
    "DEBUG": "PASS",
    "INFO": "PASS",
    "WARNING": "FLAG",
    "ERROR": "FAIL",
}

# Heuristic patterns suggesting a prompt-injection / role-override attempt in
# untrusted input. Intentionally conservative — surface as FLAG, not FAIL.
_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?previous\s+(instructions|messages|prompts)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous)\s+(instructions|messages)", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)\s+(above|prior|previous)", re.IGNORECASE),
    re.compile(r"^\s*system\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bsystem\s*<\|", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+\w+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a|an|the)\s+\w+", re.IGNORECASE),
    re.compile(r"<\s*\|?\s*(im_start|system|assistant|user)\s*\|?\s*>", re.IGNORECASE),
    re.compile(r"</?\s*system\s*>", re.IGNORECASE),
    re.compile(r"role\s*[:=]\s*[\"']?(system|developer|root|admin)", re.IGNORECASE),
)


@dataclass
class _MappingTable:
    type_to_control: dict[str, str]
    level_to_result: dict[str, str]


def _load_mappings() -> _MappingTable:
    """Load the Langfuse type → AKSI control mapping from the shared table."""
    type_to_control: dict[str, str] = {}
    level_to_result: dict[str, str] = dict(_DEFAULT_LEVEL_TO_RESULT)
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            type_to_control = {str(k).upper(): str(v) for k, v in raw.items()}
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            mapped = meta.get("level_to_result", {})
            if isinstance(mapped, dict):
                for k, v in mapped.items():
                    level_to_result[str(k).upper()] = str(v).upper()
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return _MappingTable(type_to_control=type_to_control, level_to_result=level_to_result)


def _map_observation_type(obs_type: str, table: _MappingTable) -> str:
    return table.type_to_control.get(obs_type.upper(), _UNMAPPED_CONTROL)


def _level_to_result(level: str, table: _MappingTable) -> str:
    return table.level_to_result.get((level or "DEFAULT").upper(), "PASS")


def _detect_prompt_injection(text: str) -> list[str]:
    """Return a list of matched pattern names for a string, or [] if clean."""
    if not text:
        return []
    hits: list[str] = []
    for pattern in _PROMPT_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append(match.group(0).strip()[:80])
    return hits


def _stringify(value: Any) -> str:
    """Coerce a Langfuse input/output value to a single string for heuristic scanning."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL string, ignoring blank lines."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        yield json.loads(line)


class LangfuseImporter:
    """Parse a Langfuse trace export and convert to ``EvaluationResult`` records."""

    def __init__(self, agent_id: str = "import", mode: str = "audit") -> None:
        self.agent_id = agent_id
        self.mode = mode
        self._mappings = _load_mappings()

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Langfuse export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        traces = self._traces_from_text(text)
        return [self._parse_trace(t, file_sha256=file_sha256) for t in traces]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Langfuse export content from a string (JSON or JSONL)."""
        traces = self._traces_from_text(content)
        return [self._parse_trace(t) for t in traces]

    # -- Internals ----------------------------------------------------------

    def _traces_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect whether the export is JSON or JSONL and return traces."""
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Fall through to JSONL — some exports are line-delimited even if
                # the first line happens to look like a complete object.
                return list(_iter_jsonl(text))
            if isinstance(doc, dict):
                if "traces" in doc and isinstance(doc["traces"], list):
                    return [t for t in doc["traces"] if isinstance(t, dict)]
                # Single trace object
                return [doc]
            if isinstance(doc, list):
                return [t for t in doc if isinstance(t, dict)]
            return []
        # Otherwise treat as JSONL.
        return list(_iter_jsonl(text))

    def _parse_trace(
        self,
        trace: dict[str, Any],
        *,
        file_sha256: str | None = None,
    ) -> EvaluationResult:
        trace_id = str(trace.get("id") or trace.get("traceId") or uuid.uuid4().hex[:12])
        trace_name = str(trace.get("name") or "langfuse-trace")
        session_id = trace.get("sessionId") or trace.get("session_id")
        project_id = trace.get("projectId") or trace.get("project_id") or ""
        timestamp = (
            trace.get("timestamp")
            or trace.get("createdAt")
            or datetime.now(timezone.utc).isoformat()
        )
        release = trace.get("release", "")
        version = trace.get("version", "")
        tags = trace.get("tags", []) or []

        source_tool = "langfuse"
        if release:
            source_tool = f"langfuse/{release}"
        source_provenance: dict[str, Any] = {
            "source_format": "langfuse",
            "source_tool_name": "langfuse",
            "source_tool_version": str(release or version or ""),
            "trace_id": trace_id,
            "project_id": str(project_id),
        }
        if file_sha256 is not None:
            source_provenance["original_file_sha256"] = file_sha256

        observations = trace.get("observations", []) or []

        control_results: list[ControlResult] = []
        usage_totals = {"input": 0, "output": 0, "total": 0}
        usage_unit: str | None = None
        usage_seen = False
        worst_result = "PASS"

        # Per-observation control results.
        for obs in observations:
            if not isinstance(obs, dict):
                continue
            cr = self._observation_to_control_result(obs, source_provenance)
            control_results.append(cr)
            worst_result = _max_result(worst_result, cr.result)

            # Aggregate usage.
            usage = obs.get("usage")
            if isinstance(usage, dict):
                usage_seen = True
                for key in ("input", "output", "total"):
                    val = usage.get(key)
                    if isinstance(val, (int, float)):
                        usage_totals[key] += int(val)
                if usage_unit is None and isinstance(usage.get("unit"), str):
                    usage_unit = usage["unit"]

        # Aggregate token-usage record (PR-04 — surfaces resource/governance evidence).
        if usage_seen:
            if usage_totals["total"] == 0:
                usage_totals["total"] = usage_totals["input"] + usage_totals["output"]
            control_results.append(
                ControlResult(
                    control_id="PR-04",
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="PASS",
                    detail=(
                        f"Token usage aggregated from {len(observations)} observation(s): "
                        f"input={usage_totals['input']} output={usage_totals['output']} "
                        f"total={usage_totals['total']}"
                    ),
                    evidence_data={
                        "usage": dict(usage_totals),
                        "unit": usage_unit or "TOKENS",
                        "source_tool": source_tool,
                        "source_provenance": source_provenance,
                    },
                )
            )

        # Prompt-injection heuristic across trace + observation inputs.
        injection_findings = self._scan_trace_for_injection(trace, observations)
        if injection_findings:
            control_results.append(
                ControlResult(
                    control_id="PR-01",
                    control_name=_CONTROL_NAMES["PR-01"],
                    result="FLAG",
                    detail=(
                        f"Prompt-injection heuristic matched {len(injection_findings)} pattern(s) "
                        f"in trace input(s)."
                    ),
                    evidence_data={
                        "matches": injection_findings,
                        "source_tool": source_tool,
                        "source_provenance": source_provenance,
                    },
                )
            )
            worst_result = _max_result(worst_result, "FLAG")

        # If a trace has no observations and no injection hits, emit a clean PASS.
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=f"Imported empty Langfuse trace '{trace_name}' (no observations).",
                    evidence_data={
                        "source_tool": source_tool,
                        "source_provenance": source_provenance,
                        "trace_id": trace_id,
                    },
                )
            )

        decision = {
            "FAIL": "BLOCK",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst_result, "ALLOW")

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"langfuse-import-{trace_id[:8]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="langfuse_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=(
                f"Imported Langfuse trace '{trace_name}' "
                f"({len(observations)} observation(s))"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=_total_duration_ms(observations),
            session_id=str(session_id) if session_id is not None else None,
        )

    def _observation_to_control_result(
        self,
        obs: dict[str, Any],
        source_provenance: dict[str, Any],
    ) -> ControlResult:
        obs_type = str(obs.get("type") or "EVENT").upper()
        level = str(obs.get("level") or "DEFAULT").upper()
        control_id = _map_observation_type(obs_type, self._mappings)
        control_name = _CONTROL_NAMES.get(control_id, control_id)
        result = _level_to_result(level, self._mappings)

        obs_id = str(obs.get("id") or "")
        obs_name = str(obs.get("name") or obs_type.lower())
        status_message = str(obs.get("statusMessage") or "")
        model = obs.get("model") or ""

        detail_bits = [f"{obs_type} '{obs_name}'"]
        if level not in ("DEFAULT", "INFO"):
            detail_bits.append(f"level={level}")
        if status_message:
            detail_bits.append(status_message[:200])
        detail = " | ".join(detail_bits)

        evidence_data: dict[str, Any] = {
            "observation_id": obs_id,
            "observation_type": obs_type,
            "observation_name": obs_name,
            "level": level,
            "model": model,
            "status_message": status_message,
            "start_time": obs.get("startTime", ""),
            "end_time": obs.get("endTime", ""),
            "source_provenance": source_provenance,
        }
        usage = obs.get("usage")
        if isinstance(usage, dict):
            evidence_data["usage"] = {
                k: usage.get(k) for k in ("input", "output", "total", "unit")
                if k in usage
            }
        return ControlResult(
            control_id=control_id,
            control_name=control_name,
            result=result,
            detail=detail,
            evidence_data=evidence_data,
        )

    def _scan_trace_for_injection(
        self,
        trace: dict[str, Any],
        observations: list[Any],
    ) -> list[dict[str, Any]]:
        """Run the prompt-injection heuristic over trace + observation inputs."""
        findings: list[dict[str, Any]] = []
        # Trace-level input.
        trace_input = _stringify(trace.get("input"))
        for hit in _detect_prompt_injection(trace_input):
            findings.append({"location": "trace.input", "pattern": hit})
        # Observation-level inputs.
        for obs in observations:
            if not isinstance(obs, dict):
                continue
            obs_input = _stringify(obs.get("input"))
            for hit in _detect_prompt_injection(obs_input):
                findings.append(
                    {
                        "location": f"observation[{obs.get('id', '')}].input",
                        "observation_type": str(obs.get("type", "")).upper(),
                        "pattern": hit,
                    }
                )
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    """Return the more severe of two ControlResult result strings."""
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _total_duration_ms(observations: list[Any]) -> float:
    """Sum the elapsed time across observations that have start/end ISO timestamps."""
    total = 0.0
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        start = obs.get("startTime")
        end = obs.get("endTime")
        if not (isinstance(start, str) and isinstance(end, str) and start and end):
            continue
        try:
            t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
            total += max(0.0, (t1 - t0).total_seconds() * 1000.0)
        except ValueError:
            continue
    return total
