"""LangSmith trace importer — converts LangSmith run exports to AKSI EvaluationResults.

Supports both ``{"runs": [...]}`` JSON exports and JSON-Lines streams (one run object per
line). Runs are grouped into traces (by ``trace_id``) by default, producing one
EvaluationResult per trace whose control_results capture each constituent run. Pass
``per_run=True`` to emit one EvaluationResult per run instead.

The SDK is importable without the ``langsmith`` package — this importer parses the JSON
schema directly.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


def _resolve_mapping_path() -> Path:
    """Locate ``shared/mappings/langsmith-aksi-controls.json`` by walking upward."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "shared" / "mappings" / "langsmith-aksi-controls.json"
        if candidate.exists():
            return candidate
    # Fallback: return a non-existent path five levels up (matches the SARIF layout).
    return here.parents[4] / "shared" / "mappings" / "langsmith-aksi-controls.json"


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

_DEFAULT_CONTROL = "PR-05"

# Lightweight PII detectors used to flag exposure on llm/retriever runs.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")


def _load_mappings() -> dict[str, str]:
    """Load LangSmith run_type → AKSI control mapping from the shared table."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        mappings = data.get("mappings", {})
        if isinstance(mappings, dict):
            return {str(k): str(v) for k, v in mappings.items()}
        return {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _map_run_to_control(
    run_type: str,
    *,
    has_error: bool,
    mappings: dict[str, str],
) -> str:
    """Return the AKSI control for a run_type, preferring the error variant if applicable."""
    run_type = run_type or "unknown"
    if has_error:
        err_key = f"{run_type}.error"
        if err_key in mappings:
            return mappings[err_key]
    if run_type in mappings:
        return mappings[run_type]
    if "unknown" in mappings:
        return mappings["unknown"]
    return _DEFAULT_CONTROL


def _detect_pii_markers(payload: Any) -> list[str]:
    """Return a list of PII marker categories present in a payload (best-effort)."""
    if payload is None:
        return []
    try:
        text = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        text = str(payload)
    markers: list[str] = []
    if _EMAIL_RE.search(text):
        markers.append("email")
    if _SSN_RE.search(text):
        markers.append("ssn")
    if _CC_RE.search(text):
        markers.append("credit_card")
    return markers


def _safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _latency_ms(run: dict[str, Any]) -> float | None:
    """Compute latency in ms from start_time/end_time when both are present."""
    extra = run.get("extra") or {}
    metadata = extra.get("metadata") or {}
    # Some exports surface latency directly in metadata.
    direct = _safe_float(metadata.get("latency_ms"))
    if direct is not None:
        return direct

    start = run.get("start_time")
    end = run.get("end_time")
    if not start or not end:
        return None
    try:
        # LangSmith timestamps may be ISO strings with or without trailing 'Z'.
        start_dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (end_dt - start_dt).total_seconds() * 1000.0


def _token_usage(run: dict[str, Any]) -> dict[str, Any]:
    """Extract a token usage record from a run, if present.

    Looks at common locations: ``extra.metadata.usage``, ``extra.metadata.token_usage``,
    and ``outputs.llm_output.token_usage``.
    """
    extra = run.get("extra") or {}
    metadata = extra.get("metadata") or {}
    for key in ("usage", "token_usage", "tokens"):
        usage = metadata.get(key)
        if isinstance(usage, dict) and usage:
            return dict(usage)

    outputs = run.get("outputs") or {}
    if isinstance(outputs, dict):
        llm_out = outputs.get("llm_output") or {}
        if isinstance(llm_out, dict):
            usage = llm_out.get("token_usage") or llm_out.get("usage")
            if isinstance(usage, dict) and usage:
                return dict(usage)
    return {}


def _run_error_detail(run: dict[str, Any]) -> str:
    """Return a human-readable error detail string, or '' if no error."""
    error = run.get("error")
    if error is None:
        return ""
    if isinstance(error, dict):
        # LangSmith sometimes wraps errors as {"detail": "...", "type": "..."}
        return str(error.get("detail") or error.get("message") or json.dumps(error))
    return str(error)


def _control_result_for_run(
    run: dict[str, Any],
    mappings: dict[str, str],
) -> ControlResult:
    """Build a ControlResult capturing the safety/exposure posture of a single run."""
    run_type = str(run.get("run_type") or "unknown")
    name = str(run.get("name") or run_type)
    error_detail = _run_error_detail(run)
    has_error = bool(error_detail)

    control_id = _map_run_to_control(run_type, has_error=has_error, mappings=mappings)
    control_name = _CONTROL_NAMES.get(control_id, control_id)

    # PII exposure check on llm/retriever inputs.
    pii_markers: list[str] = []
    if run_type in ("llm", "retriever"):
        pii_markers = _detect_pii_markers(run.get("inputs"))

    if has_error:
        result = "FAIL"
        detail = f"{run_type}:{name} errored — {error_detail[:300]}"
    elif pii_markers:
        result = "FLAG"
        detail = (
            f"{run_type}:{name} inputs contain potential PII markers: "
            f"{', '.join(pii_markers)}"
        )
    else:
        result = "PASS"
        detail = f"{run_type}:{name} completed cleanly"

    usage = _token_usage(run)
    latency = _latency_ms(run)

    evidence_data: dict[str, Any] = {
        "run_id": run.get("id", ""),
        "run_type": run_type,
        "run_name": name,
        "trace_id": run.get("trace_id", ""),
        "parent_run_id": run.get("parent_run_id"),
        "session_id": run.get("session_id"),
    }
    if usage:
        evidence_data["token_usage"] = usage
    if latency is not None:
        evidence_data["latency_ms"] = latency
    if pii_markers:
        evidence_data["pii_markers"] = pii_markers
    if has_error:
        evidence_data["error"] = error_detail

    extra = run.get("extra") or {}
    tags = extra.get("tags") if isinstance(extra, dict) else None
    if tags:
        evidence_data["tags"] = list(tags) if isinstance(tags, (list, tuple)) else [tags]

    return ControlResult(
        control_id=control_id,
        control_name=control_name,
        result=result,
        detail=detail,
        evidence_data=evidence_data,
        duration_ms=latency or 0.0,
    )


def _iter_runs_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield run dicts from a JSON-lines stream, ignoring blank lines."""
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def _is_jsonl(content: str) -> bool:
    """Best-effort detection of JSON-Lines vs single-JSON-document."""
    stripped = content.lstrip()
    if not stripped:
        return False
    # A JSON document starts with '{' or '['; if there are multiple lines and the first
    # parse-able line is a dict but the whole content does not parse as JSON, treat as
    # JSONL.
    try:
        json.loads(content)
        return False
    except json.JSONDecodeError:
        # Not a single JSON document — try line-by-line.
        return any(True for _ in _iter_runs_jsonl(content))


class LangSmithImporter:
    """Parse LangSmith run exports and convert them to EvaluationResults.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        per_run: when ``True`` emit one EvaluationResult per run; when ``False`` (default)
            group runs by ``trace_id`` and emit one EvaluationResult per trace.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        per_run: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.per_run = per_run
        self._mappings = _load_mappings()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a LangSmith export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        runs = list(self._extract_runs(text))
        return self._build_results(runs, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a LangSmith export from a string (JSON or JSONL)."""
        runs = list(self._extract_runs(content))
        return self._build_results(runs, file_sha256=None)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _extract_runs(self, content: str) -> Iterable[dict[str, Any]]:
        """Yield run dicts from either JSON or JSONL content."""
        if not content.strip():
            return []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return list(_iter_runs_jsonl(content))

        if isinstance(doc, dict):
            runs = doc.get("runs")
            if isinstance(runs, list):
                return [r for r in runs if isinstance(r, dict)]
            # Sometimes a single run is exported as a bare object.
            if "id" in doc or "run_type" in doc:
                return [doc]
            return []
        if isinstance(doc, list):
            return [r for r in doc if isinstance(r, dict)]
        return []

    def _build_results(
        self,
        runs: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not runs:
            return [self._empty_result(file_sha256=file_sha256)]

        if self.per_run:
            return [
                self._build_evaluation([r], file_sha256=file_sha256)
                for r in runs
            ]

        # Group by trace_id, falling back to the run's own id when trace_id is missing.
        groups: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for r in runs:
            key = str(r.get("trace_id") or r.get("id") or uuid.uuid4().hex)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(r)

        return [
            self._build_evaluation(groups[k], file_sha256=file_sha256, trace_id=k)
            for k in order
        ]

    def _build_evaluation(
        self,
        runs: list[dict[str, Any]],
        *,
        file_sha256: str | None,
        trace_id: str | None = None,
    ) -> EvaluationResult:
        control_results = [_control_result_for_run(r, self._mappings) for r in runs]

        # Decision: BLOCK if any FAIL, FLAG if any FLAG, else ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        provenance = self._source_provenance(runs, file_sha256=file_sha256)
        # Stamp provenance on every control result so it survives the evidence store.
        for cr in control_results:
            cr.evidence_data["source_provenance"] = provenance

        total_latency = sum(
            (cr.duration_ms for cr in control_results if cr.duration_ms),
            0.0,
        )

        session_id = None
        for r in runs:
            sid = r.get("session_id")
            if sid:
                session_id = str(sid)
                break

        first_run = runs[0]
        action_id = (
            f"langsmith-trace-{(trace_id or first_run.get('id') or uuid.uuid4().hex)[:12]}"
        )

        decision_reason = (
            f"Imported LangSmith trace ({len(runs)} run(s)); "
            f"trace_id={trace_id or first_run.get('trace_id', 'n/a')}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="langsmith_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=total_latency,
            session_id=session_id,
        )

    def _empty_result(self, *, file_sha256: str | None) -> EvaluationResult:
        provenance = self._source_provenance([], file_sha256=file_sha256)
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail="Empty LangSmith export (no runs)",
            evidence_data={"source_provenance": provenance, "run_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"langsmith-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="langsmith_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty LangSmith export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _source_provenance(
        self,
        runs: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "langsmith",
            "source_tool_name": "langsmith",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        if runs:
            provenance["run_count"] = len(runs)
            run_types = sorted({str(r.get("run_type") or "unknown") for r in runs})
            provenance["run_types"] = run_types
        return provenance
