"""LiteLLM gateway log importer — converts LLM callback logs to AKSI EvaluationResults.

LiteLLM (https://github.com/BerriAI/litellm) is the dominant LLM gateway in
production: it normalizes 100+ providers behind an OpenAI-compatible API and
emits callback logs / Langfuse-style traces. Every request flowing through a
LiteLLM proxy becomes one entry in the export, regardless of upstream
provider (OpenAI, Anthropic, Vertex, Bedrock, Azure, ...).

This importer accepts three on-disk shapes:

  1. JSON array of entries:           ``[{...}, {...}]``
  2. JSONL stream:                     one JSON object per line
  3. Spend-log envelope:               ``{"data": [{...}, ...]}``

Signal mapping (see shared/mappings/litellm-aksi-controls.json):
  * ``call_type=completion`` & success           → PR-01 PASS
  * ``call_type=embeddings`` & success           → PR-04 PASS  (data exposure)
  * ``call_type=moderation`` & success           → PR-04 PASS  (governance)
  * ``call_type=image_generation`` & success     → PR-04 PASS
  * ``status=failure``                            → DE-01 FAIL  (provider failure)
  * ``response_cost > threshold``                 → PR-04 FLAG  (cost exposure)
  * metadata contains ``guardrail_violation`` /
    ``blocked``                                   → PR-02 FAIL  (scope violation)

Sanitization: prompt/response messages are NEVER stored verbatim. We capture
only the message count, role distribution, and a sha256 over the joined
content blob so downstream evidence can prove a body existed and detect
tampering without leaking content.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table.
# This file lives at <repo>/python/src/ancilis/importers/litellm.py — five
# .parent traversals after .resolve() reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "litellm-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_COST_THRESHOLD_USD = 1.0

# Fallback control IDs if the mapping file is missing or stripped.
_DEFAULT_CALL_TYPE_CONTROLS: dict[str, str] = {
    "completion": "PR-01",
    "embeddings": "PR-04",
    "moderation": "PR-04",
    "image_generation": "PR-04",
}
_DEFAULT_STATUS_FAILURE_CONTROL = "DE-01"
_DEFAULT_GUARDRAIL_CONTROL = "PR-02"
_DEFAULT_COST_CONTROL = "PR-04"

# Substrings in metadata flags that count as a guardrail violation. Matched
# case-insensitively against keys *and* string values.
_GUARDRAIL_TOKENS: tuple[str, ...] = (
    "guardrail_violation",
    "guardrail_violated",
    "blocked",
    "policy_violation",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------

def _load_mapping_table() -> dict[str, Any]:
    """Load the litellm-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# Body / message sanitization
# ---------------------------------------------------------------------------

def _stringify(value: Any) -> str:
    """Coerce any value to a stable string for hashing only."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _sanitize_messages(messages: Any) -> dict[str, Any]:
    """Reduce a chat-completion ``messages`` array to a non-sensitive summary.

    Stores only:
      - message count
      - role distribution (e.g. ``{"system": 1, "user": 2, "assistant": 1}``)
      - sha256 of the joined string content
      - total content byte length

    Raw text NEVER appears in the returned dict.
    """
    if messages is None:
        return {"present": False, "message_count": 0}
    if not isinstance(messages, list):
        # Coerce singletons or oddly-shaped payloads to a hash-only summary.
        encoded = _stringify(messages).encode("utf-8")
        return {
            "present": True,
            "message_count": 0,
            "kind": type(messages).__name__,
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "role_distribution": {},
        }

    role_counts: dict[str, int] = {}
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            parts.append(_stringify(msg))
            continue
        role = str(msg.get("role") or "unknown")
        role_counts[role] = role_counts.get(role, 0) + 1
        content = msg.get("content")
        parts.append(_stringify(content))
    joined = "\n".join(parts).encode("utf-8")
    return {
        "present": True,
        "message_count": len(messages),
        "role_distribution": role_counts,
        "byte_length": len(joined),
        "sha256": hashlib.sha256(joined).hexdigest(),
    }


def _sanitize_input(value: Any) -> dict[str, Any]:
    """Summarise embeddings/moderation ``input`` (str or list[str])."""
    if value is None:
        return {"present": False}
    if isinstance(value, list):
        encoded = "\n".join(_stringify(v) for v in value).encode("utf-8")
        return {
            "present": True,
            "kind": "list",
            "item_count": len(value),
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    encoded = _stringify(value).encode("utf-8")
    return {
        "present": True,
        "kind": type(value).__name__,
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _sanitize_response(response: Any) -> dict[str, Any]:
    """Summarise an OpenAI-shaped response without retaining raw choices/text."""
    if response is None:
        return {"present": False}
    if not isinstance(response, dict):
        encoded = _stringify(response).encode("utf-8")
        return {
            "present": True,
            "kind": type(response).__name__,
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    encoded = json.dumps(response, sort_keys=True, default=str).encode("utf-8")
    summary: dict[str, Any] = {
        "present": True,
        "kind": "object",
        "body_keys": sorted(response.keys()),
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    choices = response.get("choices")
    if isinstance(choices, list):
        summary["choice_count"] = len(choices)
    return summary


# ---------------------------------------------------------------------------
# Guardrail detection
# ---------------------------------------------------------------------------

def _detect_guardrail_violation(metadata: Any) -> list[str]:
    """Return matched guardrail tokens found in metadata keys/values.

    Recursive but bounded — only inspects str keys/values and obvious nested
    dicts/lists. Match is case-insensitive substring against ``_GUARDRAIL_TOKENS``.
    """
    if metadata is None:
        return []
    hits: list[str] = []
    seen: set[int] = set()

    def _scan(value: Any, depth: int = 0) -> None:
        if depth > 6:
            return
        if id(value) in seen:
            return
        if isinstance(value, dict):
            seen.add(id(value))
            for k, v in value.items():
                k_str = str(k).lower()
                for token in _GUARDRAIL_TOKENS:
                    if token in k_str:
                        # Treat truthy values for guardrail-style keys as a hit.
                        if v not in (None, False, 0, "", [], {}):
                            hits.append(f"key={k}")
                            break
                _scan(v, depth + 1)
        elif isinstance(value, list):
            seen.add(id(value))
            for item in value:
                _scan(item, depth + 1)
        elif isinstance(value, str):
            v_lower = value.lower()
            for token in _GUARDRAIL_TOKENS:
                if token in v_lower:
                    hits.append(f"value contains {token!r}")
                    break

    _scan(metadata)
    # De-duplicate while preserving order.
    seen_hits: set[str] = set()
    deduped: list[str] = []
    for h in hits:
        if h not in seen_hits:
            seen_hits.add(h)
            deduped.append(h)
    return deduped


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------

def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class LiteLLMImporter:
    """Parse a LiteLLM callback / spend-log export and convert to EvaluationResults."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cost_threshold_usd: float | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        if cost_threshold_usd is not None:
            self.cost_threshold_usd = float(cost_threshold_usd)
        else:
            self.cost_threshold_usd = float(
                meta.get("default_cost_threshold_usd", _DEFAULT_COST_THRESHOLD_USD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a LiteLLM export file (JSON, JSONL, or spend-log) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        entries = self._entries_from_text(text)
        return [self._parse_entry(e, file_sha256=file_sha256) for e in entries]

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse LiteLLM export content from a string."""
        entries = self._entries_from_text(content)
        return [self._parse_entry(e, file_sha256=None) for e in entries]

    # -- Internals ----------------------------------------------------------

    def _entries_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect JSON / JSONL / spend-log envelope and return entry dicts."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [e for e in doc if isinstance(e, dict)]
            if isinstance(doc, dict):
                # Spend-log envelope.
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Some exports wrap entries under "logs".
                if "logs" in doc and isinstance(doc["logs"], list):
                    return [e for e in doc["logs"] if isinstance(e, dict)]
                # Single entry.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "litellm",
            "source_tool_name": "litellm",
            "source_tool_version": "",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _parse_entry(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        request_id = str(entry.get("id") or entry.get("request_id") or uuid.uuid4())
        call_type_raw = str(entry.get("call_type") or "completion").strip().lower()
        call_type = call_type_raw or "completion"
        model = str(entry.get("model") or "unknown")
        status = str(entry.get("status") or "success").strip().lower()
        exception = entry.get("exception") or ""

        litellm_params = entry.get("litellm_params") or {}
        if not isinstance(litellm_params, dict):
            litellm_params = {}
        provider_routed_to = str(
            litellm_params.get("custom_llm_provider")
            or litellm_params.get("provider")
            or entry.get("custom_llm_provider")
            or entry.get("provider")
            or ""
        )
        api_base = str(litellm_params.get("api_base") or "")

        usage = entry.get("usage") or {}
        if not isinstance(usage, dict):
            usage = {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        total_tokens = int(
            usage.get("total_tokens") or (prompt_tokens + completion_tokens)
        )

        try:
            response_cost = float(entry.get("response_cost") or 0.0)
        except (TypeError, ValueError):
            response_cost = 0.0

        metadata = entry.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        user_id = metadata.get("user_id") or entry.get("user")
        trace_id = metadata.get("trace_id")
        tags = metadata.get("tags") or []

        # Sanitize bodies — no raw text retained.
        messages_summary = _sanitize_messages(entry.get("messages"))
        input_summary = _sanitize_input(entry.get("input"))
        response_summary = _sanitize_response(entry.get("response"))

        source_provenance = self._source_provenance(file_sha256=file_sha256)
        common_evidence: dict[str, Any] = {
            "litellm_request_id": request_id,
            "call_type": call_type,
            "model": model,
            "provider_routed_to": provider_routed_to,
            "api_base": api_base,
            "status": status,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "response_cost_usd": response_cost,
            "user_id": user_id,
            "trace_id": trace_id,
            "tags": tags,
            "messages_summary": messages_summary,
            "input_summary": input_summary,
            "response_summary": response_summary,
            "source_provenance": source_provenance,
            "source_tool": "litellm",
        }

        control_results: list[ControlResult] = []

        # 1. Guardrail violation — highest priority, FAIL.
        guardrail_hits = _detect_guardrail_violation(metadata)
        # Some exports stash the flag at the top level too.
        if not guardrail_hits:
            guardrail_hits = _detect_guardrail_violation(
                {k: v for k, v in entry.items() if k not in ("messages", "response", "input")}
            )

        if guardrail_hits:
            control_id = _control_for(
                "guardrail_violation", self._mappings, _DEFAULT_GUARDRAIL_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"LiteLLM request {request_id} flagged by guardrail "
                        f"({len(guardrail_hits)} match(es); call_type={call_type})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "guardrail_violation",
                        "guardrail_matches": guardrail_hits,
                    },
                )
            )

        # 2. Status / exception — FAIL on failure.
        if status == "failure" or exception:
            control_id = _control_for(
                "status_failure", self._mappings, _DEFAULT_STATUS_FAILURE_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"LiteLLM request {request_id} failed via {provider_routed_to or 'unknown'}: "
                        f"{str(exception)[:200] if exception else 'status=failure'}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "status_failure",
                        "exception": str(exception)[:500],
                    },
                )
            )
        else:
            # 3. call_type → control PASS for successful requests.
            control_id = _control_for(
                call_type, self._mappings,
                _DEFAULT_CALL_TYPE_CONTROLS.get(call_type, "PR-01"),
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"LiteLLM {call_type} succeeded via "
                        f"{provider_routed_to or 'unknown'}/{model} "
                        f"tokens={total_tokens} cost=${response_cost:.4f}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": f"{call_type}_success",
                    },
                )
            )

        # 4. Cost-threshold exceeded — additive FLAG.
        if response_cost > self.cost_threshold_usd:
            control_id = _control_for(
                "cost_threshold_exceeded", self._mappings, _DEFAULT_COST_CONTROL
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"LiteLLM request {request_id} cost ${response_cost:.4f} exceeds "
                        f"threshold ${self.cost_threshold_usd:.4f} (exposure)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "cost_threshold_exceeded",
                        "cost_threshold_usd": self.cost_threshold_usd,
                    },
                )
            )

        # Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from LiteLLM: {provider_routed_to or 'unknown'}/{model} "
            f"call_type={call_type} status={status} tokens={total_tokens} "
            f"cost=${response_cost:.4f}"
        )

        timestamp = (
            entry.get("end_time")
            or entry.get("start_time")
            or datetime.now(timezone.utc).isoformat()
        )

        total_duration_ms = _duration_ms(
            entry.get("start_time"), entry.get("end_time")
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"litellm-{str(request_id)[:32]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="litellm_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=total_duration_ms,
            session_id=str(trace_id) if trace_id else None,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _duration_ms(start: Any, end: Any) -> float:
    """Compute (end - start) in milliseconds for ISO-8601 strings; tolerate None."""
    if not (isinstance(start, str) and isinstance(end, str) and start and end):
        return 0.0
    try:
        t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return max(0.0, (t1 - t0).total_seconds() * 1000.0)
    except ValueError:
        return 0.0
