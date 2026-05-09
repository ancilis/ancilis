"""OpenTelemetry GenAI semantic-convention importer.

Parses OTLP/JSON span exports (single-document or JSONL stream) and emits one
:class:`EvaluationResult` per span that carries the ``gen_ai.*`` semantic
conventions (https://opentelemetry.io/docs/specs/semconv/gen-ai/).

Design notes
------------
* The importer is intentionally vendor-neutral: any OTel-instrumented agent
  (OpenAI, Anthropic, Bedrock, Vertex, Azure OpenAI, Cohere, Groq, ...) emits
  the same ``gen_ai.*`` keys, so a single decoder can ingest evidence from any
  of them without per-vendor code.
* A "gen_ai span" is defined as any span whose attribute set contains *at
  least one* key starting with ``gen_ai.``. All other spans are filtered out
  silently — OTLP exports routinely interleave HTTP/DB/internal spans with
  the model spans we care about.
* OTLP wraps every attribute value in a oneof (``stringValue``, ``intValue``,
  ``doubleValue``, ``boolValue``, ``arrayValue``, ``kvlistValue``,
  ``bytesValue``). :func:`_decode_any_value` unwraps these recursively so
  callers can work with native Python types.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

_MAPPING_FILENAME = "otel-genai-aksi-controls.json"


def _resolve_mapping_path() -> Path:
    """Walk up from this file to find ``shared/mappings/<filename>``.

    The repo layout places ``shared/`` next to ``python/`` and ``typescript/``,
    but the depth varies between checkouts (worktrees, installed packages).
    A bounded walk is more robust than a hard-coded ``parent.parent...`` chain.
    """
    here = Path(__file__).resolve()
    for ancestor in [here.parent, *here.parents]:
        candidate = ancestor / "shared" / "mappings" / _MAPPING_FILENAME
        if candidate.is_file():
            return candidate
    # Fall back to the historical path; _load_mappings tolerates missing files.
    return (
        here.parent.parent.parent.parent.parent.parent
        / "shared" / "mappings" / _MAPPING_FILENAME
    )


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CONTROL = "PR-03"


def _load_mappings() -> tuple[dict[str, str], dict[str, Any]]:
    """Load the operation→control mapping and the ``_metadata`` block."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ({}, {})
    raw = data.get("mappings", {})
    mappings: dict[str, str] = {}
    if isinstance(raw, dict):
        mappings = {str(k).lower(): str(v) for k, v in raw.items()}
    metadata = data.get("_metadata", {}) if isinstance(data, dict) else {}
    return mappings, metadata


def _map_operation_to_control(operation: str, mappings: dict[str, str]) -> str:
    """Return the AKSI control ID for an OTel ``gen_ai.operation.name`` value."""
    if not operation:
        return _DEFAULT_CONTROL
    return mappings.get(operation.lower(), _DEFAULT_CONTROL)


# ---------------------------------------------------------------------------
# OTLP attribute decoder
# ---------------------------------------------------------------------------

def _decode_any_value(value: Any) -> Any:
    """Unwrap an OTLP/JSON ``AnyValue`` oneof into a native Python value.

    OTLP wraps every attribute value:
        {"stringValue": "..."} | {"intValue": 42} | {"doubleValue": 1.5} |
        {"boolValue": true}    | {"bytesValue": "..."} |
        {"arrayValue": {"values": [AnyValue, ...]}} |
        {"kvlistValue": {"values": [{"key", "value": AnyValue}, ...]}}

    Strings/ints/bools that arrive already-unwrapped (some exporters) are
    passed through unchanged, which keeps tests resilient to format drift.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        # OTLP encodes int64 as either an int or a string — handle both.
        raw = value["intValue"]
        try:
            return int(raw)
        except (TypeError, ValueError):
            return raw
    if "doubleValue" in value:
        try:
            return float(value["doubleValue"])
        except (TypeError, ValueError):
            return value["doubleValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        inner = value["arrayValue"].get("values", []) if isinstance(value["arrayValue"], dict) else []
        return [_decode_any_value(v) for v in inner]
    if "kvlistValue" in value:
        inner = value["kvlistValue"].get("values", []) if isinstance(value["kvlistValue"], dict) else []
        return {kv.get("key", ""): _decode_any_value(kv.get("value")) for kv in inner}
    return value


def _decode_attributes(attrs: Any) -> dict[str, Any]:
    """Convert an OTLP attributes list ``[{"key", "value": AnyValue}, ...]``
    (or already-flat dict) into a flat ``{key: native_value}`` dict."""
    if isinstance(attrs, dict):
        return {str(k): _decode_any_value(v) for k, v in attrs.items()}
    out: dict[str, Any] = {}
    if not isinstance(attrs, list):
        return out
    for entry in attrs:
        if not isinstance(entry, dict):
            continue
        key = entry.get("key")
        if not key:
            continue
        out[str(key)] = _decode_any_value(entry.get("value"))
    return out


def _decode_status(status: Any) -> str:
    """Return a normalized OTLP status code string (default UNSET)."""
    if not isinstance(status, dict):
        return "STATUS_CODE_UNSET"
    code = status.get("code", "STATUS_CODE_UNSET")
    if isinstance(code, int):
        # OTLP/proto numeric codes: 0=UNSET, 1=OK, 2=ERROR
        return {0: "STATUS_CODE_UNSET", 1: "STATUS_CODE_OK", 2: "STATUS_CODE_ERROR"}.get(
            code, "STATUS_CODE_UNSET"
        )
    return str(code)


def _is_gen_ai_span(attrs: dict[str, Any]) -> bool:
    """A span is a "gen_ai span" iff any attribute key starts with ``gen_ai.``."""
    return any(k.startswith("gen_ai.") for k in attrs)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class OtelGenAIImporter:
    """Parse OTLP/JSON span exports into AKSI :class:`EvaluationResult` records.

    Accepts two on-disk shapes:

    * **Standard OTLP/JSON** — a single document with a top-level
      ``resourceSpans`` (or snake_case ``resource_spans``) array.
    * **JSONL stream** — one OTLP document, or a single ``ResourceSpans``
      object, per line. Blank lines and comment lines (``# ...``) are ignored.
    """

    def __init__(self, agent_id: str = "import", mode: str = "audit") -> None:
        self.agent_id = agent_id
        self.mode = mode
        self._mappings, self._mapping_metadata = _load_mappings()

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an OTLP/JSON file (single doc or JSONL) from disk."""
        content = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content).hexdigest()
        text = content.decode("utf-8")
        return self._parse_text(text, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse OTLP/JSON content from a string (no file hash recorded)."""
        return self._parse_text(content, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _parse_text(
        self,
        text: str,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        documents = list(self._iter_documents(text))
        results: list[EvaluationResult] = []
        for doc in documents:
            results.extend(self._parse_document(doc, file_sha256=file_sha256))
        return results

    def _iter_documents(self, text: str) -> Iterable[dict[str, Any]]:
        """Yield one OTLP-shaped dict per logical input record.

        Heuristic: if the stripped content begins with ``{`` and the whole
        thing parses as JSON, treat it as a single document. Otherwise fall
        back to JSONL (one record per non-empty line).
        """
        stripped = text.strip()
        if not stripped:
            return
        if stripped.startswith("{"):
            try:
                doc = json.loads(stripped)
            except json.JSONDecodeError:
                doc = None
            if isinstance(doc, dict):
                yield doc
                return
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj

    def _parse_document(
        self,
        doc: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Walk a parsed OTLP document and emit one EvaluationResult per gen_ai span."""
        # Tolerate both camelCase (proto JSON) and snake_case (some exporters).
        resource_spans = doc.get("resourceSpans") or doc.get("resource_spans") or []
        # Allow callers to pass a bare ResourceSpans entry as the document root.
        if not resource_spans and ("scopeSpans" in doc or "scope_spans" in doc or "resource" in doc):
            resource_spans = [doc]

        results: list[EvaluationResult] = []
        for rs in resource_spans:
            if not isinstance(rs, dict):
                continue
            resource_attrs = _decode_attributes(rs.get("resource", {}).get("attributes", []))
            scope_spans = rs.get("scopeSpans") or rs.get("scope_spans") or []
            for ss in scope_spans:
                if not isinstance(ss, dict):
                    continue
                scope = ss.get("scope", {}) or {}
                scope_name = scope.get("name", "")
                scope_version = scope.get("version", "")
                spans = ss.get("spans", [])
                for span in spans:
                    if not isinstance(span, dict):
                        continue
                    er = self._parse_span(
                        span,
                        resource_attrs=resource_attrs,
                        scope_name=scope_name,
                        scope_version=scope_version,
                        file_sha256=file_sha256,
                    )
                    if er is not None:
                        results.append(er)
        return results

    def _parse_span(
        self,
        span: dict[str, Any],
        *,
        resource_attrs: dict[str, Any],
        scope_name: str,
        scope_version: str,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        attrs = _decode_attributes(span.get("attributes", []))
        if not _is_gen_ai_span(attrs):
            return None

        operation = str(attrs.get("gen_ai.operation.name", "") or "")
        system = str(attrs.get("gen_ai.system", "") or "")
        request_model = attrs.get("gen_ai.request.model", "")
        response_model = attrs.get("gen_ai.response.model", "")

        status_code = _decode_status(span.get("status"))
        error_type = attrs.get("error.type")

        is_error = status_code == "STATUS_CODE_ERROR" or bool(error_type)
        cr_result = "FAIL" if is_error else "PASS"

        control_id = _map_operation_to_control(operation, self._mappings)
        control_name = _CONTROL_NAMES.get(control_id, control_id)

        trace_id = str(span.get("traceId") or span.get("trace_id") or "")
        span_id = str(span.get("spanId") or span.get("span_id") or "")
        parent_span_id = str(span.get("parentSpanId") or span.get("parent_span_id") or "")
        span_name = str(span.get("name", "") or "")

        # Token usage (OTLP ints can arrive as str — _decode_any_value handles both).
        usage = {
            "input_tokens": _coerce_int(attrs.get("gen_ai.usage.input_tokens")),
            "output_tokens": _coerce_int(attrs.get("gen_ai.usage.output_tokens")),
            "total_tokens": _coerce_int(attrs.get("gen_ai.usage.total_tokens")),
        }

        request_params = {
            "temperature": attrs.get("gen_ai.request.temperature"),
            "top_p": attrs.get("gen_ai.request.top_p"),
            "max_tokens": _coerce_int(attrs.get("gen_ai.request.max_tokens")),
        }

        finish_reasons = attrs.get("gen_ai.response.finish_reasons")
        if isinstance(finish_reasons, str):
            finish_reasons = [finish_reasons]

        tool_name = attrs.get("gen_ai.tool.name")
        tool_call_id = attrs.get("gen_ai.tool.call.id")

        source_tool = scope_name or "otel-genai"
        if scope_version:
            source_tool = f"{source_tool}/{scope_version}"

        source_provenance: dict[str, Any] = {
            "source_format": "otel-genai",
            "source_tool_name": scope_name or "otel-genai",
            "source_tool_version": scope_version,
            "scope_name": scope_name,
            "scope_version": scope_version,
            "spec_url": self._mapping_metadata.get(
                "spec_url", "https://opentelemetry.io/docs/specs/semconv/gen-ai/"
            ),
        }
        if file_sha256 is not None:
            source_provenance["original_file_sha256"] = file_sha256

        evidence_data: dict[str, Any] = {
            "operation": operation,
            "system": system,
            "request_model": request_model,
            "response_model": response_model,
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "span_name": span_name,
            "status_code": status_code,
            "error_type": error_type,
            "usage": usage,
            "request_params": request_params,
            "finish_reasons": finish_reasons,
            "tool_name": tool_name,
            "tool_call_id": tool_call_id,
            "resource_attributes": resource_attrs,
            "gen_ai_attributes": {k: v for k, v in attrs.items() if k.startswith("gen_ai.")},
            "source_tool": source_tool,
            "source_provenance": source_provenance,
        }

        detail_parts = [f"gen_ai.operation={operation or 'unknown'}"]
        if system:
            detail_parts.append(f"system={system}")
        if request_model:
            detail_parts.append(f"model={request_model}")
        if tool_name:
            detail_parts.append(f"tool={tool_name}")
        if is_error:
            detail_parts.append(f"error={error_type or status_code}")
        detail = " ".join(detail_parts)

        decision = "BLOCK" if is_error and self.mode == "enforce" else (
            "FLAG" if is_error else "ALLOW"
        )
        decision_reason = (
            f"OTel gen_ai span ({operation or 'unknown'}) "
            f"status={status_code}"
        )
        if system:
            decision_reason += f" system={system}"

        # Convert OTel start time (unix nanos) into ISO timestamp where present.
        ts = _otlp_nanos_to_iso(span.get("startTimeUnixNano") or span.get("start_time_unix_nano"))
        end_ts = _otlp_nanos_to_iso(span.get("endTimeUnixNano") or span.get("end_time_unix_nano"))
        if ts is None:
            ts = datetime.now(timezone.utc).isoformat()
        evidence_data["start_time"] = ts
        if end_ts is not None:
            evidence_data["end_time"] = end_ts

        duration_ms = _otlp_duration_ms(
            span.get("startTimeUnixNano") or span.get("start_time_unix_nano"),
            span.get("endTimeUnixNano") or span.get("end_time_unix_nano"),
        )

        control_results = [
            ControlResult(
                control_id=control_id,
                control_name=control_name,
                result=cr_result,
                detail=detail,
                evidence_data=evidence_data,
                duration_ms=duration_ms,
            )
        ]

        action_id = span_id or f"otel-genai-{uuid.uuid4().hex[:8]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=ts,
            agent_id=self.agent_id,
            source_type="otel_genai_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=trace_id or None,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _otlp_nanos_to_iso(nanos: Any) -> str | None:
    """Convert an OTLP unix-nanos value (int or str) to an ISO-8601 UTC string."""
    if nanos is None or nanos == "":
        return None
    try:
        n = int(nanos)
    except (TypeError, ValueError):
        return None
    seconds = n / 1_000_000_000
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _otlp_duration_ms(start: Any, end: Any) -> float:
    if start in (None, "") or end in (None, ""):
        return 0.0
    try:
        s = int(start)
        e = int(end)
    except (TypeError, ValueError):
        return 0.0
    if e < s:
        return 0.0
    return (e - s) / 1_000_000.0
