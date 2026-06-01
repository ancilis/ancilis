"""Pydantic Logfire span importer.

Logfire (https://logfire.pydantic.dev) is the Pydantic team's OpenTelemetry-based
observability product. Its on-the-wire format is OTLP/JSON with vendor-specific
extension attributes:

* ``logfire.msg`` — the formatted log message
* ``logfire.level_name`` — ``trace|debug|info|notice|warn|error|fatal``
* ``logfire.tags`` — list of free-form tags
* ``logfire.exception_type`` — exception class name when a span captured a raise
* ``logfire.json_schema`` — JSON schema for structured kwargs
* ``pydantic_ai.agent_name`` / ``pydantic_ai.tool_name`` / ``pydantic_ai.run_id``
* ``pydantic.validation.errors`` — count of pydantic validation errors
* ``code.filepath`` / ``code.function`` / ``code.lineno`` — source location
* HTTP semconv (``http.method``, ``http.url``, ``http.status_code``)
* DB semconv (``db.system``, ``db.statement`` — never stored)

Design notes
------------
* Logfire is *broader* than OTel-GenAI: a Logfire span need not carry any
  ``gen_ai.*`` attribute to be useful evidence. We therefore emit one
  :class:`EvaluationResult` per span (no ``gen_ai`` filtering).
* When ``gen_ai.*`` *is* present we layer the otel-genai operation→control
  mapping over the Logfire-native level/exception/HTTP/validation rules: the
  most-severe finding wins, and the gen_ai operation provides the primary
  control id.
* User content is *not* trusted — we never store ``db.statement``, the query
  portion of ``http.url``, or the full ``logfire.msg``. The msg is recorded as
  the first 80 chars + a SHA-256 of the original.
* The SDK does not require ``logfire`` or ``pydantic`` to be importable: we
  consume raw OTLP/JSON dicts only.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

from ancilis.engine.result import ControlResult, EvaluationResult


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

_MAPPING_FILENAME = "logfire-aksi-controls.json"


def _resolve_mapping_path() -> Path:
    """Walk up from this file to find ``shared/mappings/<filename>``."""
    here = Path(__file__).resolve()
    for ancestor in [here.parent, *here.parents]:
        candidate = ancestor / "shared" / "mappings" / _MAPPING_FILENAME
        if candidate.is_file():
            return candidate
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

_DEFAULT_CONTROL = "PR-05"
_MAX_MSG_CHARS = 80

# Built-in fallbacks if the mapping file is unreachable / malformed.
_DEFAULT_LEVEL_TO_RESULT: dict[str, str] = {
    "trace": "PASS",
    "debug": "PASS",
    "info": "PASS",
    "notice": "PASS",
    "warn": "FLAG",
    "warning": "FLAG",
    "error": "FAIL",
    "fatal": "FAIL",
    "critical": "FAIL",
}

_DEFAULT_LEVEL_TO_CONTROL: dict[str, str] = {
    "trace": "PR-05",
    "debug": "PR-05",
    "info": "PR-05",
    "notice": "PR-05",
    "warn": "PR-05",
    "warning": "PR-05",
    "error": "DE-01",
    "fatal": "DE-01",
    "critical": "DE-01",
}

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _load_mappings() -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, Any]]:
    """Return (gen_ai_mappings, level_to_result, level_to_control, _metadata)."""
    gen_ai: dict[str, str] = {}
    level_to_result: dict[str, str] = dict(_DEFAULT_LEVEL_TO_RESULT)
    level_to_control: dict[str, str] = dict(_DEFAULT_LEVEL_TO_CONTROL)
    metadata: dict[str, Any] = {}
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return gen_ai, level_to_result, level_to_control, metadata

    raw = data.get("mappings", {})
    if isinstance(raw, dict):
        gen_ai = {str(k).lower(): str(v) for k, v in raw.items()}
    meta = data.get("_metadata", {})
    if isinstance(meta, dict):
        metadata = meta
        l2r = meta.get("level_to_result", {})
        if isinstance(l2r, dict):
            for k, v in l2r.items():
                level_to_result[str(k).lower()] = str(v).upper()
        l2c = meta.get("level_to_control", {})
        if isinstance(l2c, dict):
            for k, v in l2c.items():
                level_to_control[str(k).lower()] = str(v).upper()
    return gen_ai, level_to_result, level_to_control, metadata


# ---------------------------------------------------------------------------
# OTLP attribute decoder (mirrors otel_genai.py — Logfire emits the same shape)
# ---------------------------------------------------------------------------

def _decode_any_value(value: Any) -> Any:
    """Unwrap an OTLP/JSON ``AnyValue`` oneof into a native Python value."""
    if value is None:
        return None
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
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
        inner = (
            value["arrayValue"].get("values", [])
            if isinstance(value["arrayValue"], dict)
            else []
        )
        return [_decode_any_value(v) for v in inner]
    if "kvlistValue" in value:
        inner = (
            value["kvlistValue"].get("values", [])
            if isinstance(value["kvlistValue"], dict)
            else []
        )
        return {kv.get("key", ""): _decode_any_value(kv.get("value")) for kv in inner}
    return value


def _decode_attributes(attrs: Any) -> dict[str, Any]:
    """Flatten OTLP attributes (list-of-kv or dict) into ``{key: native_value}``."""
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
        return {0: "STATUS_CODE_UNSET", 1: "STATUS_CODE_OK", 2: "STATUS_CODE_ERROR"}.get(
            code, "STATUS_CODE_UNSET"
        )
    return str(code)


def _is_gen_ai_span(attrs: dict[str, Any]) -> bool:
    return any(k.startswith("gen_ai.") for k in attrs)


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _otlp_nanos_to_iso(nanos: Any) -> str | None:
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


def _strip_url_query(url: str) -> str:
    """Drop the query and fragment portions of ``url``; keep scheme+netloc+path."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _truncate_with_hash(text: str, *, max_chars: int = _MAX_MSG_CHARS) -> dict[str, Any]:
    """Return ``{preview, sha256, truncated, length}`` for a possibly-untrusted string."""
    if text is None:
        return {"preview": "", "sha256": "", "truncated": False, "length": 0}
    s = str(text)
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    truncated = len(s) > max_chars
    return {
        "preview": s[:max_chars],
        "sha256": digest,
        "truncated": truncated,
        "length": len(s),
    }


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class LogfireImporter:
    """Parse Pydantic Logfire OTLP/JSON span exports into AKSI evidence.

    Accepts two on-disk shapes:

    * **Standard OTLP/JSON** — top-level ``resourceSpans`` (or
      ``resource_spans``) array. Bare ``ResourceSpans`` objects also work.
    * **JSONL stream** — one OTLP document or ``ResourceSpans`` object per
      line. Blank lines and ``# ...`` comment lines are ignored.
    """

    def __init__(self, agent_id: str = "import", mode: str = "audit") -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._gen_ai_mappings,
            self._level_to_result,
            self._level_to_control,
            self._mapping_metadata,
        ) = _load_mappings()

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Logfire OTLP/JSON file (single doc or JSONL) from disk."""
        content = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content).hexdigest()
        text = content.decode("utf-8")
        return self._parse_text(text, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Logfire OTLP/JSON content from a string (no file hash recorded)."""
        return self._parse_text(content, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _parse_text(
        self,
        text: str,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []
        for doc in self._iter_documents(text):
            results.extend(self._parse_document(doc, file_sha256=file_sha256))
        return results

    def _iter_documents(self, text: str) -> Iterable[dict[str, Any]]:
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
        resource_spans = doc.get("resourceSpans") or doc.get("resource_spans") or []
        if not resource_spans and (
            "scopeSpans" in doc or "scope_spans" in doc or "resource" in doc
        ):
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
        # Logfire is broader than otel-genai; we do NOT filter to gen_ai-only spans.

        status_code = _decode_status(span.get("status"))
        is_otel_error = status_code == "STATUS_CODE_ERROR"

        level_raw = str(attrs.get("logfire.level_name", "") or "").lower()
        exception_type = attrs.get("logfire.exception_type")
        validation_errors = _coerce_int(attrs.get("pydantic.validation.errors"))
        http_status = _coerce_int(attrs.get("http.status_code"))
        http_method = attrs.get("http.method")
        pydantic_tool_name = attrs.get("pydantic_ai.tool_name")
        gen_ai_present = _is_gen_ai_span(attrs)
        operation = str(attrs.get("gen_ai.operation.name", "") or "")
        gen_ai_system = str(attrs.get("gen_ai.system", "") or "")

        # ---- Choose primary control + base result -------------------------
        # Precedence:
        #   1. gen_ai operation (when present) — closest semantic control
        #   2. pydantic_ai.tool_name → PR-02 (tool scope)
        #   3. HTTP status semantics
        #   4. logfire level → DE-01 (error/fatal) or PR-05 (info/warn/debug)
        primary_control = _DEFAULT_CONTROL
        result = "PASS"

        if gen_ai_present:
            primary_control = self._gen_ai_mappings.get(operation.lower(), _DEFAULT_CONTROL)
            # gen_ai spans default to PASS unless layered rules escalate.
        elif pydantic_tool_name:
            primary_control = "PR-02"
        elif http_status is not None and 400 <= http_status < 600:
            primary_control = "DE-01" if http_status >= 500 else "PR-02"
        elif level_raw:
            primary_control = self._level_to_control.get(level_raw, _DEFAULT_CONTROL)

        # ---- Layer Logfire-native rules (most-severe wins) ----------------
        layered_findings: list[dict[str, Any]] = []

        # logfire level
        if level_raw:
            level_result = self._level_to_result.get(level_raw, "PASS")
            result = _max_result(result, level_result)
            if level_result != "PASS":
                layered_findings.append(
                    {"rule": "logfire.level_name", "level": level_raw, "result": level_result}
                )

        # pydantic validation errors → PR-03 FAIL when > 0
        if validation_errors is not None and validation_errors > 0:
            result = _max_result(result, "FAIL")
            primary_control = "PR-03"
            layered_findings.append(
                {
                    "rule": "pydantic.validation.errors",
                    "errors": validation_errors,
                    "result": "FAIL",
                }
            )

        # logfire.exception_type set → DE-01 FAIL
        if exception_type:
            result = _max_result(result, "FAIL")
            if not gen_ai_present and not pydantic_tool_name:
                primary_control = "DE-01"
            layered_findings.append(
                {
                    "rule": "logfire.exception_type",
                    "exception_type": str(exception_type),
                    "result": "FAIL",
                }
            )

        # HTTP semantics
        if http_status is not None:
            if http_status >= 500:
                result = _max_result(result, "FAIL")
                if not gen_ai_present:
                    primary_control = "DE-01"
                layered_findings.append(
                    {"rule": "http.status_code", "status": http_status, "result": "FAIL"}
                )
            elif 400 <= http_status < 500:
                result = _max_result(result, "FLAG")
                if not gen_ai_present:
                    primary_control = "PR-02"
                layered_findings.append(
                    {"rule": "http.status_code", "status": http_status, "result": "FLAG"}
                )

        # OTLP status=ERROR overrides to FAIL regardless of how we got here.
        if is_otel_error:
            result = "FAIL"
            layered_findings.append({"rule": "status.code", "status": status_code, "result": "FAIL"})

        # ---- Build evidence_data (carefully redacted) ---------------------

        trace_id = str(span.get("traceId") or span.get("trace_id") or "")
        span_id = str(span.get("spanId") or span.get("span_id") or "")
        parent_span_id = str(span.get("parentSpanId") or span.get("parent_span_id") or "")
        span_name = str(span.get("name", "") or "")

        msg_redacted = _truncate_with_hash(attrs.get("logfire.msg", ""))

        evidence_data: dict[str, Any] = {
            "span_name": span_name,
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "status_code": status_code,
            "logfire": {
                "level_name": level_raw or None,
                "tags": attrs.get("logfire.tags") or [],
                "exception_type": str(exception_type) if exception_type else None,
                "json_schema": attrs.get("logfire.json_schema"),
                "msg": msg_redacted,
            },
            "pydantic_ai": {
                "agent_name": attrs.get("pydantic_ai.agent_name"),
                "tool_name": pydantic_tool_name,
                "run_id": attrs.get("pydantic_ai.run_id"),
            },
            "pydantic": {
                "validation_errors": validation_errors,
            },
            "code": {
                # Source location only — never source line content.
                "filepath": attrs.get("code.filepath"),
                "function": attrs.get("code.function"),
                "lineno": _coerce_int(attrs.get("code.lineno")),
            },
            "layered_findings": layered_findings,
            "resource_attributes": resource_attrs,
        }

        if http_status is not None or http_method:
            evidence_data["http"] = {
                "method": http_method,
                "status_code": http_status,
                "url": _strip_url_query(str(attrs.get("http.url") or "")) or None,
            }

        if gen_ai_present:
            request_model = attrs.get("gen_ai.request.model", "")
            response_model = attrs.get("gen_ai.response.model", "")
            evidence_data["gen_ai"] = {
                "system": gen_ai_system,
                "operation": operation,
                "request_model": request_model,
                "response_model": response_model,
                "usage": {
                    "input_tokens": _coerce_int(attrs.get("gen_ai.usage.input_tokens")),
                    "output_tokens": _coerce_int(attrs.get("gen_ai.usage.output_tokens")),
                    "total_tokens": _coerce_int(attrs.get("gen_ai.usage.total_tokens")),
                },
                "tool_name": attrs.get("gen_ai.tool.name"),
                "tool_call_id": attrs.get("gen_ai.tool.call.id"),
            }

        # Explicit redaction guarantees: db.statement is *never* stored.
        if "db.system" in attrs:
            evidence_data["db"] = {
                "system": attrs.get("db.system"),
                "statement_redacted": True,
            }

        # ---- Source provenance ------------------------------------------
        source_tool = scope_name or "logfire"
        if scope_version:
            source_tool = f"{source_tool}/{scope_version}"
        source_provenance: dict[str, Any] = {
            "source_format": "logfire",
            "source_tool_name": scope_name or "logfire",
            "source_tool_version": scope_version,
            "scope_name": scope_name,
            "scope_version": scope_version,
            "vendor": "pydantic",
            "spec_url": self._mapping_metadata.get(
                "spec_url", "https://logfire.pydantic.dev/docs/"
            ),
        }
        if file_sha256 is not None:
            source_provenance["original_file_sha256"] = file_sha256
        evidence_data["source_tool"] = source_tool
        evidence_data["source_provenance"] = source_provenance

        # ---- Time + duration --------------------------------------------
        start_iso = _otlp_nanos_to_iso(
            span.get("startTimeUnixNano") or span.get("start_time_unix_nano")
        )
        end_iso = _otlp_nanos_to_iso(
            span.get("endTimeUnixNano") or span.get("end_time_unix_nano")
        )
        if start_iso is None:
            start_iso = datetime.now(timezone.utc).isoformat()
        evidence_data["start_time"] = start_iso
        if end_iso is not None:
            evidence_data["end_time"] = end_iso

        duration_ms = _otlp_duration_ms(
            span.get("startTimeUnixNano") or span.get("start_time_unix_nano"),
            span.get("endTimeUnixNano") or span.get("end_time_unix_nano"),
        )

        # ---- Build ControlResult ----------------------------------------
        control_name = _CONTROL_NAMES.get(primary_control, primary_control)

        detail_parts: list[str] = [f"logfire span '{span_name or 'unnamed'}'"]
        if level_raw:
            detail_parts.append(f"level={level_raw}")
        if gen_ai_present:
            detail_parts.append(f"gen_ai.operation={operation or 'unknown'}")
            if gen_ai_system:
                detail_parts.append(f"system={gen_ai_system}")
        if pydantic_tool_name:
            detail_parts.append(f"tool={pydantic_tool_name}")
        if validation_errors:
            detail_parts.append(f"validation_errors={validation_errors}")
        if exception_type:
            detail_parts.append(f"exception={exception_type}")
        if http_status is not None:
            detail_parts.append(f"http={http_status}")
        if is_otel_error:
            detail_parts.append("status=ERROR")
        detail = " | ".join(detail_parts)

        control_results = [
            ControlResult(
                control_id=primary_control,
                control_name=control_name,
                result=result,
                detail=detail,
                evidence_data=evidence_data,
                duration_ms=duration_ms,
            )
        ]

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(result, "ALLOW")

        decision_reason_bits = [f"Logfire span ({span_name or 'unnamed'})"]
        if level_raw:
            decision_reason_bits.append(f"level={level_raw}")
        if gen_ai_present and operation:
            decision_reason_bits.append(f"gen_ai.operation={operation}")
        if exception_type:
            decision_reason_bits.append(f"exception={exception_type}")
        if validation_errors:
            decision_reason_bits.append(f"pydantic_errors={validation_errors}")
        if http_status is not None:
            decision_reason_bits.append(f"http_status={http_status}")
        decision_reason = " ".join(decision_reason_bits)

        action_id = span_id or f"logfire-{uuid.uuid4().hex[:8]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=start_iso,
            agent_id=self.agent_id,
            source_type="logfire_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=trace_id or None,
        )
