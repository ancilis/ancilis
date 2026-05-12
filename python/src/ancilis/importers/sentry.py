# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Sentry event importer — converts Sentry error / transaction events to AKSI EvaluationResults.

Sentry (https://sentry.io) is the dominant error-monitoring + APM platform for
production code, including AI agents. Sentry's AI Monitoring (launched 2024)
ingests prompt/response telemetry alongside exceptions, so every agent crash,
exception, and transaction-degradation event flows through Sentry's
``/api/0/projects/{org}/{proj}/events/`` endpoint. This importer parses that
JSON (or JSONL) export and converts each event into an ``EvaluationResult``.

Mapping (see ``shared/mappings/sentry-aksi-controls.json``):

  - type=error level=fatal              → DE-01 FAIL  (fatal crash)
  - type=error level=error is_unhandled → DE-01 FAIL  (uncaught production exception)
  - type=error level=error handled      → PR-05 FLAG  (handled but logged — surface)
  - type=error level=warning            → PR-05 FLAG  (warning — surface for review)
  - type=transaction                    → PR-05 PASS  (audit-trail of transaction)
  - response_quality_score < threshold  → PR-03 FLAG  (degraded AI quality)
  - contexts.ai.operation=chat / embeddings / agent_run → PR-01 captured
  - contexts.ai.operation=tool_call     → PR-02 captured
  - exception keyword (SecurityError, credential, secret, API key, ...) → PR-01 FLAG
  - group event_count > 1000 AND user_count > 100 → PR-04 FLAG (widespread)

Sanitization:

* ``contexts.user.email`` — only the domain portion is stored (``@example.com``).
* ``contexts.user.id`` — middle masked (``u1234...xyz4``).
* ``title`` — first 200 chars + sha256; raw never stored (titles can leak prompt content).
* ``exception.values[].value`` — length + sha256; full text never stored.
* ``exception.values[].stacktrace.frames`` — only ``filename`` / ``function`` /
  ``lineno`` retained; source-line content (``context_line`` / ``pre_context`` /
  ``post_context``) is NEVER stored.
* ``extra`` — dict reduced to its key list; values are dropped (extra often
  contains user-supplied diagnostic blobs).

The SDK is importable without ``sentry-sdk`` installed; this importer parses
the JSON schema directly.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

_MAPPING_FILENAME = "sentry-aksi-controls.json"


def _resolve_mapping_path() -> Path:
    """Locate ``shared/mappings/<filename>`` by walking upward from this file."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "shared" / "mappings" / _MAPPING_FILENAME
        if candidate.is_file():
            return candidate
    return here.parents[4] / "shared" / "mappings" / _MAPPING_FILENAME


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

_DEFAULT_SIGNAL_TO_CONTROL: dict[str, str] = {
    "type_error_fatal": "DE-01",
    "type_error_unhandled": "DE-01",
    "type_error_handled": "PR-05",
    "type_warning": "PR-05",
    "type_transaction": "PR-05",
    "low_quality_score": "PR-03",
    "security_keyword": "PR-01",
    "widespread_error": "PR-04",
    "operation_chat": "PR-01",
    "operation_embeddings": "PR-01",
    "operation_agent_run": "PR-01",
    "operation_tool_call": "PR-02",
}

_DEFAULT_SIGNAL_RESULT: dict[str, str] = {
    "type_error_fatal": "FAIL",
    "type_error_unhandled": "FAIL",
    "type_error_handled": "FLAG",
    "type_warning": "FLAG",
    "type_transaction": "PASS",
    "low_quality_score": "FLAG",
    "security_keyword": "FLAG",
    "widespread_error": "FLAG",
    "operation_chat": "PASS",
    "operation_embeddings": "PASS",
    "operation_agent_run": "PASS",
    "operation_tool_call": "PASS",
}

_DEFAULT_SECURITY_PATTERNS: list[str] = [
    "*SecurityError*",
    "*PermissionError*",
    "*AuthenticationFailed*",
    "*Unauthorized*",
    "*Forbidden*",
    "*credential*",
    "*Credential*",
    "*secret*",
    "*Secret*",
    "*API key*",
    "*api_key*",
    "*api key*",
]

_DEFAULT_GROUP_EVENT_THRESHOLD = 1000
_DEFAULT_GROUP_USER_THRESHOLD = 100
_DEFAULT_RESPONSE_QUALITY_THRESHOLD = 0.5

_TITLE_MAX_CHARS = 200

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _load_mapping_table() -> tuple[
    dict[str, str], dict[str, str], list[str], int, int, float
]:
    """Return (signal_to_control, signal_result, security_patterns, event_thr, user_thr, quality_thr)."""
    signal_to_control: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    signal_result: dict[str, str] = dict(_DEFAULT_SIGNAL_RESULT)
    patterns: list[str] = list(_DEFAULT_SECURITY_PATTERNS)
    event_thr = _DEFAULT_GROUP_EVENT_THRESHOLD
    user_thr = _DEFAULT_GROUP_USER_THRESHOLD
    quality_thr = _DEFAULT_RESPONSE_QUALITY_THRESHOLD

    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return signal_to_control, signal_result, patterns, event_thr, user_thr, quality_thr

    if isinstance(data, dict):
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                signal_to_control[str(key)] = str(value)
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            sec = meta.get("security_keyword_patterns")
            if isinstance(sec, list) and sec:
                patterns = [str(p) for p in sec]
            results_meta = meta.get("result_levels")
            if isinstance(results_meta, dict):
                for k, v in results_meta.items():
                    signal_result[str(k)] = str(v).upper()
            ev = meta.get("default_group_event_threshold")
            if isinstance(ev, (int, float)):
                event_thr = int(ev)
            us = meta.get("default_group_user_threshold")
            if isinstance(us, (int, float)):
                user_thr = int(us)
            qt = meta.get("default_response_quality_threshold")
            if isinstance(qt, (int, float)):
                quality_thr = float(qt)

    return signal_to_control, signal_result, patterns, event_thr, user_thr, quality_thr


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

def _coerce_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "y", "1"):
            return True
        if v in ("false", "no", "n", "0"):
            return False
    if isinstance(value, (int, float)):
        return value != 0
    return None


def _truncate_with_hash(text: str, *, max_chars: int = _TITLE_MAX_CHARS) -> dict[str, Any]:
    """Return ``{preview, sha256, truncated, length}`` for an untrusted string."""
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


def _redact_email(email: str | None) -> str | None:
    """Keep the domain portion; drop the local-part."""
    if not email:
        return None
    s = str(email)
    if "@" not in s:
        return None
    domain = s.rsplit("@", 1)[-1].strip()
    return f"@{domain}" if domain else None


def _mask_user_id(user_id: Any) -> str | None:
    """Mask the middle of a user id: keep first 4 + last 4 chars, replace middle with ``...``."""
    if user_id is None:
        return None
    s = str(user_id)
    if not s:
        return None
    if len(s) <= 8:
        # too short to safely mask middle — keep first 2, mask the rest
        return s[:2] + "***" if len(s) > 2 else "***"
    return f"{s[:4]}...{s[-4:]}"


def _redact_value(value: Any) -> dict[str, Any]:
    """Redact ``exception.value`` style strings — store length + sha256 only."""
    if value is None:
        return {"present": False}
    s = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    encoded = s.encode("utf-8")
    return {
        "present": True,
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _safe_frames(frames: Any) -> list[dict[str, Any]]:
    """Return frame metadata only — NEVER ``context_line`` / ``pre_context`` / ``post_context``."""
    if not isinstance(frames, list):
        return []
    out: list[dict[str, Any]] = []
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        out.append(
            {
                "filename": frame.get("filename"),
                "function": frame.get("function"),
                "lineno": _coerce_int(frame.get("lineno")),
                "module": frame.get("module"),
                "in_app": frame.get("in_app"),
            }
        )
    return out


def _summarize_exception(exc_block: Any) -> dict[str, Any]:
    """Summarize ``exception`` block, redacting ``value`` and stripping source-line content."""
    if not isinstance(exc_block, dict):
        return {"present": False}
    values = exc_block.get("values")
    if not isinstance(values, list):
        return {"present": False}
    summary: list[dict[str, Any]] = []
    for v in values:
        if not isinstance(v, dict):
            continue
        stack = v.get("stacktrace") if isinstance(v.get("stacktrace"), dict) else {}
        summary.append(
            {
                "type": v.get("type"),
                "module": v.get("module"),
                "value_redacted": _redact_value(v.get("value")),
                "frames": _safe_frames(stack.get("frames")),
                "frame_count": len(_safe_frames(stack.get("frames"))),
            }
        )
    return {"present": True, "values": summary}


def _summarize_extra(extra: Any) -> dict[str, Any]:
    """Drop extra-dict values; keep only keys (often contains user-supplied data)."""
    if not isinstance(extra, dict):
        return {"present": bool(extra)}
    return {"present": True, "keys": sorted([str(k) for k in extra])}


def _tags_to_dict(tags: Any) -> dict[str, str]:
    """Sentry tags can be ``[{"key": ..., "value": ...}]`` or ``{key: value}``."""
    out: dict[str, str] = {}
    if isinstance(tags, list):
        for entry in tags:
            if isinstance(entry, dict):
                k = entry.get("key")
                v = entry.get("value")
                if k is not None and v is not None:
                    out[str(k)] = str(v)
            elif isinstance(entry, list) and len(entry) == 2:
                out[str(entry[0])] = str(entry[1])
    elif isinstance(tags, dict):
        for k, v in tags.items():
            out[str(k)] = str(v)
    return out


def _hash_fingerprint(fingerprint: Any) -> str | None:
    if fingerprint is None:
        return None
    encoded = json.dumps(fingerprint, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
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

class SentryImporter:
    """Parse Sentry event exports and convert each event into an EvaluationResult.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        group_event_threshold: events-per-group floor for widespread-error
            flagging (default from mapping metadata, falling back to 1000).
        group_user_threshold: users-per-group floor for widespread-error
            flagging (default 100).
        response_quality_threshold: ``contexts.ai.response_quality_score``
            value below which we emit a PR-03 FLAG (default 0.5).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        group_event_threshold: int | None = None,
        group_user_threshold: int | None = None,
        response_quality_threshold: float | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._signal_to_control,
            self._signal_result,
            self._security_patterns,
            event_thr,
            user_thr,
            quality_thr,
        ) = _load_mapping_table()
        self.group_event_threshold = (
            int(group_event_threshold) if group_event_threshold is not None else event_thr
        )
        self.group_user_threshold = (
            int(group_user_threshold) if group_user_threshold is not None else user_thr
        )
        self.response_quality_threshold = (
            float(response_quality_threshold)
            if response_quality_threshold is not None
            else quality_thr
        )

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Sentry event export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = list(self._extract_events(text))
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Sentry event export content from a string (no file hash recorded)."""
        events = list(self._extract_events(content))
        return self._build_results(events, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _extract_events(self, content: str) -> Iterable[dict[str, Any]]:
        if not content.strip():
            return []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return list(_iter_jsonl(content))

        if isinstance(doc, dict):
            data = doc.get("data")
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
            if isinstance(data, dict):
                return [data]
            # Bare event-shaped object.
            if "eventID" in doc or "event_id" in doc or "type" in doc or "id" in doc:
                return [doc]
            return []
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        return []

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not events:
            return [self._empty_result(file_sha256=file_sha256)]
        return [self._build_event_result(e, file_sha256=file_sha256) for e in events]

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "sentry",
            "source_tool_name": "sentry",
            "source_tool_version": "v0",
            "spec_url": "https://docs.sentry.io/api/events/",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _matches_security_keyword(self, *texts: str) -> str | None:
        for text in texts:
            if not text:
                continue
            for pattern in self._security_patterns:
                if fnmatch.fnmatch(text, pattern):
                    return pattern
        return None

    def _build_event_result(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)

        event_id = str(event.get("eventID") or event.get("event_id") or event.get("id") or "")
        group_id = str(event.get("groupID") or event.get("group_id") or "")
        evt_type = str(event.get("type") or "default").lower()
        level = str(event.get("level") or "").lower()
        platform = str(event.get("platform") or "")
        transaction_path = str(event.get("transaction") or "")
        culprit = str(event.get("culprit") or "")
        environment = str(event.get("environment") or "")
        release = str(event.get("release") or "")
        timestamp_raw = event.get("timestamp") or event.get("received") or ""
        is_unhandled = bool(event.get("is_unhandled"))
        is_resolved = bool(event.get("is_resolved"))
        event_count = _coerce_int(event.get("event_count")) or 0
        user_count = _coerce_int(event.get("user_count")) or 0
        title_raw = str(event.get("title") or "")
        fingerprint = event.get("fingerprint")

        contexts = event.get("contexts") if isinstance(event.get("contexts"), dict) else {}
        ai_ctx = contexts.get("ai") if isinstance(contexts.get("ai"), dict) else {}
        trace_ctx = contexts.get("trace") if isinstance(contexts.get("trace"), dict) else {}
        user_ctx = contexts.get("user") if isinstance(contexts.get("user"), dict) else {}
        runtime_ctx = contexts.get("runtime") if isinstance(contexts.get("runtime"), dict) else {}
        browser_ctx = contexts.get("browser") if isinstance(contexts.get("browser"), dict) else {}

        ai_operation = str(ai_ctx.get("operation") or "").lower() if ai_ctx else ""
        ai_model = ai_ctx.get("model") if ai_ctx else None
        ai_input_tokens = _coerce_int(ai_ctx.get("input_tokens")) if ai_ctx else None
        ai_output_tokens = _coerce_int(ai_ctx.get("output_tokens")) if ai_ctx else None
        ai_total_tokens = _coerce_int(ai_ctx.get("total_tokens")) if ai_ctx else None
        ai_tool_name = ai_ctx.get("tool_name") if ai_ctx else None
        ai_pipeline_name = ai_ctx.get("pipeline_name") if ai_ctx else None
        ai_quality_score = _coerce_float(ai_ctx.get("response_quality_score")) if ai_ctx else None

        tags = _tags_to_dict(event.get("tags"))
        agent_framework = tags.get("agent.framework") or tags.get("framework")

        exception_summary = _summarize_exception(event.get("exception"))
        first_exception_type = ""
        first_exception_value_present = False
        # Surface the first exception's type for routing/detail (value stays redacted).
        if exception_summary.get("present"):
            values = exception_summary.get("values") or []
            if values:
                first_exception_type = str(values[0].get("type") or "")
                first_exception_value_present = bool(
                    (values[0].get("value_redacted") or {}).get("present")
                )

        title_redacted = _truncate_with_hash(title_raw)

        priority = "high" if (
            environment == "production" and level in ("fatal", "error", "critical")
        ) else "normal"

        widespread = (
            event_count > self.group_event_threshold
            and user_count > self.group_user_threshold
        )

        # Original raw exception value — used ONLY for keyword matching, not stored.
        raw_exception_values: list[str] = []
        exc_block = event.get("exception")
        if isinstance(exc_block, dict):
            for v in exc_block.get("values") or []:
                if isinstance(v, dict):
                    val = v.get("value")
                    if val:
                        raw_exception_values.append(str(val))
                    typ = v.get("type")
                    if typ:
                        raw_exception_values.append(str(typ))
        keyword_match = self._matches_security_keyword(
            title_raw, *raw_exception_values
        )

        # Common evidence (carefully redacted).
        evidence_data: dict[str, Any] = {
            "eventID": event_id,
            "groupID": group_id,
            "type": evt_type,
            "level": level,
            "platform": platform,
            "transaction": transaction_path,
            "culprit": culprit,
            "environment": environment,
            "release": release,
            "is_unhandled": is_unhandled,
            "is_resolved": is_resolved,
            "event_count": event_count,
            "user_count": user_count,
            "priority": priority,
            "title_redacted": title_redacted,
            "fingerprint_sha256": _hash_fingerprint(fingerprint),
            "tags": tags,
            "agent_framework": agent_framework,
            "ai": {
                "operation": ai_operation or None,
                "model": ai_model,
                "input_tokens": ai_input_tokens,
                "output_tokens": ai_output_tokens,
                "total_tokens": ai_total_tokens,
                "tool_name": ai_tool_name,
                "pipeline_name": ai_pipeline_name,
                "response_quality_score": ai_quality_score,
            },
            "trace": {
                "trace_id": trace_ctx.get("trace_id") if trace_ctx else None,
                "span_id": trace_ctx.get("span_id") if trace_ctx else None,
            },
            "user": {
                "id_masked": _mask_user_id(user_ctx.get("id")) if user_ctx else None,
                "email_domain": _redact_email(user_ctx.get("email")) if user_ctx else None,
            },
            "runtime": {
                "name": runtime_ctx.get("name") if runtime_ctx else None,
                "version": runtime_ctx.get("version") if runtime_ctx else None,
            },
            "browser": {
                "name": browser_ctx.get("name") if browser_ctx else None,
                "version": browser_ctx.get("version") if browser_ctx else None,
            },
            "exception": exception_summary,
            "extra_summary": _summarize_extra(event.get("extra")),
            "source_tool": "sentry",
            "source_provenance": provenance,
        }

        control_results: list[ControlResult] = []
        layered_findings: list[dict[str, Any]] = []
        worst = "PASS"

        # 1. Baseline type/level signal.
        signal: str | None = None
        if evt_type == "error" and level == "fatal":
            signal = "type_error_fatal"
        elif evt_type == "error" and level == "error":
            signal = "type_error_unhandled" if is_unhandled else "type_error_handled"
        elif evt_type == "error" and level == "warning":
            signal = "type_warning"
        elif evt_type == "transaction":
            signal = "type_transaction"
        elif evt_type == "error":
            # error events with non-fatal/error/warning level (e.g. info/debug)
            signal = "type_warning"

        if signal is not None:
            control_id = self._signal_to_control.get(signal, "PR-05")
            result = self._signal_result.get(signal, "PASS")
            worst = _max_result(worst, result)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Sentry {evt_type} event {event_id or '?'} "
                        f"level={level or 'unknown'} unhandled={is_unhandled} "
                        f"transaction={transaction_path or '-'}"
                    ),
                    evidence_data={**evidence_data, "signal": signal},
                )
            )
            layered_findings.append({"signal": signal, "result": result})

        # 2. Low AI response-quality score on transactions.
        if (
            evt_type == "transaction"
            and ai_quality_score is not None
            and ai_quality_score < self.response_quality_threshold
        ):
            control_id = self._signal_to_control.get("low_quality_score", "PR-03")
            result = self._signal_result.get("low_quality_score", "FLAG")
            worst = _max_result(worst, result)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Sentry transaction {event_id or '?'} response_quality_score "
                        f"{ai_quality_score:.3f} < threshold "
                        f"{self.response_quality_threshold:.3f}"
                    ),
                    evidence_data={
                        **evidence_data,
                        "signal": "low_quality_score",
                        "response_quality_score": ai_quality_score,
                        "response_quality_threshold": self.response_quality_threshold,
                    },
                )
            )
            layered_findings.append(
                {"signal": "low_quality_score", "result": result, "score": ai_quality_score}
            )

        # 3. AI operation captures.
        if ai_operation:
            op_signal = f"operation_{ai_operation}"
            if op_signal in self._signal_to_control:
                control_id = self._signal_to_control[op_signal]
                result = self._signal_result.get(op_signal, "PASS")
                worst = _max_result(worst, result)
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=result,
                        detail=(
                            f"Sentry AI Monitoring operation={ai_operation} "
                            f"model={ai_model or '-'} tool={ai_tool_name or '-'}"
                        ),
                        evidence_data={**evidence_data, "signal": op_signal},
                    )
                )
                layered_findings.append({"signal": op_signal, "result": result})

        # 4. Security-keyword detection in exception value or title.
        if keyword_match:
            control_id = self._signal_to_control.get("security_keyword", "PR-01")
            result = self._signal_result.get("security_keyword", "FLAG")
            worst = _max_result(worst, result)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Sentry event {event_id or '?'} matches security keyword "
                        f"pattern '{keyword_match}' "
                        f"(exception_type={first_exception_type or 'unknown'})"
                    ),
                    evidence_data={
                        **evidence_data,
                        "signal": "security_keyword",
                        "matched_pattern": keyword_match,
                        "exception_type": first_exception_type,
                    },
                )
            )
            layered_findings.append(
                {"signal": "security_keyword", "matched_pattern": keyword_match}
            )

        # 5. Widespread group-level error.
        if widespread:
            control_id = self._signal_to_control.get("widespread_error", "PR-04")
            result = self._signal_result.get("widespread_error", "FLAG")
            worst = _max_result(worst, result)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Sentry group {group_id or '?'} widespread: "
                        f"{event_count} events, {user_count} users affected "
                        f"(thresholds {self.group_event_threshold}/"
                        f"{self.group_user_threshold})"
                    ),
                    evidence_data={
                        **evidence_data,
                        "signal": "widespread_error",
                        "group_event_threshold": self.group_event_threshold,
                        "group_user_threshold": self.group_user_threshold,
                    },
                )
            )
            layered_findings.append(
                {
                    "signal": "widespread_error",
                    "event_count": event_count,
                    "user_count": user_count,
                }
            )

        # Guarantee at least one control result.
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Sentry event {event_id or '?'} type={evt_type} imported "
                        f"(no signals matched)"
                    ),
                    evidence_data={**evidence_data, "signal": "default"},
                )
            )

        # Stamp layered_findings on every emitted control result.
        for cr in control_results:
            cr.evidence_data["layered_findings"] = layered_findings

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst, "ALLOW")

        # Timestamp normalization.
        timestamp_iso = self._normalize_timestamp(timestamp_raw)

        action_id = (
            f"sentry-{event_id[:16]}" if event_id else f"sentry-{uuid.uuid4().hex[:8]}"
        )

        decision_reason_parts = [
            f"Sentry {evt_type} event {event_id or '?'}",
            f"level={level or 'unknown'}",
        ]
        if is_unhandled:
            decision_reason_parts.append("unhandled")
        if first_exception_type:
            decision_reason_parts.append(f"exception={first_exception_type}")
        if ai_operation:
            decision_reason_parts.append(f"ai.operation={ai_operation}")
        if widespread:
            decision_reason_parts.append("widespread")
        if keyword_match:
            decision_reason_parts.append("security_keyword")
        decision_reason = " ".join(decision_reason_parts)

        # Mark exception value redaction for the test suite to assert.
        if first_exception_value_present:
            for cr in control_results:
                cr.evidence_data["exception_value_redacted"] = True

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="sentry_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=str(trace_ctx.get("trace_id")) if trace_ctx and trace_ctx.get("trace_id") else None,
        )

    def _normalize_timestamp(self, raw: Any) -> str:
        """Best-effort ISO-8601 timestamp; fall back to UTC now."""
        if raw is None or raw == "":
            return datetime.now(timezone.utc).isoformat()
        if isinstance(raw, (int, float)):
            try:
                return datetime.fromtimestamp(float(raw), tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                return datetime.now(timezone.utc).isoformat()
        s = str(raw)
        # Already ISO-8601 — return as-is.
        try:
            datetime.fromisoformat(s.replace("Z", "+00:00"))
            return s
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    def _empty_result(self, *, file_sha256: str | None) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail="Empty Sentry event export (no events)",
            evidence_data={"source_provenance": provenance, "event_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sentry-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sentry_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty Sentry event export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
