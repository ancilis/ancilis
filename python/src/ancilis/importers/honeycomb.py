"""Honeycomb for LLMs event importer — converts Honeycomb event spans to AKSI EvaluationResults.

Honeycomb (https://docs.honeycomb.io) is THE distributed-tracing platform for
high-cardinality observability. The 2024 *Honeycomb for LLMs* offering ingests
OpenTelemetry GenAI spans and adds **derivative computed fields** (per-tenant
cost, latency-p95, error-rate over rolling windows) plus **trigger annotations**
(alerts, SLO-burn warnings, BubbleUp anomaly detections).

This importer reads Honeycomb's native event export format from
``/1/events/{dataset}/query`` and converts each event to an
:class:`EvaluationResult`. It interprets:

* Standard ``gen_ai.*`` semconv attributes (matching ``otel_genai.py``) for
  the baseline operation→control mapping (chat/embeddings → PR-01/PR-04;
  execute_tool → PR-02).
* ``status_code=ERROR`` / ``error=true`` → DE-01 FAIL (with ``exception.type``).
* Honeycomb-specific ``honeycomb.trigger.*`` fields:
    - ``trigger.type=alert`` + ``severity=critical`` → DE-01 FAIL
      (Honeycomb already escalated; treat as a confirmed incident).
    - ``trigger.type=slo_burn`` + ``severity=critical`` → PR-05 FAIL
      (SLO burn = production trust degradation; audit-trail integrity).
    - ``trigger.type=anomaly_detection`` → PR-05 FLAG
      (BubbleUp surfaced an anomaly worth human review).
* Honeycomb-specific ``honeycomb.derivative.*`` computed fields:
    - ``error_rate_24h > 0.05`` → PR-03 FLAG (recent prompt/tenant degradation).
    - ``cost_per_tenant_usd_24h > $100`` → PR-04 FLAG (tenant-cost anomaly).
    - ``latency_p95_ms_24h > 30000ms`` → PR-03 FLAG (quality degradation).
* ``prompt.template_id`` present without ``prompt.version`` → PR-05 FLAG
  (un-versioned prompt = unauditable).
* ``agent.framework`` absent on a gen_ai span → PR-05 FLAG (raw API use
  without framework attribution = audit-completeness gap).

Sanitization
------------
* ``exception.message`` is NEVER stored verbatim — only its byte length and
  SHA-256 are kept. Stack traces and exception messages routinely carry user
  input echoed by instrumentation.
* The ``name`` field is truncated to the first 80 characters in evidence;
  some OTel instrumentations interpolate user prompts into span names.

The SDK is importable without ``libhoney`` installed; this module parses the
JSON wire format directly.
"""

from __future__ import annotations

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

_MAPPING_FILENAME = "honeycomb-aksi-controls.json"


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
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

_DEFAULT_OPERATION_TO_CONTROL: dict[str, str] = {
    "chat": "PR-01",
    "text_completion": "PR-01",
    "completion": "PR-01",
    "embeddings": "PR-04",
    "embedding": "PR-04",
    "execute_tool": "PR-02",
    "tool_use": "PR-02",
}

_DEFAULT_ERROR_RATE_THRESHOLD = 0.05
_DEFAULT_TENANT_COST_THRESHOLD_USD = 100.0
_DEFAULT_LATENCY_P95_THRESHOLD_MS = 30000

# Honeycomb interpolates user prompts into span names via some auto-instrumentations.
_MAX_NAME_CHARS = 80


def _load_mapping_table() -> tuple[dict[str, str], dict[str, Any]]:
    """Return (signal→control map, _metadata block). Tolerates missing file."""
    signal_to_control: dict[str, str] = {}
    # Seed with defaults so absent mapping files still produce coherent output.
    for op, ctrl in _DEFAULT_OPERATION_TO_CONTROL.items():
        signal_to_control[f"operation_{op}"] = ctrl
    signal_to_control.update(
        {
            "status_error": "DE-01",
            "trigger_alert_critical": "DE-01",
            "trigger_slo_burn_critical": "PR-05",
            "trigger_anomaly_detection": "PR-05",
            "derivative_high_error_rate_24h": "PR-03",
            "derivative_high_tenant_cost_24h": "PR-04",
            "derivative_high_latency_p95_24h": "PR-03",
            "prompt_unversioned": "PR-05",
            "framework_missing": "PR-05",
        }
    )

    metadata: dict[str, Any] = {}
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    if isinstance(data, dict):
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                signal_to_control[str(key)] = str(value)
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            metadata = meta

    return signal_to_control, metadata


_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
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


def _redact_message(message: Any) -> dict[str, Any]:
    """Return a non-sensitive summary of an exception message.

    Honeycomb instrumentations often echo user inputs into ``exception.message``,
    so the importer NEVER stores the raw text. Length and SHA-256 are sufficient
    to detect tampering and prove a body existed.
    """
    if message is None:
        return {"present": False}
    text = message if isinstance(message, str) else json.dumps(
        message, sort_keys=True, default=str
    )
    encoded = text.encode("utf-8")
    return {
        "present": True,
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _truncate_name(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    return name[:_MAX_NAME_CHARS]


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


def _extract_event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Return the inner ``data`` payload of a Honeycomb event.

    Honeycomb's canonical envelope wraps each event as
    ``{"Timestamp": "...", "data": {...}}``. Some exports flatten this, in
    which case the event itself is the payload.
    """
    inner = event.get("data")
    if isinstance(inner, dict):
        return inner
    return event


def _is_gen_ai_event(payload: dict[str, Any]) -> bool:
    return any(k.startswith("gen_ai.") for k in payload)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class HoneycombImporter:
    """Parse Honeycomb event exports and convert to AKSI EvaluationResults.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        error_rate_threshold: derivative-field threshold for ``error_rate_24h``
            above which a PR-03 FLAG is emitted (default ``0.05`` = 5%).
        tenant_cost_threshold_usd: derivative-field threshold for
            ``cost_per_tenant_usd_24h`` above which a PR-04 FLAG is emitted
            (default $100).
        latency_p95_threshold_ms: derivative-field threshold for
            ``latency_p95_ms_24h`` above which a PR-03 FLAG is emitted
            (default 30000ms = 30s).

    Accepts these wire shapes:
      * Honeycomb canonical: ``{"data": [{"Timestamp": "...", "data": {...}}, ...]}``
      * Flat envelope: ``{"events": [{...}, ...]}``
      * JSONL stream of events
      * A single bare event object
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        error_rate_threshold: float | None = None,
        tenant_cost_threshold_usd: float | None = None,
        latency_p95_threshold_ms: float | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        signal_map, metadata = _load_mapping_table()
        self._signal_to_control = signal_map
        self._metadata = metadata

        meta_err = metadata.get("default_error_rate_threshold")
        meta_cost = metadata.get("default_tenant_cost_threshold_usd")
        meta_lat = metadata.get("default_latency_p95_threshold_ms")

        self.error_rate_threshold = (
            float(error_rate_threshold)
            if error_rate_threshold is not None
            else (float(meta_err) if isinstance(meta_err, (int, float)) else _DEFAULT_ERROR_RATE_THRESHOLD)
        )
        self.tenant_cost_threshold_usd = (
            float(tenant_cost_threshold_usd)
            if tenant_cost_threshold_usd is not None
            else (
                float(meta_cost)
                if isinstance(meta_cost, (int, float))
                else _DEFAULT_TENANT_COST_THRESHOLD_USD
            )
        )
        self.latency_p95_threshold_ms = (
            float(latency_p95_threshold_ms)
            if latency_p95_threshold_ms is not None
            else (
                float(meta_lat)
                if isinstance(meta_lat, (int, float))
                else _DEFAULT_LATENCY_P95_THRESHOLD_MS
            )
        )

    # ---------------------------------------------------------------- public

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Honeycomb export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = list(self._extract_events(text))
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Honeycomb export content from a string."""
        events = list(self._extract_events(content))
        return self._build_results(events, file_sha256=None)

    # --------------------------------------------------------------- private

    def _extract_events(self, content: str) -> Iterable[dict[str, Any]]:
        if not content.strip():
            return []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return list(_iter_jsonl(content))

        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        if isinstance(doc, dict):
            for key in ("data", "events", "results"):
                arr = doc.get(key)
                if isinstance(arr, list):
                    return [e for e in arr if isinstance(e, dict)]
            # Bare single event (either canonical wrap or flat).
            if "data" in doc and isinstance(doc.get("data"), dict):
                return [doc]
            # Flat event lacking envelope.
            if any(k.startswith("gen_ai.") or k.startswith("honeycomb.") for k in doc):
                return [doc]
            if "Timestamp" in doc or "trace.trace_id" in doc or "name" in doc:
                return [doc]
            return []
        return []

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "honeycomb",
            "source_tool_name": "honeycomb",
            "source_tool_version": self._metadata.get("schema", "honeycomb-events-v1"),
            "spec_url": self._metadata.get(
                "spec_url", "https://docs.honeycomb.io/api/tag/Events/"
            ),
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not events:
            return [self._empty_result(file_sha256=file_sha256)]
        return [
            self._build_evaluation_for_event(e, file_sha256=file_sha256)
            for e in events
        ]

    def _build_evaluation_for_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        payload = _extract_event_data(event)

        common = self._common_evidence(event, payload, provenance)
        control_results = self._evaluate_event(payload, common)

        worst = "PASS"
        for cr in control_results:
            worst = _max_result(worst, cr.result)

        decision = {"FAIL": "BLOCK", "FLAG": "FLAG", "PASS": "ALLOW"}.get(
            worst, "ALLOW"
        )
        if decision == "BLOCK" and self.mode != "enforce":
            decision = "FLAG"

        trace_id = str(payload.get("trace.trace_id") or "")
        span_id = str(payload.get("trace.span_id") or "")
        action_id = (
            f"honeycomb-{(span_id or trace_id or uuid.uuid4().hex)[:16]}"
        )

        ts = (
            event.get("Timestamp")
            or payload.get("Timestamp")
            or payload.get("timestamp")
        )
        if not isinstance(ts, str) or not ts:
            ts = datetime.now(timezone.utc).isoformat()

        operation = str(payload.get("gen_ai.operation.name") or "") or "unknown"
        decision_reason = (
            f"Imported Honeycomb event span={span_id or '?'} "
            f"operation={operation} status={payload.get('status_code', 'UNSET')}"
        )

        duration_ms = _coerce_float(payload.get("duration_ms")) or 0.0

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=ts,
            agent_id=self.agent_id,
            source_type="honeycomb_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=trace_id or None,
        )

    # ---- Per-event evaluation -------------------------------------------

    def _common_evidence(
        self,
        event: dict[str, Any],
        payload: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        """Capture the field set required for downstream evidence reconstruction."""
        evidence: dict[str, Any] = {
            "trace_id": payload.get("trace.trace_id"),
            "span_id": payload.get("trace.span_id"),
            "parent_span_id": payload.get("trace.parent_id"),
            "name": _truncate_name(payload.get("name")),
            "service_name": payload.get("service.name"),
            "duration_ms": _coerce_float(payload.get("duration_ms")),
            "status_code": payload.get("status_code"),
            "error": _coerce_bool(payload.get("error")),
            "gen_ai_system": payload.get("gen_ai.system"),
            "gen_ai_operation": payload.get("gen_ai.operation.name"),
            "gen_ai_request_model": payload.get("gen_ai.request.model"),
            "gen_ai_response_model": payload.get("gen_ai.response.model"),
            "gen_ai_input_tokens": _coerce_int(
                payload.get("gen_ai.usage.input_tokens")
            ),
            "gen_ai_output_tokens": _coerce_int(
                payload.get("gen_ai.usage.output_tokens")
            ),
            "honeycomb_cost_usd": _coerce_float(payload.get("honeycomb.cost_usd")),
            "honeycomb_trigger_type": payload.get("honeycomb.trigger.type"),
            "honeycomb_trigger_severity": payload.get("honeycomb.trigger.severity"),
            "honeycomb_derivative_cost_per_tenant_usd_24h": _coerce_float(
                payload.get("honeycomb.derivative.cost_per_tenant_usd_24h")
            ),
            "honeycomb_derivative_latency_p95_ms_24h": _coerce_float(
                payload.get("honeycomb.derivative.latency_p95_ms_24h")
            ),
            "honeycomb_derivative_error_rate_24h": _coerce_float(
                payload.get("honeycomb.derivative.error_rate_24h")
            ),
            "honeycomb_bubbleup_dimensions": payload.get(
                "honeycomb.bubbleup.dimensions"
            ),
            "agent_framework": payload.get("agent.framework"),
            "agent_tenant_id": payload.get("agent.tenant_id"),
            "prompt_template_id": payload.get("prompt.template_id"),
            "prompt_version": payload.get("prompt.version"),
            "exception_type": payload.get("exception.type"),
            "exception_message_summary": _redact_message(
                payload.get("exception.message")
            ),
            "envelope_timestamp": event.get("Timestamp"),
            "source_tool": "honeycomb",
            "source_provenance": provenance,
        }
        return evidence

    def _evaluate_event(
        self,
        payload: dict[str, Any],
        common: dict[str, Any],
    ) -> list[ControlResult]:
        results: list[ControlResult] = []
        duration_ms = _coerce_float(payload.get("duration_ms")) or 0.0
        span_id = str(payload.get("trace.span_id") or "?")

        is_gen_ai = _is_gen_ai_event(payload)
        operation = str(payload.get("gen_ai.operation.name") or "").strip().lower()
        status_code = str(payload.get("status_code") or "").strip().upper()
        error_flag = _coerce_bool(payload.get("error")) is True
        is_error = error_flag or status_code == "ERROR"

        # 1. Baseline operation→control PASS for non-error gen_ai spans.
        if is_gen_ai and not is_error:
            signal = f"operation_{operation}" if operation else "operation_unknown"
            control_id = self._signal_to_control.get(
                signal,
                _DEFAULT_OPERATION_TO_CONTROL.get(operation, "PR-03"),
            )
            results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Honeycomb event span={span_id} operation={operation or 'unknown'} "
                        f"status={status_code or 'UNSET'} completed"
                    ),
                    evidence_data={**common, "signal": signal},
                    duration_ms=duration_ms,
                )
            )

        # 2. status_code=ERROR / error=true → DE-01 FAIL.
        if is_error:
            err_type = payload.get("exception.type") or ""
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get("status_error", "DE-01"),
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=(
                        f"Honeycomb event span={span_id} status={status_code or 'ERROR'} "
                        f"exception.type={err_type or 'unknown'}"
                    ),
                    evidence_data={
                        **common,
                        "signal": "status_error",
                        "error_type": err_type,
                    },
                    duration_ms=duration_ms,
                )
            )

        # 3. Honeycomb trigger annotations.
        trigger_type = str(payload.get("honeycomb.trigger.type") or "").strip().lower()
        trigger_severity = (
            str(payload.get("honeycomb.trigger.severity") or "").strip().lower()
        )

        if trigger_type == "alert" and trigger_severity == "critical":
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "trigger_alert_critical", "DE-01"
                    ),
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=(
                        f"Honeycomb critical alert fired on span={span_id} "
                        f"(Honeycomb already escalated this trace)"
                    ),
                    evidence_data={
                        **common,
                        "signal": "trigger_alert_critical",
                        "trigger_type": "alert",
                        "trigger_severity": "critical",
                    },
                    duration_ms=duration_ms,
                )
            )
        elif trigger_type == "slo_burn" and trigger_severity == "critical":
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "trigger_slo_burn_critical", "PR-05"
                    ),
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FAIL",
                    detail=(
                        f"Honeycomb SLO burn (critical) on span={span_id} — "
                        f"production trust degradation"
                    ),
                    evidence_data={
                        **common,
                        "signal": "trigger_slo_burn_critical",
                        "trigger_type": "slo_burn",
                        "trigger_severity": "critical",
                    },
                    duration_ms=duration_ms,
                )
            )
        elif trigger_type == "anomaly_detection":
            dims = payload.get("honeycomb.bubbleup.dimensions")
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "trigger_anomaly_detection", "PR-05"
                    ),
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Honeycomb BubbleUp anomaly on span={span_id} "
                        f"dimensions={dims or 'unknown'}"
                    ),
                    evidence_data={
                        **common,
                        "signal": "trigger_anomaly_detection",
                        "trigger_type": "anomaly_detection",
                        "trigger_severity": trigger_severity or None,
                        "bubbleup_dimensions": dims,
                    },
                    duration_ms=duration_ms,
                )
            )

        # 4. Derivative-field threshold breaches.
        error_rate = _coerce_float(payload.get("honeycomb.derivative.error_rate_24h"))
        if error_rate is not None and error_rate > self.error_rate_threshold:
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "derivative_high_error_rate_24h", "PR-03"
                    ),
                    control_name=_CONTROL_NAMES["PR-03"],
                    result="FLAG",
                    detail=(
                        f"Honeycomb 24h error_rate {error_rate:.4f} exceeds threshold "
                        f"{self.error_rate_threshold:.4f} on span={span_id}"
                    ),
                    evidence_data={
                        **common,
                        "signal": "derivative_high_error_rate_24h",
                        "error_rate_24h": error_rate,
                        "error_rate_threshold": self.error_rate_threshold,
                    },
                    duration_ms=duration_ms,
                )
            )

        tenant_cost = _coerce_float(
            payload.get("honeycomb.derivative.cost_per_tenant_usd_24h")
        )
        if tenant_cost is not None and tenant_cost > self.tenant_cost_threshold_usd:
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "derivative_high_tenant_cost_24h", "PR-04"
                    ),
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="FLAG",
                    detail=(
                        f"Honeycomb 24h tenant cost ${tenant_cost:.2f} exceeds "
                        f"threshold ${self.tenant_cost_threshold_usd:.2f} on span={span_id}"
                    ),
                    evidence_data={
                        **common,
                        "signal": "derivative_high_tenant_cost_24h",
                        "cost_per_tenant_usd_24h": tenant_cost,
                        "tenant_cost_threshold_usd": self.tenant_cost_threshold_usd,
                    },
                    duration_ms=duration_ms,
                )
            )

        latency_p95 = _coerce_float(
            payload.get("honeycomb.derivative.latency_p95_ms_24h")
        )
        if latency_p95 is not None and latency_p95 > self.latency_p95_threshold_ms:
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "derivative_high_latency_p95_24h", "PR-03"
                    ),
                    control_name=_CONTROL_NAMES["PR-03"],
                    result="FLAG",
                    detail=(
                        f"Honeycomb 24h latency_p95 {latency_p95:.0f}ms exceeds "
                        f"threshold {self.latency_p95_threshold_ms:.0f}ms on span={span_id}"
                    ),
                    evidence_data={
                        **common,
                        "signal": "derivative_high_latency_p95_24h",
                        "latency_p95_ms_24h": latency_p95,
                        "latency_p95_threshold_ms": self.latency_p95_threshold_ms,
                    },
                    duration_ms=duration_ms,
                )
            )

        # 5. Un-versioned prompt template.
        prompt_template_id = payload.get("prompt.template_id")
        prompt_version = payload.get("prompt.version")
        if prompt_template_id and not prompt_version:
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "prompt_unversioned", "PR-05"
                    ),
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Honeycomb event span={span_id} carries prompt.template_id="
                        f"{prompt_template_id!r} without prompt.version "
                        f"(un-versioned prompt = unauditable)"
                    ),
                    evidence_data={
                        **common,
                        "signal": "prompt_unversioned",
                        "prompt_template_id": prompt_template_id,
                    },
                    duration_ms=duration_ms,
                )
            )

        # 6. Missing framework attribution on a gen_ai span.
        if is_gen_ai and not payload.get("agent.framework"):
            results.append(
                ControlResult(
                    control_id=self._signal_to_control.get(
                        "framework_missing", "PR-05"
                    ),
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Honeycomb gen_ai span={span_id} lacks agent.framework "
                        f"(raw API use without framework attribution = audit-completeness gap)"
                    ),
                    evidence_data={
                        **common,
                        "signal": "framework_missing",
                    },
                    duration_ms=duration_ms,
                )
            )

        # Guarantee at least one ControlResult for traceability.
        if not results:
            results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Honeycomb event span={span_id} imported (no signals matched)"
                    ),
                    evidence_data={**common, "signal": "default"},
                    duration_ms=duration_ms,
                )
            )

        return results

    def _empty_result(self, *, file_sha256: str | None) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail="Empty Honeycomb export (no events)",
            evidence_data={"source_provenance": provenance, "event_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"honeycomb-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="honeycomb_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty Honeycomb export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
