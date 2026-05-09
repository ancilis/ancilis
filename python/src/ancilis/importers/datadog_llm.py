"""Datadog LLM Observability span importer — converts Datadog LLM-Obs span events to AKSI EvaluationResults.

Datadog LLM Observability (https://docs.datadoghq.com/llm_observability/) exposes
agent traces via the ``/api/v2/llm-obs/spans/events/search`` API. The wire format is
either a ``{"data": [...]}`` envelope (per the Datadog v2 API), a single
``{"data": <event>}`` event, or a JSON-Lines stream.

Each span event has a ``kind`` (llm / tool / agent / task / workflow / embedding /
retrieval), an optional ``error`` block when ``status == "error"``, and a list of
``annotations`` produced by Datadog evaluators (faithfulness, hallucination, PII
detection, prompt-injection detection, etc.). The importer maps these signals to
AKSI controls via ``shared/mappings/datadog-llm-aksi-controls.json``:

  - kind=llm / workflow                → PR-01 PASS  (identity / authorized call)
  - kind=tool                          → PR-02 PASS  (scope-checked tool call)
  - kind=embedding / retrieval         → PR-04 PASS  (data access surface)
  - kind=task / agent                  → PR-05 PASS  (audit-trail surface)
  - status=error                       → DE-01 FAIL  (error.type / message in evidence)
  - annotation prompt_injection=true   → PR-01 FAIL  (top-priority security signal)
  - annotation pii_detected=true       → PR-04 FLAG  (exposure)
  - annotation hallucination=yes / score>threshold → PR-03 FLAG (provenance)
  - annotation faithfulness < 0.8      → PR-03 FLAG  (provenance)
  - total_cost > threshold (default $1) → PR-04 FLAG (exposure / governance)

Sanitization: ``meta.input.messages`` and ``meta.output.messages`` are NEVER stored
verbatim. Only a structural summary (count, role distribution, sha256) is kept so
downstream evidence can prove a body existed and detect tampering without leaking
prompt/response content. Annotation labels and scores ARE stored — they are
evaluator outputs, not user data.

The SDK is importable without ``datadog`` or ``ddtrace`` installed; this importer
parses the JSON schema directly.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


def _resolve_mapping_path() -> Path:
    """Locate ``shared/mappings/datadog-llm-aksi-controls.json`` by walking upward."""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "shared" / "mappings" / "datadog-llm-aksi-controls.json"
        if candidate.exists():
            return candidate
    return here.parents[4] / "shared" / "mappings" / "datadog-llm-aksi-controls.json"


_MAPPING_PATH = _resolve_mapping_path()

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

# Default kind → control mapping; overridden by mapping file if present.
_DEFAULT_KIND_TO_CONTROL: dict[str, str] = {
    "llm": "PR-01",
    "workflow": "PR-01",
    "tool": "PR-02",
    "embedding": "PR-04",
    "retrieval": "PR-04",
    "task": "PR-05",
    "agent": "PR-05",
}

_DEFAULT_COST_THRESHOLD_USD = 1.0
_DEFAULT_FAITHFULNESS_THRESHOLD = 0.8
_DEFAULT_HALLUCINATION_SCORE_THRESHOLD = 0.5

# Annotation labels recognized as security-critical (case-insensitive).
_PROMPT_INJECTION_LABELS = {"prompt_injection", "promptinjection", "prompt-injection"}
_PII_LABELS = {"pii_detected", "pii", "pii-detected"}
_HALLUCINATION_LABELS = {"hallucination", "hallucinated"}
_FAITHFULNESS_LABELS = {"faithfulness", "groundedness"}


@dataclass
class _MappingTable:
    kind_to_control: dict[str, str]
    signal_to_control: dict[str, str]
    cost_threshold_usd: float
    faithfulness_threshold: float
    hallucination_score_threshold: float


def _load_mapping_table() -> _MappingTable:
    """Load the Datadog LLM-Obs mapping table; tolerate missing file."""
    kind_to_control: dict[str, str] = {
        f"kind_{k}": v for k, v in _DEFAULT_KIND_TO_CONTROL.items()
    }
    signal_to_control: dict[str, str] = {
        "status_error": "DE-01",
        "prompt_injection": "PR-01",
        "pii_detected": "PR-04",
        "hallucination": "PR-03",
        "low_faithfulness": "PR-03",
        "cost_threshold_exceeded": "PR-04",
    }
    cost_threshold = _DEFAULT_COST_THRESHOLD_USD
    faithfulness_threshold = _DEFAULT_FAITHFULNESS_THRESHOLD
    hallucination_threshold = _DEFAULT_HALLUCINATION_SCORE_THRESHOLD

    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    if isinstance(data, dict):
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                key_str = str(key)
                if key_str.startswith("kind_"):
                    kind_to_control[key_str] = str(value)
                else:
                    signal_to_control[key_str] = str(value)
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            ct = meta.get("default_cost_threshold_usd")
            if isinstance(ct, (int, float)):
                cost_threshold = float(ct)
            ft = meta.get("faithfulness_threshold")
            if isinstance(ft, (int, float)):
                faithfulness_threshold = float(ft)
            ht = meta.get("hallucination_score_threshold")
            if isinstance(ht, (int, float)):
                hallucination_threshold = float(ht)

    return _MappingTable(
        kind_to_control=kind_to_control,
        signal_to_control=signal_to_control,
        cost_threshold_usd=cost_threshold,
        faithfulness_threshold=faithfulness_threshold,
        hallucination_score_threshold=hallucination_threshold,
    )


def _summarize_messages(messages: Any) -> dict[str, Any]:
    """Produce a non-sensitive structural summary of a messages list.

    NEVER stores message text. Captures count, role distribution, and a sha256
    over the JSON-encoded list so downstream evidence can detect tampering
    without leaking content.
    """
    if messages is None:
        return {"present": False}
    if not isinstance(messages, list):
        # Coerce primitives / dict-shaped inputs to a sha-only summary.
        encoded = json.dumps(messages, sort_keys=True, default=str).encode("utf-8")
        return {
            "present": True,
            "kind": type(messages).__name__,
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    role_counts: dict[str, int] = {}
    for m in messages:
        if isinstance(m, dict):
            role = str(m.get("role") or "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1
    encoded = json.dumps(messages, sort_keys=True, default=str).encode("utf-8")
    return {
        "present": True,
        "kind": "list",
        "count": len(messages),
        "role_counts": role_counts,
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _summarize_io(io_block: Any) -> dict[str, Any]:
    """Summarize ``meta.input`` or ``meta.output``; redacts text but keeps shape."""
    if io_block is None:
        return {"present": False}
    if not isinstance(io_block, dict):
        encoded = json.dumps(io_block, sort_keys=True, default=str).encode("utf-8")
        return {
            "present": True,
            "kind": type(io_block).__name__,
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    summary: dict[str, Any] = {"present": True, "kind": "object"}
    if "messages" in io_block:
        summary["messages_summary"] = _summarize_messages(io_block.get("messages"))
    if "value" in io_block:
        # Always treat ``value`` as opaque — never store the text.
        value = io_block.get("value")
        if value is None:
            summary["value_summary"] = {"present": False}
        else:
            text = value if isinstance(value, str) else json.dumps(
                value, sort_keys=True, default=str
            )
            encoded = text.encode("utf-8")
            summary["value_summary"] = {
                "present": True,
                "byte_length": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
    return summary


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool | None:
    """Best-effort bool coercion for annotation scores."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "y", "1"):
            return True
        if v in ("false", "no", "n", "0"):
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return None


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


def _extract_attributes(event: dict[str, Any]) -> dict[str, Any]:
    """Return the span 'attributes' block, accepting both wrapped and flat shapes."""
    attrs = event.get("attributes")
    if isinstance(attrs, dict):
        return attrs
    return event


_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


class DatadogLLMImporter:
    """Parse Datadog LLM Observability span events and convert to EvaluationResults.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        per_trace: when ``True`` group spans by ``trace_id`` and emit one
            EvaluationResult per trace; when ``False`` (default) emit one
            EvaluationResult per span event.
        cost_threshold_usd: override the per-span cost threshold (default from
            mapping metadata, falling back to $1.0).
        faithfulness_threshold: numeric annotation score below which a
            ``faithfulness`` annotation is FLAGged (default 0.8).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        per_trace: bool = False,
        cost_threshold_usd: float | None = None,
        faithfulness_threshold: float | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.per_trace = per_trace
        table = _load_mapping_table()
        self._mappings = table
        self.cost_threshold_usd = (
            float(cost_threshold_usd)
            if cost_threshold_usd is not None
            else table.cost_threshold_usd
        )
        self.faithfulness_threshold = (
            float(faithfulness_threshold)
            if faithfulness_threshold is not None
            else table.faithfulness_threshold
        )

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Datadog LLM-Obs export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = list(self._extract_events(text))
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Datadog LLM-Obs export content from a string (JSON or JSONL)."""
        events = list(self._extract_events(content))
        return self._build_results(events, file_sha256=None)

    # ----------------------------------------------------------------- private
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
            if "attributes" in doc or "kind" in doc or "span_id" in doc:
                return [doc]
            return []
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        return []

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "datadog_llm",
            "source_tool_name": "datadog_llm_observability",
            "source_tool_version": "v2",
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

        if not self.per_trace:
            return [
                self._build_evaluation_for_spans([e], file_sha256=file_sha256)
                for e in events
            ]

        # Group by trace_id, falling back to span_id when trace_id is missing.
        groups: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for e in events:
            attrs = _extract_attributes(e)
            key = str(
                attrs.get("trace_id")
                or attrs.get("span_id")
                or e.get("id")
                or uuid.uuid4().hex
            )
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(e)

        return [
            self._build_evaluation_for_spans(
                groups[k], file_sha256=file_sha256, trace_id=k
            )
            for k in order
        ]

    def _build_evaluation_for_spans(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
        trace_id: str | None = None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        control_results: list[ControlResult] = []
        worst = "PASS"
        total_duration_ms = 0.0
        session_id: str | None = None

        for event in events:
            span_results, span_duration_ms = self._evaluate_span(event, provenance)
            for cr in span_results:
                control_results.append(cr)
                worst = _max_result(worst, cr.result)
            total_duration_ms += span_duration_ms

            attrs = _extract_attributes(event)
            if session_id is None:
                sid = attrs.get("session_id")
                if sid:
                    session_id = str(sid)

        decision = {"FAIL": "BLOCK", "FLAG": "FLAG", "PASS": "ALLOW"}.get(
            worst, "ALLOW"
        )

        first_attrs = _extract_attributes(events[0])
        eff_trace_id = (
            trace_id
            or str(first_attrs.get("trace_id") or first_attrs.get("span_id") or "")
            or uuid.uuid4().hex
        )
        ml_app = first_attrs.get("ml_app") or first_attrs.get("service") or "datadog"

        if self.per_trace:
            action_id = f"datadog-llm-trace-{eff_trace_id[:16]}"
            decision_reason = (
                f"Imported Datadog LLM-Obs trace {eff_trace_id} "
                f"({len(events)} span(s), ml_app={ml_app})"
            )
        else:
            span_id = str(first_attrs.get("span_id") or first_attrs.get("trace_id") or "")
            action_id = f"datadog-llm-span-{(span_id or uuid.uuid4().hex)[:16]}"
            decision_reason = (
                f"Imported Datadog LLM-Obs span {span_id} "
                f"(kind={first_attrs.get('kind', 'unknown')}, ml_app={ml_app})"
            )

        # Use Datadog start_ns when available; else current UTC.
        timestamp = datetime.now(timezone.utc).isoformat()
        start_ns = first_attrs.get("start_ns")
        if isinstance(start_ns, (int, float)) and start_ns > 0:
            with contextlib.suppress(ValueError, OSError, OverflowError):
                timestamp = datetime.fromtimestamp(
                    float(start_ns) / 1_000_000_000.0, tz=timezone.utc
                ).isoformat()

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="datadog_llm_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=total_duration_ms,
            session_id=session_id,
        )

    def _evaluate_span(
        self,
        event: dict[str, Any],
        provenance: dict[str, Any],
    ) -> tuple[list[ControlResult], float]:
        """Return all control results emitted by a single span event + duration ms."""
        attrs = _extract_attributes(event)
        kind = str(attrs.get("kind") or "").lower()
        status = str(attrs.get("status") or "ok").lower()
        meta = attrs.get("meta") if isinstance(attrs.get("meta"), dict) else {}
        metrics = (
            attrs.get("metrics") if isinstance(attrs.get("metrics"), dict) else {}
        )
        annotations = (
            attrs.get("annotations")
            if isinstance(attrs.get("annotations"), list)
            else []
        )

        duration_ns = attrs.get("duration")
        try:
            duration_ms = (
                float(duration_ns) / 1_000_000.0
                if isinstance(duration_ns, (int, float)) and duration_ns > 0
                else 0.0
            )
        except (TypeError, ValueError):
            duration_ms = 0.0

        common_evidence = self._common_evidence(
            attrs, meta, metrics, annotations, provenance, duration_ms
        )

        results: list[ControlResult] = []

        # 1. Baseline kind-based control result.
        baseline = self._kind_baseline_result(
            kind, status, attrs, common_evidence, duration_ms
        )
        if baseline is not None:
            results.append(baseline)

        # 2. status=error → DE-01 FAIL.
        if status == "error":
            error_block = (
                attrs.get("error") if isinstance(attrs.get("error"), dict) else {}
            )
            err_type = str(error_block.get("type") or "")
            err_msg = str(error_block.get("message") or "")
            results.append(
                ControlResult(
                    control_id=self._mappings.signal_to_control.get(
                        "status_error", "DE-01"
                    ),
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=(
                        f"Datadog span {attrs.get('span_id', '?')} kind={kind or 'unknown'} "
                        f"status=error type={err_type or 'unknown'}: {err_msg[:200]}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "status_error",
                        "error_type": err_type,
                        "error_message": err_msg,
                    },
                    duration_ms=duration_ms,
                )
            )

        # 3. Annotation-driven signals.
        results.extend(
            self._annotation_results(
                annotations, attrs, common_evidence, duration_ms
            )
        )

        # 4. Cost threshold.
        total_cost = _coerce_float(metrics.get("total_cost"))
        if total_cost is not None and total_cost > self.cost_threshold_usd:
            results.append(
                ControlResult(
                    control_id=self._mappings.signal_to_control.get(
                        "cost_threshold_exceeded", "PR-04"
                    ),
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="FLAG",
                    detail=(
                        f"Datadog span {attrs.get('span_id', '?')} total_cost "
                        f"${total_cost:.4f} exceeds threshold "
                        f"${self.cost_threshold_usd:.4f}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": "cost_threshold_exceeded",
                        "total_cost": total_cost,
                        "cost_threshold_usd": self.cost_threshold_usd,
                    },
                    duration_ms=duration_ms,
                )
            )

        # Guarantee at least one control result.
        if not results:
            results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Datadog span {attrs.get('span_id', '?')} kind={kind or 'unknown'} "
                        f"imported (no signals matched)"
                    ),
                    evidence_data={**common_evidence, "signal": "kind_default"},
                    duration_ms=duration_ms,
                )
            )

        return results, duration_ms

    def _common_evidence(
        self,
        attrs: dict[str, Any],
        meta: dict[str, Any],
        metrics: dict[str, Any],
        annotations: list[Any],
        provenance: dict[str, Any],
        duration_ms: float,
    ) -> dict[str, Any]:
        meta_metadata = (
            meta.get("metadata") if isinstance(meta.get("metadata"), dict) else {}
        )
        model_name = (
            meta.get("model_name")
            or meta_metadata.get("model_name")
            or attrs.get("model_name")
            or ""
        )
        model_provider = (
            meta.get("model_provider")
            or meta_metadata.get("model_provider")
            or attrs.get("model_provider")
            or ""
        )
        annotations_summary: list[dict[str, Any]] = []
        for ann in annotations:
            if isinstance(ann, dict):
                annotations_summary.append(
                    {
                        "label": ann.get("label"),
                        "score": ann.get("score"),
                        "type": ann.get("type"),
                    }
                )

        return {
            "span_id": attrs.get("span_id"),
            "trace_id": attrs.get("trace_id"),
            "parent_span_id": attrs.get("parent_span_id"),
            "service": attrs.get("service"),
            "session_id": attrs.get("session_id"),
            "ml_app": attrs.get("ml_app"),
            "name": attrs.get("name"),
            "kind": attrs.get("kind"),
            "status": attrs.get("status"),
            "model_name": model_name,
            "model_provider": model_provider,
            "tags": meta.get("tags") if isinstance(meta.get("tags"), list) else [],
            "input_summary": _summarize_io(meta.get("input")),
            "output_summary": _summarize_io(meta.get("output")),
            "input_tokens": metrics.get("input_tokens"),
            "output_tokens": metrics.get("output_tokens"),
            "total_tokens": metrics.get("total_tokens"),
            "input_cost": metrics.get("input_cost"),
            "output_cost": metrics.get("output_cost"),
            "total_cost": metrics.get("total_cost"),
            "duration_ms": duration_ms,
            "annotations": annotations_summary,
            "source_tool": "datadog_llm",
            "source_provenance": provenance,
        }

    def _kind_baseline_result(
        self,
        kind: str,
        status: str,
        attrs: dict[str, Any],
        common_evidence: dict[str, Any],
        duration_ms: float,
    ) -> ControlResult | None:
        """Emit the baseline control result selected by the span's ``kind``.

        When status=error we skip the baseline PASS — the DE-01 FAIL control
        result fully captures the span outcome and a duplicate baseline PASS
        would understate severity.
        """
        if status == "error":
            return None
        signal = f"kind_{kind}" if kind else "kind_default"
        control_id = self._mappings.kind_to_control.get(signal)
        if control_id is None:
            control_id = _DEFAULT_KIND_TO_CONTROL.get(kind, "PR-05")
        control_name = _CONTROL_NAMES.get(control_id, control_id)
        return ControlResult(
            control_id=control_id,
            control_name=control_name,
            result="PASS",
            detail=(
                f"Datadog span {attrs.get('span_id', '?')} kind={kind or 'unknown'} "
                f"status={status} completed"
            ),
            evidence_data={**common_evidence, "signal": signal},
            duration_ms=duration_ms,
        )

    def _annotation_results(
        self,
        annotations: list[Any],
        attrs: dict[str, Any],
        common_evidence: dict[str, Any],
        duration_ms: float,
    ) -> list[ControlResult]:
        """Convert annotation entries into ControlResults for security signals."""
        results: list[ControlResult] = []
        for ann in annotations:
            if not isinstance(ann, dict):
                continue
            label = str(ann.get("label") or "").strip().lower()
            score = ann.get("score")
            ann_type = str(ann.get("type") or "").lower()

            if label in _PROMPT_INJECTION_LABELS:
                detected = _coerce_bool(score)
                if detected is True:
                    results.append(
                        ControlResult(
                            control_id=self._mappings.signal_to_control.get(
                                "prompt_injection", "PR-01"
                            ),
                            control_name=_CONTROL_NAMES["PR-01"],
                            result="FAIL",
                            detail=(
                                f"Datadog evaluator detected prompt injection on span "
                                f"{attrs.get('span_id', '?')} (annotation '{label}')"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": "prompt_injection",
                                "annotation_label": ann.get("label"),
                                "annotation_score": score,
                                "annotation_type": ann.get("type"),
                            },
                            duration_ms=duration_ms,
                        )
                    )
                continue

            if label in _PII_LABELS:
                detected = _coerce_bool(score)
                if detected is True:
                    results.append(
                        ControlResult(
                            control_id=self._mappings.signal_to_control.get(
                                "pii_detected", "PR-04"
                            ),
                            control_name=_CONTROL_NAMES["PR-04"],
                            result="FLAG",
                            detail=(
                                f"Datadog evaluator detected PII on span "
                                f"{attrs.get('span_id', '?')} (annotation '{label}')"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": "pii_detected",
                                "annotation_label": ann.get("label"),
                                "annotation_score": score,
                                "annotation_type": ann.get("type"),
                            },
                            duration_ms=duration_ms,
                        )
                    )
                continue

            if label in _HALLUCINATION_LABELS:
                triggered = False
                if ann_type == "categorical" or isinstance(score, str):
                    triggered = str(score).strip().lower() in (
                        "yes",
                        "true",
                        "hallucinated",
                        "y",
                    )
                else:
                    numeric = _coerce_float(score)
                    if numeric is not None and numeric > self._mappings.hallucination_score_threshold:
                        triggered = True
                    bool_val = _coerce_bool(score)
                    if bool_val is True:
                        triggered = True
                if triggered:
                    results.append(
                        ControlResult(
                            control_id=self._mappings.signal_to_control.get(
                                "hallucination", "PR-03"
                            ),
                            control_name=_CONTROL_NAMES["PR-03"],
                            result="FLAG",
                            detail=(
                                f"Datadog evaluator flagged hallucination on span "
                                f"{attrs.get('span_id', '?')} (annotation '{label}', "
                                f"score={score!r})"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": "hallucination",
                                "annotation_label": ann.get("label"),
                                "annotation_score": score,
                                "annotation_type": ann.get("type"),
                            },
                            duration_ms=duration_ms,
                        )
                    )
                continue

            if label in _FAITHFULNESS_LABELS:
                numeric = _coerce_float(score)
                if numeric is not None and numeric < self.faithfulness_threshold:
                    results.append(
                        ControlResult(
                            control_id=self._mappings.signal_to_control.get(
                                "low_faithfulness", "PR-03"
                            ),
                            control_name=_CONTROL_NAMES["PR-03"],
                            result="FLAG",
                            detail=(
                                f"Datadog faithfulness score {numeric:.3f} below "
                                f"threshold {self.faithfulness_threshold:.3f} on span "
                                f"{attrs.get('span_id', '?')}"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": "low_faithfulness",
                                "annotation_label": ann.get("label"),
                                "annotation_score": numeric,
                                "annotation_type": ann.get("type"),
                                "faithfulness_threshold": self.faithfulness_threshold,
                            },
                            duration_ms=duration_ms,
                        )
                    )
                continue

            # Unknown / custom annotation: captured in common_evidence.annotations.
            # No ControlResult emitted for unknown labels.
        return results

    def _empty_result(self, *, file_sha256: str | None) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail="Empty Datadog LLM-Obs export (no spans)",
            evidence_data={"source_provenance": provenance, "span_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"datadog-llm-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="datadog_llm_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty Datadog LLM-Obs export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
