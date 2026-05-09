"""Weights & Biases Weave call importer — converts Weave call exports to AKSI EvaluationResults.

W&B Weave (https://weave.wandb.ai) is W&B's LLM-observability + evaluation platform. ML
teams already on W&B for model training universally adopt Weave for agent evaluation,
so an Ancilis importer for Weave is required to bring those teams' evidence into the
same posture/audit pipeline as runtime traces.

Accepted shapes (all from `/api/v2/calls/stream_query` or equivalent exports):

    {"calls": [...]}                # canonical Weave envelope
    {"data":  [...]}                # alternative envelope used by some Weave exports
    [...]                           # bare list of calls
    {<single call object>}          # bare single-call object
    JSONL                           # one call per line

Modes:

  * Default (per-call):  one ``EvaluationResult`` per call. Each call yields one or
    more ``ControlResult`` records — at least one for the op_name → control mapping,
    plus one per named score in ``summary.scores``, plus one per negative feedback
    record, plus one DE-01 FAIL when the call exception field is populated.
  * ``per_trace=True``:  calls are grouped by ``trace_id`` (or ``traceId``), and one
    aggregate ``EvaluationResult`` is emitted per trace. Score values are mean-aggregated
    across the trace's calls and bucketed against the same threshold bands as per-call
    mode.

Sanitization:

The Weave export's ``inputs`` and ``output`` fields contain raw user/assistant text
and tool I/O. Per the SDK no-PII guarantee these are NEVER persisted — only structural
counts (top-level keys, byte length) and a sha256 of the JSON-encoded value are kept.

Op-name → AKSI control mapping (configured in
``shared/mappings/wandb-weave-aksi-controls.json``):

  * ``*.ChatCompletion.*`` / ``*.Messages.*`` / ``llm.*``  → PR-01 (Identity)
  * ``*.Evaluation.*`` / ``weave.summarize``                → PR-03 (Provenance)
  * ``tool.*``                                              → PR-02 (Scope)
  * ``embedding.*`` / ``*.embeddings.*``                    → PR-04 (Exposure)
  * exception present                                       → DE-01 FAIL
  * negative feedback (``thumbs_down``)                     → PR-05 FLAG

Score → AKSI control + thresholds (mirrors the Braintrust importer):

  * faithfulness, factuality, groundedness     → PR-03 (high=PASS, low=FAIL)
  * hallucination, hallucination_rate          → PR-03 INVERTED (low=PASS, high=FAIL)
  * toxicity, bias                             → PR-03 INVERTED (low=PASS, high=FAIL)
  * safety                                     → DE-01 (high=PASS, low=FAIL)
  * relevance                                  → PR-04 (high=PASS, low=FAIL)

Threshold bucketing (overridable via ``_metadata.thresholds`` in the mapping file):

  * score >= 0.9                  → PASS
  * 0.7 <= score < 0.9            → FLAG
  * score < 0.7                   → FAIL

Inverted threshold bucketing (overridable via ``_metadata.inverted_thresholds``):

  * score <= 0.05                 → PASS
  * 0.05 < score <= 0.3           → FLAG
  * score > 0.3                   → FAIL
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping file lives at <repo>/shared/mappings/wandb-weave-aksi-controls.json.
# This source file lives at <repo>/python/src/ancilis/importers/wandb_weave.py,
# so .resolve() + 5 .parent traversals land at the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "wandb-weave-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Identity & Authentication",
    "PR-02": "Scope & Authorization",
    "PR-03": "Provenance & Input Validation",
    "PR-04": "Exposure & Data Access",
    "PR-05": "Audit Trail & Chain of Custody",
    "DE-01": "Baseline Detection",
}

_DEFAULT_UNMAPPED_CONTROL = "PR-05"

# Default thresholds — overridden by the mapping file's `_metadata.thresholds` block.
_DEFAULT_PASS_MIN = 0.9
_DEFAULT_FLAG_MIN = 0.7
# For inverted scorers (lower-is-better) the same band shape is mirrored.
_DEFAULT_INVERTED_PASS_MAX = 0.05
_DEFAULT_INVERTED_FLAG_MAX = 0.3

_DEFAULT_INVERTED_SCORES: tuple[str, ...] = (
    "hallucination",
    "hallucination_rate",
    "toxicity",
    "bias",
    "harm",
    "harmfulness",
)

_DEFAULT_OP_PATTERNS: tuple[tuple[str, str], ...] = (
    ("*.ChatCompletion.*", "PR-01"),
    ("*.Messages.*", "PR-01"),
    ("llm.*", "PR-01"),
    ("*.Evaluation.*", "PR-03"),
    ("weave.summarize", "PR-03"),
    ("weave.Evaluation.*", "PR-03"),
    ("tool.*", "PR-02"),
    ("embedding.*", "PR-04"),
    ("*.embeddings.*", "PR-04"),
)


@dataclass
class _MappingTable:
    score_to_control: dict[str, str] = field(default_factory=dict)
    score_aliases: dict[str, str] = field(default_factory=dict)
    inverted_scores: set[str] = field(default_factory=set)
    op_patterns: list[tuple[str, str]] = field(default_factory=list)
    pass_min: float = _DEFAULT_PASS_MIN
    flag_min: float = _DEFAULT_FLAG_MIN
    inverted_pass_max: float = _DEFAULT_INVERTED_PASS_MAX
    inverted_flag_max: float = _DEFAULT_INVERTED_FLAG_MAX
    default_control: str = _DEFAULT_UNMAPPED_CONTROL


def _load_mapping_table() -> _MappingTable:
    """Load wandb-weave-aksi-controls.json, tolerating a missing or malformed file."""
    table = _MappingTable(
        inverted_scores=set(_DEFAULT_INVERTED_SCORES),
        op_patterns=list(_DEFAULT_OP_PATTERNS),
    )
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return table

    raw_scores = data.get("score_mappings") or data.get("mappings") or {}
    if isinstance(raw_scores, dict):
        table.score_to_control = {
            str(k).lower(): str(v) for k, v in raw_scores.items()
        }

    meta = data.get("_metadata", {}) or {}
    if isinstance(meta, dict):
        thresholds = meta.get("thresholds", {})
        if isinstance(thresholds, dict):
            # Accept both `pass_min` (Braintrust style) and `pass_threshold`
            # (the spec's preferred name) so the mapping file can use either.
            table.pass_min = float(
                thresholds.get(
                    "pass_threshold",
                    thresholds.get("pass_min", _DEFAULT_PASS_MIN),
                )
            )
            table.flag_min = float(
                thresholds.get(
                    "flag_threshold",
                    thresholds.get("flag_min", _DEFAULT_FLAG_MIN),
                )
            )

        inverted_thresholds = meta.get("inverted_thresholds", {})
        if isinstance(inverted_thresholds, dict):
            table.inverted_pass_max = float(
                inverted_thresholds.get(
                    "inverted_pass_threshold",
                    inverted_thresholds.get("pass_max", _DEFAULT_INVERTED_PASS_MAX),
                )
            )
            table.inverted_flag_max = float(
                inverted_thresholds.get(
                    "inverted_flag_threshold",
                    inverted_thresholds.get("flag_max", _DEFAULT_INVERTED_FLAG_MAX),
                )
            )

        inverted = meta.get("inverted_scores")
        if isinstance(inverted, list):
            table.inverted_scores = {str(s).lower() for s in inverted}

        aliases = meta.get("score_aliases", {})
        if isinstance(aliases, dict):
            table.score_aliases = {
                str(k).lower(): str(v).lower() for k, v in aliases.items()
            }

        default_ctrl = meta.get("default_unmapped_control")
        if isinstance(default_ctrl, str) and default_ctrl:
            table.default_control = default_ctrl

        op_patterns = meta.get("op_patterns")
        if isinstance(op_patterns, list):
            parsed: list[tuple[str, str]] = []
            for entry in op_patterns:
                if not isinstance(entry, dict):
                    continue
                pattern = entry.get("pattern")
                control = entry.get("control")
                if isinstance(pattern, str) and isinstance(control, str):
                    parsed.append((pattern, control))
            if parsed:
                table.op_patterns = parsed

    return table


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL string, skipping blank lines."""
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


def _coerce_float(value: Any) -> float | None:
    """Coerce a value to float, returning None for non-finite or non-numeric inputs."""
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _extract_score_value(raw: Any) -> float | None:
    """Pull a numeric score out of a Weave score record.

    Weave aggregates scores as ``{"mean": float, "stderr": float, ...}`` after
    an Evaluation.summarize, but per-call user scores are often stored as bare
    floats. Some scorers return nested dicts like ``{"score": 0.92}`` or
    ``{"value": 0.92}``. Return None when no numeric value is recoverable.
    """
    if isinstance(raw, dict):
        for key in ("mean", "score", "value", "average"):
            if key in raw:
                f = _coerce_float(raw[key])
                if f is not None:
                    return f
        return None
    return _coerce_float(raw)


def _stringify(value: Any) -> str:
    """Render a Weave inputs/output value to a single string for hashing only."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _summarize_payload(value: Any) -> dict[str, Any]:
    """Reduce inputs/output to a content-free structural summary.

    The full text is intentionally NEVER stored — only the type, top-level keys
    (for objects), byte length, and a sha256 over the JSON-encoded value. This
    keeps the importer compatible with the SDK's no-raw-text guarantee while
    still letting downstream consumers prove the payload existed and detect
    tampering.
    """
    if value is None:
        return {"present": False}
    encoded = _stringify(value).encode("utf-8")
    summary: dict[str, Any] = {
        "present": True,
        "kind": type(value).__name__,
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    if isinstance(value, dict):
        summary["top_level_keys"] = sorted(str(k) for k in value)
    elif isinstance(value, list):
        summary["length"] = len(value)
    return summary


def _bucket_score(
    score: float,
    *,
    inverted: bool,
    table: _MappingTable,
) -> str:
    """Return PASS / FLAG / FAIL for a numeric score, using normal or inverted bands."""
    if inverted:
        if score <= table.inverted_pass_max:
            return "PASS"
        if score <= table.inverted_flag_max:
            return "FLAG"
        return "FAIL"
    if score >= table.pass_min:
        return "PASS"
    if score >= table.flag_min:
        return "FLAG"
    return "FAIL"


_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _decision_from(worst: str) -> str:
    return {"PASS": "ALLOW", "FLAG": "FLAG", "FAIL": "BLOCK"}.get(worst, "ALLOW")


def _latency_from_iso(started: str | None, ended: str | None) -> float | None:
    """Compute latency in ms from ISO-8601 started/ended timestamps."""
    if not (isinstance(started, str) and isinstance(ended, str) and started and ended):
        return None
    try:
        t0 = datetime.fromisoformat(started.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(ended.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0.0, (t1 - t0).total_seconds() * 1000.0)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class WandbWeaveImporter:
    """Parse a W&B Weave call export and convert to ``EvaluationResult`` records.

    Args:
      agent_id: Logical agent ID stamped onto produced EvaluationResults.
      mode: ``"audit"`` or ``"enforce"`` — recorded on every produced result.
      per_trace: When True, group calls by ``trace_id`` and emit one
        EvaluationResult per trace; when False (default), emit one
        EvaluationResult per call.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        per_trace: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.per_trace = bool(per_trace)
        self._table = _load_mapping_table()

    # ------------------------------------------------------------------ public

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Weave call export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        return self._parse_text(text, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a Weave call export from a string (JSON or JSONL)."""
        return self._parse_text(content, file_sha256=None)

    # ----------------------------------------------------------------- private

    def _parse_text(
        self,
        text: str,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        calls = self._extract_calls(text)
        if not calls:
            return []
        if self.per_trace:
            return self._aggregate_by_trace(calls, file_sha256=file_sha256)
        return [
            self._call_to_result(call, file_sha256=file_sha256) for call in calls
        ]

    def _extract_calls(self, text: str) -> list[dict[str, Any]]:
        """Return the list of call dicts for every supported input shape."""
        stripped = text.lstrip()
        if not stripped:
            return []

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Fall through to JSONL.
                return list(_iter_jsonl(text))

            if isinstance(doc, dict):
                for key in ("calls", "data"):
                    raw = doc.get(key)
                    if isinstance(raw, list):
                        return [c for c in raw if isinstance(c, dict)]
                # Unknown object shape — treat as a single bare call.
                return [doc]

            if isinstance(doc, list):
                return [c for c in doc if isinstance(c, dict)]
            return []

        # Treat as JSONL.
        return list(_iter_jsonl(text))

    # ---------- op_name → control resolution -------------------------------

    def _control_for_op(self, op_name: str) -> str | None:
        """Return the AKSI control for a Weave op_name via fnmatch patterns.

        Patterns are tried in declaration order; the first match wins. Returns
        None when no pattern matches so the caller can fall back to the default
        control or skip emitting an op-level ControlResult.
        """
        if not op_name:
            return None
        for pattern, control in self._table.op_patterns:
            if fnmatch.fnmatchcase(op_name, pattern):
                return control
        return None

    def _resolve_score_name(self, score_name: str) -> str:
        normalized = score_name.lower()
        return self._table.score_aliases.get(normalized, normalized)

    def _control_for_score(self, score_name: str) -> str:
        resolved = self._resolve_score_name(score_name)
        return self._table.score_to_control.get(resolved, self._table.default_control)

    def _is_inverted(self, score_name: str) -> bool:
        return self._resolve_score_name(score_name) in self._table.inverted_scores

    # ---------- record builders --------------------------------------------

    def _call_provenance(
        self,
        call: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        """Build the source_provenance block for a single Weave call."""
        provenance: dict[str, Any] = {
            "source_format": "wandb_weave",
            "source_tool_name": "wandb_weave",
            "source_tool_version": "",
            "call_id": str(call.get("id", "")),
            "trace_id": str(call.get("trace_id") or call.get("traceId") or ""),
            "parent_id": str(call.get("parent_id") or call.get("parentId") or ""),
            "op_name": str(call.get("op_name") or call.get("opName") or ""),
        }
        wb_run_id = call.get("wb_run_id") or call.get("wbRunId")
        if wb_run_id:
            provenance["wb_run_id"] = str(wb_run_id)
        wb_user_id = call.get("wb_user_id") or call.get("wbUserId")
        if wb_user_id:
            provenance["wb_user_id"] = str(wb_user_id)
        attributes = call.get("attributes")
        if isinstance(attributes, dict) and attributes:
            # Surface the most common scalar attributes (model, temperature) without
            # forcing consumers to drill into source_provenance.
            provenance["attributes"] = dict(attributes)
            model = attributes.get("model")
            if isinstance(model, str) and model:
                provenance["model"] = model
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _call_evidence_base(
        self,
        call: dict[str, Any],
        *,
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        """Common evidence_data fields shared by every ControlResult on a call."""
        summary = call.get("summary") or {}
        weave_meta = summary.get("weave") if isinstance(summary, dict) else {}
        usage = summary.get("usage") if isinstance(summary, dict) else {}

        latency_ms: float | None = None
        trace_name = ""
        if isinstance(weave_meta, dict):
            trace_name = str(weave_meta.get("trace_name") or "")
            latency_ms = _coerce_float(weave_meta.get("latency_ms"))
        if latency_ms is None:
            latency_ms = _latency_from_iso(
                call.get("started_at") or call.get("startedAt"),
                call.get("ended_at") or call.get("endedAt"),
            )

        token_usage: dict[str, Any] = {}
        if isinstance(usage, dict):
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                v = _coerce_float(usage.get(key))
                if v is not None:
                    token_usage[key] = int(v)

        evidence: dict[str, Any] = {
            "call_id": provenance["call_id"],
            "trace_id": provenance["trace_id"],
            "op_name": provenance["op_name"],
            "trace_name": trace_name,
            "latency_ms": latency_ms or 0.0,
            "wb_run_id": provenance.get("wb_run_id", ""),
            "wb_user_id": provenance.get("wb_user_id", ""),
            "token_usage": token_usage,
            "inputs_summary": _summarize_payload(call.get("inputs")),
            "output_summary": _summarize_payload(call.get("output")),
            "tags": list(call.get("tags") or []),
            "feedback_count": int(_coerce_float(call.get("feedback_count")) or 0),
            "source_tool": "wandb_weave",
            "source_provenance": provenance,
        }
        return evidence

    def _call_to_result(
        self,
        call: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._call_provenance(call, file_sha256=file_sha256)
        call_id = provenance["call_id"] or uuid.uuid4().hex[:12]
        op_name = provenance["op_name"] or "weave-call"
        common_evidence = self._call_evidence_base(call, provenance=provenance)

        control_results: list[ControlResult] = []
        worst = "PASS"

        # 1. Op-name → control mapping (always emit at least one ControlResult).
        op_control = self._control_for_op(op_name) or self._table.default_control
        op_result = "PASS"
        op_detail = f"Weave op '{op_name}' on call {call_id}"
        control_results.append(
            ControlResult(
                control_id=op_control,
                control_name=_CONTROL_NAMES.get(op_control, op_control),
                result=op_result,
                detail=op_detail,
                evidence_data={**common_evidence, "evidence_kind": "op_name"},
                duration_ms=common_evidence["latency_ms"],
            )
        )

        # 2. Exception → DE-01 FAIL.
        exception = call.get("exception")
        if exception:
            exception_text = (
                exception
                if isinstance(exception, str)
                else json.dumps(exception, default=str)
            )
            control_results.append(
                ControlResult(
                    control_id="DE-01",
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=(
                        f"Weave op '{op_name}' raised exception: "
                        f"{exception_text[:300]}"
                    ),
                    evidence_data={
                        **common_evidence,
                        "evidence_kind": "exception",
                        "exception": exception_text[:1000],
                    },
                )
            )
            worst = _max_result(worst, "FAIL")

        # 3. Score-name → control mapping (with threshold bucketing).
        scores_block = (call.get("summary") or {}).get("scores")
        if isinstance(scores_block, dict):
            for score_name, raw_value in sorted(scores_block.items()):
                value = _extract_score_value(raw_value)
                if value is None:
                    continue
                control_id = self._control_for_score(score_name)
                inverted = self._is_inverted(score_name)
                bucket = _bucket_score(value, inverted=inverted, table=self._table)
                worst = _max_result(worst, bucket)

                stderr = (
                    _coerce_float(raw_value.get("stderr"))
                    if isinstance(raw_value, dict)
                    else None
                )
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=bucket,
                        detail=(
                            f"Weave score '{score_name}' = {value:.4f} "
                            f"({'inverted' if inverted else 'normal'} band) "
                            f"on call {call_id}"
                        ),
                        evidence_data={
                            **common_evidence,
                            "evidence_kind": "score",
                            "score_name": str(score_name),
                            "score_value": value,
                            "score_stderr": stderr,
                            "score_shape": (
                                "dict_with_mean" if isinstance(raw_value, dict)
                                else "scalar"
                            ),
                            "inverted": inverted,
                            "aggregation": "per_call",
                        },
                    )
                )

        # 4. Negative feedback → PR-05 FLAG.
        feedback = (call.get("summary") or {}).get("feedback")
        if isinstance(feedback, list):
            for entry in feedback:
                if not isinstance(entry, dict):
                    continue
                ftype = str(entry.get("feedback_type") or "").lower()
                if ftype in ("thumbs_down", "negative", "downvote"):
                    control_results.append(
                        ControlResult(
                            control_id="PR-05",
                            control_name=_CONTROL_NAMES["PR-05"],
                            result="FLAG",
                            detail=(
                                f"Weave call {call_id} received negative feedback "
                                f"from {entry.get('creator', 'unknown')}"
                            ),
                            evidence_data={
                                **common_evidence,
                                "evidence_kind": "feedback",
                                "feedback_type": ftype,
                                "creator": str(entry.get("creator") or ""),
                            },
                        )
                    )
                    worst = _max_result(worst, "FLAG")

        timestamp = (
            call.get("started_at")
            or call.get("startedAt")
            or call.get("ended_at")
            or call.get("endedAt")
            or datetime.now(timezone.utc).isoformat()
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"weave-call-{call_id[:24]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="wandb_weave_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"Weave call {call_id} (op '{op_name}'): "
                f"{len(control_results)} control(s)"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=common_evidence["latency_ms"],
            session_id=provenance["trace_id"] or None,
        )

    def _aggregate_by_trace(
        self,
        calls: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Group calls by trace_id and emit one aggregate EvaluationResult per trace."""
        groups: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for call in calls:
            key = str(
                call.get("trace_id")
                or call.get("traceId")
                or call.get("id")
                or uuid.uuid4().hex
            )
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(call)
        return [
            self._trace_to_result(groups[k], trace_id=k, file_sha256=file_sha256)
            for k in order
        ]

    def _trace_to_result(
        self,
        calls: list[dict[str, Any]],
        *,
        trace_id: str,
        file_sha256: str | None,
    ) -> EvaluationResult:
        first = calls[0]
        provenance = self._call_provenance(first, file_sha256=file_sha256)
        provenance["trace_id"] = trace_id
        provenance["call_count"] = len(calls)

        # Score values aggregated across all calls in the trace.
        score_values: dict[str, list[float]] = {}
        latencies: list[float] = []
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        ops: list[str] = []
        any_exception = False
        negative_feedback = 0
        trace_name = ""

        for call in calls:
            op = str(call.get("op_name") or call.get("opName") or "")
            if op:
                ops.append(op)
            if call.get("exception"):
                any_exception = True

            summary = call.get("summary") or {}
            weave_meta = summary.get("weave") if isinstance(summary, dict) else {}
            if isinstance(weave_meta, dict) and not trace_name:
                trace_name = str(weave_meta.get("trace_name") or "")
            lat = (
                _coerce_float(weave_meta.get("latency_ms"))
                if isinstance(weave_meta, dict)
                else None
            )
            if lat is None:
                lat = _latency_from_iso(
                    call.get("started_at") or call.get("startedAt"),
                    call.get("ended_at") or call.get("endedAt"),
                )
            if lat is not None:
                latencies.append(lat)

            usage = summary.get("usage") if isinstance(summary, dict) else {}
            if isinstance(usage, dict):
                prompt_tokens += int(_coerce_float(usage.get("prompt_tokens")) or 0)
                completion_tokens += int(
                    _coerce_float(usage.get("completion_tokens")) or 0
                )
                total_tokens += int(_coerce_float(usage.get("total_tokens")) or 0)

            scores_block = summary.get("scores") if isinstance(summary, dict) else None
            if isinstance(scores_block, dict):
                for score_name, raw_value in scores_block.items():
                    value = _extract_score_value(raw_value)
                    if value is None:
                        continue
                    score_values.setdefault(str(score_name), []).append(value)

            feedback = summary.get("feedback") if isinstance(summary, dict) else None
            if isinstance(feedback, list):
                for entry in feedback:
                    if isinstance(entry, dict) and str(
                        entry.get("feedback_type") or ""
                    ).lower() in ("thumbs_down", "negative", "downvote"):
                        negative_feedback += 1

        provenance["op_names"] = sorted(set(ops))

        control_results: list[ControlResult] = []
        worst = "PASS"

        # One ControlResult per aggregated score.
        for score_name, values in sorted(score_values.items()):
            mean_value = statistics.fmean(values)
            control_id = self._control_for_score(score_name)
            inverted = self._is_inverted(score_name)
            bucket = _bucket_score(mean_value, inverted=inverted, table=self._table)
            worst = _max_result(worst, bucket)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=bucket,
                    detail=(
                        f"Weave score '{score_name}' mean={mean_value:.4f} "
                        f"over {len(values)} call(s) in trace {trace_id} "
                        f"({'inverted' if inverted else 'normal'} band)"
                    ),
                    evidence_data={
                        "trace_id": trace_id,
                        "trace_name": trace_name,
                        "score_name": score_name,
                        "score_mean": mean_value,
                        "score_min": min(values),
                        "score_max": max(values),
                        "score_count": len(values),
                        "inverted": inverted,
                        "aggregation": "per_trace_mean",
                        "source_tool": "wandb_weave",
                        "source_provenance": provenance,
                    },
                )
            )

        # Aggregate exception → DE-01 FAIL.
        if any_exception:
            control_results.append(
                ControlResult(
                    control_id="DE-01",
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=(
                        f"Weave trace {trace_id} contains at least one "
                        f"call with an exception."
                    ),
                    evidence_data={
                        "trace_id": trace_id,
                        "trace_name": trace_name,
                        "source_tool": "wandb_weave",
                        "source_provenance": provenance,
                    },
                )
            )
            worst = _max_result(worst, "FAIL")

        # Aggregate negative feedback.
        if negative_feedback > 0:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Weave trace {trace_id} has {negative_feedback} "
                        f"negative-feedback record(s)."
                    ),
                    evidence_data={
                        "trace_id": trace_id,
                        "trace_name": trace_name,
                        "negative_feedback_count": negative_feedback,
                        "source_tool": "wandb_weave",
                        "source_provenance": provenance,
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # Aggregate metrics record (PR-04).
        latency_max = max(latencies) if latencies else 0.0
        control_results.append(
            ControlResult(
                control_id="PR-04",
                control_name=_CONTROL_NAMES["PR-04"],
                result="PASS",
                detail=(
                    f"Weave trace {trace_id} aggregate metrics: "
                    f"calls={len(calls)} prompt_tokens={prompt_tokens} "
                    f"completion_tokens={completion_tokens} "
                    f"latency_max_ms={latency_max:.2f}"
                ),
                evidence_data={
                    "trace_id": trace_id,
                    "trace_name": trace_name,
                    "call_count": len(calls),
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                    "latency_max_ms": latency_max,
                    "op_names": provenance["op_names"],
                    "source_tool": "wandb_weave",
                    "source_provenance": provenance,
                },
            )
        )

        # Fallback if a trace had no scores / no exception / no feedback (edge case).
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id=self._table.default_control,
                    control_name=_CONTROL_NAMES.get(
                        self._table.default_control, self._table.default_control
                    ),
                    result="FLAG",
                    detail=f"Weave trace {trace_id} has no scoreable evidence.",
                    evidence_data={
                        "trace_id": trace_id,
                        "source_tool": "wandb_weave",
                        "source_provenance": provenance,
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"weave-trace-{trace_id[:24]}",
            timestamp=str(
                first.get("started_at")
                or first.get("startedAt")
                or datetime.now(timezone.utc).isoformat()
            ),
            agent_id=self.agent_id,
            source_type="wandb_weave_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"Imported Weave trace {trace_id} "
                f"({len(calls)} call(s), {len(score_values)} scorer(s))"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=latency_max,
            session_id=trace_id or None,
        )
