"""Braintrust eval scorecard importer — converts experiment events to AKSI EvaluationResults.

Braintrust (https://braintrust.dev) is the leading LLM evaluation platform. Agent
teams run scorers (faithfulness, factuality, hallucination_rate, safety, toxicity,
bias, relevance, ...) over experiments and store the per-event results. Regulators
need proof an agent was tested before deployment — this importer turns Braintrust
experiment exports into Ancilis evidence so that scorecard runs become first-class
compliance artifacts in the same posture/audit pipeline as runtime traces.

Accepted shapes:

    {"experiment": {...}, "events": [...]}
    {"experiments": [{"experiment": {...}, "events": [...]}, ...]}
    JSONL where each line is an event record (events grouped under a synthetic experiment).

Modes:

  * Default (per-experiment): one ``EvaluationResult`` per experiment, with one
    ``ControlResult`` per scorer. Score values are aggregated across events using
    arithmetic mean before being bucketed into PASS / FLAG / FAIL.
  * ``per_event=True``: one ``EvaluationResult`` per event with one ``ControlResult``
    per scorer.

Sanitization: per the SDK no-PII guarantee, raw ``input``/``output``/``expected``
text is NEVER persisted. Only structural counts (top-level keys, byte length) and
a sha256 over the joined input strings are kept so downstream evidence can prove
an event existed and detect tampering without leaking content.

Score → AKSI mapping (see ``shared/mappings/braintrust-aksi-controls.json``):

  * faithfulness, factuality, hallucination_rate → PR-03 (input/output validation)
  * safety, toxicity, bias                        → DE-01 (harm / exfiltration prevention)
  * relevance, accuracy                           → PR-04 (data exposure quality)

Threshold bucketing (from ``_metadata.thresholds`` in the mapping file):

  * score >= 0.9                  → PASS
  * 0.7 <= score < 0.9            → FLAG
  * score < 0.7                   → FAIL

Inverted scorers (``hallucination_rate``, ``toxicity``, ``bias``) are interpreted
in reverse — lower is better:

  * score <= 0.05                 → PASS
  * 0.05 < score <= 0.3           → FLAG
  * score > 0.3                   → FAIL
"""

from __future__ import annotations

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


# Mapping file lives at <repo>/shared/mappings/braintrust-aksi-controls.json.
# This source file lives at <repo>/python/src/ancilis/importers/braintrust.py,
# so .resolve() + 5 .parent traversals land at the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "braintrust-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_UNMAPPED_CONTROL = "PR-03"

# Default thresholds — overridden by the mapping file's `_metadata.thresholds` block.
_DEFAULT_PASS_MIN = 0.9
_DEFAULT_FLAG_MIN = 0.7
# For inverted scorers (lower-is-better) the same band shape is mirrored.
_DEFAULT_INVERTED_PASS_MAX = 0.05
_DEFAULT_INVERTED_FLAG_MAX = 0.3

_DEFAULT_INVERTED_SCORES: tuple[str, ...] = (
    "hallucination_rate",
    "hallucination",
    "toxicity",
    "bias",
)


@dataclass
class _MappingTable:
    score_to_control: dict[str, str] = field(default_factory=dict)
    score_aliases: dict[str, str] = field(default_factory=dict)
    inverted_scores: set[str] = field(default_factory=set)
    pass_min: float = _DEFAULT_PASS_MIN
    flag_min: float = _DEFAULT_FLAG_MIN
    inverted_pass_max: float = _DEFAULT_INVERTED_PASS_MAX
    inverted_flag_max: float = _DEFAULT_INVERTED_FLAG_MAX
    default_control: str = _DEFAULT_UNMAPPED_CONTROL


def _load_mapping_table() -> _MappingTable:
    """Load braintrust-aksi-controls.json, tolerating a missing or malformed file."""
    table = _MappingTable()
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Fall back to defaults plus a hard-coded inverted set so the importer
        # remains usable in environments where the shared/ directory is not
        # packaged alongside the SDK.
        table.inverted_scores = set(_DEFAULT_INVERTED_SCORES)
        return table

    raw_mappings = data.get("mappings", {}) or {}
    if isinstance(raw_mappings, dict):
        table.score_to_control = {
            str(k).lower(): str(v) for k, v in raw_mappings.items()
        }

    meta = data.get("_metadata", {}) or {}
    if isinstance(meta, dict):
        thresholds = meta.get("thresholds", {})
        if isinstance(thresholds, dict):
            table.pass_min = float(thresholds.get("pass_min", _DEFAULT_PASS_MIN))
            table.flag_min = float(thresholds.get("flag_min", _DEFAULT_FLAG_MIN))

        inverted_thresholds = meta.get("inverted_thresholds", {})
        if isinstance(inverted_thresholds, dict):
            table.inverted_pass_max = float(
                inverted_thresholds.get("pass_max", _DEFAULT_INVERTED_PASS_MAX)
            )
            table.inverted_flag_max = float(
                inverted_thresholds.get("flag_max", _DEFAULT_INVERTED_FLAG_MAX)
            )

        inverted = meta.get("inverted_scores")
        if isinstance(inverted, list):
            table.inverted_scores = {str(s).lower() for s in inverted}
        else:
            table.inverted_scores = set(_DEFAULT_INVERTED_SCORES)

        aliases = meta.get("score_aliases", {})
        if isinstance(aliases, dict):
            table.score_aliases = {
                str(k).lower(): str(v).lower() for k, v in aliases.items()
            }

        default_ctrl = meta.get("default_unmapped_control")
        if isinstance(default_ctrl, str) and default_ctrl:
            table.default_control = default_ctrl
    else:
        table.inverted_scores = set(_DEFAULT_INVERTED_SCORES)

    return table


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from a JSONL string, skipping blank lines."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        yield json.loads(line)


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _stringify(value: Any) -> str:
    """Render a Braintrust input/output value to a single string for hashing only."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _summarize_payload(value: Any) -> dict[str, Any]:
    """Reduce input/output/expected to a content-free structural summary.

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


def _percentile(values: list[float], p: float) -> float:
    """Compute an inclusive percentile (linear interpolation) of a list of floats.

    Returns 0.0 for an empty list. ``p`` is given as a fraction in [0, 1].
    """
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    sorted_vals = sorted(values)
    rank = p * (len(sorted_vals) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return float(sorted_vals[lower])
    frac = rank - lower
    return float(sorted_vals[lower] + (sorted_vals[upper] - sorted_vals[lower]) * frac)


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


class BraintrustImporter:
    """Parse a Braintrust experiment export and convert to ``EvaluationResult`` records.

    Args:
      agent_id: Logical agent ID stamped onto produced EvaluationResults.
      mode: ``"audit"`` or ``"enforce"`` — recorded on every produced result.
      per_event: When True, emit one EvaluationResult per event (with one
        ControlResult per scorer); when False (default), aggregate events into
        one EvaluationResult per experiment.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        per_event: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        self.per_event = bool(per_event)
        self._table = _load_mapping_table()

    # ------------------------------------------------------------------ public
    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Braintrust export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        return self._parse_text(text, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Braintrust export content from a string (JSON or JSONL)."""
        return self._parse_text(content, file_sha256=None)

    # ----------------------------------------------------------------- private
    def _parse_text(
        self,
        text: str,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        bundles = self._extract_experiment_bundles(text)
        results: list[EvaluationResult] = []
        for experiment, events in bundles:
            if self.per_event:
                for event in events:
                    results.append(
                        self._event_to_result(
                            experiment=experiment,
                            event=event,
                            file_sha256=file_sha256,
                        )
                    )
            else:
                results.append(
                    self._aggregate_to_result(
                        experiment=experiment,
                        events=events,
                        file_sha256=file_sha256,
                    )
                )
        return results

    def _extract_experiment_bundles(
        self,
        text: str,
    ) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
        """Return [(experiment_meta, events), ...] for every supported input shape."""
        stripped = text.lstrip()
        if not stripped:
            return []

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Fall through to JSONL.
                return [(_synthetic_experiment(), list(_iter_jsonl(text)))]

            if isinstance(doc, dict):
                # Multi-experiment envelope.
                if "experiments" in doc and isinstance(doc["experiments"], list):
                    out: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
                    for entry in doc["experiments"]:
                        if not isinstance(entry, dict):
                            continue
                        exp = entry.get("experiment") or {}
                        events = entry.get("events") or []
                        out.append((
                            exp if isinstance(exp, dict) else {},
                            [e for e in events if isinstance(e, dict)],
                        ))
                    return out
                # Single-experiment envelope.
                if "experiment" in doc or "events" in doc:
                    exp = doc.get("experiment") or {}
                    events = doc.get("events") or []
                    return [(
                        exp if isinstance(exp, dict) else {},
                        [e for e in events if isinstance(e, dict)],
                    )]
                # Unknown object shape — treat as a single bare event.
                return [(_synthetic_experiment(), [doc])]

            if isinstance(doc, list):
                # Bare list of events.
                return [(
                    _synthetic_experiment(),
                    [e for e in doc if isinstance(e, dict)],
                )]
            return []

        # Treat as JSONL of events under a synthetic experiment.
        return [(_synthetic_experiment(), list(_iter_jsonl(text)))]

    # ---------------- score → control bookkeeping ---------------------------
    def _resolve_score_name(self, score_name: str) -> str:
        """Apply alias resolution (e.g. hallucination → hallucination_rate)."""
        normalized = score_name.lower()
        return self._table.score_aliases.get(normalized, normalized)

    def _control_for_score(self, score_name: str) -> str:
        resolved = self._resolve_score_name(score_name)
        return self._table.score_to_control.get(resolved, self._table.default_control)

    def _is_inverted(self, score_name: str) -> bool:
        return self._resolve_score_name(score_name) in self._table.inverted_scores

    # ---------------- record builders ---------------------------------------
    def _experiment_provenance(
        self,
        experiment: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        """Build the source_provenance block — surfaces git_commit + model metadata for code-link."""
        provenance: dict[str, Any] = {
            "source_format": "braintrust",
            "source_tool_name": "braintrust",
            "source_tool_version": "",
            "experiment_id": str(experiment.get("id", "")),
            "experiment_name": str(experiment.get("name", "")),
            "project_id": str(experiment.get("project_id", "")),
            "dataset_id": str(experiment.get("dataset_id", "")),
        }
        git_commit = experiment.get("git_commit")
        if git_commit:
            provenance["git_commit"] = str(git_commit)
        model_metadata = experiment.get("model_metadata")
        if isinstance(model_metadata, dict) and model_metadata:
            # Surface scalar fields directly so reports can show model + temperature
            # without having to drill into the source_provenance subtree.
            provenance["model_metadata"] = dict(model_metadata)
            model = model_metadata.get("model")
            if isinstance(model, str) and model:
                provenance["model"] = model
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _event_score_summary(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Per-event no-PII summary block. NEVER includes raw input/output/expected text."""
        scores = event.get("scores")
        scores_summary: dict[str, float] = {}
        if isinstance(scores, dict):
            for k, v in scores.items():
                f = _coerce_float(v)
                if f is not None:
                    scores_summary[str(k)] = f

        return {
            "event_id": str(event.get("id", "")),
            "input_summary": _summarize_payload(event.get("input")),
            "output_summary": _summarize_payload(event.get("output")),
            "expected_summary": _summarize_payload(event.get("expected")),
            "scores": scores_summary,
            "metadata_keys": sorted(
                str(k) for k in (event.get("metadata") or {})
            ) if isinstance(event.get("metadata"), dict) else [],
            "tags": list(event.get("tags") or []),
        }

    def _aggregate_metrics(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Aggregate per-event metrics: tokens summed, latency p95."""
        tokens_in = 0
        tokens_out = 0
        latencies: list[float] = []
        for ev in events:
            metrics = ev.get("metrics")
            if not isinstance(metrics, dict):
                continue
            t_in = _coerce_float(metrics.get("tokens_in"))
            t_out = _coerce_float(metrics.get("tokens_out"))
            lat = _coerce_float(metrics.get("latency_ms"))
            if t_in is not None:
                tokens_in += int(t_in)
            if t_out is not None:
                tokens_out += int(t_out)
            if lat is not None:
                latencies.append(lat)
        return {
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "tokens_total": tokens_in + tokens_out,
            "latency_ms_p95": _percentile(latencies, 0.95),
            "event_count": len(events),
        }

    def _event_to_result(
        self,
        *,
        experiment: dict[str, Any],
        event: dict[str, Any],
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._experiment_provenance(experiment, file_sha256=file_sha256)
        event_id = str(event.get("id") or uuid.uuid4().hex[:12])
        scores = event.get("scores") or {}
        score_summary = self._event_score_summary(event)
        metrics = event.get("metrics") or {}

        common_evidence: dict[str, Any] = {
            "experiment_id": provenance["experiment_id"],
            "experiment_name": provenance["experiment_name"],
            "event_id": event_id,
            "source_provenance": provenance,
            "source_tool": "braintrust",
            "event_summary": score_summary,
            "metrics": {
                "tokens_in": _coerce_float(metrics.get("tokens_in")) or 0,
                "tokens_out": _coerce_float(metrics.get("tokens_out")) or 0,
                "latency_ms": _coerce_float(metrics.get("latency_ms")) or 0,
            },
        }

        control_results: list[ControlResult] = []
        worst = "PASS"
        if isinstance(scores, dict) and scores:
            for score_name, raw_value in scores.items():
                value = _coerce_float(raw_value)
                if value is None:
                    continue
                control_id = self._control_for_score(score_name)
                inverted = self._is_inverted(score_name)
                bucket = _bucket_score(value, inverted=inverted, table=self._table)
                worst = _max_result(worst, bucket)
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=bucket,
                        detail=(
                            f"Braintrust scorer '{score_name}' = {value:.4f} "
                            f"({'inverted' if inverted else 'normal'} band) "
                            f"on event {event_id}"
                        ),
                        evidence_data={
                            **common_evidence,
                            "score_name": score_name,
                            "score_value": value,
                            "inverted": inverted,
                            "aggregation": "per_event",
                        },
                    )
                )
        else:
            # No scores recorded — surface as a FLAG rather than silent PASS so
            # an empty scorecard does not look like compliance evidence.
            control_results.append(
                ControlResult(
                    control_id=self._table.default_control,
                    control_name=_CONTROL_NAMES.get(
                        self._table.default_control, self._table.default_control
                    ),
                    result="FLAG",
                    detail=(
                        f"Braintrust event {event_id} has no scorers recorded — "
                        f"cannot establish PASS/FAIL evidence."
                    ),
                    evidence_data={**common_evidence, "score_name": None},
                )
            )
            worst = _max_result(worst, "FLAG")

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"braintrust-event-{event_id[:24]}",
            timestamp=str(
                event.get("created")
                or experiment.get("created")
                or datetime.now(timezone.utc).isoformat()
            ),
            agent_id=self.agent_id,
            source_type="braintrust_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"Braintrust event {event_id} (experiment "
                f"'{provenance['experiment_name']}'): {len(control_results)} scorer(s)"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=_coerce_float(metrics.get("latency_ms")) or 0.0,
            session_id=provenance["experiment_id"] or None,
        )

    def _aggregate_to_result(
        self,
        *,
        experiment: dict[str, Any],
        events: list[dict[str, Any]],
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._experiment_provenance(experiment, file_sha256=file_sha256)
        experiment_id = provenance["experiment_id"] or uuid.uuid4().hex[:12]
        experiment_name = provenance["experiment_name"] or "braintrust-experiment"

        # Collect score values across events and compute joined-input hash.
        score_values: dict[str, list[float]] = {}
        joined_inputs: list[str] = []
        event_summaries: list[dict[str, Any]] = []
        for ev in events:
            event_summaries.append(self._event_score_summary(ev))
            joined_inputs.append(_stringify(ev.get("input")))
            scores = ev.get("scores")
            if isinstance(scores, dict):
                for score_name, raw_value in scores.items():
                    value = _coerce_float(raw_value)
                    if value is None:
                        continue
                    score_values.setdefault(str(score_name), []).append(value)

        joined_input_sha = hashlib.sha256(
            "\x1e".join(joined_inputs).encode("utf-8")
        ).hexdigest()
        metrics_agg = self._aggregate_metrics(events)

        control_results: list[ControlResult] = []
        worst = "PASS"

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
                        f"Braintrust scorer '{score_name}' mean={mean_value:.4f} "
                        f"over {len(values)} event(s) "
                        f"({'inverted' if inverted else 'normal'} band) "
                        f"in experiment '{experiment_name}'"
                    ),
                    evidence_data={
                        "experiment_id": experiment_id,
                        "experiment_name": experiment_name,
                        "score_name": score_name,
                        "score_mean": mean_value,
                        "score_min": min(values),
                        "score_max": max(values),
                        "score_count": len(values),
                        "inverted": inverted,
                        "aggregation": "per_experiment_mean",
                        "metrics": metrics_agg,
                        "joined_input_sha256": joined_input_sha,
                        "source_tool": "braintrust",
                        "source_provenance": provenance,
                    },
                )
            )

        # Aggregate token / latency record (PR-04).
        if metrics_agg["event_count"] > 0:
            control_results.append(
                ControlResult(
                    control_id="PR-04",
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="PASS",
                    detail=(
                        f"Braintrust experiment '{experiment_name}' aggregate metrics: "
                        f"tokens_in={metrics_agg['tokens_in']} "
                        f"tokens_out={metrics_agg['tokens_out']} "
                        f"latency_p95_ms={metrics_agg['latency_ms_p95']:.2f} "
                        f"events={metrics_agg['event_count']}"
                    ),
                    evidence_data={
                        "experiment_id": experiment_id,
                        "experiment_name": experiment_name,
                        "metrics": metrics_agg,
                        "joined_input_sha256": joined_input_sha,
                        "event_count": metrics_agg["event_count"],
                        "event_summaries": event_summaries,
                        "source_tool": "braintrust",
                        "source_provenance": provenance,
                    },
                )
            )

        # If there were no scores at all, still emit a record.
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id=self._table.default_control,
                    control_name=_CONTROL_NAMES.get(
                        self._table.default_control, self._table.default_control
                    ),
                    result="FLAG",
                    detail=(
                        f"Braintrust experiment '{experiment_name}' has no events "
                        f"or scorers — no compliance evidence can be derived."
                    ),
                    evidence_data={
                        "experiment_id": experiment_id,
                        "experiment_name": experiment_name,
                        "source_tool": "braintrust",
                        "source_provenance": provenance,
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"braintrust-import-{experiment_id[:24]}",
            timestamp=str(
                experiment.get("created")
                or datetime.now(timezone.utc).isoformat()
            ),
            agent_id=self.agent_id,
            source_type="braintrust_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"Imported Braintrust experiment '{experiment_name}' "
                f"({metrics_agg['event_count']} event(s), "
                f"{len(score_values)} scorer(s))"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=metrics_agg["latency_ms_p95"],
            session_id=experiment_id or None,
        )


def _synthetic_experiment() -> dict[str, Any]:
    """Build a placeholder experiment for bare-event-list / JSONL inputs."""
    return {
        "id": f"bt-anon-{uuid.uuid4().hex[:8]}",
        "name": "braintrust-anonymous-export",
        "project_id": "",
        "dataset_id": "",
    }
