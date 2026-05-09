"""MLflow runs / model registry / audit-log importer — converts MLflow exports to AKSI EvaluationResults.

MLflow (https://mlflow.org) is the dominant open-source MLOps platform — it tracks
model versions, runs experiments, manages a model registry, and deploys to
production. For agent quality assurance and reproducibility, MLflow's run/model/
audit trail is the canonical evidence source: regulators and security teams need
proof an agent's training and deployment lifecycle is reproducible, not silently
auto-promoted, and not destructively edited. This importer turns MLflow exports
into Ancilis evidence so that MLOps lifecycle events become first-class
compliance artifacts in the same posture/audit pipeline as runtime traces.

Accepted shapes (all common MLflow REST shapes plus generic envelopes):

    {"runs": [...]}                           # /api/2.0/mlflow/runs/search
    {"registered_models": [...]}              # /api/2.0/mlflow/registered-models/search
    {"audit_logs": [...]}                     # MLflow audit-log export
    {"data": [...]}                           # generic envelope; record kind auto-detected
    [...]                                     # bare list; record kind auto-detected per record
    JSONL                                     # one record per line

Record-kind dispatch:

  * Top-level ``runs`` key  → run records (one EvaluationResult per run)
  * Top-level ``registered_models`` key → model records (one per registered model)
  * Top-level ``audit_logs`` key → audit records (one per action)
  * Generic ``data`` envelope or bare list → each record dispatched by shape:
    presence of ``info`` + ``data`` → run; ``latest_versions`` → registered model;
    ``action`` + ``target_type`` → audit log.

Sanitization (per the SDK no-PII guarantee):

  * ``artifact_uri`` is truncated to host + first two path components (paths can
    contain user-id-like material).
  * ``run_name`` is replaced by ``{length, sha256}`` (could be PII like
    "alice-experiment-1").
  * ``params`` values are replaced by ``{key, value_length, value_sha256}``
    (params can carry secrets — API keys, prompts).
  * ``tags`` raw VALUES other than well-known keys (``mlflow.source.git.commit``,
    ``mlflow.source.type``) are replaced by ``{length, sha256}``.
  * ``inputs[].dataset.name`` is replaced by ``{length, sha256}`` (dataset names
    can be PII like ``customer_pii_v3``); only the digest prefix (last 8 chars
    of the algo:hex form) is retained verbatim because it is non-identifying.
  * Metric values are stored verbatim — they are non-sensitive scores.
  * ``audit_logs[].details`` is stored verbatim — it is structured (not free
    text) and reviewers need it to assess approvals/transitions.

AKSI mapping for runs:

  * ``info.status=FINISHED`` + metrics aggregated:
      - hallucination_rate < 0.05 → PR-03 PASS; > 0.30 → FAIL; mid → FLAG
      - toxicity_score < 0.05 → DE-01 PASS; > 0.30 → FAIL; mid → FLAG
      - accuracy / f1 > 0.9 → PR-03 PASS; < 0.7 → FAIL; mid → FLAG
  * ``info.status=FAILED`` → DE-01 FAIL
  * ``info.status=KILLED`` → PR-05 FLAG (manual termination — surface)
  * tags ``deploy_to_production`` = "true" + status FINISHED → PR-05 FLAG
    (production-deployment trigger; surface for review)
  * tags missing ``mlflow.source.git.commit`` → PR-05 FLAG (un-versioned)
  * params missing ``prompt_template_id`` or ``model_name`` → PR-05 FLAG
  * inputs[].dataset.digest missing → PR-05 FLAG (un-pinned dataset)
  * info.lifecycle_stage=deleted → PR-05 PASS (audit-trail evidence)
  * info.user_id matches bot/agent patterns + tags["mlflow.source.type"]=LOCAL
    → PR-05 FLAG (agent running ad-hoc local — should use JOB/PIPELINE)

AKSI mapping for registered models:

  * latest_versions has stage=Production AND status_message contains warning
    patterns → PR-03 FLAG
  * Multiple Production versions for same model → PR-05 FAIL (registry
    inconsistency — every registered model should have at most one Production
    version at any time).

AKSI mapping for audit logs:

  * action=run.delete → PR-02 FLAG
  * action=experiment.delete → PR-02 FAIL (audit destruction)
  * action=model_version.transition_stage details.new_stage=Production +
    details.approved_by=null → PR-02 FAIL (auto-promotion without approval)
  * action=model_version.transition_stage details.new_stage=Production +
    details.approved_by set → PR-05 PASS (approved promotion logged)
  * action=permission.grant → PR-02 FLAG
  * action=model_version.archive → PR-05 PASS
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import statistics
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping file lives at <repo>/shared/mappings/mlflow-aksi-controls.json.
# This source file lives at <repo>/python/src/ancilis/importers/mlflow.py,
# so .resolve() + 5 .parent traversals land at the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "mlflow-aksi-controls.json"
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

# Default thresholds — overridden by the mapping file's `_metadata.thresholds`.
_DEFAULT_ACCURACY_PASS_MIN = 0.9
_DEFAULT_ACCURACY_FAIL_MAX = 0.7
_DEFAULT_HALLUCINATION_PASS_MAX = 0.05
_DEFAULT_HALLUCINATION_FAIL_MIN = 0.3
_DEFAULT_TOXICITY_PASS_MAX = 0.05
_DEFAULT_TOXICITY_FAIL_MIN = 0.3

_DEFAULT_WELL_KNOWN_TAG_KEYS: tuple[str, ...] = (
    "mlflow.source.git.commit",
    "mlflow.source.type",
    "mlflow.runName",
    "mlflow.parentRunId",
    "mlflow.user",
    "deploy_to_production",
)

# Tag keys whose VALUES we keep verbatim (the rest are length+sha256).
_VERBATIM_TAG_KEYS: frozenset[str] = frozenset({
    "mlflow.source.git.commit",
    "mlflow.source.type",
})

_DEFAULT_BOT_USER_PATTERNS: tuple[str, ...] = (
    "*-svc",
    "*-bot",
    "*-agent",
    "agent-*",
    "bot-*",
    "svc-*",
    "*-automation",
    "ci-*",
    "*-ci",
)

_WARNING_STATUS_PATTERNS: tuple[str, ...] = (
    "warn",
    "warning",
    "deprecat",
    "stale",
    "regress",
    "drift",
    "degrad",
    "unhealthy",
)


@dataclass
class _MappingTable:
    metric_to_control: dict[str, dict[str, Any]] = field(default_factory=dict)
    audit_action_rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    well_known_tag_keys: set[str] = field(
        default_factory=lambda: set(_DEFAULT_WELL_KNOWN_TAG_KEYS)
    )
    bot_user_patterns: list[str] = field(
        default_factory=lambda: list(_DEFAULT_BOT_USER_PATTERNS)
    )
    accuracy_pass_min: float = _DEFAULT_ACCURACY_PASS_MIN
    accuracy_fail_max: float = _DEFAULT_ACCURACY_FAIL_MAX
    hallucination_pass_max: float = _DEFAULT_HALLUCINATION_PASS_MAX
    hallucination_fail_min: float = _DEFAULT_HALLUCINATION_FAIL_MIN
    toxicity_pass_max: float = _DEFAULT_TOXICITY_PASS_MAX
    toxicity_fail_min: float = _DEFAULT_TOXICITY_FAIL_MIN
    default_control: str = _DEFAULT_UNMAPPED_CONTROL


def _load_mapping_table() -> _MappingTable:
    """Load mlflow-aksi-controls.json, tolerating a missing or malformed file."""
    table = _MappingTable()
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return table

    raw_metrics = data.get("metric_mappings") or {}
    if isinstance(raw_metrics, dict):
        for k, v in raw_metrics.items():
            if isinstance(v, dict):
                table.metric_to_control[str(k).lower()] = {
                    "control": str(v.get("control", "PR-03")),
                    "inverted": bool(v.get("inverted", False)),
                }

    raw_actions = data.get("audit_action_mappings") or {}
    if isinstance(raw_actions, dict):
        for k, v in raw_actions.items():
            if isinstance(v, dict):
                table.audit_action_rules[str(k)] = dict(v)

    meta = data.get("_metadata", {}) or {}
    if isinstance(meta, dict):
        thresholds = meta.get("thresholds", {})
        if isinstance(thresholds, dict):
            table.accuracy_pass_min = float(
                thresholds.get("accuracy_pass_min", _DEFAULT_ACCURACY_PASS_MIN)
            )
            table.accuracy_fail_max = float(
                thresholds.get("accuracy_fail_max", _DEFAULT_ACCURACY_FAIL_MAX)
            )
            table.hallucination_pass_max = float(
                thresholds.get(
                    "hallucination_pass_max", _DEFAULT_HALLUCINATION_PASS_MAX
                )
            )
            table.hallucination_fail_min = float(
                thresholds.get(
                    "hallucination_fail_min", _DEFAULT_HALLUCINATION_FAIL_MIN
                )
            )
            table.toxicity_pass_max = float(
                thresholds.get("toxicity_pass_max", _DEFAULT_TOXICITY_PASS_MAX)
            )
            table.toxicity_fail_min = float(
                thresholds.get("toxicity_fail_min", _DEFAULT_TOXICITY_FAIL_MIN)
            )

        wk = meta.get("well_known_tag_keys")
        if isinstance(wk, list):
            table.well_known_tag_keys = {str(s) for s in wk}

        bots = meta.get("bot_user_patterns")
        if isinstance(bots, list):
            table.bot_user_patterns = [str(s) for s in bots]

        default_ctrl = meta.get("default_unmapped_control")
        if isinstance(default_ctrl, str) and default_ctrl:
            table.default_control = default_ctrl

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
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _redact(value: Any) -> dict[str, Any]:
    """Replace a sensitive value with {length, sha256} so existence is provable
    but content is not retained."""
    if value is None:
        return {"present": False}
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    return {
        "present": True,
        "length": len(s),
        "sha256": _sha256(s),
    }


def _truncate_artifact_uri(uri: str | None) -> str | None:
    """Keep scheme + host + first 2 path components only — paths can carry user IDs."""
    if not isinstance(uri, str) or not uri:
        return None
    try:
        parsed = urlparse(uri)
    except ValueError:
        return None
    if not parsed.scheme:
        # File path or DBFS path without scheme.
        parts = uri.split("/")
        head = "/".join(parts[:3])
        return head + ("/..." if len(parts) > 3 else "")
    host = parsed.netloc
    path_parts = [p for p in parsed.path.split("/") if p]
    kept = path_parts[:2]
    truncated_path = "/" + "/".join(kept) if kept else ""
    suffix = "/..." if len(path_parts) > 2 else ""
    return f"{parsed.scheme}://{host}{truncated_path}{suffix}"


def _digest_prefix(digest: str | None) -> str | None:
    """Return the last 8 chars of an MLflow dataset digest like ``sha256:abc...``.

    The digest itself is non-identifying (it's a hash) so storing the trailing 8
    hex chars preserves evidence linkage without retaining the full hash.
    """
    if not isinstance(digest, str) or not digest:
        return None
    body = digest.split(":", 1)[-1]
    return body[-8:] if len(body) > 8 else body


def _kv_list_to_dict(kvs: Any) -> dict[str, str]:
    """Convert MLflow's [{key, value}, ...] shape to a plain dict."""
    out: dict[str, str] = {}
    if isinstance(kvs, list):
        for entry in kvs:
            if not isinstance(entry, dict):
                continue
            k = entry.get("key")
            v = entry.get("value")
            if k is None:
                continue
            out[str(k)] = "" if v is None else str(v)
    elif isinstance(kvs, dict):
        for k, v in kvs.items():
            out[str(k)] = "" if v is None else str(v)
    return out


_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _decision_from(worst: str) -> str:
    return {"PASS": "ALLOW", "FLAG": "FLAG", "FAIL": "BLOCK"}.get(worst, "ALLOW")


def _ms_to_iso(ms: Any) -> str:
    """Convert an MLflow epoch-ms field to an ISO-8601 UTC timestamp."""
    f = _coerce_float(ms)
    if f is None:
        return datetime.now(timezone.utc).isoformat()
    try:
        return datetime.fromtimestamp(f / 1000.0, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def _is_warning_status_message(msg: str | None) -> bool:
    if not isinstance(msg, str) or not msg:
        return False
    low = msg.lower()
    return any(p in low for p in _WARNING_STATUS_PATTERNS)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class MLflowImporter:
    """Parse an MLflow runs / registered-models / audit-log export and convert
    to ``EvaluationResult`` records.

    Args:
      agent_id: Logical agent ID stamped onto produced EvaluationResults.
      mode: ``"audit"`` or ``"enforce"`` — recorded on every produced result.
    """

    def __init__(self, agent_id: str = "import", mode: str = "audit") -> None:
        self.agent_id = agent_id
        self.mode = mode
        self._table = _load_mapping_table()

    # ------------------------------------------------------------------ public

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an MLflow export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        return self._parse_text(text, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse an MLflow export from a string (JSON or JSONL)."""
        return self._parse_text(content, file_sha256=None)

    # ----------------------------------------------------------------- private

    def _parse_text(
        self,
        text: str,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        runs, models, audits = self._extract_records(text)
        results: list[EvaluationResult] = []
        for run in runs:
            results.append(self._run_to_result(run, file_sha256=file_sha256))
        for model in models:
            results.append(self._model_to_result(model, file_sha256=file_sha256))
        for entry in audits:
            results.append(self._audit_to_result(entry, file_sha256=file_sha256))
        return results

    def _extract_records(
        self,
        text: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Return (runs, registered_models, audit_logs) lists in canonical shape."""
        stripped = text.lstrip()
        if not stripped:
            return [], [], []

        runs: list[dict[str, Any]] = []
        models: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Fall through to JSONL handling.
                doc = None

            if doc is not None:
                if isinstance(doc, dict):
                    for r in doc.get("runs") or []:
                        if isinstance(r, dict):
                            runs.append(r)
                    for m in doc.get("registered_models") or []:
                        if isinstance(m, dict):
                            models.append(m)
                    for a in doc.get("audit_logs") or []:
                        if isinstance(a, dict):
                            audits.append(a)
                    # Generic envelope.
                    if not (runs or models or audits):
                        for entry in doc.get("data") or []:
                            if isinstance(entry, dict):
                                self._dispatch_record(entry, runs, models, audits)
                        # If still nothing matched, treat the whole doc as a single record.
                        if not (runs or models or audits):
                            self._dispatch_record(doc, runs, models, audits)
                    return runs, models, audits
                if isinstance(doc, list):
                    for entry in doc:
                        if isinstance(entry, dict):
                            self._dispatch_record(entry, runs, models, audits)
                    return runs, models, audits
                return [], [], []

        # JSONL fallback.
        for entry in _iter_jsonl(text):
            self._dispatch_record(entry, runs, models, audits)
        return runs, models, audits

    @staticmethod
    def _dispatch_record(
        record: dict[str, Any],
        runs: list[dict[str, Any]],
        models: list[dict[str, Any]],
        audits: list[dict[str, Any]],
    ) -> None:
        """Route a single record to runs / models / audits by shape."""
        if "info" in record and isinstance(record.get("info"), dict):
            runs.append(record)
            return
        if "latest_versions" in record:
            models.append(record)
            return
        if "action" in record and "target_type" in record:
            audits.append(record)
            return
        # Unknown shape — ignore to avoid producing spurious evidence.

    # ---------------------------------------------------------------- runs

    def _bucket_metric(
        self,
        metric_name: str,
        value: float,
    ) -> tuple[str, str, bool]:
        """Return (control_id, result, inverted) for a metric value."""
        norm = metric_name.lower()
        rule = self._table.metric_to_control.get(norm)
        if not rule:
            # No explicit mapping — surface as default control PASS.
            return self._table.default_control, "PASS", False
        control = rule["control"]
        inverted = bool(rule.get("inverted"))
        if "hallucination" in norm:
            if value < self._table.hallucination_pass_max:
                return control, "PASS", inverted
            if value > self._table.hallucination_fail_min:
                return control, "FAIL", inverted
            return control, "FLAG", inverted
        if "toxicity" in norm:
            if value < self._table.toxicity_pass_max:
                return control, "PASS", inverted
            if value > self._table.toxicity_fail_min:
                return control, "FAIL", inverted
            return control, "FLAG", inverted
        # Default direction — higher is better.
        if value > self._table.accuracy_pass_min:
            return control, "PASS", inverted
        if value < self._table.accuracy_fail_max:
            return control, "FAIL", inverted
        return control, "FLAG", inverted

    def _is_bot_user(self, user_id: str) -> bool:
        if not user_id:
            return False
        return any(
            fnmatch.fnmatchcase(user_id, pat)
            for pat in self._table.bot_user_patterns
        )

    def _run_provenance(
        self,
        run: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        info = run.get("info") or {}
        outputs = run.get("outputs") or {}
        tags = _kv_list_to_dict((run.get("data") or {}).get("tags"))
        provenance: dict[str, Any] = {
            "source_format": "mlflow",
            "source_tool_name": "mlflow",
            "source_tool_version": "",
            "record_kind": "run",
            "run_id": str(info.get("run_id", "")),
            "experiment_id": str(info.get("experiment_id", "")),
            "user_id": str(info.get("user_id", "")),
            "status": str(info.get("status", "")),
            "lifecycle_stage": str(info.get("lifecycle_stage", "")),
            "start_time": _coerce_float(info.get("start_time")) or 0.0,
            "end_time": _coerce_float(info.get("end_time")) or 0.0,
            "artifact_uri_truncated": _truncate_artifact_uri(info.get("artifact_uri")),
            "run_name_redacted": _redact(info.get("run_name")),
        }
        # Source tracking.
        git_commit = tags.get("mlflow.source.git.commit")
        if git_commit is not None:
            provenance["source_git_commit"] = git_commit
        source_type = tags.get("mlflow.source.type")
        if source_type is not None:
            provenance["source_type_tag"] = source_type
        # Output linkage to model registry.
        if isinstance(outputs, dict):
            if outputs.get("model_uri"):
                provenance["model_uri"] = str(outputs["model_uri"])
            if outputs.get("model_version"):
                provenance["model_version"] = str(outputs["model_version"])
            if outputs.get("registered_model_name"):
                provenance["registered_model_name"] = str(
                    outputs["registered_model_name"]
                )
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _run_evidence_base(
        self,
        run: dict[str, Any],
        *,
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        info = run.get("info") or {}
        data = run.get("data") or {}
        tags_raw = _kv_list_to_dict(data.get("tags"))
        params_raw = _kv_list_to_dict(data.get("params"))
        metrics_raw = data.get("metrics")
        metrics: dict[str, float] = {}
        if isinstance(metrics_raw, list):
            for entry in metrics_raw:
                if not isinstance(entry, dict):
                    continue
                k = entry.get("key")
                v = _coerce_float(entry.get("value"))
                if k is None or v is None:
                    continue
                metrics.setdefault(str(k), v)
        elif isinstance(metrics_raw, dict):
            for k, v in metrics_raw.items():
                f = _coerce_float(v)
                if f is not None:
                    metrics[str(k)] = f

        # Tag handling: keep verbatim for well-known keys, redact rest.
        tags_view: dict[str, Any] = {}
        for k, v in tags_raw.items():
            if k in _VERBATIM_TAG_KEYS:
                tags_view[k] = v
            else:
                tags_view[k] = _redact(v)

        # Param handling: redact every value (may carry secrets).
        params_view: dict[str, Any] = {
            k: _redact(v) for k, v in params_raw.items()
        }

        # Inputs handling: dataset.name redacted; digest prefix kept.
        inputs_view: list[dict[str, Any]] = []
        for entry in run.get("inputs") or []:
            if not isinstance(entry, dict):
                continue
            ds = entry.get("dataset") or {}
            if not isinstance(ds, dict):
                continue
            inputs_view.append({
                "dataset_name_redacted": _redact(ds.get("name")),
                "dataset_digest_prefix": _digest_prefix(ds.get("digest")),
                "dataset_source_type": str(ds.get("source_type", "")),
                "tags": [
                    {"key": str((t or {}).get("key", "")), "value": _redact((t or {}).get("value"))}
                    for t in (entry.get("tags") or [])
                    if isinstance(t, dict)
                ],
            })

        evidence: dict[str, Any] = {
            "run_id": provenance["run_id"],
            "experiment_id": provenance["experiment_id"],
            "user_id": provenance["user_id"],
            "status": provenance["status"],
            "lifecycle_stage": provenance["lifecycle_stage"],
            "start_time_ms": _coerce_float(info.get("start_time")) or 0,
            "end_time_ms": _coerce_float(info.get("end_time")) or 0,
            "artifact_uri_truncated": provenance.get("artifact_uri_truncated"),
            "run_name_redacted": provenance.get("run_name_redacted"),
            "metrics": metrics,
            "tags": tags_view,
            "params": params_view,
            "inputs": inputs_view,
            "source_tool": "mlflow",
            "source_provenance": provenance,
        }
        return evidence

    def _run_to_result(
        self,
        run: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._run_provenance(run, file_sha256=file_sha256)
        evidence_base = self._run_evidence_base(run, provenance=provenance)
        info = run.get("info") or {}
        run_id = provenance["run_id"] or uuid.uuid4().hex[:12]
        status = provenance["status"]
        lifecycle = provenance["lifecycle_stage"]
        tags_raw = _kv_list_to_dict((run.get("data") or {}).get("tags"))
        params_raw = _kv_list_to_dict((run.get("data") or {}).get("params"))

        control_results: list[ControlResult] = []
        worst = "PASS"

        # 1. Status-based controls.
        if status == "FINISHED":
            metrics = evidence_base["metrics"]
            metric_seen = False
            for metric_name, value in sorted(metrics.items()):
                if metric_name.lower() not in self._table.metric_to_control:
                    continue
                metric_seen = True
                control_id, bucket, inverted = self._bucket_metric(metric_name, value)
                worst = _max_result(worst, bucket)
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result=bucket,
                        detail=(
                            f"MLflow run {run_id} metric '{metric_name}'={value:.4f} "
                            f"({'inverted' if inverted else 'normal'} band)"
                        ),
                        evidence_data={
                            **evidence_base,
                            "evidence_kind": "metric",
                            "metric_name": metric_name,
                            "metric_value": value,
                            "inverted": inverted,
                        },
                    )
                )
            if not metric_seen:
                # Surface FINISHED with no recognized metrics.
                control_results.append(
                    ControlResult(
                        control_id="PR-03",
                        control_name=_CONTROL_NAMES["PR-03"],
                        result="FLAG",
                        detail=(
                            f"MLflow run {run_id} FINISHED but no recognized "
                            f"quality metrics recorded — cannot establish PASS evidence."
                        ),
                        evidence_data={
                            **evidence_base,
                            "evidence_kind": "metric_missing",
                        },
                    )
                )
                worst = _max_result(worst, "FLAG")
        elif status == "FAILED":
            control_results.append(
                ControlResult(
                    control_id="DE-01",
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=f"MLflow run {run_id} terminated with status=FAILED",
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "status_failed",
                    },
                )
            )
            worst = _max_result(worst, "FAIL")
        elif status == "KILLED":
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"MLflow run {run_id} terminated with status=KILLED "
                        f"(manual termination — surface for review)"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "status_killed",
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # 2. Reproducibility checks.
        if "mlflow.source.git.commit" not in tags_raw or not tags_raw.get(
            "mlflow.source.git.commit"
        ):
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"MLflow run {run_id} missing mlflow.source.git.commit "
                        f"— un-versioned source, un-reproducible"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "missing_git_commit",
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        for required in ("model_name", "prompt_template_id"):
            if required not in params_raw or not params_raw.get(required):
                control_results.append(
                    ControlResult(
                        control_id="PR-05",
                        control_name=_CONTROL_NAMES["PR-05"],
                        result="FLAG",
                        detail=(
                            f"MLflow run {run_id} missing param '{required}' "
                            f"— under-specified run config"
                        ),
                        evidence_data={
                            **evidence_base,
                            "evidence_kind": "missing_param",
                            "missing_param": required,
                        },
                    )
                )
                worst = _max_result(worst, "FLAG")

        # 3. Dataset digest pinning.
        for entry in run.get("inputs") or []:
            if not isinstance(entry, dict):
                continue
            ds = entry.get("dataset") or {}
            if not isinstance(ds, dict):
                continue
            if not ds.get("digest"):
                control_results.append(
                    ControlResult(
                        control_id="PR-05",
                        control_name=_CONTROL_NAMES["PR-05"],
                        result="FLAG",
                        detail=(
                            f"MLflow run {run_id} input dataset missing digest "
                            f"— un-pinned dataset, un-reproducible"
                        ),
                        evidence_data={
                            **evidence_base,
                            "evidence_kind": "missing_dataset_digest",
                            "dataset_source_type": str(ds.get("source_type", "")),
                        },
                    )
                )
                worst = _max_result(worst, "FLAG")

        # 4. deploy_to_production tag.
        if (
            tags_raw.get("deploy_to_production", "").lower() == "true"
            and status == "FINISHED"
        ):
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"MLflow run {run_id} tagged deploy_to_production=true "
                        f"on FINISHED run — production-deployment trigger; "
                        f"surface for review"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "deploy_to_production",
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # 5. Bot user + LOCAL source-type combination.
        user_id = provenance["user_id"]
        source_type_tag = tags_raw.get("mlflow.source.type", "").upper()
        if self._is_bot_user(user_id) and source_type_tag == "LOCAL":
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"MLflow run {run_id} created by bot/agent user '{user_id}' "
                        f"with mlflow.source.type=LOCAL — agent should use JOB/PIPELINE"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "bot_local_source",
                        "bot_user_id": user_id,
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # 6. Lifecycle deletion → audit-trail PASS.
        if lifecycle == "deleted":
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"MLflow run {run_id} lifecycle_stage=deleted — "
                        f"deletion captured in audit trail"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "lifecycle_deleted",
                    },
                )
            )

        # Fallback record.
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id=self._table.default_control,
                    control_name=_CONTROL_NAMES.get(
                        self._table.default_control, self._table.default_control
                    ),
                    result="FLAG",
                    detail=f"MLflow run {run_id} has no extractable evidence",
                    evidence_data={**evidence_base, "evidence_kind": "empty"},
                )
            )
            worst = _max_result(worst, "FLAG")

        timestamp = _ms_to_iso(info.get("start_time"))
        end_ms = _coerce_float(info.get("end_time")) or 0.0
        start_ms = _coerce_float(info.get("start_time")) or 0.0
        duration = max(0.0, end_ms - start_ms)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mlflow-run-{run_id[:24]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="mlflow_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"MLflow run {run_id} (status={status}): "
                f"{len(control_results)} control(s)"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration,
            session_id=provenance["experiment_id"] or None,
        )

    # ---------------------------------------------------------- registered models

    def _model_to_result(
        self,
        model: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        name = str(model.get("name", "")) or "unknown-model"
        latest_versions = model.get("latest_versions") or []
        creation_ms = _coerce_float(model.get("creation_timestamp")) or 0.0
        provenance: dict[str, Any] = {
            "source_format": "mlflow",
            "source_tool_name": "mlflow",
            "source_tool_version": "",
            "record_kind": "registered_model",
            "registered_model_name": name,
            "creation_timestamp_ms": creation_ms,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256

        # Summarize versions (no PII risk — versions are integers/strings).
        version_view: list[dict[str, Any]] = []
        production_versions: list[dict[str, Any]] = []
        warning_productions: list[dict[str, Any]] = []
        for v in latest_versions:
            if not isinstance(v, dict):
                continue
            stage = str(v.get("current_stage", ""))
            ver = str(v.get("version", ""))
            run_id = str(v.get("run_id", ""))
            status_msg = v.get("status_message")
            entry = {
                "version": ver,
                "current_stage": stage,
                "status": str(v.get("status", "")),
                "run_id": run_id,
                "status_message": status_msg if isinstance(status_msg, str) else "",
            }
            version_view.append(entry)
            if stage == "Production":
                production_versions.append(entry)
                if _is_warning_status_message(status_msg):
                    warning_productions.append(entry)

        evidence_base: dict[str, Any] = {
            "registered_model_name": name,
            "creation_timestamp_ms": creation_ms,
            "latest_versions": version_view,
            "production_version_count": len(production_versions),
            "source_tool": "mlflow",
            "source_provenance": provenance,
        }

        control_results: list[ControlResult] = []
        worst = "PASS"

        # Multiple Production versions → PR-05 FAIL.
        if len(production_versions) > 1:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FAIL",
                    detail=(
                        f"Registered model '{name}' has "
                        f"{len(production_versions)} versions in stage=Production "
                        f"— registry inconsistency"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "multiple_production_versions",
                        "production_versions": [v["version"] for v in production_versions],
                    },
                )
            )
            worst = _max_result(worst, "FAIL")

        # Warning-status Production versions → PR-03 FLAG.
        for v in warning_productions:
            control_results.append(
                ControlResult(
                    control_id="PR-03",
                    control_name=_CONTROL_NAMES["PR-03"],
                    result="FLAG",
                    detail=(
                        f"Registered model '{name}' v{v['version']} "
                        f"in stage=Production with warning status_message"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "production_warning_status",
                        "version": v["version"],
                        "status_message": v["status_message"],
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Registered model '{name}' captured "
                        f"({len(version_view)} version(s) in registry)"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "registry_snapshot",
                    },
                )
            )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mlflow-model-{name[:24]}",
            timestamp=_ms_to_iso(creation_ms),
            agent_id=self.agent_id,
            source_type="mlflow_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"MLflow registered model '{name}' "
                f"({len(version_view)} version(s), {len(production_versions)} in Production)"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=name or None,
        )

    # ---------------------------------------------------------- audit logs

    def _audit_to_result(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        action = str(entry.get("action", ""))
        target_type = str(entry.get("target_type", ""))
        target_id = str(entry.get("target_id", ""))
        user_id = str(entry.get("user_id", ""))
        ts = entry.get("timestamp")
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        log_id = str(entry.get("id", "")) or uuid.uuid4().hex[:12]

        provenance: dict[str, Any] = {
            "source_format": "mlflow",
            "source_tool_name": "mlflow",
            "source_tool_version": "",
            "record_kind": "audit_log",
            "log_id": log_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "user_id": user_id,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256

        evidence_base: dict[str, Any] = {
            "log_id": log_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "user_id": user_id,
            "timestamp": str(ts or ""),
            "details": dict(details),  # structured — verbatim is OK
            "source_tool": "mlflow",
            "source_provenance": provenance,
        }

        # Decide control + result.
        control_id = "PR-05"
        result = "PASS"
        detail = (
            f"MLflow audit log {log_id}: action='{action}' "
            f"on {target_type} {target_id} by {user_id}"
        )

        if action == "experiment.delete":
            control_id, result = "PR-02", "FAIL"
            detail = (
                f"MLflow audit: experiment.delete on {target_id} by {user_id} "
                f"— audit destruction"
            )
        elif action == "run.delete":
            control_id, result = "PR-02", "FLAG"
            detail = (
                f"MLflow audit: run.delete on {target_id} by {user_id} "
                f"— audit completeness risk"
            )
        elif action == "permission.grant":
            control_id, result = "PR-02", "FLAG"
            detail = (
                f"MLflow audit: permission.grant on {target_type} {target_id} "
                f"by {user_id} — review for least-privilege"
            )
        elif action == "model_version.archive":
            control_id, result = "PR-05", "PASS"
            detail = (
                f"MLflow audit: model_version.archive on {target_id} by {user_id}"
            )
        elif action == "model_version.transition_stage":
            new_stage = str(details.get("new_stage", ""))
            approved_by = details.get("approved_by")
            if new_stage == "Production" and (approved_by is None or approved_by == ""):
                control_id, result = "PR-02", "FAIL"
                detail = (
                    f"MLflow audit: model_version.transition_stage to Production "
                    f"on {target_id} by {user_id} with NO approver "
                    f"— auto-promotion without approval"
                )
            elif new_stage == "Production" and approved_by:
                control_id, result = "PR-05", "PASS"
                detail = (
                    f"MLflow audit: model_version.transition_stage to Production "
                    f"on {target_id} by {user_id}, approved_by={approved_by}"
                )
            else:
                control_id, result = "PR-05", "PASS"
                detail = (
                    f"MLflow audit: model_version.transition_stage to "
                    f"'{new_stage}' on {target_id} by {user_id}"
                )

        control_result = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=result,
            detail=detail,
            evidence_data={
                **evidence_base,
                "evidence_kind": f"audit_{action}" if action else "audit",
            },
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mlflow-audit-{log_id[:24]}",
            timestamp=str(ts or datetime.now(timezone.utc).isoformat()),
            agent_id=self.agent_id,
            source_type="mlflow_import",
            mode=self.mode,
            control_results=[control_result],
            decision=_decision_from(result),
            decision_reason=detail,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=target_id or None,
        )
