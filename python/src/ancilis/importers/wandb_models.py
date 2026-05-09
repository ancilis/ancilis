"""Weights & Biases Models importer — converts W&B Models exports to AKSI EvaluationResults.

W&B Models (https://wandb.ai) is W&B's core MLOps platform — model registry, run
tracking, sweeps, artifacts. It is distinct from W&B Weave (LLM-ops); customers
using W&B's full platform need both importers to cover the full lifecycle.
W&B Models tracks training-run state, the registered-model registry (aliases,
version counts, protection rules), and platform audit events (run/artifact/
project deletion, alias promotions, public report sharing, API-key issuance).

Accepted shapes (all common W&B Models REST shapes plus generic envelopes):

    {"runs": [...]}                # /api/v1/runs
    {"registered_models": [...]}   # /api/v1/registered_models
    {"audit_logs": [...]}          # /api/v1/audit_logs
    {"data": [...]}                # generic envelope; record kind auto-detected
    [...]                          # bare list; record kind auto-detected per record
    JSONL                          # one record per line

Record-kind dispatch:

  * Top-level ``runs`` key → run records (one EvaluationResult per run)
  * Top-level ``registered_models`` key → model records (one per registered model)
  * Top-level ``audit_logs`` key → audit records (one per action)
  * Generic ``data`` envelope or bare list → each record dispatched by shape:
    ``state`` + ``project`` → run; ``aliases`` + ``version_count`` → registered
    model; ``action`` + ``target_type`` → audit log.

Sanitization (per the SDK no-PII guarantee):

  * ``run.name`` is replaced by ``{length, sha256}`` (could be PII like
    "alice-eval-pii-2026q2").
  * ``config`` raw values are dropped — the importer keeps the config key names
    plus a sha256 of each value (configs can carry secrets like API keys).
  * ``summary_metrics`` values for well-known metric names are stored verbatim
    (numeric scores are non-sensitive); arbitrary user-named metrics are stored
    as ``{name_sha256, value}`` so existence is provable but the metric name
    isn't retained.
  * ``tags`` raw values that aren't in the well-known tag list are replaced by
    ``{length, sha256}``; well-known tags (``production``, ``staging``,
    ``automated``, etc.) are kept verbatim because they drive evaluation rules.
  * ``host`` is replaced by ``{length, sha256}``.
  * ``git.commit`` is truncated to the last 8 hex characters (the prefix is
    non-identifying and provides reproducibility evidence).
  * ``audit_logs[].details`` is stored verbatim — it is structured (not free
    text) and reviewers need it to assess approvals/transitions.

AKSI mapping for runs:

  * state=finished + summary_metrics applied:
      - hallucination_rate < 0.05 → PR-03 PASS; > 0.30 → FAIL; mid → FLAG
      - toxicity < 0.05 → DE-01 PASS; > 0.30 → FAIL; mid → FLAG
      - accuracy / f1 > 0.9 → PR-03 PASS; < 0.7 → FAIL; mid → FLAG
  * state=failed → DE-01 FAIL
  * state=crashed → DE-01 FAIL (worse than failed — host issue)
  * state=killed → PR-05 FLAG
  * git.is_dirty=true on production tag → PR-05 FLAG (un-pinned source)
  * git.commit missing → PR-05 FAIL (un-reproducible)
  * tags contains "production" + state in {running, failed, crashed} → PR-05
    FAIL (production run in bad state)
  * compute_config.gpu_count > threshold (default 8) → PR-04 FLAG (high compute
    cost — surface for review)
  * username matches bot/agent patterns + tags missing "automated" → PR-05 FLAG
  * is_sweep=true → PR-05 PASS (sweep run — expected)

AKSI mapping for registered models:

  * latest_alias=production + is_protected=false → PR-02 FAIL (production model
    without protection rule)
  * latest_alias=production + version_count > threshold (default 50) → PR-04
    FLAG (model registry sprawl)

AKSI mapping for audit logs:

  * action=run.delete → PR-02 FLAG (audit completeness)
  * action=project.delete → PR-02 FAIL (project destruction)
  * action=artifact.delete + target was referenced by Production model → PR-02
    FAIL (deleting artifact still in production = breaking change)
  * action=model.alias.set new_alias=production approved_by=null AND
    target.is_protected=true → PR-02 FAIL (auto-promotion to protected
    production alias without approval)
  * action=model.alias.set new_alias=production approved_by set → PR-05 PASS
  * action=report.shared_publicly → PR-04 FAIL (public report = potential data
    exposure; reports often contain run charts with sensitive values)
  * action=api_key.created → PR-01 FLAG (key issuance)
  * action=service_account.created → PR-01 FLAG (service account creation)
  * action=team.member.role.changed details.new_role=admin → PR-02 FLAG
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping file lives at <repo>/shared/mappings/wandb-models-aksi-controls.json.
# This source file lives at <repo>/python/src/ancilis/importers/wandb_models.py,
# so .resolve() + 5 .parent traversals land at the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "wandb-models-aksi-controls.json"
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
_DEFAULT_GPU_COUNT_THRESHOLD = 8
_DEFAULT_VERSION_COUNT_THRESHOLD = 50

_DEFAULT_WELL_KNOWN_METRIC_NAMES: tuple[str, ...] = (
    "accuracy",
    "loss",
    "f1",
    "f1_score",
    "precision",
    "recall",
    "auc",
    "roc_auc",
    "perplexity",
    "hallucination_rate",
    "hallucination",
    "toxicity",
    "toxicity_score",
    "bias",
    "safety",
    "groundedness",
    "faithfulness",
    "factuality",
    "relevance",
    "bleu",
    "rouge",
    "exact_match",
    "mae",
    "mse",
    "rmse",
)

_DEFAULT_WELL_KNOWN_TAG_NAMES: tuple[str, ...] = (
    "production",
    "staging",
    "development",
    "baseline",
    "experiment",
    "automated",
    "manual",
    "sweep",
    "evaluation",
    "training",
    "fine-tune",
    "fine-tuning",
    "rlhf",
    "sft",
    "ablation",
)

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

_BAD_PRODUCTION_STATES: frozenset[str] = frozenset({"running", "failed", "crashed"})


@dataclass
class _MappingTable:
    metric_to_control: dict[str, dict[str, Any]] = field(default_factory=dict)
    audit_action_rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    well_known_metric_names: set[str] = field(
        default_factory=lambda: set(_DEFAULT_WELL_KNOWN_METRIC_NAMES)
    )
    well_known_tag_names: set[str] = field(
        default_factory=lambda: set(_DEFAULT_WELL_KNOWN_TAG_NAMES)
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
    gpu_count_threshold: int = _DEFAULT_GPU_COUNT_THRESHOLD
    version_count_threshold: int = _DEFAULT_VERSION_COUNT_THRESHOLD
    default_control: str = _DEFAULT_UNMAPPED_CONTROL


def _load_mapping_table() -> _MappingTable:
    """Load wandb-models-aksi-controls.json, tolerating a missing/malformed file."""
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
            table.gpu_count_threshold = int(
                thresholds.get("gpu_count_threshold", _DEFAULT_GPU_COUNT_THRESHOLD)
            )
            table.version_count_threshold = int(
                thresholds.get(
                    "version_count_threshold", _DEFAULT_VERSION_COUNT_THRESHOLD
                )
            )

        wk_metrics = meta.get("well_known_metric_names")
        if isinstance(wk_metrics, list):
            table.well_known_metric_names = {str(s).lower() for s in wk_metrics}

        wk_tags = meta.get("well_known_tag_names")
        if isinstance(wk_tags, list):
            table.well_known_tag_names = {str(s).lower() for s in wk_tags}

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
    s = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
    return {
        "present": True,
        "length": len(s),
        "sha256": _sha256(s),
    }


def _commit_prefix(commit: str | None) -> str | None:
    """Return the last 8 hex characters of a git commit hash.

    The prefix is non-identifying but provides reproducibility evidence —
    consumers can verify two runs share the same source commit without
    retaining the full hash.
    """
    if not isinstance(commit, str) or not commit:
        return None
    body = commit.strip()
    return body[-8:] if len(body) > 8 else body


_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _decision_from(worst: str) -> str:
    return {"PASS": "ALLOW", "FLAG": "FLAG", "FAIL": "BLOCK"}.get(worst, "ALLOW")


def _normalize_tags(raw: Any) -> list[str]:
    """Coerce a tags field to a list of normalized lowercase strings."""
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item:
            out.append(item.strip().lower())
    return out


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class WandbModelsImporter:
    """Parse a W&B Models runs / registered-models / audit-log export and
    convert to ``EvaluationResult`` records.

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
        """Parse a W&B Models export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        return self._parse_text(text, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse a W&B Models export from a string (JSON or JSONL)."""
        return self._parse_text(content, file_sha256=None)

    # ----------------------------------------------------------------- private

    def _parse_text(
        self,
        text: str,
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        runs, models, audits = self._extract_records(text)
        # Production-artifact index (artifact_id → registered_model_name) so
        # audit_log artifact.delete events can be cross-checked against any
        # registered model that pinned that artifact in production.
        prod_artifact_index = self._build_production_artifact_index(models)
        # Protection map (registered_model_name → is_protected) so audit_log
        # alias.set events can decide FAIL vs PASS without re-walking models.
        model_protection_map = {
            str(m.get("name", "")): bool(m.get("is_protected", False))
            for m in models
            if isinstance(m, dict) and m.get("name")
        }

        results: list[EvaluationResult] = []
        for run in runs:
            results.append(self._run_to_result(run, file_sha256=file_sha256))
        for model in models:
            results.append(self._model_to_result(model, file_sha256=file_sha256))
        for entry in audits:
            results.append(
                self._audit_to_result(
                    entry,
                    file_sha256=file_sha256,
                    prod_artifact_index=prod_artifact_index,
                    model_protection_map=model_protection_map,
                )
            )
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
                    if not (runs or models or audits):
                        for entry in doc.get("data") or []:
                            if isinstance(entry, dict):
                                self._dispatch_record(entry, runs, models, audits)
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
        if "action" in record and "target_type" in record:
            audits.append(record)
            return
        if "aliases" in record and "version_count" in record:
            models.append(record)
            return
        if "state" in record and "project" in record:
            runs.append(record)
            return
        # Unknown shape — ignore to avoid producing spurious evidence.

    @staticmethod
    def _build_production_artifact_index(
        models: list[dict[str, Any]],
    ) -> dict[str, str]:
        """Index artifact IDs referenced by any production-aliased model.

        W&B doesn't expose artifact-id pinning in the registered_models payload
        we accept, but exporters often include a ``production_artifact_ids``
        list (or per-alias ``artifact_id``). We collect any such IDs so an
        ``artifact.delete`` audit entry can FAIL when the deleted artifact was
        actively pinned in production.
        """
        index: dict[str, str] = {}
        for m in models:
            if not isinstance(m, dict):
                continue
            name = str(m.get("name", ""))
            if not name:
                continue
            latest_alias = str(m.get("latest_alias", "")).lower()
            if latest_alias != "production":
                continue
            for art_id in m.get("production_artifact_ids") or []:
                if isinstance(art_id, str) and art_id:
                    index[art_id] = name
            for alias_entry in m.get("aliases") or []:
                if not isinstance(alias_entry, dict):
                    continue
                if str(alias_entry.get("alias", "")).lower() != "production":
                    continue
                art_id = alias_entry.get("artifact_id")
                if isinstance(art_id, str) and art_id:
                    index[art_id] = name
        return index

    # ---------- redaction helpers ------------------------------------------

    def _summarize_config(self, config: Any) -> dict[str, Any]:
        """Return key names + sha256 of values; never store values verbatim.

        W&B run configs can carry secrets (API keys, prompts) embedded as
        scalar values. We keep the key NAMES (non-identifying — they're
        config schema, not user data) and a sha256 of each value so consumers
        can detect tampering without retaining the secret.
        """
        if not isinstance(config, dict):
            return {"present": False}
        keys: list[str] = []
        digests: dict[str, str] = {}
        for k, v in config.items():
            sk = str(k)
            keys.append(sk)
            try:
                serialized = json.dumps(v, default=str, sort_keys=True)
            except (TypeError, ValueError):
                serialized = str(v)
            digests[sk] = _sha256(serialized)
        return {
            "present": True,
            "key_count": len(keys),
            "keys": sorted(keys),
            "value_sha256_by_key": digests,
        }

    def _summarize_metrics(
        self,
        metrics: Any,
    ) -> tuple[dict[str, float], list[dict[str, Any]]]:
        """Split summary_metrics into well-known and arbitrary buckets.

        Well-known metric names (accuracy, loss, hallucination_rate, etc.) are
        non-sensitive scoring signals — keep verbatim with their numeric value.
        Arbitrary user-named metrics may encode information about the user's
        domain (e.g. ``customer_pii_v3_accuracy``) so we keep only a sha256 of
        the name plus the numeric value.
        """
        well_known: dict[str, float] = {}
        arbitrary: list[dict[str, Any]] = []
        if not isinstance(metrics, dict):
            return well_known, arbitrary
        for k, v in metrics.items():
            sk = str(k)
            if sk.startswith("_"):
                # Internal W&B fields (e.g. _wandb, _runtime) — ignore.
                continue
            f = _coerce_float(v)
            if f is None:
                continue
            if sk.lower() in self._table.well_known_metric_names:
                well_known[sk] = f
            else:
                arbitrary.append({
                    "name_sha256": _sha256(sk),
                    "name_length": len(sk),
                    "value": f,
                })
        return well_known, arbitrary

    def _summarize_tags(self, tags: Any) -> tuple[list[str], list[dict[str, Any]]]:
        """Split tags into well-known (verbatim) and arbitrary (redacted)."""
        well_known: list[str] = []
        arbitrary: list[dict[str, Any]] = []
        if not isinstance(tags, list):
            return well_known, arbitrary
        for raw in tags:
            if not isinstance(raw, str) or not raw:
                continue
            norm = raw.strip().lower()
            if norm in self._table.well_known_tag_names:
                well_known.append(norm)
            else:
                arbitrary.append({
                    "length": len(raw),
                    "sha256": _sha256(raw),
                })
        return well_known, arbitrary

    # ---------- run handling -----------------------------------------------

    def _bucket_metric(
        self,
        metric_name: str,
        value: float,
    ) -> tuple[str, str, bool]:
        """Return (control_id, result, inverted) for a metric value."""
        norm = metric_name.lower()
        rule = self._table.metric_to_control.get(norm)
        if not rule:
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

    def _is_bot_user(self, username: str) -> bool:
        if not username:
            return False
        return any(
            fnmatch.fnmatchcase(username, pat)
            for pat in self._table.bot_user_patterns
        )

    def _run_provenance(
        self,
        run: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        project = run.get("project") or {}
        project_name = ""
        entity = ""
        if isinstance(project, dict):
            project_name = str(project.get("name", ""))
            entity = str(project.get("entity", ""))
        git = run.get("git") if isinstance(run.get("git"), dict) else {}

        provenance: dict[str, Any] = {
            "source_format": "wandb_models",
            "source_tool_name": "wandb_models",
            "source_tool_version": "",
            "record_kind": "run",
            "run_id": str(run.get("id", "")),
            "username": str(run.get("username", "")),
            "user_id": str(run.get("user_id", "")),
            "project": project_name,
            "entity": entity,
            "state": str(run.get("state", "")).lower(),
            "compute_type": str(run.get("compute_type", "")),
            "is_sweep": bool(run.get("is_sweep", False)),
            "sweep_id": str(run.get("sweep_id") or ""),
            "started_at": str(run.get("started_at", "")),
            "ended_at": str(run.get("ended_at", "")),
            "duration_ms": _coerce_float(run.get("duration_ms")) or 0.0,
            "artifact_count": int(_coerce_float(run.get("artifact_count")) or 0),
            "run_name_redacted": _redact(run.get("name")),
            "host_redacted": _redact(run.get("host")),
        }
        if isinstance(git, dict):
            commit = git.get("commit")
            provenance["git_commit_prefix"] = _commit_prefix(commit)
            provenance["git_commit_present"] = bool(commit)
            provenance["git_branch"] = str(git.get("branch", ""))
            provenance["git_is_dirty"] = bool(git.get("is_dirty", False))
        else:
            provenance["git_commit_prefix"] = None
            provenance["git_commit_present"] = False
            provenance["git_branch"] = ""
            provenance["git_is_dirty"] = False
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _run_evidence_base(
        self,
        run: dict[str, Any],
        *,
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        well_known_metrics, arbitrary_metrics = self._summarize_metrics(
            run.get("summary_metrics")
        )
        well_known_tags, arbitrary_tags = self._summarize_tags(run.get("tags"))
        config_summary = self._summarize_config(run.get("config"))

        compute_config_raw = run.get("compute_config")
        compute_config: dict[str, Any] = {}
        gpu_count: int | None = None
        if isinstance(compute_config_raw, dict):
            gc = _coerce_float(compute_config_raw.get("gpu_count"))
            if gc is not None:
                gpu_count = int(gc)
                compute_config["gpu_count"] = gpu_count
            gpu_type = compute_config_raw.get("gpu_type")
            if isinstance(gpu_type, str) and gpu_type:
                compute_config["gpu_type"] = gpu_type

        evidence: dict[str, Any] = {
            "run_id": provenance["run_id"],
            "project": provenance["project"],
            "entity": provenance["entity"],
            "state": provenance["state"],
            "username": provenance["username"],
            "started_at": provenance["started_at"],
            "ended_at": provenance["ended_at"],
            "duration_ms": provenance["duration_ms"],
            "artifact_count": provenance["artifact_count"],
            "compute_type": provenance["compute_type"],
            "compute_config": compute_config,
            "gpu_count": gpu_count,
            "is_sweep": provenance["is_sweep"],
            "sweep_id": provenance["sweep_id"],
            "run_name_redacted": provenance["run_name_redacted"],
            "host_redacted": provenance["host_redacted"],
            "git_commit_prefix": provenance["git_commit_prefix"],
            "git_commit_present": provenance["git_commit_present"],
            "git_branch": provenance["git_branch"],
            "git_is_dirty": provenance["git_is_dirty"],
            "well_known_metrics": well_known_metrics,
            "arbitrary_metrics": arbitrary_metrics,
            "well_known_tags": well_known_tags,
            "arbitrary_tags": arbitrary_tags,
            "config_summary": config_summary,
            "source_tool": "wandb_models",
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
        run_id = provenance["run_id"] or uuid.uuid4().hex[:12]
        state = provenance["state"]
        well_known_tags = evidence_base["well_known_tags"]
        is_production_tagged = "production" in well_known_tags
        username = provenance["username"]

        control_results: list[ControlResult] = []
        worst = "PASS"

        # 1. State-based controls.
        if state == "finished":
            metric_seen = False
            for metric_name, value in sorted(evidence_base["well_known_metrics"].items()):
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
                            f"W&B run {run_id} metric '{metric_name}'={value:.4f} "
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
                control_results.append(
                    ControlResult(
                        control_id="PR-03",
                        control_name=_CONTROL_NAMES["PR-03"],
                        result="FLAG",
                        detail=(
                            f"W&B run {run_id} state=finished but no recognized "
                            f"quality metrics recorded — cannot establish PASS evidence"
                        ),
                        evidence_data={
                            **evidence_base,
                            "evidence_kind": "metric_missing",
                        },
                    )
                )
                worst = _max_result(worst, "FLAG")
        elif state == "failed":
            control_results.append(
                ControlResult(
                    control_id="DE-01",
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=f"W&B run {run_id} state=failed (training error)",
                    evidence_data={**evidence_base, "evidence_kind": "state_failed"},
                )
            )
            worst = _max_result(worst, "FAIL")
        elif state == "crashed":
            control_results.append(
                ControlResult(
                    control_id="DE-01",
                    control_name=_CONTROL_NAMES["DE-01"],
                    result="FAIL",
                    detail=(
                        f"W&B run {run_id} state=crashed (host issue — "
                        f"worse than failed)"
                    ),
                    evidence_data={**evidence_base, "evidence_kind": "state_crashed"},
                )
            )
            worst = _max_result(worst, "FAIL")
        elif state == "killed":
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"W&B run {run_id} state=killed (manual termination — "
                        f"surface for review)"
                    ),
                    evidence_data={**evidence_base, "evidence_kind": "state_killed"},
                )
            )
            worst = _max_result(worst, "FLAG")

        # 2. Reproducibility — git commit must be present.
        if not provenance["git_commit_present"]:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FAIL",
                    detail=(
                        f"W&B run {run_id} missing git.commit — un-reproducible"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "missing_git_commit",
                    },
                )
            )
            worst = _max_result(worst, "FAIL")

        # 3. Dirty git tree on production-tagged run.
        if provenance["git_is_dirty"] and is_production_tagged:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"W&B run {run_id} git.is_dirty=true on production-tagged "
                        f"run — un-pinned source"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "dirty_git_with_production_tag",
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # 4. Production-tagged run in bad state.
        if is_production_tagged and state in _BAD_PRODUCTION_STATES:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FAIL",
                    detail=(
                        f"W&B run {run_id} tagged 'production' but state={state} "
                        f"— production run in bad state"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "production_run_in_bad_state",
                    },
                )
            )
            worst = _max_result(worst, "FAIL")

        # 5. High GPU count.
        gpu_count = evidence_base.get("gpu_count")
        if isinstance(gpu_count, int) and gpu_count > self._table.gpu_count_threshold:
            control_results.append(
                ControlResult(
                    control_id="PR-04",
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="FLAG",
                    detail=(
                        f"W&B run {run_id} compute_config.gpu_count={gpu_count} "
                        f"exceeds threshold {self._table.gpu_count_threshold} "
                        f"— high compute cost; surface for review"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "high_gpu_count",
                        "gpu_count_threshold": self._table.gpu_count_threshold,
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # 6. Bot user without 'automated' tag.
        if self._is_bot_user(username) and "automated" not in well_known_tags:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"W&B run {run_id} created by bot user '{username}' "
                        f"but missing 'automated' tag — bot run without proper tagging"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "bot_run_without_automated_tag",
                        "bot_username": username,
                    },
                )
            )
            worst = _max_result(worst, "FLAG")

        # 7. Sweep run — expected lifecycle event.
        if provenance["is_sweep"]:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"W&B run {run_id} is a sweep run "
                        f"(sweep_id={provenance['sweep_id']}) — expected lifecycle"
                    ),
                    evidence_data={**evidence_base, "evidence_kind": "sweep_run"},
                )
            )

        if not control_results:
            control_results.append(
                ControlResult(
                    control_id=self._table.default_control,
                    control_name=_CONTROL_NAMES.get(
                        self._table.default_control, self._table.default_control
                    ),
                    result="FLAG",
                    detail=f"W&B run {run_id} has no extractable evidence",
                    evidence_data={**evidence_base, "evidence_kind": "empty"},
                )
            )
            worst = _max_result(worst, "FLAG")

        timestamp = (
            provenance["started_at"]
            or provenance["ended_at"]
            or datetime.now(timezone.utc).isoformat()
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"wandb-models-run-{run_id[:24]}",
            timestamp=str(timestamp),
            agent_id=self.agent_id,
            source_type="wandb_models_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"W&B run {run_id} (state={state}): "
                f"{len(control_results)} control(s)"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=provenance["duration_ms"],
            session_id=provenance["project"] or None,
        )

    # ---------- registered model handling ----------------------------------

    def _model_to_result(
        self,
        model: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        name = str(model.get("name", "")) or "unknown-model"
        entity = str(model.get("entity", ""))
        latest_alias = str(model.get("latest_alias", "")).lower()
        is_protected = bool(model.get("is_protected", False))
        version_count = int(_coerce_float(model.get("version_count")) or 0)
        registered_at = str(model.get("registered_at", ""))
        ml_task_type = str(model.get("ml_task_type", ""))

        aliases_view: list[dict[str, Any]] = []
        for entry in model.get("aliases") or []:
            if not isinstance(entry, dict):
                continue
            aliases_view.append({
                "alias": str(entry.get("alias", "")),
                "version": str(entry.get("version", "")),
                "created_at": str(entry.get("created_at", "")),
                "created_by": str(entry.get("created_by", "")),
            })

        provenance: dict[str, Any] = {
            "source_format": "wandb_models",
            "source_tool_name": "wandb_models",
            "source_tool_version": "",
            "record_kind": "registered_model",
            "registered_model_name": name,
            "entity": entity,
            "latest_alias": latest_alias,
            "is_protected": is_protected,
            "version_count": version_count,
            "ml_task_type": ml_task_type,
            "registered_at": registered_at,
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256

        evidence_base: dict[str, Any] = {
            "registered_model_name": name,
            "entity": entity,
            "latest_alias": latest_alias,
            "is_protected": is_protected,
            "version_count": version_count,
            "ml_task_type": ml_task_type,
            "registered_at": registered_at,
            "aliases": aliases_view,
            "source_tool": "wandb_models",
            "source_provenance": provenance,
        }

        control_results: list[ControlResult] = []
        worst = "PASS"

        # 1. Production alias without protection rule → PR-02 FAIL.
        if latest_alias == "production" and not is_protected:
            control_results.append(
                ControlResult(
                    control_id="PR-02",
                    control_name=_CONTROL_NAMES["PR-02"],
                    result="FAIL",
                    detail=(
                        f"Registered model '{name}' has latest_alias=production "
                        f"but is_protected=false — production model without "
                        f"protection rule"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "unprotected_production_alias",
                    },
                )
            )
            worst = _max_result(worst, "FAIL")

        # 2. Production model with version-count sprawl → PR-04 FLAG.
        if (
            latest_alias == "production"
            and version_count > self._table.version_count_threshold
        ):
            control_results.append(
                ControlResult(
                    control_id="PR-04",
                    control_name=_CONTROL_NAMES["PR-04"],
                    result="FLAG",
                    detail=(
                        f"Registered model '{name}' has version_count="
                        f"{version_count} (> {self._table.version_count_threshold}) "
                        f"on production alias — registry sprawl"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "version_count_sprawl",
                        "version_count_threshold": self._table.version_count_threshold,
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
                        f"({version_count} version(s), latest_alias='{latest_alias}', "
                        f"is_protected={is_protected})"
                    ),
                    evidence_data={
                        **evidence_base,
                        "evidence_kind": "registry_snapshot",
                    },
                )
            )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"wandb-models-model-{name[:24]}",
            timestamp=registered_at or datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="wandb_models_import",
            mode=self.mode,
            control_results=control_results,
            decision=_decision_from(worst),
            decision_reason=(
                f"W&B registered model '{name}' "
                f"({version_count} version(s), latest_alias='{latest_alias}')"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=name or None,
        )

    # ---------- audit-log handling -----------------------------------------

    def _audit_to_result(
        self,
        entry: dict[str, Any],
        *,
        file_sha256: str | None,
        prod_artifact_index: dict[str, str],
        model_protection_map: dict[str, bool],
    ) -> EvaluationResult:
        action = str(entry.get("action", ""))
        target_type = str(entry.get("target_type", ""))
        target_id = str(entry.get("target_id", ""))
        user_id = str(entry.get("user_id", ""))
        ts = entry.get("timestamp")
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        log_id = str(entry.get("id", "")) or uuid.uuid4().hex[:12]

        provenance: dict[str, Any] = {
            "source_format": "wandb_models",
            "source_tool_name": "wandb_models",
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
            "source_tool": "wandb_models",
            "source_provenance": provenance,
        }

        # Default: every audit log produces PR-05 PASS (audit trail captured).
        control_id = "PR-05"
        result = "PASS"
        detail = (
            f"W&B audit log {log_id}: action='{action}' on "
            f"{target_type} {target_id} by {user_id}"
        )
        evidence_kind = f"audit_{action}" if action else "audit"

        if action == "run.delete":
            control_id, result = "PR-02", "FLAG"
            detail = (
                f"W&B audit: run.delete on {target_id} by {user_id} "
                f"— audit completeness risk"
            )
        elif action == "project.delete":
            control_id, result = "PR-02", "FAIL"
            detail = (
                f"W&B audit: project.delete on {target_id} by {user_id} "
                f"— project destruction"
            )
        elif action == "artifact.delete":
            referenced_model = prod_artifact_index.get(target_id)
            if referenced_model:
                control_id, result = "PR-02", "FAIL"
                detail = (
                    f"W&B audit: artifact.delete on {target_id} by {user_id} — "
                    f"artifact was referenced by Production model "
                    f"'{referenced_model}' (breaking change)"
                )
                evidence_base["referenced_production_model"] = referenced_model
            else:
                control_id, result = "PR-02", "FLAG"
                detail = (
                    f"W&B audit: artifact.delete on {target_id} by {user_id} "
                    f"— review for downstream impact"
                )
        elif action == "model.alias.set":
            new_alias = str(details.get("new_alias", "")).lower()
            approved_by = details.get("approved_by")
            # Trust the audit-log's own target.is_protected flag if the model
            # is missing from the protection map (audit-only feeds).
            target_is_protected = bool(
                details.get("target_is_protected")
                if details.get("target_is_protected") is not None
                else model_protection_map.get(target_id, False)
            )
            if (
                new_alias == "production"
                and target_is_protected
                and (approved_by is None or approved_by == "")
            ):
                control_id, result = "PR-02", "FAIL"
                detail = (
                    f"W&B audit: model.alias.set new_alias=production on "
                    f"protected model {target_id} by {user_id} with NO approver "
                    f"— auto-promotion without approval"
                )
            elif new_alias == "production" and approved_by:
                control_id, result = "PR-05", "PASS"
                detail = (
                    f"W&B audit: model.alias.set new_alias=production on "
                    f"{target_id} by {user_id}, approved_by={approved_by}"
                )
            else:
                control_id, result = "PR-05", "PASS"
                detail = (
                    f"W&B audit: model.alias.set new_alias='{new_alias}' on "
                    f"{target_id} by {user_id}"
                )
        elif action == "model.alias.remove":
            control_id, result = "PR-02", "FLAG"
            detail = (
                f"W&B audit: model.alias.remove on {target_id} by {user_id} "
                f"— registry mutation"
            )
        elif action == "report.shared_publicly":
            control_id, result = "PR-04", "FAIL"
            visibility = str(details.get("sharing_visibility", "public"))
            detail = (
                f"W&B audit: report.shared_publicly on {target_id} by {user_id} "
                f"(visibility={visibility}) — public report = potential data "
                f"exposure (run charts may contain customer values)"
            )
        elif action == "api_key.created":
            control_id, result = "PR-01", "FLAG"
            detail = (
                f"W&B audit: api_key.created by {user_id} "
                f"— surface for identity governance"
            )
        elif action == "service_account.created":
            control_id, result = "PR-01", "FLAG"
            detail = (
                f"W&B audit: service_account.created on {target_id} by {user_id} "
                f"— surface for identity governance"
            )
        elif action == "team.member.added":
            control_id, result = "PR-02", "FLAG"
            detail = (
                f"W&B audit: team.member.added on {target_id} by {user_id} "
                f"— review for least-privilege"
            )
        elif action == "team.member.role.changed":
            new_role = str(details.get("new_role", "")).lower()
            if new_role == "admin":
                control_id, result = "PR-02", "FLAG"
                detail = (
                    f"W&B audit: team.member.role.changed on {target_id} by "
                    f"{user_id} new_role=admin — privilege escalation, review"
                )
            else:
                control_id, result = "PR-02", "PASS"
                detail = (
                    f"W&B audit: team.member.role.changed on {target_id} by "
                    f"{user_id} new_role='{new_role}'"
                )

        control_result = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=result,
            detail=detail,
            evidence_data={**evidence_base, "evidence_kind": evidence_kind},
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"wandb-models-audit-{log_id[:24]}",
            timestamp=str(ts or datetime.now(timezone.utc).isoformat()),
            agent_id=self.agent_id,
            source_type="wandb_models_import",
            mode=self.mode,
            control_results=[control_result],
            decision=_decision_from(result),
            decision_reason=detail,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=target_id or None,
        )


# Suppress F401 for the otherwise-unused helper kept for public test reuse.
_ = _normalize_tags
