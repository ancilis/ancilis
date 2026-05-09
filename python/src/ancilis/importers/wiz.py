"""Wiz CSPM issue importer — converts Wiz issue exports to AKSI EvaluationResults.

Wiz (https://www.wiz.io) is the dominant Cloud Security Posture Management
(CSPM) platform: it inspects deployed cloud state across AWS / GCP / Azure
for misconfigurations, exposed secrets, malware-bearing workloads, vulnerable
images, anonymous-accessible resources, attack paths, and "toxic
combinations" (combinations of conditions that together create exposure).

This is distinct from code-/dependency-scanners (Snyk) and SAST tools
(Semgrep): Wiz looks at runtime, deployed cloud posture — exactly where
AI agents now introduce drift (overly permissive IAM grants, exposed S3
buckets, public databases, secret leaks committed to cloud config).

This importer ingests Wiz issue exports in four shapes:

    1. ``{"issues": [...]}``  — canonical Wiz GraphQL export envelope
    2. ``{"data":   [...]}``  — REST-style envelope (some connectors)
    3. JSONL                   — one issue per line
    4. single object           — a bare issue

Mapping (see ``shared/mappings/wiz-aksi-controls.json``):

  * status=OPEN severity=CRITICAL                         → DE-01 FAIL  (open critical posture issue)
  * status=OPEN severity=HIGH + is_publicly_accessible    → DE-01 FAIL  (public + high = real attack surface)
  * status=OPEN severity=HIGH                             → PR-04 FAIL
  * status=OPEN severity=MEDIUM                           → PR-04 FLAG
  * status=OPEN severity=LOW                              → PR-05 PASS  (audit only)
  * type=ATTACK_PATH                                      → DE-01 FAIL  (constructed attack path = highest priority)
  * type=EXPOSED_SECRET                                   → DE-01 FAIL  (secret in cloud config)
  * type=TOXIC_COMBINATION                                → PR-04 FAIL  (Wiz flagship signal)
  * type=MALWARE                                          → DE-01 FAIL
  * type=VULNERABILITY severity=CRITICAL on internet-facing → DE-01 FAIL
  * data_classification ∋ {PII,PHI,credentials} & severity HIGH/CRITICAL → PR-04 FAIL
  * exposure.anonymous_access=true                        → PR-01 FAIL  (anonymous-accessible resource)
  * status=RESOLVED                                       → PR-05 PASS  (audit trail)
  * status=REJECTED + ignore_reason=null                  → PR-02 FAIL  (governance violation)
  * status=REJECTED + ignore_reason in {false_positive, approved_exception} → PR-05 PASS
  * is_due_diligence_done=false on HIGH/CRITICAL          → PR-05 FLAG  (open with no investigation)
  * due_date in past + status=OPEN                        → PR-02 FAIL  (overdue)
  * framework_compliance_failed ∋ {SOC2,PCI-DSS,HIPAA} & severity HIGH/CRITICAL → PR-04 FLAG
  * is_attack_path_root=true                              → DE-01 FAIL  (attack-path entry point)

Synthetic findings:

  * > concentration_threshold OPEN CRITICAL issues in the same control_category
    → DE-01 FAIL  (broken control area)
  * > resource_focus_threshold issues against the same resource
    → PR-04 FLAG  (broken resource)
  * > cloud_concentration_threshold issues against the same cloud_provider
    → PR-04 FLAG  (environment-wide drift)

Sanitization (security-critical — Wiz issues frequently encode tenant info):

  * ``resource.id`` raw is NOT stored; only the trailing 8 characters are
    captured because Wiz resource IDs are ARN-shaped and frequently encode
    account, region, and tenant identifiers in their full form.
  * ``resource.name`` raw is NOT stored; only the length + sha256 are
    captured because resource names can carry tenant- or customer-specific
    information (e.g. ``cust-acme-prod-rag-corpus``).
  * ``resource.subscription_id`` raw is NOT stored; only the trailing 8
    characters are captured.
  * ``resource.tags`` raw values are NOT stored; only the key list is
    captured. Values are kept verbatim ONLY for well-known classification
    keys (e.g. ``environment``, ``tier``, ``data-classification``) defined
    in the mapping's ``well_known_tag_keys``.
  * ``ignore_reason`` raw is NOT stored when free-form (anything other
    than the well-known sentinels ``approved_exception`` /
    ``false_positive``); only its length + sha256 are captured.
  * ``ai_recommendation`` raw is NOT stored; only its length is captured.
  * Original file is hashed (sha256) for source provenance.

The SDK does NOT depend on a ``wiz`` Python package; the Wiz API uses
GraphQL over raw HTTP and this importer is a pure JSON parser.
"""

from __future__ import annotations

import fnmatch  # noqa: F401  (parity with snyk.py — pattern matching reserved for future glob mappings)
import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Locate ``shared/mappings/wiz-aksi-controls.json`` by walking upward from this file.
_MAPPING_FILENAME = "wiz-aksi-controls.json"


def _resolve_mapping_path() -> Path:
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


_DEFAULT_MAPPINGS: dict[str, dict[str, str]] = {
    "open_critical":                          {"control": "DE-01", "result": "FAIL"},
    "open_high_publicly_accessible":          {"control": "DE-01", "result": "FAIL"},
    "open_high":                              {"control": "PR-04", "result": "FAIL"},
    "open_medium":                            {"control": "PR-04", "result": "FLAG"},
    "open_low":                               {"control": "PR-05", "result": "PASS"},
    "type_attack_path":                       {"control": "DE-01", "result": "FAIL"},
    "type_exposed_secret":                    {"control": "DE-01", "result": "FAIL"},
    "type_toxic_combination":                 {"control": "PR-04", "result": "FAIL"},
    "type_malware":                           {"control": "DE-01", "result": "FAIL"},
    "vulnerability_critical_internet_facing": {"control": "DE-01", "result": "FAIL"},
    "sensitive_data_high_severity":           {"control": "PR-04", "result": "FAIL"},
    "anonymous_access":                       {"control": "PR-01", "result": "FAIL"},
    "status_resolved":                        {"control": "PR-05", "result": "PASS"},
    "rejected_no_reason":                     {"control": "PR-02", "result": "FAIL"},
    "rejected_false_positive":                {"control": "PR-05", "result": "PASS"},
    "rejected_approved_exception":            {"control": "PR-05", "result": "PASS"},
    "no_due_diligence_high":                  {"control": "PR-05", "result": "FLAG"},
    "due_date_overdue":                       {"control": "PR-02", "result": "FAIL"},
    "compliance_relevant":                    {"control": "PR-04", "result": "FLAG"},
    "attack_path_root":                       {"control": "DE-01", "result": "FAIL"},
}


_DEFAULT_SYNTHETICS: dict[str, dict[str, str]] = {
    "concentration":       {"control": "DE-01", "result": "FAIL"},
    "resource_focus":      {"control": "PR-04", "result": "FLAG"},
    "cloud_concentration": {"control": "PR-04", "result": "FLAG"},
}


_DEFAULT_CONCENTRATION_THRESHOLD = 5
_DEFAULT_RESOURCE_FOCUS_THRESHOLD = 10
_DEFAULT_CLOUD_CONCENTRATION_THRESHOLD = 100
_DEFAULT_SENSITIVE_CLASSIFICATIONS = ["PII", "PHI", "credentials", "financial"]
_DEFAULT_COMPLIANCE_FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "GDPR", "NIST", "CIS"]
_DEFAULT_WELL_KNOWN_TAG_KEYS = [
    "environment", "env", "tier", "criticality", "owner", "team",
    "service", "application", "component", "cost-center",
    "compliance", "data-classification", "managed-by",
]

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}

# Severity normalization — Wiz uses uppercase tokens.
_SEV_HIGH_OR_CRITICAL = {"HIGH", "CRITICAL"}

# Sentinels accepted as "structured" ignore reasons (kept verbatim because
# they're enum-like and don't carry free-form data).
_STRUCTURED_IGNORE_REASONS = {"false_positive", "approved_exception"}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


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
# Sanitization helpers
# ---------------------------------------------------------------------------


def _truncate_resource_id(raw: Any) -> str | None:
    """Return only the trailing 8 characters of a Wiz resource id (ARN-shaped)."""
    if raw is None:
        return None
    s = str(raw)
    if not s:
        return None
    return s[-8:] if len(s) > 8 else s


def _redact_resource_name(raw: Any) -> dict[str, Any] | None:
    """Reduce a resource name to (length, sha256). Names can carry tenant info."""
    if raw is None:
        return None
    s = str(raw)
    if not s:
        return None
    return {
        "length": len(s),
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _truncate_subscription_id(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw)
    if not s:
        return None
    return s[-8:] if len(s) > 8 else s


def _summarize_tags(tags: Any, well_known_keys: set[str]) -> dict[str, Any]:
    """Capture tag KEYS verbatim, but VALUES only for well-known classification keys.

    Wiz tag values frequently carry tenant- or customer-identifying data
    (e.g. ``customer-id=acme-corp``); we only retain values where the key is
    a structured classification field (``environment``, ``tier``, etc.).
    """
    keys: list[str] = []
    well_known: dict[str, str] = {}
    if isinstance(tags, list):
        for tag in tags:
            if not isinstance(tag, dict):
                continue
            k = tag.get("key")
            v = tag.get("value")
            if k is None:
                continue
            ks = str(k)
            keys.append(ks)
            if ks in well_known_keys and v is not None:
                well_known[ks] = str(v)
    elif isinstance(tags, dict):
        for k, v in tags.items():
            ks = str(k)
            keys.append(ks)
            if ks in well_known_keys and v is not None:
                well_known[ks] = str(v)
    return {
        "keys": sorted(set(keys)),
        "well_known": well_known,
        "tag_count": len(keys),
    }


def _hash_ignore_reason(reason: Any) -> dict[str, Any] | None:
    """For free-form ignore reasons, store length + sha256. For sentinels, store verbatim."""
    if reason is None:
        return None
    s = str(reason)
    if s in _STRUCTURED_IGNORE_REASONS:
        return {"sentinel": s}
    return {
        "length": len(s),
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _length_only(text: Any) -> dict[str, Any] | None:
    """Capture only the length of a free-form string (for ai_recommendation)."""
    if text is None:
        return None
    s = str(text)
    return {"length": len(s)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "y", "1")
    if isinstance(value, (int, float)):
        return value != 0
    return False


def _normalize_severity(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    return raw.strip().upper()


def _normalize_status(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    return raw.strip().upper()


def _normalize_type(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    return raw.strip().upper()


def _parse_iso_date(raw: Any) -> datetime | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        # Fall back to date-only.
        try:
            dt = datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class WizImporter:
    """Parse a Wiz CSPM issues export and emit AKSI EvaluationResults.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        concentration_threshold: open-CRITICAL count per control_category that
            triggers a synthetic broken-control-area finding (default 5).
        resource_focus_threshold: per-resource issue count that triggers a
            synthetic broken-resource finding (default 10).
        cloud_concentration_threshold: per-cloud_provider issue count that
            triggers a synthetic environment-wide-drift finding (default 100).
        now: optional override for "current time" used in due-date evaluation;
            primarily for tests.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        concentration_threshold: int | None = None,
        resource_focus_threshold: int | None = None,
        cloud_concentration_threshold: int | None = None,
        now: datetime | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode

        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}

        raw_mappings = table.get("mappings") if isinstance(table, dict) else None
        self._mappings: dict[str, dict[str, str]] = (
            raw_mappings if isinstance(raw_mappings, dict) and raw_mappings else _DEFAULT_MAPPINGS
        )
        raw_synth = table.get("synthetics") if isinstance(table, dict) else None
        self._synthetics: dict[str, dict[str, str]] = (
            raw_synth if isinstance(raw_synth, dict) and raw_synth else _DEFAULT_SYNTHETICS
        )

        self.concentration_threshold = (
            concentration_threshold
            if concentration_threshold is not None
            else int(meta.get("concentration_threshold", _DEFAULT_CONCENTRATION_THRESHOLD))
        )
        self.resource_focus_threshold = (
            resource_focus_threshold
            if resource_focus_threshold is not None
            else int(meta.get("resource_focus_threshold", _DEFAULT_RESOURCE_FOCUS_THRESHOLD))
        )
        self.cloud_concentration_threshold = (
            cloud_concentration_threshold
            if cloud_concentration_threshold is not None
            else int(meta.get("cloud_concentration_threshold", _DEFAULT_CLOUD_CONCENTRATION_THRESHOLD))
        )

        sens = meta.get("sensitive_classifications")
        self._sensitive_classifications: set[str] = (
            {str(x) for x in sens} if isinstance(sens, list) and sens else set(_DEFAULT_SENSITIVE_CLASSIFICATIONS)
        )
        frameworks = meta.get("compliance_frameworks_to_track")
        self._compliance_frameworks: set[str] = (
            {str(x) for x in frameworks} if isinstance(frameworks, list) and frameworks
            else set(_DEFAULT_COMPLIANCE_FRAMEWORKS)
        )
        well_known = meta.get("well_known_tag_keys")
        self._well_known_tag_keys: set[str] = (
            {str(x) for x in well_known} if isinstance(well_known, list) and well_known
            else set(_DEFAULT_WELL_KNOWN_TAG_KEYS)
        )

        self._now = now if now is not None else datetime.now(timezone.utc)

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Wiz issues export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        issues = self._issues_from_text(text)
        return self._build_results(issues, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Wiz issue content from a JSON or JSONL string."""
        issues = self._issues_from_text(content)
        return self._build_results(issues, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _issues_from_text(self, text: str) -> list[dict[str, Any]]:
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
                if "issues" in doc and isinstance(doc["issues"], list):
                    return [e for e in doc["issues"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single bare issue.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        issue_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "wiz",
            "source_tool_name": "wiz",
            "source_tool_version": "v1",
            "spec_url": "https://docs.wiz.io/docs/issues",
        }
        if issue_id is not None:
            provenance["issue_id"] = issue_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        issues: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass — aggregate concentration counters.
        category_open_critical: dict[str, int] = {}
        per_resource_count: dict[str, int] = {}
        per_cloud_count: dict[str, int] = {}

        for issue in issues:
            status = _normalize_status(issue.get("status"))
            severity = _normalize_severity(issue.get("severity"))
            category = str(issue.get("control_category") or "") or "<uncategorized>"
            resource = issue.get("resource") if isinstance(issue.get("resource"), dict) else {}
            resource_id = str(resource.get("id") or "")
            cloud_provider = str(resource.get("cloud_provider") or "")

            if status == "OPEN" and severity == "CRITICAL":
                category_open_critical[category] = category_open_critical.get(category, 0) + 1
            if resource_id:
                per_resource_count[resource_id] = per_resource_count.get(resource_id, 0) + 1
            if cloud_provider:
                per_cloud_count[cloud_provider] = per_cloud_count.get(cloud_provider, 0) + 1

        results: list[EvaluationResult] = []
        for issue in issues:
            res = self._parse_issue(issue, file_sha256=file_sha256)
            if res is not None:
                results.append(res)

        # ---- Synthetic findings ----

        # 1. Concentration of OPEN+CRITICAL within a control_category.
        for category, count in sorted(category_open_critical.items()):
            if count > self.concentration_threshold:
                results.append(
                    self._synthetic_concentration(
                        category=category,
                        count=count,
                        file_sha256=file_sha256,
                    )
                )

        # 2. Resource-focus pattern (issues piling up on the same resource).
        for resource_id, count in sorted(per_resource_count.items()):
            if count > self.resource_focus_threshold:
                results.append(
                    self._synthetic_resource_focus(
                        resource_id=resource_id,
                        count=count,
                        file_sha256=file_sha256,
                    )
                )

        # 3. Cloud-provider concentration pattern.
        for cloud_provider, count in sorted(per_cloud_count.items()):
            if count > self.cloud_concentration_threshold:
                results.append(
                    self._synthetic_cloud_concentration(
                        cloud_provider=cloud_provider,
                        count=count,
                        file_sha256=file_sha256,
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Per-issue parsing
    # ------------------------------------------------------------------

    def _parse_issue(
        self,
        issue: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult | None:
        issue_id = str(issue.get("id") or "") or None
        issue_type = _normalize_type(issue.get("type"))
        status = _normalize_status(issue.get("status"))
        severity = _normalize_severity(issue.get("severity"))
        control_name = issue.get("control_name") if isinstance(issue.get("control_name"), str) else None
        control_category = issue.get("control_category") if isinstance(issue.get("control_category"), str) else None

        framework_compliance_failed_raw = issue.get("framework_compliance_failed")
        framework_compliance_failed: list[str] = (
            [str(x) for x in framework_compliance_failed_raw]
            if isinstance(framework_compliance_failed_raw, list)
            else []
        )

        data_classification_raw = issue.get("data_classification")
        data_classification: list[str] = (
            [str(x) for x in data_classification_raw]
            if isinstance(data_classification_raw, list)
            else []
        )

        resource = issue.get("resource") if isinstance(issue.get("resource"), dict) else {}
        resource_type = str(resource.get("type") or "") or None
        cloud_provider = str(resource.get("cloud_provider") or "") or None
        region = str(resource.get("region") or "") or None
        resource_id_truncated = _truncate_resource_id(resource.get("id"))
        resource_name_redacted = _redact_resource_name(resource.get("name"))
        subscription_id_truncated = _truncate_subscription_id(resource.get("subscription_id"))
        tags_summary = _summarize_tags(resource.get("tags"), self._well_known_tag_keys)

        exposure = issue.get("exposure") if isinstance(issue.get("exposure"), dict) else {}
        is_internet_facing = _coerce_bool(exposure.get("is_internet_facing"))
        is_publicly_accessible = _coerce_bool(exposure.get("is_publicly_accessible"))
        anonymous_access = _coerce_bool(exposure.get("anonymous_access"))

        kill_chain = issue.get("kill_chain") if isinstance(issue.get("kill_chain"), str) else None
        is_due_diligence_done = _coerce_bool(issue.get("is_due_diligence_done"))
        ignore_reason_raw = issue.get("ignore_reason")
        ignore_reason_info = _hash_ignore_reason(ignore_reason_raw)
        ignored_until = issue.get("ignored_until") if isinstance(issue.get("ignored_until"), str) else None
        ai_recommendation_info = _length_only(issue.get("ai_recommendation"))
        auto_remediation_available = _coerce_bool(issue.get("auto_remediation_available"))
        is_attack_path_root = _coerce_bool(issue.get("is_attack_path_root"))
        linked_issues_count_raw = issue.get("linked_issues_count")
        linked_issues_count = (
            int(linked_issues_count_raw)
            if isinstance(linked_issues_count_raw, (int, float)) and not isinstance(linked_issues_count_raw, bool)
            else 0
        )
        first_seen = issue.get("first_seen") if isinstance(issue.get("first_seen"), str) else None
        due_date_str = issue.get("due_date") if isinstance(issue.get("due_date"), str) else None
        due_date_dt = _parse_iso_date(due_date_str)
        is_overdue = (
            status == "OPEN"
            and due_date_dt is not None
            and due_date_dt < self._now
        )

        sensitive_data_present = any(c in self._sensitive_classifications for c in data_classification)
        compliance_frameworks_hit = [
            f for f in framework_compliance_failed if f in self._compliance_frameworks
        ]

        # Common evidence (sanitized).
        evidence_data: dict[str, Any] = {
            "id": issue_id,
            "type": issue_type or None,
            "status": status or None,
            "severity": severity or None,
            "control_name": control_name,  # vendor-supplied, safe — kept verbatim
            "control_category": control_category,
            "framework_compliance_failed": framework_compliance_failed,
            "data_classification": data_classification,
            "resource": {
                "id_truncated": resource_id_truncated,
                "name_redacted": resource_name_redacted,
                "subscription_id_truncated": subscription_id_truncated,
                "type": resource_type,
                "cloud_provider": cloud_provider,
                "region": region,
                "tags_summary": tags_summary,
            },
            "exposure": {
                "is_internet_facing": is_internet_facing,
                "is_publicly_accessible": is_publicly_accessible,
                "anonymous_access": anonymous_access,
            },
            "kill_chain": kill_chain,
            "is_due_diligence_done": is_due_diligence_done,
            "ignore_reason": ignore_reason_info,
            "ignored_until": ignored_until,
            "ai_recommendation_redacted": ai_recommendation_info,
            "auto_remediation_available": auto_remediation_available,
            "is_attack_path_root": is_attack_path_root,
            "linked_issues_count": linked_issues_count,
            "first_seen": first_seen,
            "due_date": due_date_str,
            "is_overdue": is_overdue,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_id=issue_id),
        }

        # Layered classifier — each rule emits its own ControlResult; we
        # track the worst and emit a unified decision for the EvaluationResult.
        control_results: list[ControlResult] = []
        layered_findings: list[dict[str, Any]] = []
        worst = "PASS"

        def _emit(signal: str, *, detail: str, extra: dict[str, Any] | None = None) -> None:
            nonlocal worst
            mapping = self._mappings.get(signal, _DEFAULT_MAPPINGS.get(signal, {"control": "PR-04", "result": "FLAG"}))
            control_id = mapping.get("control", "PR-04")
            result_level = mapping.get("result", "FLAG")
            worst = _max_result(worst, result_level)
            cr_evidence = {**evidence_data, "signal": signal}
            if extra:
                cr_evidence.update(extra)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=detail,
                    evidence_data=cr_evidence,
                )
            )
            layered_findings.append({"signal": signal, "result": result_level})

        # --- Identity / anonymous access (highest priority — anonymous-accessible resource) ---
        if anonymous_access:
            _emit(
                "anonymous_access",
                detail=(
                    f"Wiz issue {issue_id or '?'} resource is anonymous-access "
                    f"(type={resource_type or '-'} provider={cloud_provider or '-'})"
                ),
            )

        # --- Attack-path entry points ---
        if is_attack_path_root:
            _emit(
                "attack_path_root",
                detail=f"Wiz issue {issue_id or '?'} marked as attack-path root (entry point)",
            )

        # --- Type-driven highest-priority signals ---
        if status == "OPEN" and issue_type == "ATTACK_PATH":
            _emit(
                "type_attack_path",
                detail=f"Wiz constructed attack path {issue_id or '?'} severity={severity or '-'}",
            )

        if status == "OPEN" and issue_type == "EXPOSED_SECRET":
            _emit(
                "type_exposed_secret",
                detail=f"Wiz exposed-secret finding {issue_id or '?'} severity={severity or '-'}",
            )

        if status == "OPEN" and issue_type == "TOXIC_COMBINATION":
            _emit(
                "type_toxic_combination",
                detail=(
                    f"Wiz toxic-combination {issue_id or '?'} — combined conditions create exposure "
                    f"(severity={severity or '-'}, category={control_category or '-'})"
                ),
            )

        if status == "OPEN" and issue_type == "MALWARE":
            _emit(
                "type_malware",
                detail=f"Wiz malware finding {issue_id or '?'} on {resource_type or 'resource'}",
            )

        if (
            status == "OPEN"
            and issue_type == "VULNERABILITY"
            and severity == "CRITICAL"
            and is_internet_facing
        ):
            _emit(
                "vulnerability_critical_internet_facing",
                detail=(
                    f"Wiz CRITICAL vulnerability {issue_id or '?'} on internet-facing "
                    f"{resource_type or 'resource'}"
                ),
            )

        # --- Sensitive-data + serious severity escalation ---
        if (
            status == "OPEN"
            and sensitive_data_present
            and severity in _SEV_HIGH_OR_CRITICAL
        ):
            _emit(
                "sensitive_data_high_severity",
                detail=(
                    f"Wiz issue {issue_id or '?'} touches sensitive data "
                    f"({','.join(sorted(set(data_classification) & self._sensitive_classifications))}) "
                    f"at severity={severity}"
                ),
                extra={"sensitive_classifications_hit": sorted(
                    set(data_classification) & self._sensitive_classifications
                )},
            )

        # --- Severity ladder for OPEN issues ---
        if status == "OPEN":
            if severity == "CRITICAL":
                _emit(
                    "open_critical",
                    detail=f"Wiz CRITICAL open issue {issue_id or '?'} on {resource_type or 'resource'}",
                )
            elif severity == "HIGH":
                if is_publicly_accessible:
                    _emit(
                        "open_high_publicly_accessible",
                        detail=(
                            f"Wiz HIGH open issue {issue_id or '?'} on publicly-accessible "
                            f"{resource_type or 'resource'} — real attack surface"
                        ),
                    )
                else:
                    _emit(
                        "open_high",
                        detail=f"Wiz HIGH open issue {issue_id or '?'} on {resource_type or 'resource'}",
                    )
            elif severity == "MEDIUM":
                _emit(
                    "open_medium",
                    detail=f"Wiz MEDIUM open issue {issue_id or '?'} on {resource_type or 'resource'}",
                )
            elif severity == "LOW":
                _emit(
                    "open_low",
                    detail=f"Wiz LOW open issue {issue_id or '?'} on {resource_type or 'resource'} (audit only)",
                )

        # --- Lifecycle: resolved / rejected ---
        if status == "RESOLVED":
            _emit(
                "status_resolved",
                detail=f"Wiz issue {issue_id or '?'} resolved (audit trail)",
            )

        if status == "REJECTED":
            if ignore_reason_raw is None or (
                isinstance(ignore_reason_raw, str) and ignore_reason_raw.strip() == ""
            ):
                _emit(
                    "rejected_no_reason",
                    detail=(
                        f"Wiz issue {issue_id or '?'} rejected without reason — governance violation"
                    ),
                )
            elif isinstance(ignore_reason_raw, str) and ignore_reason_raw == "false_positive":
                _emit(
                    "rejected_false_positive",
                    detail=f"Wiz issue {issue_id or '?'} rejected as false_positive (audit trail)",
                )
            elif isinstance(ignore_reason_raw, str) and ignore_reason_raw == "approved_exception":
                _emit(
                    "rejected_approved_exception",
                    detail=f"Wiz issue {issue_id or '?'} rejected as approved_exception (audit trail)",
                )
            else:
                # Free-form reason — treat governance as PASS audit (reason captured/redacted).
                _emit(
                    "rejected_approved_exception",
                    detail=f"Wiz issue {issue_id or '?'} rejected with free-form reason (redacted, audit trail)",
                )

        # --- Due-diligence missing on serious open issues ---
        if (
            status == "OPEN"
            and not is_due_diligence_done
            and severity in _SEV_HIGH_OR_CRITICAL
        ):
            _emit(
                "no_due_diligence_high",
                detail=(
                    f"Wiz issue {issue_id or '?'} severity={severity} has no due-diligence "
                    f"investigation — open with no investigation"
                ),
            )

        # --- Overdue (due_date in past + still OPEN) ---
        if is_overdue:
            _emit(
                "due_date_overdue",
                detail=(
                    f"Wiz issue {issue_id or '?'} overdue (due={due_date_str}) and still OPEN"
                ),
            )

        # --- Compliance-relevant flag ---
        if (
            compliance_frameworks_hit
            and severity in _SEV_HIGH_OR_CRITICAL
            and any(f in {"SOC2", "PCI-DSS", "HIPAA"} for f in compliance_frameworks_hit)
        ):
            _emit(
                "compliance_relevant",
                detail=(
                    f"Wiz issue {issue_id or '?'} fails compliance frameworks "
                    f"{','.join(sorted(compliance_frameworks_hit))} at severity={severity}"
                ),
                extra={"compliance_frameworks_hit": sorted(compliance_frameworks_hit)},
            )

        # If nothing fired, emit a PASS audit-trail record so the file is captured.
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"Wiz issue {issue_id or '?'} captured (no rule fired) "
                        f"status={status or 'unknown'} severity={severity or '-'}"
                    ),
                    evidence_data={**evidence_data, "signal": "none"},
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

        # Use first_seen as event timestamp when present; otherwise now.
        timestamp_iso = self._normalize_timestamp(first_seen or issue.get("createdAt"))

        action_id = (
            f"wiz-{issue_id[:16].replace(' ', '_')}" if issue_id else f"wiz-{uuid.uuid4().hex[:8]}"
        )

        decision_reason_parts = [f"Wiz {issue_type or 'issue'} {issue_id or '?'}"]
        if status:
            decision_reason_parts.append(f"status={status}")
        if severity:
            decision_reason_parts.append(f"severity={severity}")
        if anonymous_access:
            decision_reason_parts.append("anonymous_access")
        if is_attack_path_root:
            decision_reason_parts.append("attack_path_root")
        if is_overdue:
            decision_reason_parts.append("overdue")
        decision_reason = " ".join(decision_reason_parts)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="wiz_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _normalize_timestamp(self, raw: Any) -> str:
        if raw is None or raw == "":
            return datetime.now(timezone.utc).isoformat()
        if isinstance(raw, (int, float)):
            try:
                return datetime.fromtimestamp(float(raw), tz=timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                return datetime.now(timezone.utc).isoformat()
        s = str(raw)
        try:
            datetime.fromisoformat(s.replace("Z", "+00:00"))
            return s
        except ValueError:
            return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Synthetic builders
    # ------------------------------------------------------------------

    def _synthetic_concentration(
        self,
        *,
        category: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("concentration", _DEFAULT_SYNTHETICS["concentration"])
        control_id = synth.get("control", "DE-01")
        result_level = synth.get("result", "FAIL")
        synth_id = f"wiz-concentration-{category}".replace(" ", "_")
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "concentration",
            "control_category": category,
            "open_critical_count": count,
            "threshold": self.concentration_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="wiz_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Wiz synthetic finding: control_category {category!r} has "
                        f"{count} OPEN+CRITICAL issues (threshold "
                        f"{self.concentration_threshold}) — broken control area"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Wiz: synthetic concentration pattern for category {category!r}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_resource_focus(
        self,
        *,
        resource_id: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("resource_focus", _DEFAULT_SYNTHETICS["resource_focus"])
        control_id = synth.get("control", "PR-04")
        result_level = synth.get("result", "FLAG")
        rid_trunc = resource_id[-8:] if len(resource_id) > 8 else resource_id
        synth_id = f"wiz-resource-focus-{rid_trunc}"
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "resource_focus",
            "resource_id_truncated": rid_trunc,
            "issue_count": count,
            "threshold": self.resource_focus_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="wiz_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Wiz synthetic finding: resource ...{rid_trunc} has "
                        f"{count} issues (threshold {self.resource_focus_threshold}) — broken resource"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Wiz: synthetic resource-focus pattern for resource ...{rid_trunc}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    def _synthetic_cloud_concentration(
        self,
        *,
        cloud_provider: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        synth = self._synthetics.get("cloud_concentration", _DEFAULT_SYNTHETICS["cloud_concentration"])
        control_id = synth.get("control", "PR-04")
        result_level = synth.get("result", "FLAG")
        synth_id = f"wiz-cloud-concentration-{cloud_provider}".replace(" ", "_")
        evidence_data: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": "cloud_concentration",
            "cloud_provider": cloud_provider,
            "issue_count": count,
            "threshold": self.cloud_concentration_threshold,
            "source_provenance": self._source_provenance(file_sha256=file_sha256, issue_id=synth_id),
        }
        decision = "BLOCK" if result_level == "FAIL" else "FLAG"
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="wiz_import",
            mode=self.mode,
            control_results=[
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result_level,
                    detail=(
                        f"Wiz synthetic finding: cloud_provider {cloud_provider!r} has "
                        f"{count} issues (threshold {self.cloud_concentration_threshold}) — "
                        f"environment-wide drift"
                    ),
                    evidence_data=evidence_data,
                )
            ],
            decision=decision,
            decision_reason=(
                f"Imported from Wiz: synthetic cloud-concentration pattern for {cloud_provider!r}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
