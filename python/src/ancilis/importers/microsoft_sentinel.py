# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""Microsoft Sentinel incidents importer — converts Sentinel incident exports
to AKSI EvaluationResults.

Microsoft Sentinel (https://azure.microsoft.com/en-us/products/microsoft-sentinel)
is Azure's cloud-native SIEM/SOAR platform — the Microsoft-side parallel to
Splunk for SOC operations. Sentinel exports incidents and their underlying
alerts via the Microsoft Graph Security API
(``/v1.0/security/incidents``). This importer parses that JSON / JSONL output
and converts each incident (with aggregated alerts) into an
``EvaluationResult``.

Mapping (see ``shared/mappings/microsoft-sentinel-aksi-controls.json``):

  - severity=High   + status in {New, Active}        → DE-01 FAIL  (open high incident)
  - severity=High   + status=Resolved
    + classification=TruePositive                    → PR-05 FAIL  (confirmed real — audit closure)
  - severity=High   + status=Closed
    + classification=FalsePositive                   → PR-05 PASS
  - severity=Medium + status in {New, Active}        → DE-01 FAIL
  - severity=Low    + status in {New, Active}        → PR-05 FLAG
  - severity=Informational                           → PR-05 PASS  (audit only)
  - alerts.category=Exfiltration                     → PR-04 FAIL
  - alerts.category=CredentialAccess                 → PR-01 FAIL
  - alerts.category=PrivilegeEscalation              → PR-02 FAIL
  - alerts.category=Impact                           → DE-01 FAIL
  - alerts.kill_chain contains InitialAccess +
    severity in {High, Medium}                       → PR-01 FAIL
  - alerts.techniques contains T1078 / T1110         → PR-01 FAIL  (valid-account / brute-force)
  - alerts.techniques contains T1041 / T1567         → PR-04 FAIL  (exfil over C2)
  - labels contains ai-related / prompt-injection /
    ai-incident / ml-attack / data-exfiltration     → PR-05 FLAG (AI-related — captured)
  - automatedResponse.playbook_executed=true +
    approval_required=true + approved_by=null       → PR-02 FAIL  (auto-action without approval)
  - automatedResponse.playbook_executed=true +
    actions_taken in high_impact_actions +
    approval_required=true + approved_by=null       → PR-02 FAIL  (high-impact w/o approval)
  - automatedResponse.playbook_executed=true +
    approved_by set                                  → PR-05 PASS  (governance functioning)
  - tags contains customer-impacting +
    status in {New, Active}                          → PR-04 FAIL  (customer impact + open)

Synthetic cross-incident signals:

  - same alerts.product_name with > N TruePositive incidents in 7d
    (default 5)                                      → DE-01 FLAG synthetic (recurring real attack)
  - same alert name with > N FalsePositive in 7d
    (default 20)                                     → PR-03 FLAG synthetic (rule needs tuning)

Sanitization:

* ``title`` — first 80 chars + sha256; raw never stored (titles can leak
  victim/customer-identifying detail). Microsoft already truncates / passes a
  ``description_length`` field — we do the same conservative redaction for the
  title.
* ``description`` — only ``description_length`` is preserved (input gives us
  the length only).
* ``classificationComment`` — length only.
* ``owner.email`` — only the domain portion is stored (``@example.com``).
* ``owner.name`` — length + sha256; full text never stored.
* ``playbook_name`` — verbatim (vendor-supplied + structured, low PII risk).

The SDK is importable without ``azure-mgmt-securityinsight`` installed; this
importer parses the Microsoft Graph Security incident JSON schema directly.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# ---------------------------------------------------------------------------
# Mapping table
# ---------------------------------------------------------------------------

_MAPPING_FILENAME = "microsoft-sentinel-aksi-controls.json"


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
    "high_open": "DE-01",
    "high_resolved_true_positive": "PR-05",
    "high_closed_false_positive": "PR-05",
    "medium_open": "DE-01",
    "low_open": "PR-05",
    "informational": "PR-05",
    "category_exfiltration": "PR-04",
    "category_credential_access": "PR-01",
    "category_privilege_escalation": "PR-02",
    "category_impact": "DE-01",
    "kill_chain_initial_access": "PR-01",
    "mitre_technique_pr01": "PR-01",
    "mitre_technique_pr04": "PR-04",
    "auto_response_no_approval": "PR-02",
    "high_impact_action_no_approval": "PR-02",
    "auto_response_approved": "PR-05",
    "customer_impacting_open": "PR-04",
    "ai_related_label": "PR-05",
    "recurring_attack_synthetic": "DE-01",
    "repeated_fp_synthetic": "PR-03",
}

_DEFAULT_SIGNAL_RESULT: dict[str, str] = {
    "high_open": "FAIL",
    "high_resolved_true_positive": "FAIL",
    "high_closed_false_positive": "PASS",
    "medium_open": "FAIL",
    "low_open": "FLAG",
    "informational": "PASS",
    "category_exfiltration": "FAIL",
    "category_credential_access": "FAIL",
    "category_privilege_escalation": "FAIL",
    "category_impact": "FAIL",
    "kill_chain_initial_access": "FAIL",
    "mitre_technique_pr01": "FAIL",
    "mitre_technique_pr04": "FAIL",
    "auto_response_no_approval": "FAIL",
    "high_impact_action_no_approval": "FAIL",
    "auto_response_approved": "PASS",
    "customer_impacting_open": "FAIL",
    "ai_related_label": "FLAG",
    "recurring_attack_synthetic": "FLAG",
    "repeated_fp_synthetic": "FLAG",
}

_DEFAULT_RECURRING_ATTACK_THRESHOLD = 5
_DEFAULT_REPEATED_FP_THRESHOLD = 20

_DEFAULT_HIGH_IMPACT_ACTIONS: list[str] = [
    "disable_user",
    "reset_password",
    "quarantine_email",
    "isolate_host",
    "block_ip",
]

_DEFAULT_AI_LABEL_PATTERNS: list[str] = [
    "ai-related",
    "prompt-injection",
    "ai-incident",
    "ml-attack",
    "data-exfiltration",
]

_DEFAULT_MITRE_TECHNIQUE_TO_CONTROL: dict[str, str] = {
    "T1078": "PR-01",
    "T1110": "PR-01",
    "T1041": "PR-04",
    "T1059": "PR-02",
    "T1068": "PR-02",
    "T1098": "PR-02",
    "T1003": "PR-01",
    "T1083": "PR-04",
    "T1486": "DE-01",
    "T1567": "PR-04",
}

_OPEN_STATUSES = {"new", "active"}
_CLOSED_STATUSES = {"resolved", "closed"}

_TITLE_MAX_CHARS = 80
_NAME_MAX_CHARS = 30

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _load_mapping_table() -> tuple[
    dict[str, str],
    dict[str, str],
    int,
    int,
    list[str],
    list[str],
    dict[str, str],
]:
    """Return (signal_to_control, signal_result, recurring_thr, fp_thr,
    high_impact_actions, ai_label_patterns, mitre_technique_to_control)."""
    signal_to_control: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    signal_result: dict[str, str] = dict(_DEFAULT_SIGNAL_RESULT)
    recurring_thr = _DEFAULT_RECURRING_ATTACK_THRESHOLD
    fp_thr = _DEFAULT_REPEATED_FP_THRESHOLD
    high_impact_actions = list(_DEFAULT_HIGH_IMPACT_ACTIONS)
    ai_label_patterns = list(_DEFAULT_AI_LABEL_PATTERNS)
    mitre = dict(_DEFAULT_MITRE_TECHNIQUE_TO_CONTROL)

    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return (
            signal_to_control,
            signal_result,
            recurring_thr,
            fp_thr,
            high_impact_actions,
            ai_label_patterns,
            mitre,
        )

    if isinstance(data, dict):
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                signal_to_control[str(key)] = str(value)
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            ra = meta.get("default_recurring_attack_threshold")
            if isinstance(ra, (int, float)):
                recurring_thr = int(ra)
            fp = meta.get("default_repeated_fp_threshold")
            if isinstance(fp, (int, float)):
                fp_thr = int(fp)
            ha = meta.get("high_impact_actions")
            if isinstance(ha, list) and ha:
                high_impact_actions = [str(a).lower() for a in ha]
            ai = meta.get("ai_label_patterns")
            if isinstance(ai, list) and ai:
                ai_label_patterns = [str(a).lower() for a in ai]
            mt = meta.get("mitre_technique_to_control")
            if isinstance(mt, dict):
                for tech, ctl in mt.items():
                    mitre[str(tech).upper()] = str(ctl)
            results_meta = meta.get("result_levels")
            if isinstance(results_meta, dict):
                for k, v in results_meta.items():
                    signal_result[str(k)] = str(v).upper()

    return (
        signal_to_control,
        signal_result,
        recurring_thr,
        fp_thr,
        high_impact_actions,
        ai_label_patterns,
        mitre,
    )


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

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


def _truncate_with_hash(
    text: str | None, *, max_chars: int = _TITLE_MAX_CHARS
) -> dict[str, Any]:
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


def _name_redact(name: str | None) -> dict[str, Any]:
    """Owner / display names — store length + sha256 only."""
    if name is None or name == "":
        return {"present": False}
    s = str(name)
    return {
        "present": True,
        "length": len(s),
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _redact_email_domain(email: str | None) -> str | None:
    """Keep only the domain portion of an email address."""
    if not email:
        return None
    s = str(email)
    if "@" not in s:
        return None
    domain = s.rsplit("@", 1)[-1].strip()
    return f"@{domain}" if domain else None


def _normalize_severity(severity: Any) -> str:
    """Microsoft Sentinel severities are strings (Informational/Low/Medium/High).
    Normalize to lowercase for matching."""
    if severity is None:
        return "unknown"
    if isinstance(severity, str):
        return severity.strip().lower()
    return "unknown"


def _normalize_status(status: Any) -> str:
    if status is None:
        return ""
    return str(status).strip().lower()


def _normalize_classification(classification: Any) -> str | None:
    if classification is None or classification == "":
        return None
    return str(classification).strip().lower()


def _to_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    if isinstance(value, str):
        if "," in value:
            return [p.strip() for p in value.split(",") if p.strip()]
        return [value.strip()] if value.strip() else []
    return [str(value)]


def _matches_ai_label(labels: list[str], patterns: list[str]) -> list[str]:
    """Return the AI-related labels matched against the configured patterns."""
    matched: list[str] = []
    label_set_lower = [lbl.strip().lower() for lbl in labels if isinstance(lbl, str)]
    for lbl in label_set_lower:
        for pattern in patterns:
            if fnmatch.fnmatch(lbl, pattern):
                matched.append(lbl)
                break
    return matched


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


def _parse_time(raw: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp string."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(raw)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class MicrosoftSentinelImporter:
    """Parse Microsoft Sentinel incident exports and convert each incident
    (with aggregated alerts) into an ``EvaluationResult``.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        recurring_attack_threshold: TruePositive incidents per product_name
            in a 7-day window above which a DE-01 synthetic FLAG is emitted
            (default from mapping metadata, falling back to 5).
        repeated_fp_threshold: FalsePositive incidents per alert name in a
            7-day window above which a PR-03 synthetic FLAG is emitted
            (default 20).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        recurring_attack_threshold: int | None = None,
        repeated_fp_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._signal_to_control,
            self._signal_result,
            recurring_thr,
            fp_thr,
            self._high_impact_actions,
            self._ai_label_patterns,
            self._mitre_technique_to_control,
        ) = _load_mapping_table()
        self.recurring_attack_threshold = (
            int(recurring_attack_threshold)
            if recurring_attack_threshold is not None
            else recurring_thr
        )
        self.repeated_fp_threshold = (
            int(repeated_fp_threshold)
            if repeated_fp_threshold is not None
            else fp_thr
        )

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Microsoft Sentinel incidents export (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        incidents = list(self._extract_incidents(text))
        return self._build_results(incidents, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Microsoft Sentinel incidents export content from a string."""
        incidents = list(self._extract_incidents(content))
        return self._build_results(incidents, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _extract_incidents(self, content: str) -> Iterable[dict[str, Any]]:
        if not content.strip():
            return []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return list(_iter_jsonl(content))

        if isinstance(doc, dict):
            for key in ("incidents", "data", "value"):
                value = doc.get(key)
                if isinstance(value, list):
                    return [e for e in value if isinstance(e, dict)]
                if isinstance(value, dict):
                    return [value]
            # Bare incident-shaped object.
            if any(
                k in doc
                for k in ("incidentNumber", "id", "severity", "alerts", "title")
            ):
                return [doc]
            return []
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        return []

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "microsoft_sentinel",
            "source_tool_name": "microsoft_sentinel",
            "source_tool_version": "v0",
            "spec_url": "https://learn.microsoft.com/en-us/graph/api/resources/security-incident",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        incidents: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not incidents:
            return [self._empty_result(file_sha256=file_sha256)]
        results = [
            self._build_incident_result(i, file_sha256=file_sha256)
            for i in incidents
        ]
        synthetics = self._build_synthetic_results(incidents, file_sha256=file_sha256)
        results.extend(synthetics)
        return results

    # ---- per-incident evaluation ----------------------------------------

    def _build_incident_result(
        self,
        incident: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        evidence_data = self._common_evidence(incident, provenance)

        severity = _normalize_severity(incident.get("severity"))
        status = _normalize_status(incident.get("status"))
        classification = _normalize_classification(incident.get("classification"))
        labels = _to_list(incident.get("labels"))
        tags = _to_list(incident.get("tags"))
        incident_id = str(
            incident.get("id")
            or incident.get("incidentNumber")
            or ""
        )

        alerts = incident.get("alerts")
        alert_list: list[dict[str, Any]] = (
            [a for a in alerts if isinstance(a, dict)]
            if isinstance(alerts, list)
            else []
        )

        # Aggregate alert categories, kill_chain, techniques, product names.
        alert_categories: list[str] = []
        kill_chain: list[str] = []
        techniques: list[str] = []
        product_names: list[str] = []
        for a in alert_list:
            cat = a.get("category")
            if cat:
                alert_categories.append(str(cat))
            kc = _to_list(a.get("kill_chain"))
            kill_chain.extend(kc)
            tch = _to_list(a.get("techniques"))
            techniques.extend([t.upper() for t in tch])
            prod = a.get("product_name")
            if prod:
                product_names.append(str(prod))

        category_lower = [c.strip().lower().replace(" ", "") for c in alert_categories]
        kill_chain_lower = [k.strip().lower().replace(" ", "") for k in kill_chain]

        auto_response = (
            incident.get("automatedResponse")
            if isinstance(incident.get("automatedResponse"), dict)
            else {}
        )
        playbook_executed = _coerce_bool(auto_response.get("playbook_executed"))
        approval_required = _coerce_bool(auto_response.get("approval_required"))
        approved_by_raw = auto_response.get("approved_by")
        approved_by = (
            str(approved_by_raw).strip()
            if approved_by_raw not in (None, "")
            else None
        )
        actions_taken_raw = auto_response.get("actions_taken")
        actions_taken: list[str] = (
            [str(a).strip().lower() for a in actions_taken_raw]
            if isinstance(actions_taken_raw, list)
            else []
        )
        playbook_name = auto_response.get("playbook_name")

        ai_labels_matched = _matches_ai_label(labels, self._ai_label_patterns)

        control_results: list[ControlResult] = []
        layered_findings: list[dict[str, Any]] = []
        worst = "PASS"
        emitted_signals: set[str] = set()

        def _emit(
            signal: str,
            *,
            detail: str,
            extra: dict[str, Any] | None = None,
            control_id_override: str | None = None,
        ) -> None:
            nonlocal worst
            if signal in emitted_signals:
                return
            emitted_signals.add(signal)
            control_id = (
                control_id_override
                if control_id_override is not None
                else self._signal_to_control.get(signal, "PR-05")
            )
            result = self._signal_result.get(signal, "PASS")
            worst = _max_result(worst, result)
            ev = {**evidence_data, "signal": signal}
            if extra:
                ev.update(extra)
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=detail,
                    evidence_data=ev,
                )
            )
            layered_findings.append({"signal": signal, "result": result})

        # 1. Severity + status + classification baseline.
        if severity == "high":
            if status in _OPEN_STATUSES:
                _emit(
                    "high_open",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=High status={status} (open high incident)"
                    ),
                )
            elif (
                status in _CLOSED_STATUSES
                and classification == "truepositive"
            ):
                _emit(
                    "high_resolved_true_positive",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=High status={status} classification=TruePositive "
                        f"(confirmed real incident — audit-trail closure)"
                    ),
                )
            elif (
                status in _CLOSED_STATUSES
                and classification == "falsepositive"
            ):
                _emit(
                    "high_closed_false_positive",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=High status={status} classification=FalsePositive"
                    ),
                )
            else:
                _emit(
                    "informational",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=High status={status or 'unknown'} "
                        f"classification={classification or 'none'}"
                    ),
                )
        elif severity == "medium":
            if status in _OPEN_STATUSES:
                _emit(
                    "medium_open",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=Medium status={status}"
                    ),
                )
            else:
                _emit(
                    "informational",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=Medium status={status or 'unknown'}"
                    ),
                )
        elif severity == "low":
            if status in _OPEN_STATUSES:
                _emit(
                    "low_open",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=Low status={status}"
                    ),
                )
            else:
                _emit(
                    "informational",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"severity=Low status={status or 'unknown'}"
                    ),
                )
        elif severity == "informational":
            _emit(
                "informational",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} "
                    f"severity=Informational (audit only)"
                ),
            )
        else:
            _emit(
                "informational",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} "
                    f"severity={severity} (unknown — audit trail)"
                ),
            )

        # 2. Alert category-based controls.
        if "exfiltration" in category_lower:
            _emit(
                "category_exfiltration",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} contains "
                    f"alerts category=Exfiltration (high-priority data movement)"
                ),
                extra={"alert_categories": alert_categories},
            )
        if "credentialaccess" in category_lower:
            _emit(
                "category_credential_access",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} contains "
                    f"alerts category=CredentialAccess"
                ),
                extra={"alert_categories": alert_categories},
            )
        if "privilegeescalation" in category_lower:
            _emit(
                "category_privilege_escalation",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} contains "
                    f"alerts category=PrivilegeEscalation"
                ),
                extra={"alert_categories": alert_categories},
            )
        if "impact" in category_lower:
            _emit(
                "category_impact",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} contains "
                    f"alerts category=Impact"
                ),
                extra={"alert_categories": alert_categories},
            )

        # 3. Kill-chain InitialAccess + High/Medium severity → PR-01 FAIL.
        if "initialaccess" in kill_chain_lower and severity in ("high", "medium"):
            _emit(
                "kill_chain_initial_access",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} "
                    f"alerts.kill_chain contains InitialAccess + "
                    f"severity={severity} (ongoing intrusion)"
                ),
                extra={"kill_chain": kill_chain},
            )

        # 4. MITRE technique-based controls. Each technique maps to a single
        #    control via the configured table; we emit a per-control bucket
        #    signal so multiple techniques targeting the same control collapse
        #    into one finding.
        techniques_upper = sorted(set(t.upper() for t in techniques))
        techniques_by_control: dict[str, list[str]] = defaultdict(list)
        for tech in techniques_upper:
            ctl = self._mitre_technique_to_control.get(tech)
            if ctl:
                techniques_by_control[ctl].append(tech)

        for ctl, techs in techniques_by_control.items():
            if ctl == "PR-01":
                _emit(
                    "mitre_technique_pr01",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"alerts.techniques contain {','.join(techs)} → PR-01"
                    ),
                    extra={"mitre_techniques": techs, "mitre_control": ctl},
                )
            elif ctl == "PR-04":
                _emit(
                    "mitre_technique_pr04",
                    detail=(
                        f"Microsoft Sentinel incident {incident_id or '?'} "
                        f"alerts.techniques contain {','.join(techs)} → PR-04"
                    ),
                    extra={"mitre_techniques": techs, "mitre_control": ctl},
                )
            # Other PR-02/PR-05/DE-01 mappings are informational; the category
            # routing above already covers the strong signals.

        # 5. Automated response (Sentinel playbook) governance.
        high_impact_in_actions = [
            a for a in actions_taken if a in self._high_impact_actions
        ]
        if playbook_executed is True:
            if (
                approval_required is True
                and approved_by is None
                and high_impact_in_actions
            ):
                _emit(
                    "high_impact_action_no_approval",
                    detail=(
                        f"Microsoft Sentinel playbook '{playbook_name or '?'}' "
                        f"executed on incident {incident_id or '?'} with "
                        f"high-impact actions {high_impact_in_actions} "
                        f"and approval_required=true but approved_by=null"
                    ),
                    extra={
                        "playbook_name": playbook_name,
                        "actions_taken": actions_taken,
                        "high_impact_actions_executed": high_impact_in_actions,
                        "approval_required": approval_required,
                        "approved_by": None,
                    },
                )
            elif approval_required is True and approved_by is None:
                _emit(
                    "auto_response_no_approval",
                    detail=(
                        f"Microsoft Sentinel playbook '{playbook_name or '?'}' "
                        f"executed on incident {incident_id or '?'} with "
                        f"approval_required=true but approved_by=null "
                        f"(auto-action without required approval)"
                    ),
                    extra={
                        "playbook_name": playbook_name,
                        "actions_taken": actions_taken,
                        "approval_required": approval_required,
                        "approved_by": None,
                    },
                )
            elif approved_by:
                _emit(
                    "auto_response_approved",
                    detail=(
                        f"Microsoft Sentinel playbook '{playbook_name or '?'}' "
                        f"executed on incident {incident_id or '?'} approved "
                        f"by '{_redact_email_domain(approved_by) or approved_by}' "
                        f"(governance functioning)"
                    ),
                    extra={
                        "playbook_name": playbook_name,
                        "actions_taken": actions_taken,
                        "approved_by_domain": _redact_email_domain(approved_by),
                    },
                )

        # 6. Customer-impacting + open.
        tags_lower = [t.strip().lower() for t in tags]
        if "customer-impacting" in tags_lower and status in _OPEN_STATUSES:
            _emit(
                "customer_impacting_open",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} tagged "
                    f"customer-impacting + status={status} "
                    f"(customer impact on open incident)"
                ),
                extra={"tags": tags},
            )

        # 7. AI-related labels — captured (FLAG, parallel to Splunk AI/ML).
        if ai_labels_matched:
            _emit(
                "ai_related_label",
                detail=(
                    f"Microsoft Sentinel incident {incident_id or '?'} labels "
                    f"contain AI-related markers {ai_labels_matched}"
                ),
                extra={"ai_labels_matched": ai_labels_matched, "labels": labels},
            )

        # Stamp aggregated alert metadata + layered_findings on every emitted
        # control result.
        for cr in control_results:
            cr.evidence_data["alert_categories"] = alert_categories
            cr.evidence_data["kill_chain"] = kill_chain
            cr.evidence_data["mitre_techniques"] = techniques_upper
            cr.evidence_data["alert_product_names"] = product_names
            cr.evidence_data["layered_findings"] = layered_findings

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst, "ALLOW")

        timestamp_iso = self._normalize_timestamp(
            incident.get("createdTimeUtc") or incident.get("lastUpdatedTimeUtc")
        )

        action_id_seed = incident_id or uuid.uuid4().hex
        action_id = f"sentinel-{action_id_seed[:16]}"

        decision_reason_parts = [
            f"Microsoft Sentinel incident {incident_id or '?'}",
            f"severity={severity}",
            f"status={status or 'unknown'}",
        ]
        if classification:
            decision_reason_parts.append(f"classification={classification}")
        if alert_categories:
            decision_reason_parts.append(
                "categories=" + ",".join(sorted(set(alert_categories)))
            )
        if techniques_upper:
            decision_reason_parts.append("techniques=" + ",".join(techniques_upper))
        if playbook_executed is True:
            decision_reason_parts.append("playbook=executed")
        if ai_labels_matched:
            decision_reason_parts.append("ai_labels")
        decision_reason = " ".join(decision_reason_parts)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="microsoft_sentinel_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=incident_id or None,
        )

    def _common_evidence(
        self,
        incident: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        title_redacted = _truncate_with_hash(incident.get("title"))

        owner = incident.get("owner") if isinstance(incident.get("owner"), dict) else {}
        owner_email_domain = _redact_email_domain(owner.get("email")) if owner else None
        owner_name_redacted = _name_redact(owner.get("name")) if owner else {"present": False}
        owner_object_id = owner.get("objectId") if owner else None

        description_length = _coerce_int(incident.get("description_length"))
        classification_comment_length = _coerce_int(
            incident.get("classificationComment_length")
        )

        alert_count = _coerce_int(incident.get("alertCount"))
        if alert_count is None and isinstance(incident.get("alerts"), list):
            alert_count = len(incident["alerts"])

        # Per-alert sanitized summary.
        alerts_summary: list[dict[str, Any]] = []
        if isinstance(incident.get("alerts"), list):
            for a in incident["alerts"]:
                if not isinstance(a, dict):
                    continue
                alerts_summary.append(
                    {
                        "id": a.get("id"),
                        "name_redacted": _truncate_with_hash(
                            a.get("name"), max_chars=_NAME_MAX_CHARS
                        ),
                        "severity": _normalize_severity(a.get("severity")),
                        "category": a.get("category"),
                        "kill_chain": _to_list(a.get("kill_chain")),
                        "techniques": [
                            t.upper() for t in _to_list(a.get("techniques"))
                        ],
                        "vendor_name": a.get("vendor_name"),
                        "product_name": a.get("product_name"),
                        "entities_count": _coerce_int(a.get("entities_count")),
                    }
                )

        auto_response = (
            incident.get("automatedResponse")
            if isinstance(incident.get("automatedResponse"), dict)
            else {}
        )
        approved_by_raw = auto_response.get("approved_by") if auto_response else None
        approved_by_domain = _redact_email_domain(approved_by_raw)

        return {
            "incidentNumber": _coerce_int(incident.get("incidentNumber")),
            "id": incident.get("id"),
            "severity": _normalize_severity(incident.get("severity")),
            "status": _normalize_status(incident.get("status")),
            "classification": _normalize_classification(incident.get("classification")),
            "title_redacted": title_redacted,
            "description_length": description_length,
            "classificationComment_length": classification_comment_length,
            "createdTimeUtc": incident.get("createdTimeUtc"),
            "lastUpdatedTimeUtc": incident.get("lastUpdatedTimeUtc"),
            "alertCount": alert_count,
            "alerts": alerts_summary,
            "labels": _to_list(incident.get("labels")),
            "tags": _to_list(incident.get("tags")),
            "owner": {
                "objectId": owner_object_id,
                "email_domain": owner_email_domain,
                "name_redacted": owner_name_redacted,
            },
            "automatedResponse": {
                "playbook_executed": _coerce_bool(auto_response.get("playbook_executed"))
                if auto_response
                else None,
                "playbook_name": auto_response.get("playbook_name") if auto_response else None,
                "actions_taken": _to_list(auto_response.get("actions_taken"))
                if auto_response
                else [],
                "approval_required": _coerce_bool(auto_response.get("approval_required"))
                if auto_response
                else None,
                "approved_by_domain": approved_by_domain,
                "approved_by_present": approved_by_raw is not None
                and approved_by_raw != "",
            },
            "additionalData": incident.get("additionalData"),
            "source_tool": "microsoft_sentinel",
            "source_provenance": provenance,
        }

    # ---- synthetic cross-incident evaluation ----------------------------

    def _build_synthetic_results(
        self,
        incidents: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []
        results.extend(
            self._recurring_attack_synthetics(incidents, file_sha256=file_sha256)
        )
        results.extend(
            self._repeated_fp_synthetics(incidents, file_sha256=file_sha256)
        )
        return results

    def _recurring_attack_synthetics(
        self,
        incidents: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Bucket TruePositive incidents by (alerts.product_name, 7d-window) and
        emit a DE-01 FLAG when any bucket exceeds the threshold."""
        buckets: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)
        for inc in incidents:
            classification = _normalize_classification(inc.get("classification"))
            if classification != "truepositive":
                continue
            ts = _parse_time(
                inc.get("createdTimeUtc") or inc.get("lastUpdatedTimeUtc")
            )
            if ts is None:
                ts = datetime.now(timezone.utc)
            ts_utc = ts.astimezone(timezone.utc)
            day_index = (ts_utc - datetime(1970, 1, 1, tzinfo=timezone.utc)).days
            week_start_day = day_index - (day_index % 7)
            week_start = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                days=week_start_day
            )
            alerts = inc.get("alerts") if isinstance(inc.get("alerts"), list) else []
            seen_products: set[str] = set()
            for a in alerts:
                if not isinstance(a, dict):
                    continue
                prod = a.get("product_name")
                if not prod:
                    continue
                key = str(prod)
                if key in seen_products:
                    continue
                seen_products.add(key)
                buckets[(key, week_start)].append(inc)

        out: list[EvaluationResult] = []
        for (product_name, week_start), bucket in buckets.items():
            if len(bucket) <= self.recurring_attack_threshold:
                continue
            out.append(
                self._make_synthetic_result(
                    signal="recurring_attack_synthetic",
                    detail=(
                        f"Microsoft Sentinel product '{product_name}' produced "
                        f"{len(bucket)} TruePositive incidents in 7-day window "
                        f"starting {week_start.isoformat()} (> threshold "
                        f"{self.recurring_attack_threshold}) — recurring real attack"
                    ),
                    evidence_extra={
                        "alert_product_name": product_name,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "true_positive_count": len(bucket),
                        "recurring_attack_threshold": self.recurring_attack_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"sentinel-synthetic-attack-{product_name[:16]}",
                )
            )
        return out

    def _repeated_fp_synthetics(
        self,
        incidents: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Bucket FalsePositive incidents by (alerts.name, 7d-window) and emit
        a PR-03 FLAG when any bucket exceeds the threshold."""
        buckets: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)
        for inc in incidents:
            classification = _normalize_classification(inc.get("classification"))
            if classification != "falsepositive":
                continue
            ts = _parse_time(
                inc.get("createdTimeUtc") or inc.get("lastUpdatedTimeUtc")
            )
            if ts is None:
                ts = datetime.now(timezone.utc)
            ts_utc = ts.astimezone(timezone.utc)
            day_index = (ts_utc - datetime(1970, 1, 1, tzinfo=timezone.utc)).days
            week_start_day = day_index - (day_index % 7)
            week_start = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                days=week_start_day
            )
            alerts = inc.get("alerts") if isinstance(inc.get("alerts"), list) else []
            seen_names: set[str] = set()
            for a in alerts:
                if not isinstance(a, dict):
                    continue
                name = a.get("name")
                if not name:
                    continue
                key = str(name)
                if key in seen_names:
                    continue
                seen_names.add(key)
                buckets[(key, week_start)].append(inc)

        out: list[EvaluationResult] = []
        for (alert_name, week_start), bucket in buckets.items():
            if len(bucket) <= self.repeated_fp_threshold:
                continue
            # Don't store the alert name verbatim — hash + length.
            name_redacted = _truncate_with_hash(alert_name, max_chars=_NAME_MAX_CHARS)
            out.append(
                self._make_synthetic_result(
                    signal="repeated_fp_synthetic",
                    detail=(
                        f"Microsoft Sentinel alert '{alert_name[:_NAME_MAX_CHARS]}' "
                        f"produced {len(bucket)} FalsePositive incidents in 7-day "
                        f"window starting {week_start.isoformat()} (> threshold "
                        f"{self.repeated_fp_threshold}) — rule needs tuning"
                    ),
                    evidence_extra={
                        "alert_name_redacted": name_redacted,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "false_positive_count": len(bucket),
                        "repeated_fp_threshold": self.repeated_fp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"sentinel-synthetic-fp-{alert_name[:16]}",
                )
            )
        return out

    def _make_synthetic_result(
        self,
        *,
        signal: str,
        detail: str,
        evidence_extra: dict[str, Any],
        file_sha256: str | None,
        action_id: str,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        control_id = self._signal_to_control.get(signal, "PR-05")
        result = self._signal_result.get(signal, "FLAG")
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=result,
            detail=detail,
            evidence_data={
                "signal": signal,
                "synthetic": True,
                "source_tool": "microsoft_sentinel",
                "source_provenance": provenance,
                **evidence_extra,
            },
        )
        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(result, "FLAG")
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="microsoft_sentinel_import",
            mode=self.mode,
            control_results=[cr],
            decision=decision,
            decision_reason=detail,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    # ---- helpers --------------------------------------------------------

    def _normalize_timestamp(self, raw: Any) -> str:
        """Best-effort ISO-8601 timestamp; fall back to UTC now."""
        if raw is None or raw == "":
            return datetime.now(timezone.utc).isoformat()
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
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

    def _empty_result(self, *, file_sha256: str | None) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail="Empty Microsoft Sentinel export (no incidents)",
            evidence_data={"source_provenance": provenance, "incident_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sentinel-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="microsoft_sentinel_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty Microsoft Sentinel export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
