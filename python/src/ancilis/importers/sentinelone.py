"""SentinelOne Singularity EDR importer — converts Singularity threats +
audit-log exports to AKSI EvaluationResults.

SentinelOne Singularity (https://www.sentinelone.com/platform/) is the
parallel platform to CrowdStrike Falcon for endpoint detection and
response. Where Falcon's vocabulary leans MITRE-tactic-first, Singularity
leans behavior-first with a distinguished AI-centric classification axis
(``AI Threat``) and an autonomous-mitigation governance signal (every
threat carries an explicit ``automatedResponses`` block describing which
actions were taken, whether approval was required, and whether they were
authenticated).

This importer parses Singularity threats-API + audit-log JSON exports
(``threats[]``, ``audit_logs[]``, mixed ``data[]``, JSONL) and emits an
``EvaluationResult`` per record plus synthetic cross-event signals
(cross-host attacks, repeated false positives, recurring true positives).

Mapping (see ``shared/mappings/sentinelone-aksi-controls.json``):

  Threats — severity + verdict:
    threatInfo.severity=E_CRITICAL + incidentStatus in
      {detected, unresolved}                              → DE-01 FAIL
    severity=E_CRITICAL + incidentStatus=resolved
      + analystVerdict=true_positive                      → PR-05 FAIL
    severity=E_CRITICAL + analystVerdict=false_positive   → PR-05 PASS
    severity=E_HIGH + incidentStatus in
      {detected, unresolved}                              → DE-01 FAIL

  Threats — classification:
    classification=Ransomware                             → DE-01 FAIL → BLOCK
    classification="Supply Chain"                         → DE-01 FAIL
    classification="AI Threat"                            → DE-01 FAIL
    classification in {Malware, Trojan, Worm, Rootkit, Backdoor}
      + severity in {E_HIGH, E_CRITICAL}                  → DE-01 FAIL

  Threats — behavioral indicators:
    DataExfiltration                                      → PR-04 FAIL
    CredentialDumping                                     → PR-01 FAIL
    LateralMovement                                       → PR-02 FAIL
    CommandAndControl                                     → DE-01 FAIL
    ProcessInjection                                      → PR-03 FAIL

  Threats — binary integrity / origin:
    binary_signature_status=invalid + classification not "PUA"
                                                          → DE-01 FAIL
    binary_signature_status=unsigned + binary_path matches
      system path patterns                                → PR-04 FAIL
    kill_chain_position=exfiltration                      → PR-04 FAIL

  Threats — autonomous-response governance:
    actionsTaken intersects {kill_process, quarantine, disconnect,
      disable_user} + approvalRequired=true + approvedBy=null
                                                          → PR-02 FAIL
    actionsTaken intersects {kill, disable_user}
      + is_authenticated_response=false                   → PR-02 FAIL
    confidenceLevel=low + actionsTaken non-empty          → PR-03 FLAG

  Threats — agent posture:
    agentRealtimeInfo.agentInfected=true                  → DE-01 FAIL
    agentRealtimeInfo.agentIsActive=false on production-named host
                                                          → PR-02 FAIL
    mitigationStatus=marked_as_benign + classification in
      {Malware, Ransomware, AI Threat}                    → PR-02 FAIL

  Audit logs:
    site_settings_changed disabling protection            → PR-02 FAIL
    policy_changed weakening detection                    → PR-02 FLAG
    user_role_changed to admin                            → PR-02 FLAG
    api_token_created                                     → PR-01 FLAG
    agent_uninstalled by non-admin                        → PR-02 FAIL
    deep_visibility_query                                 → captured PR-05 PASS

Synthetic cross-event signals:
    same classification across > N hostnames in 7d
      (default 3)                                         → DE-01 FAIL synthetic
    same threatName with > N false_positive in 7d
      (default 30)                                        → PR-03 FLAG synthetic
    same threatName > N true_positive in 7d (default 5)   → DE-01 FAIL synthetic

Sanitization:
  * ``threatName`` — length + sha256 only; raw never stored
    (names can encode sensitive context).
  * ``agentComputerName`` — length + sha256 only; raw never stored
    (hostnames can encode tenant info).
  * ``agentDomain`` — length + sha256 only; raw never stored
    (domains can encode tenant info).
  * ``binary_path`` — verbatim only when already a normalized form
    (``binary_path_normalized``); raw paths are dropped.
  * ``externalTicketId`` — last 8 characters only.
  * ``actor.email`` — domain part only (everything before ``@`` dropped).
  * ``actor.username`` — last 8 characters only.
  * ``severity``, ``analystVerdict``, ``incidentStatus``,
    ``classification``, ``confidenceLevel``, ``mitigationStatus``,
    ``engines``, ``behavioralIndicators``, ``automatedResponses``
    fields, ``agentMachineType``, ``agentOsType``, ``agentVersion``,
    ``binary_signature_status``, ``kill_chain_position``,
    ``hostname_origin_country`` — verbatim (vendor-supplied, structured,
    low-PII risk).

The SDK is importable without any ``sentinelone-*`` package installed —
this importer parses the Singularity threats+audit JSON schema directly.
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

_MAPPING_FILENAME = "sentinelone-aksi-controls.json"


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
    "ransomware_classification": "DE-01",
    "supply_chain_classification": "DE-01",
    "ai_threat_classification": "DE-01",
    "critical_open": "DE-01",
    "critical_resolved_true_positive": "PR-05",
    "critical_false_positive": "PR-05",
    "high_open": "DE-01",
    "classification_high_severity_malware": "DE-01",
    "indicator_data_exfiltration": "PR-04",
    "indicator_credential_dumping": "PR-01",
    "indicator_lateral_movement": "PR-02",
    "indicator_command_and_control": "DE-01",
    "indicator_process_injection": "PR-03",
    "kill_chain_exfiltration": "PR-04",
    "binary_signature_invalid": "DE-01",
    "unsigned_binary_system_path": "PR-04",
    "autonomous_high_impact_no_approval": "PR-02",
    "unauthenticated_disruptive_response": "PR-02",
    "low_confidence_autonomous": "PR-03",
    "agent_infected": "DE-01",
    "inactive_agent_production": "PR-02",
    "marked_benign_critical_classification": "PR-02",
    "site_settings_disable_protection": "PR-02",
    "policy_weakening": "PR-02",
    "user_role_admin_change": "PR-02",
    "api_token_created": "PR-01",
    "agent_uninstalled_non_admin": "PR-02",
    "deep_visibility_query_captured": "PR-05",
    "cross_host_attack_synthetic": "DE-01",
    "repeated_fp_synthetic": "PR-03",
    "recurring_tp_synthetic": "DE-01",
}

_DEFAULT_SIGNAL_RESULT: dict[str, str] = {
    "ransomware_classification": "FAIL",
    "supply_chain_classification": "FAIL",
    "ai_threat_classification": "FAIL",
    "critical_open": "FAIL",
    "critical_resolved_true_positive": "FAIL",
    "critical_false_positive": "PASS",
    "high_open": "FAIL",
    "classification_high_severity_malware": "FAIL",
    "indicator_data_exfiltration": "FAIL",
    "indicator_credential_dumping": "FAIL",
    "indicator_lateral_movement": "FAIL",
    "indicator_command_and_control": "FAIL",
    "indicator_process_injection": "FAIL",
    "kill_chain_exfiltration": "FAIL",
    "binary_signature_invalid": "FAIL",
    "unsigned_binary_system_path": "FAIL",
    "autonomous_high_impact_no_approval": "FAIL",
    "unauthenticated_disruptive_response": "FAIL",
    "low_confidence_autonomous": "FLAG",
    "agent_infected": "FAIL",
    "inactive_agent_production": "FAIL",
    "marked_benign_critical_classification": "FAIL",
    "site_settings_disable_protection": "FAIL",
    "policy_weakening": "FLAG",
    "user_role_admin_change": "FLAG",
    "api_token_created": "FLAG",
    "agent_uninstalled_non_admin": "FAIL",
    "deep_visibility_query_captured": "PASS",
    "cross_host_attack_synthetic": "FAIL",
    "repeated_fp_synthetic": "FLAG",
    "recurring_tp_synthetic": "FAIL",
}

_DEFAULT_CROSS_HOST_THRESHOLD = 3
_DEFAULT_REPEATED_FP_THRESHOLD = 30
_DEFAULT_RECURRING_TP_THRESHOLD = 5

_DEFAULT_PRODUCTION_HOST_PATTERNS: list[str] = [
    "prod*",
    "server*",
    "agent-*",
    "svc-*",
]

_DEFAULT_SYSTEM_PATH_PATTERNS: list[str] = [
    "system/*",
    "windows/system32/*",
    "usr/bin/*",
    "usr/sbin/*",
    "bin/*",
    "sbin/*",
    "lib/*",
    "lib64/*",
]

_OPEN_INCIDENT_STATUSES = {"detected", "unresolved", "in_progress"}
_HIGH_SEVERITY_MALWARE_CLASSES = {
    "malware",
    "trojan",
    "worm",
    "rootkit",
    "backdoor",
}
_CRITICAL_CLASSIFICATION_FOR_BENIGN_OVERRIDE = {
    "malware",
    "ransomware",
    "ai threat",
}
_HIGH_OR_CRITICAL_SEVERITIES = {"e_high", "e_critical"}
_HIGH_IMPACT_AUTONOMOUS_ACTIONS = {
    "kill_process",
    "quarantine",
    "disconnect",
    "disable_user",
}
_DISRUPTIVE_AUTONOMOUS_ACTIONS = {"kill", "disable_user"}

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _load_mapping_table() -> tuple[
    dict[str, str],
    dict[str, str],
    int,
    int,
    int,
    list[str],
    list[str],
]:
    """Return (signal_to_control, signal_result, cross_host_thr,
    repeated_fp_thr, recurring_tp_thr, production_host_patterns,
    system_path_patterns)."""
    signal_to_control: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    signal_result: dict[str, str] = dict(_DEFAULT_SIGNAL_RESULT)
    cross_host_thr = _DEFAULT_CROSS_HOST_THRESHOLD
    repeated_fp_thr = _DEFAULT_REPEATED_FP_THRESHOLD
    recurring_tp_thr = _DEFAULT_RECURRING_TP_THRESHOLD
    production_patterns = list(_DEFAULT_PRODUCTION_HOST_PATTERNS)
    system_patterns = list(_DEFAULT_SYSTEM_PATH_PATTERNS)

    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return (
            signal_to_control,
            signal_result,
            cross_host_thr,
            repeated_fp_thr,
            recurring_tp_thr,
            production_patterns,
            system_patterns,
        )

    if isinstance(data, dict):
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                signal_to_control[str(key)] = str(value)
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            ch = meta.get("cross_host_threshold")
            if isinstance(ch, (int, float)):
                cross_host_thr = int(ch)
            fp = meta.get("repeated_fp")
            if isinstance(fp, (int, float)):
                repeated_fp_thr = int(fp)
            rt = meta.get("recurring_tp")
            if isinstance(rt, (int, float)):
                recurring_tp_thr = int(rt)
            pp = meta.get("production_host_patterns")
            if isinstance(pp, list) and pp:
                production_patterns = [str(p) for p in pp]
            sp = meta.get("system_path_patterns")
            if isinstance(sp, list) and sp:
                system_patterns = [str(p) for p in sp]
            results_meta = meta.get("result_levels")
            if isinstance(results_meta, dict):
                for k, v in results_meta.items():
                    signal_result[str(k)] = str(v).upper()

    return (
        signal_to_control,
        signal_result,
        cross_host_thr,
        repeated_fp_thr,
        recurring_tp_thr,
        production_patterns,
        system_patterns,
    )


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


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


def _redact_with_hash(text: str | None) -> dict[str, Any]:
    """threatName / agentComputerName / agentDomain — store length + sha256
    only. Raw text is NEVER preserved."""
    if text is None or text == "":
        return {"present": False}
    s = str(text)
    return {
        "present": True,
        "length": len(s),
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _last_n(value: Any, n: int = 8) -> str | None:
    """Keep only the last ``n`` characters of an opaque identifier."""
    if value is None or value == "":
        return None
    s = str(value)
    if len(s) <= n:
        return s
    return s[-n:]


def _email_domain_only(value: Any) -> str | None:
    """Return only the domain portion of an email address (everything after
    ``@``); the local-part is dropped."""
    if value is None or value == "":
        return None
    s = str(value).strip()
    if "@" not in s:
        return None
    _, _, domain = s.partition("@")
    domain = domain.strip().lower()
    return domain or None


def _normalize_severity(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalize_status(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalize_classification(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _to_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None and v != ""]
    if isinstance(value, str):
        if "," in value:
            return [p.strip() for p in value.split(",") if p.strip()]
        return [value.strip()] if value.strip() else []
    return [str(value)]


def _matches_pattern(text: str, patterns: list[str]) -> str | None:
    if not text:
        return None
    h = text.strip().lower()
    for pattern in patterns:
        if fnmatch.fnmatch(h, pattern.lower()):
            return pattern
    return None


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


class SentinelOneImporter:
    """Parse SentinelOne Singularity threat + audit-log exports and convert
    each record into an ``EvaluationResult``.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        cross_host_threshold: distinct hostnames per classification in a
            7-day window above which a DE-01 synthetic FAIL is emitted
            (default from mapping metadata, falling back to 3).
        repeated_fp_threshold: false_positive count per threatName in a
            7-day window above which a PR-03 synthetic FLAG is emitted
            (default 30).
        recurring_tp_threshold: true_positive count per threatName in a
            7-day window above which a DE-01 synthetic FAIL is emitted
            (default 5).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        cross_host_threshold: int | None = None,
        repeated_fp_threshold: int | None = None,
        recurring_tp_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._signal_to_control,
            self._signal_result,
            cross_host_thr,
            repeated_fp_thr,
            recurring_tp_thr,
            self._production_patterns,
            self._system_path_patterns,
        ) = _load_mapping_table()
        self.cross_host_threshold = (
            int(cross_host_threshold)
            if cross_host_threshold is not None
            else cross_host_thr
        )
        self.repeated_fp_threshold = (
            int(repeated_fp_threshold)
            if repeated_fp_threshold is not None
            else repeated_fp_thr
        )
        self.recurring_tp_threshold = (
            int(recurring_tp_threshold)
            if recurring_tp_threshold is not None
            else recurring_tp_thr
        )

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a SentinelOne export (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        threats, audit_logs = self._extract_records(text)
        return self._build_results(
            threats, audit_logs, file_sha256=file_sha256
        )

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse SentinelOne export content from a string."""
        threats, audit_logs = self._extract_records(content)
        return self._build_results(threats, audit_logs, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _extract_records(
        self, content: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not content.strip():
            return [], []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            mixed = list(_iter_jsonl(content))
            return self._split_mixed(mixed)

        if isinstance(doc, dict):
            threats_raw = doc.get("threats")
            audits_raw = doc.get("audit_logs")
            if isinstance(threats_raw, list) or isinstance(audits_raw, list):
                threats = (
                    [t for t in threats_raw if isinstance(t, dict)]
                    if isinstance(threats_raw, list)
                    else []
                )
                audits = (
                    [a for a in audits_raw if isinstance(a, dict)]
                    if isinstance(audits_raw, list)
                    else []
                )
                return threats, audits
            data_raw = doc.get("data")
            if isinstance(data_raw, list):
                return self._split_mixed(
                    [d for d in data_raw if isinstance(d, dict)]
                )
            if any(k in doc for k in ("threatInfo", "agentRealtimeInfo")):
                return [doc], []
            if "action" in doc and "actor" in doc:
                return [], [doc]
            return [], []
        if isinstance(doc, list):
            return self._split_mixed(
                [d for d in doc if isinstance(d, dict)]
            )
        return [], []

    @staticmethod
    def _split_mixed(
        records: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        threats: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []
        for r in records:
            if "threatInfo" in r or "agentRealtimeInfo" in r:
                threats.append(r)
            elif "action" in r and ("actor" in r or "target_id" in r):
                audits.append(r)
            else:
                threats.append(r)
        return threats, audits

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "sentinelone_singularity",
            "source_tool_name": "sentinelone_singularity",
            "source_tool_version": "v0",
            "spec_url": "https://usea1-partners.sentinelone.net/api-doc/overview",
        }
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _build_results(
        self,
        threats: list[dict[str, Any]],
        audit_logs: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not threats and not audit_logs:
            return [self._empty_result(file_sha256=file_sha256)]
        results: list[EvaluationResult] = []
        for t in threats:
            results.append(
                self._build_threat_result(t, file_sha256=file_sha256)
            )
        for a in audit_logs:
            results.append(
                self._build_audit_result(a, file_sha256=file_sha256)
            )
        results.extend(
            self._build_synthetic_results(threats, file_sha256=file_sha256)
        )
        return results

    # ---- per-threat evaluation ------------------------------------------

    def _build_threat_result(
        self,
        threat: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        evidence_data = self._threat_evidence(threat, provenance)

        threat_id = str(threat.get("id") or "")
        threat_info = (
            threat.get("threatInfo")
            if isinstance(threat.get("threatInfo"), dict)
            else {}
        ) or {}
        agent_info = (
            threat.get("agentRealtimeInfo")
            if isinstance(threat.get("agentRealtimeInfo"), dict)
            else {}
        ) or {}
        responses = (
            threat.get("automatedResponses")
            if isinstance(threat.get("automatedResponses"), dict)
            else {}
        ) or {}

        severity = _normalize_severity(threat_info.get("severity"))
        analyst_verdict = _normalize_status(threat_info.get("analystVerdict"))
        confidence_level = _normalize_status(threat_info.get("confidenceLevel"))
        incident_status = _normalize_status(threat_info.get("incidentStatus"))
        classification = _normalize_classification(
            threat_info.get("classification")
        )
        mitigation_status = _normalize_status(
            threat_info.get("mitigationStatus")
        )
        behavioral_indicators = _to_str_list(threat.get("behavioralIndicators"))
        indicator_set = {ind.strip().lower() for ind in behavioral_indicators}

        actions_taken = [
            str(a).strip().lower()
            for a in (responses.get("actionsTaken") or [])
            if isinstance(a, (str, int))
        ]
        approval_required = _coerce_bool(responses.get("approvalRequired"))
        approved_by_raw = responses.get("approvedBy")
        approved_by_present = bool(approved_by_raw)
        is_authenticated_response = _coerce_bool(
            threat.get("is_authenticated_response")
        )

        binary_signature_status = _normalize_status(
            threat.get("binary_signature_status")
        )
        binary_path = (
            str(threat.get("binary_path_normalized") or "").strip().lower()
        )
        kill_chain_position = _normalize_status(threat.get("kill_chain_position"))

        agent_infected = _coerce_bool(agent_info.get("agentInfected"))
        agent_is_active = _coerce_bool(agent_info.get("agentIsActive"))
        agent_computer_name = str(agent_info.get("agentComputerName") or "")

        control_results: list[ControlResult] = []
        layered_findings: list[dict[str, Any]] = []
        worst = "PASS"
        emitted_signals: set[str] = set()
        force_block = False

        def _emit(
            signal: str,
            *,
            detail: str,
            extra: dict[str, Any] | None = None,
        ) -> None:
            nonlocal worst
            if signal in emitted_signals:
                return
            emitted_signals.add(signal)
            control_id = self._signal_to_control.get(signal, "PR-05")
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

        # 1. Severity + status baseline.
        if severity == "e_critical" and incident_status in _OPEN_INCIDENT_STATUSES:
            _emit(
                "critical_open",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} severity=E_CRITICAL "
                    f"incidentStatus={incident_status} (open critical threat)"
                ),
            )
        if (
            severity == "e_critical"
            and incident_status == "resolved"
            and analyst_verdict == "true_positive"
        ):
            _emit(
                "critical_resolved_true_positive",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} severity=E_CRITICAL "
                    f"resolved + analystVerdict=true_positive "
                    f"(audit-trail of confirmed attack)"
                ),
            )
        if severity == "e_critical" and analyst_verdict == "false_positive":
            _emit(
                "critical_false_positive",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} severity=E_CRITICAL "
                    f"analystVerdict=false_positive (audit)"
                ),
            )
        if severity == "e_high" and incident_status in _OPEN_INCIDENT_STATUSES:
            _emit(
                "high_open",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} severity=E_HIGH "
                    f"incidentStatus={incident_status} (open high threat)"
                ),
            )

        # 2. Classification routing.
        if classification == "ransomware":
            force_block = True
            _emit(
                "ransomware_classification",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification=Ransomware (top priority — block)"
                ),
                extra={"classification": "ransomware"},
            )
        if classification == "supply chain":
            _emit(
                "supply_chain_classification",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification='Supply Chain' (relevant to AI-generated code)"
                ),
                extra={"classification": "supply chain"},
            )
        if classification == "ai threat":
            _emit(
                "ai_threat_classification",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification='AI Threat' "
                    f"(SentinelOne AI-specific classification)"
                ),
                extra={"classification": "ai threat"},
            )
        if (
            classification in _HIGH_SEVERITY_MALWARE_CLASSES
            and severity in _HIGH_OR_CRITICAL_SEVERITIES
        ):
            _emit(
                "classification_high_severity_malware",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification={classification} severity={severity} "
                    f"(active malware family at high severity)"
                ),
                extra={
                    "classification": classification,
                    "severity": severity,
                },
            )

        # 3. Behavioral indicators.
        if "dataexfiltration" in indicator_set:
            _emit(
                "indicator_data_exfiltration",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} behavioralIndicators "
                    f"contains DataExfiltration"
                ),
                extra={"behavioral_indicators": behavioral_indicators},
            )
        if "credentialdumping" in indicator_set:
            _emit(
                "indicator_credential_dumping",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} behavioralIndicators "
                    f"contains CredentialDumping"
                ),
                extra={"behavioral_indicators": behavioral_indicators},
            )
        if "lateralmovement" in indicator_set:
            _emit(
                "indicator_lateral_movement",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} behavioralIndicators "
                    f"contains LateralMovement (post-compromise spread)"
                ),
                extra={"behavioral_indicators": behavioral_indicators},
            )
        if "commandandcontrol" in indicator_set:
            _emit(
                "indicator_command_and_control",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} behavioralIndicators "
                    f"contains CommandAndControl"
                ),
                extra={"behavioral_indicators": behavioral_indicators},
            )
        if "processinjection" in indicator_set:
            _emit(
                "indicator_process_injection",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} behavioralIndicators "
                    f"contains ProcessInjection (runtime code-injection)"
                ),
                extra={"behavioral_indicators": behavioral_indicators},
            )

        # 4. Kill-chain position.
        if kill_chain_position == "exfiltration":
            _emit(
                "kill_chain_exfiltration",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"kill_chain_position=exfiltration"
                ),
                extra={"kill_chain_position": "exfiltration"},
            )

        # 5. Binary integrity.
        if (
            binary_signature_status == "invalid"
            and classification != "pua"
        ):
            _emit(
                "binary_signature_invalid",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"binary_signature_status=invalid "
                    f"classification={classification or 'unknown'} "
                    f"(invalid signature → code tampering)"
                ),
                extra={"binary_signature_status": "invalid"},
            )
        if (
            binary_signature_status == "unsigned"
            and binary_path
            and _matches_pattern(binary_path, self._system_path_patterns)
        ):
            _emit(
                "unsigned_binary_system_path",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"unsigned binary at system path "
                    f"(normalized={binary_path}) — high suspicion"
                ),
                extra={
                    "binary_signature_status": "unsigned",
                    "binary_path_normalized": binary_path,
                },
            )

        # 6. Autonomous-response governance.
        action_set = set(actions_taken)
        high_impact_intersect = action_set & _HIGH_IMPACT_AUTONOMOUS_ACTIONS
        if (
            high_impact_intersect
            and approval_required is True
            and not approved_by_present
        ):
            _emit(
                "autonomous_high_impact_no_approval",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} actionsTaken="
                    f"{sorted(high_impact_intersect)} approvalRequired=true "
                    f"approvedBy=null (autonomous high-impact action without "
                    f"approval)"
                ),
                extra={
                    "actions_taken": actions_taken,
                    "approval_required": True,
                    "approved_by_present": False,
                },
            )
        disruptive_intersect = action_set & _DISRUPTIVE_AUTONOMOUS_ACTIONS
        if (
            disruptive_intersect
            and is_authenticated_response is False
        ):
            _emit(
                "unauthenticated_disruptive_response",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} actionsTaken="
                    f"{sorted(disruptive_intersect)} "
                    f"is_authenticated_response=false"
                ),
                extra={
                    "actions_taken": actions_taken,
                    "is_authenticated_response": False,
                },
            )
        if confidence_level == "low" and actions_taken:
            _emit(
                "low_confidence_autonomous",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} confidenceLevel=low "
                    f"with autonomous actionsTaken={actions_taken}"
                ),
                extra={
                    "confidence_level": "low",
                    "actions_taken": actions_taken,
                },
            )

        # 7. Agent posture.
        if agent_infected is True:
            _emit(
                "agent_infected",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"agentRealtimeInfo.agentInfected=true (active infection)"
                ),
                extra={"agent_infected": True},
            )
        prod_match = _matches_pattern(
            agent_computer_name, self._production_patterns
        )
        if prod_match and agent_is_active is False:
            _emit(
                "inactive_agent_production",
                detail=(
                    f"SentinelOne agent on production-named host "
                    f"(pattern '{prod_match}') agentIsActive=false "
                    f"(protection gap)"
                ),
                extra={
                    "production_pattern_matched": prod_match,
                    "agent_is_active": False,
                },
            )
        if (
            mitigation_status == "marked_as_benign"
            and classification in _CRITICAL_CLASSIFICATION_FOR_BENIGN_OVERRIDE
        ):
            _emit(
                "marked_benign_critical_classification",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"mitigationStatus=marked_as_benign on classification="
                    f"{classification} (silencing critical detection)"
                ),
                extra={
                    "mitigation_status": "marked_as_benign",
                    "classification": classification,
                },
            )

        # Stamp aggregated metadata.
        for cr in control_results:
            cr.evidence_data["behavioral_indicators"] = behavioral_indicators
            cr.evidence_data["actions_taken"] = actions_taken
            cr.evidence_data["layered_findings"] = layered_findings

        if not control_results:
            cr = ControlResult(
                control_id="PR-05",
                control_name=_CONTROL_NAMES["PR-05"],
                result="PASS",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"severity={severity or 'unknown'} "
                    f"incidentStatus={incident_status or 'unknown'} "
                    f"classification={classification or 'unknown'} "
                    f"(no signals matched)"
                ),
                evidence_data={
                    **evidence_data,
                    "signal": "default",
                    "behavioral_indicators": behavioral_indicators,
                    "actions_taken": actions_taken,
                    "layered_findings": layered_findings,
                },
            )
            control_results.append(cr)

        if force_block:
            decision = "BLOCK" if self.mode == "enforce" else "FLAG"
        else:
            decision = {
                "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
                "FLAG": "FLAG",
                "PASS": "ALLOW",
            }.get(worst, "ALLOW")

        timestamp_iso = self._normalize_timestamp(
            threat.get("createdAt") or threat.get("updatedAt")
        )
        action_id_seed = threat_id or uuid.uuid4().hex
        action_id = f"sentinelone-{action_id_seed[:16]}"

        decision_reason_parts = [
            f"SentinelOne threat {threat_id or '?'}",
            f"severity={severity or 'unknown'}",
            f"incidentStatus={incident_status or 'unknown'}",
        ]
        if classification:
            decision_reason_parts.append(f"classification={classification}")
        if behavioral_indicators:
            decision_reason_parts.append(
                "indicators=" + ",".join(behavioral_indicators)
            )
        if actions_taken:
            decision_reason_parts.append("actions=" + ",".join(actions_taken))
        decision_reason = " ".join(decision_reason_parts)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="sentinelone_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=threat_id or None,
        )

    def _threat_evidence(
        self,
        threat: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        threat_info = (
            threat.get("threatInfo")
            if isinstance(threat.get("threatInfo"), dict)
            else {}
        ) or {}
        agent_info = (
            threat.get("agentRealtimeInfo")
            if isinstance(threat.get("agentRealtimeInfo"), dict)
            else {}
        ) or {}
        responses = (
            threat.get("automatedResponses")
            if isinstance(threat.get("automatedResponses"), dict)
            else {}
        ) or {}
        ranges = (
            threat.get("ranges") if isinstance(threat.get("ranges"), dict) else {}
        ) or {}

        engines = _to_str_list(
            threat_info.get("engines") or ranges.get("detectionEngines")
        )
        actions_taken = [
            str(a).strip().lower()
            for a in (responses.get("actionsTaken") or [])
            if isinstance(a, (str, int))
        ]

        mitigation_desc = threat.get("mitigationStatusDescription")
        mitigation_desc_len = (
            len(str(mitigation_desc))
            if mitigation_desc not in (None, "")
            else None
        )

        return {
            "threat_id": threat.get("id"),
            "created_at": threat.get("createdAt"),
            "updated_at": threat.get("updatedAt"),
            "identifier": threat_info.get("identifier"),
            "threat_name_redacted": _redact_with_hash(
                threat_info.get("threatName")
            ),
            "severity": _normalize_severity(threat_info.get("severity")),
            "analyst_verdict": _normalize_status(
                threat_info.get("analystVerdict")
            ),
            "confidence_level": _normalize_status(
                threat_info.get("confidenceLevel")
            ),
            "incident_status": _normalize_status(
                threat_info.get("incidentStatus")
            ),
            "classification": _normalize_classification(
                threat_info.get("classification")
            ),
            "mitigation_status": _normalize_status(
                threat_info.get("mitigationStatus")
            ),
            "engines": engines,
            "behavioral_indicators": _to_str_list(
                threat.get("behavioralIndicators")
            ),
            "agent_computer_name_redacted": _redact_with_hash(
                agent_info.get("agentComputerName")
            ),
            "agent_domain_redacted": _redact_with_hash(
                agent_info.get("agentDomain")
            ),
            "agent_os_type": agent_info.get("agentOsType"),
            "agent_machine_type": agent_info.get("agentMachineType"),
            "agent_version": agent_info.get("agentVersion"),
            "agent_infected": _coerce_bool(agent_info.get("agentInfected")),
            "agent_is_active": _coerce_bool(agent_info.get("agentIsActive")),
            "automated_responses": {
                "actions_taken": actions_taken,
                "approval_required": _coerce_bool(
                    responses.get("approvalRequired")
                ),
                "approved_by_present": bool(responses.get("approvedBy")),
            },
            "is_authenticated_response": _coerce_bool(
                threat.get("is_authenticated_response")
            ),
            "hostname_origin_country": threat.get("hostname_origin_country"),
            "binary_signature_status": _normalize_status(
                threat.get("binary_signature_status")
            ),
            "binary_path_normalized": threat.get("binary_path_normalized"),
            "kill_chain_position": _normalize_status(
                threat.get("kill_chain_position")
            ),
            "external_ticket_id_last8": _last_n(
                threat.get("externalTicketId"), 8
            ),
            "mitigation_status_description_length": mitigation_desc_len,
            "source_tool": "sentinelone_singularity",
            "source_provenance": provenance,
        }

    # ---- per-audit evaluation -------------------------------------------

    def _build_audit_result(
        self,
        audit: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        action = _normalize_status(audit.get("action"))
        actor = (
            audit.get("actor") if isinstance(audit.get("actor"), dict) else {}
        ) or {}
        is_admin = _coerce_bool(actor.get("is_admin"))
        details = (
            audit.get("details") if isinstance(audit.get("details"), dict) else {}
        ) or {}

        evidence_data: dict[str, Any] = {
            "audit_record": True,
            "timestamp": audit.get("timestamp"),
            "action": action,
            "actor_username_last8": _last_n(actor.get("username"), 8),
            "actor_email_domain": _email_domain_only(actor.get("email")),
            "actor_is_admin": is_admin,
            "target_id_last8": _last_n(audit.get("target_id"), 8),
            "details_keys": (
                sorted(details.keys()) if isinstance(details, dict) else []
            ),
            "source_tool": "sentinelone_singularity",
            "source_provenance": provenance,
        }

        worst = "PASS"
        emitted: list[ControlResult] = []

        def _emit(
            signal: str,
            *,
            detail: str,
            extra: dict[str, Any] | None = None,
        ) -> None:
            nonlocal worst
            control_id = self._signal_to_control.get(signal, "PR-05")
            result = self._signal_result.get(signal, "PASS")
            worst = _max_result(worst, result)
            ev = {**evidence_data, "signal": signal}
            if extra:
                ev.update(extra)
            emitted.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=detail,
                    evidence_data=ev,
                )
            )

        if action == "site_settings_changed":
            disabling = bool(
                details.get("disable_protection")
                or details.get("protection_disabled")
            )
            new_state = str(details.get("new_state") or "").strip().lower()
            if disabling or new_state in ("disabled", "off"):
                _emit(
                    "site_settings_disable_protection",
                    detail=(
                        "SentinelOne audit: site_settings_changed disabling "
                        "protection (tenant-wide protection downgrade)"
                    ),
                    extra={"details_summary": "protection_disabled"},
                )
            else:
                _emit(
                    "deep_visibility_query_captured",
                    detail=(
                        "SentinelOne audit: site_settings_changed "
                        "(informational; no explicit protection disable)"
                    ),
                )
        elif action == "policy_changed":
            _emit(
                "policy_weakening",
                detail=(
                    "SentinelOne audit: policy_changed "
                    "(potential detection weakening — review)"
                ),
            )
        elif action == "user_role_changed":
            new_role = str(details.get("new_role") or "").strip().lower()
            if new_role == "admin":
                _emit(
                    "user_role_admin_change",
                    detail=(
                        "SentinelOne audit: user_role_changed → admin "
                        "(privilege elevation)"
                    ),
                    extra={"new_role": "admin"},
                )
            else:
                _emit(
                    "deep_visibility_query_captured",
                    detail=(
                        f"SentinelOne audit: user_role_changed (new_role="
                        f"{new_role or 'unknown'})"
                    ),
                )
        elif action == "api_token_created":
            _emit(
                "api_token_created",
                detail=(
                    "SentinelOne audit: api_token_created "
                    "(new programmatic credential)"
                ),
            )
        elif action == "agent_uninstalled":
            if is_admin is False:
                _emit(
                    "agent_uninstalled_non_admin",
                    detail=(
                        "SentinelOne audit: agent_uninstalled by non-admin "
                        "(rogue agent removal — protection bypass)"
                    ),
                    extra={"actor_is_admin": False},
                )
            else:
                _emit(
                    "deep_visibility_query_captured",
                    detail=(
                        "SentinelOne audit: agent_uninstalled by admin (captured)"
                    ),
                )
        elif action == "deep_visibility_query":
            _emit(
                "deep_visibility_query_captured",
                detail=(
                    "SentinelOne audit: deep_visibility_query "
                    "(analyst-driven query captured)"
                ),
            )
        else:
            _emit(
                "deep_visibility_query_captured",
                detail=(
                    f"SentinelOne audit: action={action or 'unknown'} (captured)"
                ),
            )

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst, "ALLOW")

        timestamp_iso = self._normalize_timestamp(audit.get("timestamp"))
        action_id_seed = (
            str(audit.get("target_id") or "")
            or str(audit.get("timestamp") or "")
            or uuid.uuid4().hex
        )
        action_id = f"sentinelone-audit-{action_id_seed[-16:]}"

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="sentinelone_import",
            mode=self.mode,
            control_results=emitted,
            decision=decision,
            decision_reason=(
                f"SentinelOne audit action={action or 'unknown'} "
                f"actor_admin={is_admin}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )

    # ---- synthetic cross-event evaluation -------------------------------

    def _build_synthetic_results(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []
        results.extend(
            self._cross_host_attack_synthetics(
                threats, file_sha256=file_sha256
            )
        )
        results.extend(
            self._repeated_fp_synthetics(threats, file_sha256=file_sha256)
        )
        results.extend(
            self._recurring_tp_synthetics(threats, file_sha256=file_sha256)
        )
        return results

    def _week_bucket(self, raw: Any) -> datetime:
        ts = _parse_time(raw)
        if ts is None:
            ts = datetime.now(timezone.utc)
        ts_utc = ts.astimezone(timezone.utc)
        day_index = (ts_utc - datetime(1970, 1, 1, tzinfo=timezone.utc)).days
        week_start_day = day_index - (day_index % 7)
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
            days=week_start_day
        )

    def _cross_host_attack_synthetics(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        buckets: dict[tuple[str, datetime], set[str]] = defaultdict(set)
        for t in threats:
            ti = (
                t.get("threatInfo")
                if isinstance(t.get("threatInfo"), dict)
                else {}
            ) or {}
            ai = (
                t.get("agentRealtimeInfo")
                if isinstance(t.get("agentRealtimeInfo"), dict)
                else {}
            ) or {}
            classification = _normalize_classification(ti.get("classification"))
            if not classification:
                continue
            host_raw = str(ai.get("agentComputerName") or "").strip()
            if not host_raw:
                continue
            host_key = hashlib.sha256(
                host_raw.encode("utf-8")
            ).hexdigest()[:32]
            week_start = self._week_bucket(
                t.get("createdAt") or t.get("updatedAt")
            )
            buckets[(classification, week_start)].add(host_key)

        out: list[EvaluationResult] = []
        for (classification, week_start), hosts in buckets.items():
            if len(hosts) <= self.cross_host_threshold:
                continue
            slug = classification.replace(" ", "-")[:16]
            out.append(
                self._make_synthetic_result(
                    signal="cross_host_attack_synthetic",
                    detail=(
                        f"SentinelOne classification '{classification}' "
                        f"observed across {len(hosts)} distinct hosts in 7-day "
                        f"window starting {week_start.isoformat()} (> threshold "
                        f"{self.cross_host_threshold}) — cross-host attack pattern"
                    ),
                    evidence_extra={
                        "classification": classification,
                        "distinct_host_count": len(hosts),
                        "window_start": week_start.isoformat(),
                        "window_end": (
                            week_start + timedelta(days=7)
                        ).isoformat(),
                        "cross_host_threshold": self.cross_host_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"sentinelone-synthetic-spread-{slug}",
                )
            )
        return out

    def _threat_name_buckets(
        self,
        threats: list[dict[str, Any]],
        *,
        verdict: str,
    ) -> dict[tuple[str, datetime], int]:
        buckets: dict[tuple[str, datetime], int] = defaultdict(int)
        for t in threats:
            ti = (
                t.get("threatInfo")
                if isinstance(t.get("threatInfo"), dict)
                else {}
            ) or {}
            if _normalize_status(ti.get("analystVerdict")) != verdict:
                continue
            name = ti.get("threatName")
            if not name:
                continue
            week_start = self._week_bucket(
                t.get("createdAt") or t.get("updatedAt")
            )
            buckets[(str(name), week_start)] += 1
        return buckets

    def _repeated_fp_synthetics(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        buckets = self._threat_name_buckets(threats, verdict="false_positive")
        out: list[EvaluationResult] = []
        for (name, week_start), count in buckets.items():
            if count <= self.repeated_fp_threshold:
                continue
            name_redacted = _redact_with_hash(name)
            out.append(
                self._make_synthetic_result(
                    signal="repeated_fp_synthetic",
                    detail=(
                        f"SentinelOne threatName produced {count} false_positive "
                        f"verdicts in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.repeated_fp_threshold}) — rule needs tuning"
                    ),
                    evidence_extra={
                        "threat_name_redacted": name_redacted,
                        "false_positive_count": count,
                        "window_start": week_start.isoformat(),
                        "window_end": (
                            week_start + timedelta(days=7)
                        ).isoformat(),
                        "repeated_fp_threshold": self.repeated_fp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=(
                        "sentinelone-synthetic-fp-"
                        f"{name_redacted.get('sha256', '')[:16]}"
                    ),
                )
            )
        return out

    def _recurring_tp_synthetics(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        buckets = self._threat_name_buckets(threats, verdict="true_positive")
        out: list[EvaluationResult] = []
        for (name, week_start), count in buckets.items():
            if count <= self.recurring_tp_threshold:
                continue
            name_redacted = _redact_with_hash(name)
            out.append(
                self._make_synthetic_result(
                    signal="recurring_tp_synthetic",
                    detail=(
                        f"SentinelOne threatName produced {count} true_positive "
                        f"verdicts in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.recurring_tp_threshold}) — recurring real "
                        f"attack against this host fleet"
                    ),
                    evidence_extra={
                        "threat_name_redacted": name_redacted,
                        "true_positive_count": count,
                        "window_start": week_start.isoformat(),
                        "window_end": (
                            week_start + timedelta(days=7)
                        ).isoformat(),
                        "recurring_tp_threshold": self.recurring_tp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=(
                        "sentinelone-synthetic-tp-"
                        f"{name_redacted.get('sha256', '')[:16]}"
                    ),
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
                "source_tool": "sentinelone_singularity",
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
            source_type="sentinelone_import",
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
        if raw is None or raw == "":
            return datetime.now(timezone.utc).isoformat()
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            try:
                return datetime.fromtimestamp(
                    float(raw), tz=timezone.utc
                ).isoformat()
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
            detail="Empty SentinelOne export (no threats or audit_logs)",
            evidence_data={
                "source_provenance": provenance,
                "threat_count": 0,
                "audit_count": 0,
            },
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sentinelone-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sentinelone_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty SentinelOne export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
