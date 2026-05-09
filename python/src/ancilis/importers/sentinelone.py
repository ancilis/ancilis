"""SentinelOne Singularity EDR importer — converts Singularity threats API
exports to AKSI EvaluationResults.

SentinelOne Singularity (https://www.sentinelone.com/platform/) is the
second-largest endpoint detection-and-response (EDR) platform alongside
CrowdStrike Falcon. The Singularity threats API surfaces ``threats[]``
records containing ``threatInfo`` (aiConfidenceLevel, analystVerdict,
classification, classificationSource, fileVerificationType,
incidentStatus, mitigationStatus, threatName, fileHashSha256),
``agentRealtimeInfo`` (agentOsName, agentVersion, networkInterfaces,
agentIsActive, groupName), ``mitigationStatus[]`` autonomous-response
entries (action, status, mitigationStatus, userId, initiatedByPolicy),
MITRE ATT&CK ``indicators[]`` (category, tactic, technique), and
``network`` flow metadata. Compared to Falcon's behavior-centric model,
Singularity's distinguishing dimension is its autonomous-mitigation
governance signal — every threat carries a record of which actions were
taken, by whom (or by which policy), and whether they succeeded.

Mapping (see ``shared/mappings/sentinelone-aksi-controls.json``):

  - threatInfo.aiConfidenceLevel=malicious + incidentStatus in
    {unresolved, in_progress}                            → DE-01 FAIL
  - aiConfidenceLevel=malicious + analystVerdict=true_positive
    + incidentStatus=resolved                            → PR-05 FAIL
  - aiConfidenceLevel=malicious + analystVerdict=false_positive
                                                         → PR-05 PASS
  - aiConfidenceLevel=suspicious + incidentStatus=unresolved
                                                         → DE-01 FAIL
  - classification=Ransomware                            → DE-01 FAIL (BLOCK)
  - classification=Malware                               → DE-01 FAIL
  - classification="Credential Theft"                    → PR-01 FAIL
  - classification="Lateral Movement"                    → PR-02 FAIL
  - classification="Data Exfiltration"                   → PR-04 FAIL
  - indicators[].category=Exfiltration                   → PR-04 FAIL
  - indicators[].category=CredentialAccess               → PR-01 FAIL
  - indicators[].category=PrivilegeEscalation            → PR-02 FAIL
  - indicators[].category=Impact                         → DE-01 FAIL
  - indicators[].category=InitialAccess + non-benign     → PR-01 FAIL
  - technique in {T1078,T1110,T1003,T1056}               → PR-01 FAIL
  - technique in {T1041,T1567,T1011,T1567.002}           → PR-04 FAIL
  - technique in {T1059,T1106,T1620}                     → PR-03 FAIL
  - mitigationStatus[].action in
    {kill,quarantine,network_quarantine}
    + initiatedByPolicy=false + userId=null              → PR-02 FLAG
  - mitigationStatus[].action=rollback                   → PR-05 FLAG
  - mitigationStatus[].action in
    {kill,quarantine,network_quarantine}
    + initiatedByPolicy=true                             → captured PR-05 PASS
  - fileVerificationType=SignedRevoked                   → PR-04 FAIL
  - fileVerificationType=NotSigned + malware classification
                                                         → captured
  - groupName matches production-pattern + agentIsActive=false
                                                         → PR-01 FLAG
  - agentVersion < min_version                           → PR-05 FLAG

Synthetic cross-event signals:

  - same threat classification + storyline across > N hostnames in 7d
    (default 3)                                          → DE-01 FAIL synthetic
  - same threatName with > N false_positive in 7d (default 30)
                                                         → PR-03 FLAG synthetic
  - same threatName > N true_positive in 7d (default 5) → DE-01 FLAG synthetic
  - > N rollback actions in 1h cluster (default 5)      → PR-05 FAIL synthetic

Sanitization:

* ``threatName`` — length + sha256 only; raw is never stored (names can
  encode sensitive context).
* ``threatInfo.filePath`` — length only via ``filePath_length``.
* ``originatorProcess`` — length only via ``originatorProcess_length``.
* ``storyline`` — length + sha256 only.
* ``agentComputerName`` — length + sha256 only.
* ``agentDomain`` — verbatim if short, hashed if > 80 chars.
* ``networkInterfaces[].ip_v4`` — masked (last octet zeroed).
* ``externalIp`` / ``sourceIp`` / ``destinationIp`` — masked.
* ``destinationDomain`` — length only via ``destinationDomain_length``.
* ``description`` — length only via ``description_length``.
* ``userId`` — last 8 chars only.
* ``fileHashSha256`` — verbatim (already a hash).
* ``aiConfidenceLevel``, ``analystVerdict``, ``classification``,
  ``classificationSource``, ``incidentStatus``,
  ``mitigationStatus[].action``+``status``+``initiatedByPolicy``,
  ``fileVerificationType``, ``agentOsName``, ``agentVersion``,
  ``groupName``, ``destinationPort``, ``indicators[].category``,
  ``indicators[].technique``, ``agentIsActive`` — verbatim
  (vendor-supplied + structured, low-PII risk).

The SDK is importable without ``sentinelone-mgmt-api`` installed; this
importer parses the Singularity threats API JSON schema directly.
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
    "malicious_open": "DE-01",
    "malicious_resolved_true_positive": "PR-05",
    "malicious_false_positive": "PR-05",
    "suspicious_open": "DE-01",
    "classification_malware": "DE-01",
    "classification_credential_theft": "PR-01",
    "classification_lateral_movement": "PR-02",
    "classification_data_exfiltration": "PR-04",
    "indicator_exfiltration": "PR-04",
    "indicator_credential_access": "PR-01",
    "indicator_privilege_escalation": "PR-02",
    "indicator_impact": "DE-01",
    "indicator_initial_access": "PR-01",
    "mitre_technique_pr01": "PR-01",
    "mitre_technique_pr04": "PR-04",
    "mitre_technique_pr03": "PR-03",
    "manual_mitigation_no_user": "PR-02",
    "rollback_mitigation": "PR-05",
    "autonomous_policy_mitigation": "PR-05",
    "signed_revoked_binary": "PR-04",
    "unsigned_malware_pattern": "PR-05",
    "inactive_production_agent": "PR-01",
    "out_of_date_agent": "PR-05",
    "cross_host_attack_synthetic": "DE-01",
    "repeated_fp_synthetic": "PR-03",
    "recurring_tp_synthetic": "DE-01",
    "rollback_frequency_synthetic": "PR-05",
}

_DEFAULT_SIGNAL_RESULT: dict[str, str] = {
    "ransomware_classification": "FAIL",
    "malicious_open": "FAIL",
    "malicious_resolved_true_positive": "FAIL",
    "malicious_false_positive": "PASS",
    "suspicious_open": "FAIL",
    "classification_malware": "FAIL",
    "classification_credential_theft": "FAIL",
    "classification_lateral_movement": "FAIL",
    "classification_data_exfiltration": "FAIL",
    "indicator_exfiltration": "FAIL",
    "indicator_credential_access": "FAIL",
    "indicator_privilege_escalation": "FAIL",
    "indicator_impact": "FAIL",
    "indicator_initial_access": "FAIL",
    "mitre_technique_pr01": "FAIL",
    "mitre_technique_pr04": "FAIL",
    "mitre_technique_pr03": "FAIL",
    "manual_mitigation_no_user": "FLAG",
    "rollback_mitigation": "FLAG",
    "autonomous_policy_mitigation": "PASS",
    "signed_revoked_binary": "FAIL",
    "unsigned_malware_pattern": "PASS",
    "inactive_production_agent": "FLAG",
    "out_of_date_agent": "FLAG",
    "cross_host_attack_synthetic": "FAIL",
    "repeated_fp_synthetic": "FLAG",
    "recurring_tp_synthetic": "FLAG",
    "rollback_frequency_synthetic": "FAIL",
}

_DEFAULT_CROSS_HOST_THRESHOLD = 3
_DEFAULT_REPEATED_FP_THRESHOLD = 30
_DEFAULT_RECURRING_TP_THRESHOLD = 5
_DEFAULT_ROLLBACK_FREQUENCY_THRESHOLD = 5
_DEFAULT_ROLLBACK_FREQUENCY_WINDOW_SECONDS = 3600
_DEFAULT_MIN_AGENT_VERSION = "22.0.0"

_DEFAULT_PRODUCTION_GROUP_PATTERNS: list[str] = [
    "prod*",
    "server*",
    "agent-*",
    "svc-*",
]

_DEFAULT_MITRE_TECHNIQUE_TO_CONTROL: dict[str, str] = {
    "T1078": "PR-01",
    "T1110": "PR-01",
    "T1003": "PR-01",
    "T1056": "PR-01",
    "T1041": "PR-04",
    "T1567": "PR-04",
    "T1567.002": "PR-04",
    "T1011": "PR-04",
    "T1059": "PR-03",
    "T1106": "PR-03",
    "T1620": "PR-03",
}

_OPEN_INCIDENT_STATUSES = {"unresolved", "in_progress"}
_MALWARE_PATTERN_CLASSIFICATIONS = {
    "malware",
    "ransomware",
    "trojan",
    "pua",
    "generic.suspicious",
}
_AGENT_DOMAIN_MAX_CHARS = 80

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _load_mapping_table() -> tuple[
    dict[str, str],
    dict[str, str],
    int,
    int,
    int,
    int,
    int,
    str,
    list[str],
    dict[str, str],
]:
    """Return (signal_to_control, signal_result, cross_host_thr,
    repeated_fp_thr, recurring_tp_thr, rollback_freq_thr,
    rollback_window_sec, min_agent_version, production_group_patterns,
    mitre_technique_to_control)."""
    signal_to_control: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    signal_result: dict[str, str] = dict(_DEFAULT_SIGNAL_RESULT)
    cross_host_thr = _DEFAULT_CROSS_HOST_THRESHOLD
    repeated_fp_thr = _DEFAULT_REPEATED_FP_THRESHOLD
    recurring_tp_thr = _DEFAULT_RECURRING_TP_THRESHOLD
    rollback_freq_thr = _DEFAULT_ROLLBACK_FREQUENCY_THRESHOLD
    rollback_window_sec = _DEFAULT_ROLLBACK_FREQUENCY_WINDOW_SECONDS
    min_agent_version = _DEFAULT_MIN_AGENT_VERSION
    production_patterns = list(_DEFAULT_PRODUCTION_GROUP_PATTERNS)
    mitre = dict(_DEFAULT_MITRE_TECHNIQUE_TO_CONTROL)

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
            rollback_freq_thr,
            rollback_window_sec,
            min_agent_version,
            production_patterns,
            mitre,
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
            rb = meta.get("rollback_frequency_threshold")
            if isinstance(rb, (int, float)):
                rollback_freq_thr = int(rb)
            rbw = meta.get("rollback_frequency_window_seconds")
            if isinstance(rbw, (int, float)):
                rollback_window_sec = int(rbw)
            mv = meta.get("min_agent_version")
            if isinstance(mv, str) and mv.strip():
                min_agent_version = mv.strip()
            pp = meta.get("production_group_patterns")
            if isinstance(pp, list) and pp:
                production_patterns = [str(p) for p in pp]
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
        cross_host_thr,
        repeated_fp_thr,
        recurring_tp_thr,
        rollback_freq_thr,
        rollback_window_sec,
        min_agent_version,
        production_patterns,
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


def _redact_with_hash(text: str | None) -> dict[str, Any]:
    """For threatName / storyline / agentComputerName — store length +
    sha256 only. Raw text is NEVER preserved."""
    if text is None or text == "":
        return {"present": False}
    s = str(text)
    return {
        "present": True,
        "length": len(s),
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _truncate_or_hash(
    text: str | None, *, max_chars: int = _AGENT_DOMAIN_MAX_CHARS
) -> Any:
    """For low-PII vendor strings: keep verbatim if short, else hash + length."""
    if text is None or text == "":
        return None
    s = str(text)
    if len(s) <= max_chars:
        return s
    return {
        "redacted": True,
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


def _mask_ip(ip: Any) -> str | None:
    """Mask an IP address: zero the last IPv4 octet, /48-prefix IPv6.

    Falls back to ``"masked"`` when the input doesn't look parseable.
    """
    if ip is None or ip == "":
        return None
    s = str(ip).strip()
    if not s:
        return None
    if "." in s and ":" not in s:
        parts = s.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return ".".join(parts[:3] + ["0"])
        return "masked"
    if ":" in s:
        groups = s.split(":")
        kept = [g for g in groups if g != ""][:3]
        if not kept:
            return "masked"
        return ":".join(kept) + "::/48"
    return "masked"


def _norm_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _norm_upper(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().upper()


def _matches_pattern(name: str, patterns: list[str]) -> str | None:
    if not name:
        return None
    h = name.strip().lower()
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


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of ints (best-effort)."""
    if not version:
        return ()
    parts = str(version).strip().split(".")
    out: list[int] = []
    for p in parts:
        digits = ""
        for ch in p:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits == "":
            break
        try:
            out.append(int(digits))
        except ValueError:
            break
    return tuple(out)


def _version_lt(a: str, b: str) -> bool:
    """Return True iff version ``a`` is strictly less than version ``b``."""
    ta = _parse_version_tuple(a)
    tb = _parse_version_tuple(b)
    if not ta or not tb:
        return False
    # Pad to equal length for comparison.
    length = max(len(ta), len(tb))
    pa = ta + (0,) * (length - len(ta))
    pb = tb + (0,) * (length - len(tb))
    return pa < pb


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class SentinelOneImporter:
    """Parse SentinelOne Singularity threats API exports and convert each
    threat into an ``EvaluationResult``.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        cross_host_threshold: distinct hostnames per (classification,
            storyline) in a 7-day window above which a DE-01 synthetic
            FAIL is emitted (default from mapping metadata, falling back
            to 3).
        repeated_fp_threshold: false_positive count per threatName in a
            7-day window above which a PR-03 synthetic FLAG is emitted
            (default 30).
        recurring_tp_threshold: true_positive count per threatName in a
            7-day window above which a DE-01 synthetic FLAG is emitted
            (default 5).
        rollback_frequency_threshold: number of rollback actions in a 1h
            cluster above which a PR-05 synthetic FAIL is emitted
            (default 5).
        rollback_frequency_window_seconds: window size for the rollback
            cluster (default 3600).
        min_agent_version: minimum acceptable agentVersion; below this
            triggers a PR-05 FLAG (default ``"22.0.0"``).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        cross_host_threshold: int | None = None,
        repeated_fp_threshold: int | None = None,
        recurring_tp_threshold: int | None = None,
        rollback_frequency_threshold: int | None = None,
        rollback_frequency_window_seconds: int | None = None,
        min_agent_version: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._signal_to_control,
            self._signal_result,
            cross_host_thr,
            repeated_fp_thr,
            recurring_tp_thr,
            rollback_freq_thr,
            rollback_window_sec,
            mapping_min_version,
            self._production_patterns,
            self._mitre_technique_to_control,
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
        self.rollback_frequency_threshold = (
            int(rollback_frequency_threshold)
            if rollback_frequency_threshold is not None
            else rollback_freq_thr
        )
        self.rollback_frequency_window_seconds = (
            int(rollback_frequency_window_seconds)
            if rollback_frequency_window_seconds is not None
            else rollback_window_sec
        )
        self.min_agent_version = (
            str(min_agent_version)
            if min_agent_version is not None
            else mapping_min_version
        )

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a SentinelOne Singularity export (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        threats = list(self._extract_threats(text))
        return self._build_results(threats, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse SentinelOne Singularity export content from a string."""
        threats = list(self._extract_threats(content))
        return self._build_results(threats, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _extract_threats(self, content: str) -> Iterable[dict[str, Any]]:
        if not content.strip():
            return []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return list(_iter_jsonl(content))

        if isinstance(doc, dict):
            for key in ("threats", "data", "resources"):
                value = doc.get(key)
                if isinstance(value, list):
                    return [t for t in value if isinstance(t, dict)]
                if isinstance(value, dict):
                    return [value]
            # Bare threat-shaped object.
            if any(
                k in doc
                for k in ("id", "threatInfo", "agentRealtimeInfo", "indicators")
            ):
                return [doc]
            return []
        if isinstance(doc, list):
            return [t for t in doc if isinstance(t, dict)]
        return []

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
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        if not threats:
            return [self._empty_result(file_sha256=file_sha256)]
        results = [
            self._build_threat_result(t, file_sha256=file_sha256) for t in threats
        ]
        synthetics = self._build_synthetic_results(threats, file_sha256=file_sha256)
        results.extend(synthetics)
        return results

    # ---- per-threat evaluation ------------------------------------------

    def _build_threat_result(
        self,
        threat: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        evidence_data = self._common_evidence(threat, provenance)

        threat_id = str(threat.get("id") or "")
        info = threat.get("threatInfo") or {}
        if not isinstance(info, dict):
            info = {}
        agent_info = threat.get("agentRealtimeInfo") or {}
        if not isinstance(agent_info, dict):
            agent_info = {}

        ai_confidence = _norm_lower(info.get("aiConfidenceLevel"))
        analyst_verdict = _norm_lower(info.get("analystVerdict"))
        classification = _norm_lower(info.get("classification"))
        incident_status = _norm_lower(info.get("incidentStatus"))
        file_verification = _norm_lower(info.get("fileVerificationType"))

        indicators_raw = threat.get("indicators")
        indicators: list[dict[str, Any]] = (
            [i for i in indicators_raw if isinstance(i, dict)]
            if isinstance(indicators_raw, list)
            else []
        )
        indicator_categories = sorted(
            {_norm_lower(i.get("category")) for i in indicators if i.get("category")}
        )
        indicator_techniques = sorted(
            {
                _norm_upper(i.get("technique"))
                for i in indicators
                if i.get("technique")
            }
        )

        mitigations_raw = threat.get("mitigationStatus")
        mitigations: list[dict[str, Any]] = (
            [m for m in mitigations_raw if isinstance(m, dict)]
            if isinstance(mitigations_raw, list)
            else []
        )

        group_name = str(agent_info.get("groupName") or "")
        agent_is_active = _coerce_bool(agent_info.get("agentIsActive"))
        agent_version = str(agent_info.get("agentVersion") or "").strip()

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

        # 1. Classification (top priority — Ransomware first).
        if classification == "ransomware":
            _emit(
                "ransomware_classification",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} classification=Ransomware "
                    f"(top-priority data-loss classification — block)"
                ),
                extra={"classification": classification},
            )
        elif classification == "malware":
            _emit(
                "classification_malware",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} classification=Malware"
                ),
                extra={"classification": classification},
            )

        if classification == "credential theft":
            _emit(
                "classification_credential_theft",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification='Credential Theft'"
                ),
                extra={"classification": classification},
            )
        if classification == "lateral movement":
            _emit(
                "classification_lateral_movement",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification='Lateral Movement' (post-compromise spread)"
                ),
                extra={"classification": classification},
            )
        if classification == "data exfiltration":
            _emit(
                "classification_data_exfiltration",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"classification='Data Exfiltration'"
                ),
                extra={"classification": classification},
            )

        # 2. AI confidence + incident status routing.
        if ai_confidence == "malicious" and incident_status in _OPEN_INCIDENT_STATUSES:
            _emit(
                "malicious_open",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"aiConfidenceLevel=malicious incidentStatus={incident_status} "
                    f"(open malicious detection)"
                ),
            )
        if (
            ai_confidence == "malicious"
            and analyst_verdict == "true_positive"
            and incident_status == "resolved"
        ):
            _emit(
                "malicious_resolved_true_positive",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"aiConfidenceLevel=malicious analystVerdict=true_positive "
                    f"incidentStatus=resolved (audit-trail of confirmed attack)"
                ),
            )
        if ai_confidence == "malicious" and analyst_verdict == "false_positive":
            _emit(
                "malicious_false_positive",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"aiConfidenceLevel=malicious analystVerdict=false_positive (audit)"
                ),
            )
        if ai_confidence == "suspicious" and incident_status == "unresolved":
            _emit(
                "suspicious_open",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"aiConfidenceLevel=suspicious incidentStatus=unresolved"
                ),
            )

        # 3. MITRE indicator categories.
        if "exfiltration" in indicator_categories:
            _emit(
                "indicator_exfiltration",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} indicator category="
                    f"Exfiltration (top-priority data-loss tactic)"
                ),
                extra={"indicator_categories": indicator_categories},
            )
        if "credentialaccess" in indicator_categories:
            _emit(
                "indicator_credential_access",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} indicator category="
                    f"CredentialAccess"
                ),
                extra={"indicator_categories": indicator_categories},
            )
        if "privilegeescalation" in indicator_categories:
            _emit(
                "indicator_privilege_escalation",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} indicator category="
                    f"PrivilegeEscalation"
                ),
                extra={"indicator_categories": indicator_categories},
            )
        if "impact" in indicator_categories:
            _emit(
                "indicator_impact",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} indicator category=Impact"
                ),
                extra={"indicator_categories": indicator_categories},
            )
        if "initialaccess" in indicator_categories and ai_confidence != "benign":
            _emit(
                "indicator_initial_access",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} indicator category="
                    f"InitialAccess aiConfidenceLevel={ai_confidence or 'unknown'} "
                    f"(active intrusion)"
                ),
                extra={"indicator_categories": indicator_categories},
            )

        # 4. MITRE technique-based controls.
        techniques_by_control: dict[str, list[str]] = defaultdict(list)
        for tech in indicator_techniques:
            ctl = self._mitre_technique_to_control.get(tech)
            if ctl:
                techniques_by_control[ctl].append(tech)

        for ctl, techs in techniques_by_control.items():
            sorted_techs = sorted(set(techs))
            if ctl == "PR-01":
                _emit(
                    "mitre_technique_pr01",
                    detail=(
                        f"SentinelOne threat {threat_id or '?'} technique="
                        f"{','.join(sorted_techs)} → PR-01 (credential)"
                    ),
                    extra={"mitre_techniques": sorted_techs, "mitre_control": ctl},
                )
            elif ctl == "PR-04":
                _emit(
                    "mitre_technique_pr04",
                    detail=(
                        f"SentinelOne threat {threat_id or '?'} technique="
                        f"{','.join(sorted_techs)} → PR-04 (exfil)"
                    ),
                    extra={"mitre_techniques": sorted_techs, "mitre_control": ctl},
                )
            elif ctl == "PR-03":
                _emit(
                    "mitre_technique_pr03",
                    detail=(
                        f"SentinelOne threat {threat_id or '?'} technique="
                        f"{','.join(sorted_techs)} → PR-03 (interpreter abuse)"
                    ),
                    extra={"mitre_techniques": sorted_techs, "mitre_control": ctl},
                )

        # 5. Autonomous mitigation governance.
        for m in mitigations:
            action = _norm_lower(m.get("action"))
            initiated_by_policy = _coerce_bool(m.get("initiatedByPolicy"))
            user_id_raw = m.get("userId")
            user_id_present = user_id_raw not in (None, "", "null")

            if (
                action in {"kill", "quarantine", "network_quarantine"}
                and initiated_by_policy is False
                and not user_id_present
            ):
                _emit(
                    "manual_mitigation_no_user",
                    detail=(
                        f"SentinelOne threat {threat_id or '?'} mitigation action="
                        f"{action} initiatedByPolicy=false userId=null "
                        f"(manual unauthenticated mitigation)"
                    ),
                    extra={
                        "mitigation_action": action,
                        "initiated_by_policy": False,
                        "user_id_last8": _last_n(user_id_raw, 8),
                    },
                )

            if action == "rollback":
                _emit(
                    "rollback_mitigation",
                    detail=(
                        f"SentinelOne threat {threat_id or '?'} mitigation action="
                        f"rollback (state-rollback = data integrity event)"
                    ),
                    extra={
                        "mitigation_action": action,
                        "initiated_by_policy": initiated_by_policy,
                    },
                )

            if (
                action in {"kill", "quarantine", "network_quarantine"}
                and initiated_by_policy is True
            ):
                _emit(
                    "autonomous_policy_mitigation",
                    detail=(
                        f"SentinelOne threat {threat_id or '?'} mitigation action="
                        f"{action} initiatedByPolicy=true "
                        f"(autonomous policy mitigation captured)"
                    ),
                    extra={
                        "mitigation_action": action,
                        "initiated_by_policy": True,
                    },
                )

        # 6. File verification.
        if file_verification == "signedrevoked":
            _emit(
                "signed_revoked_binary",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} fileVerificationType="
                    f"SignedRevoked (signed-revoked binary running)"
                ),
                extra={"file_verification_type": file_verification},
            )
        if (
            file_verification == "notsigned"
            and classification in _MALWARE_PATTERN_CLASSIFICATIONS
        ):
            _emit(
                "unsigned_malware_pattern",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} fileVerificationType="
                    f"NotSigned classification={classification} (captured)"
                ),
                extra={
                    "file_verification_type": file_verification,
                    "classification": classification,
                },
            )

        # 7. Inactive production agent.
        prod_pattern = _matches_pattern(group_name, self._production_patterns)
        if prod_pattern and agent_is_active is False:
            _emit(
                "inactive_production_agent",
                detail=(
                    f"SentinelOne agent in production groupName='{group_name}' "
                    f"matching pattern '{prod_pattern}' agentIsActive=false "
                    f"(production endpoint inactive)"
                ),
                extra={
                    "production_pattern_matched": prod_pattern,
                    "group_name": group_name,
                    "agent_is_active": False,
                },
            )

        # 8. Out-of-date agent.
        if agent_version and _version_lt(agent_version, self.min_agent_version):
            _emit(
                "out_of_date_agent",
                detail=(
                    f"SentinelOne agentVersion={agent_version} "
                    f"< min_version={self.min_agent_version} (agent out-of-date)"
                ),
                extra={
                    "agent_version": agent_version,
                    "min_agent_version": self.min_agent_version,
                },
            )

        # Stamp aggregated metadata + layered_findings.
        for cr in control_results:
            cr.evidence_data["mitre_techniques"] = indicator_techniques
            cr.evidence_data["indicator_categories"] = indicator_categories
            cr.evidence_data["mitigation_actions"] = sorted(
                {_norm_lower(m.get("action")) for m in mitigations if m.get("action")}
            )
            cr.evidence_data["layered_findings"] = layered_findings

        # Guarantee at least one control result.
        if not control_results:
            cr = ControlResult(
                control_id="PR-05",
                control_name=_CONTROL_NAMES["PR-05"],
                result="PASS",
                detail=(
                    f"SentinelOne threat {threat_id or '?'} "
                    f"aiConfidenceLevel={ai_confidence or 'unknown'} "
                    f"classification={classification or 'unknown'} "
                    f"incidentStatus={incident_status or 'unknown'} "
                    f"(no signals matched)"
                ),
                evidence_data={
                    **evidence_data,
                    "signal": "default",
                    "mitre_techniques": indicator_techniques,
                    "indicator_categories": indicator_categories,
                    "mitigation_actions": [],
                    "layered_findings": layered_findings,
                },
            )
            control_results.append(cr)

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst, "ALLOW")

        timestamp_iso = self._normalize_timestamp(threat.get("createdAt"))

        action_id_seed = threat_id or uuid.uuid4().hex
        action_id = f"sentinelone-{action_id_seed[:16]}"

        decision_reason_parts = [
            f"SentinelOne threat {threat_id or '?'}",
            f"aiConfidenceLevel={ai_confidence or 'unknown'}",
            f"classification={classification or 'unknown'}",
            f"incidentStatus={incident_status or 'unknown'}",
        ]
        if indicator_categories:
            decision_reason_parts.append(
                "categories=" + ",".join(indicator_categories)
            )
        if indicator_techniques:
            decision_reason_parts.append(
                "techniques=" + ",".join(indicator_techniques)
            )
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

    def _common_evidence(
        self,
        threat: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        info = threat.get("threatInfo") or {}
        if not isinstance(info, dict):
            info = {}
        agent_info = threat.get("agentRealtimeInfo") or {}
        if not isinstance(agent_info, dict):
            agent_info = {}
        network = threat.get("network") or {}
        if not isinstance(network, dict):
            network = {}

        # Sanitize indicators[].
        indicators_summary: list[dict[str, Any]] = []
        if isinstance(threat.get("indicators"), list):
            for i in threat["indicators"]:
                if not isinstance(i, dict):
                    continue
                ids_raw = i.get("ids")
                ids_count = len(ids_raw) if isinstance(ids_raw, list) else 0
                indicators_summary.append(
                    {
                        "category": i.get("category"),
                        "tactic": i.get("tactic"),
                        "technique": (
                            _norm_upper(i.get("technique"))
                            if i.get("technique")
                            else None
                        ),
                        "ids_count": ids_count,
                        "description_length": _coerce_int(
                            i.get("description_length")
                        ),
                    }
                )

        # Sanitize mitigationStatus[].
        mitigations_summary: list[dict[str, Any]] = []
        if isinstance(threat.get("mitigationStatus"), list):
            for m in threat["mitigationStatus"]:
                if not isinstance(m, dict):
                    continue
                mitigations_summary.append(
                    {
                        "action": _norm_lower(m.get("action")) or None,
                        "status": _norm_lower(m.get("status")) or None,
                        "mitigation_status": _norm_lower(
                            m.get("mitigationStatus")
                        )
                        or None,
                        "user_id_last8": _last_n(m.get("userId"), 8),
                        "initiated_by_policy": _coerce_bool(
                            m.get("initiatedByPolicy")
                        ),
                    }
                )

        # Sanitize networkInterfaces[].ip_v4 (mask each).
        ni_raw = agent_info.get("networkInterfaces")
        network_interfaces: list[dict[str, Any]] = []
        if isinstance(ni_raw, list):
            for ni in ni_raw:
                if not isinstance(ni, dict):
                    continue
                ip4_list = ni.get("ip_v4")
                masked = []
                if isinstance(ip4_list, list):
                    for ip in ip4_list:
                        m = _mask_ip(ip)
                        if m:
                            masked.append(m)
                network_interfaces.append({"ip_v4_masked": masked})

        return {
            "threat_id": threat.get("id"),
            "created_at": threat.get("createdAt"),
            "agent_id_field": info.get("agentId"),
            "ai_confidence_level": _norm_lower(info.get("aiConfidenceLevel")) or None,
            "analyst_verdict": _norm_lower(info.get("analystVerdict")) or None,
            "classification": _norm_lower(info.get("classification")) or None,
            "classification_source": _norm_lower(info.get("classificationSource"))
            or None,
            "incident_status": _norm_lower(info.get("incidentStatus")) or None,
            "mitigation_status_top": _norm_lower(info.get("mitigationStatus")) or None,
            "file_verification_type": _norm_lower(info.get("fileVerificationType"))
            or None,
            "threat_name_redacted": _redact_with_hash(info.get("threatName")),
            "file_hash_sha256": info.get("fileHashSha256"),
            "file_path_length": _coerce_int(info.get("filePath_length")),
            "originator_process_length": _coerce_int(
                info.get("originatorProcess_length")
            ),
            "storyline_redacted": _redact_with_hash(info.get("storyline")),
            "agent_computer_name_redacted": _redact_with_hash(
                agent_info.get("agentComputerName")
            ),
            "agent_domain": _truncate_or_hash(agent_info.get("agentDomain")),
            "agent_os_name": agent_info.get("agentOsName"),
            "agent_version": (
                str(agent_info["agentVersion"]).strip()
                if agent_info.get("agentVersion")
                else None
            ),
            "agent_is_active": _coerce_bool(agent_info.get("agentIsActive")),
            "group_name": agent_info.get("groupName"),
            "network_interfaces": network_interfaces,
            "external_ip_masked": _mask_ip(network.get("externalIp")),
            "source_ip_masked": _mask_ip(network.get("sourceIp")),
            "destination_ip_masked": _mask_ip(network.get("destinationIp")),
            "destination_domain_length": _coerce_int(
                network.get("destinationDomain_length")
            ),
            "destination_port": _coerce_int(network.get("destinationPort")),
            "indicators": indicators_summary,
            "mitigations": mitigations_summary,
            "source_tool": "sentinelone_singularity",
            "source_provenance": provenance,
        }

    # ---- synthetic cross-event evaluation -------------------------------

    def _build_synthetic_results(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []
        results.extend(
            self._cross_host_attack_synthetics(threats, file_sha256=file_sha256)
        )
        results.extend(
            self._repeated_fp_synthetics(threats, file_sha256=file_sha256)
        )
        results.extend(
            self._recurring_tp_synthetics(threats, file_sha256=file_sha256)
        )
        results.extend(
            self._rollback_frequency_synthetics(threats, file_sha256=file_sha256)
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
        """Bucket threats by ((classification + storyline-hash), 7d-window)
        and emit a DE-01 FAIL synthetic when distinct hostnames > threshold.
        Hostnames are hashed before bucketing — raw is never stored."""
        buckets: dict[tuple[str, datetime], set[str]] = defaultdict(set)
        for t in threats:
            info = t.get("threatInfo") or {}
            agent_info = t.get("agentRealtimeInfo") or {}
            if not isinstance(info, dict) or not isinstance(agent_info, dict):
                continue
            classification = _norm_lower(info.get("classification"))
            storyline = info.get("storyline")
            if not classification or not storyline:
                continue
            storyline_hash = hashlib.sha256(
                str(storyline).encode("utf-8")
            ).hexdigest()[:32]
            key_id = f"{classification}|{storyline_hash}"
            host = str(agent_info.get("agentComputerName") or "").strip()
            if not host:
                continue
            host_hash = hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
            week_start = self._week_bucket(t.get("createdAt"))
            buckets[(key_id, week_start)].add(host_hash)

        out: list[EvaluationResult] = []
        for (key_id, week_start), hosts in buckets.items():
            if len(hosts) <= self.cross_host_threshold:
                continue
            out.append(
                self._make_synthetic_result(
                    signal="cross_host_attack_synthetic",
                    detail=(
                        f"SentinelOne threat key '{key_id[:32]}' observed across "
                        f"{len(hosts)} distinct hosts in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.cross_host_threshold}) — worm/spread pattern"
                    ),
                    evidence_extra={
                        "threat_key_sha256": hashlib.sha256(
                            key_id.encode("utf-8")
                        ).hexdigest(),
                        "distinct_host_count": len(hosts),
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "cross_host_threshold": self.cross_host_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"sentinelone-synthetic-spread-{key_id[:16]}",
                )
            )
        return out

    def _threat_name_buckets(
        self,
        threats: list[dict[str, Any]],
        *,
        verdict_filter: str,
    ) -> dict[tuple[str, datetime], int]:
        buckets: dict[tuple[str, datetime], int] = defaultdict(int)
        for t in threats:
            info = t.get("threatInfo") or {}
            if not isinstance(info, dict):
                continue
            verdict = _norm_lower(info.get("analystVerdict"))
            if verdict != verdict_filter:
                continue
            name = info.get("threatName")
            if not name:
                continue
            week_start = self._week_bucket(t.get("createdAt"))
            buckets[(str(name), week_start)] += 1
        return buckets

    def _repeated_fp_synthetics(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        buckets = self._threat_name_buckets(threats, verdict_filter="false_positive")
        out: list[EvaluationResult] = []
        for (threat_name, week_start), count in buckets.items():
            if count <= self.repeated_fp_threshold:
                continue
            name_redacted = _redact_with_hash(threat_name)
            out.append(
                self._make_synthetic_result(
                    signal="repeated_fp_synthetic",
                    detail=(
                        f"SentinelOne threatName (redacted, len="
                        f"{name_redacted.get('length')}) produced {count} "
                        f"false_positive verdicts in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.repeated_fp_threshold}) — rule needs tuning"
                    ),
                    evidence_extra={
                        "threat_name_redacted": name_redacted,
                        "false_positive_count": count,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "repeated_fp_threshold": self.repeated_fp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=(
                        "sentinelone-synthetic-fp-"
                        + name_redacted.get("sha256", "unknown")[:16]
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
        buckets = self._threat_name_buckets(threats, verdict_filter="true_positive")
        out: list[EvaluationResult] = []
        for (threat_name, week_start), count in buckets.items():
            if count <= self.recurring_tp_threshold:
                continue
            name_redacted = _redact_with_hash(threat_name)
            out.append(
                self._make_synthetic_result(
                    signal="recurring_tp_synthetic",
                    detail=(
                        f"SentinelOne threatName (redacted, len="
                        f"{name_redacted.get('length')}) produced {count} "
                        f"true_positive verdicts in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.recurring_tp_threshold}) — recurring real attack"
                    ),
                    evidence_extra={
                        "threat_name_redacted": name_redacted,
                        "true_positive_count": count,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "recurring_tp_threshold": self.recurring_tp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=(
                        "sentinelone-synthetic-tp-"
                        + name_redacted.get("sha256", "unknown")[:16]
                    ),
                )
            )
        return out

    def _rollback_frequency_synthetics(
        self,
        threats: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Detect rollback-frequency clusters: > N rollback actions in
        a sliding 1h window emit a PR-05 FAIL synthetic (suspicious
        recovery activity)."""
        rollbacks: list[datetime] = []
        for t in threats:
            ms = t.get("mitigationStatus")
            if not isinstance(ms, list):
                continue
            for m in ms:
                if not isinstance(m, dict):
                    continue
                if _norm_lower(m.get("action")) == "rollback":
                    ts = _parse_time(t.get("createdAt"))
                    if ts is None:
                        ts = datetime.now(timezone.utc)
                    rollbacks.append(ts.astimezone(timezone.utc))
                    break  # one rollback per threat is enough

        if len(rollbacks) <= self.rollback_frequency_threshold:
            return []
        rollbacks.sort()

        # Sliding window — emit one synthetic per non-overlapping cluster.
        window = timedelta(seconds=self.rollback_frequency_window_seconds)
        out: list[EvaluationResult] = []
        i = 0
        n = len(rollbacks)
        while i < n:
            j = i
            while j < n and rollbacks[j] - rollbacks[i] <= window:
                j += 1
            cluster_size = j - i
            if cluster_size > self.rollback_frequency_threshold:
                out.append(
                    self._make_synthetic_result(
                        signal="rollback_frequency_synthetic",
                        detail=(
                            f"SentinelOne observed {cluster_size} rollback actions "
                            f"in {self.rollback_frequency_window_seconds}s window "
                            f"starting {rollbacks[i].isoformat()} (> threshold "
                            f"{self.rollback_frequency_threshold}) — suspicious "
                            f"recovery activity"
                        ),
                        evidence_extra={
                            "rollback_count": cluster_size,
                            "window_start": rollbacks[i].isoformat(),
                            "window_end": rollbacks[j - 1].isoformat(),
                            "rollback_frequency_threshold": (
                                self.rollback_frequency_threshold
                            ),
                            "rollback_frequency_window_seconds": (
                                self.rollback_frequency_window_seconds
                            ),
                        },
                        file_sha256=file_sha256,
                        action_id=(
                            "sentinelone-synthetic-rollback-"
                            + hashlib.sha256(
                                rollbacks[i].isoformat().encode("utf-8")
                            ).hexdigest()[:16]
                        ),
                    )
                )
                i = j
            else:
                i += 1
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
            detail="Empty SentinelOne Singularity export (no threats)",
            evidence_data={"source_provenance": provenance, "threat_count": 0},
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
            decision_reason="Empty SentinelOne Singularity export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
