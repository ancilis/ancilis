"""CrowdStrike Falcon EDR importer — converts Falcon Streaming API events to
AKSI EvaluationResults.

CrowdStrike Falcon (https://www.crowdstrike.com/products/endpoint-security/)
is the dominant endpoint detection-and-response (EDR) platform. For agents
that operate on developer/server endpoints, Falcon detects suspicious
behavior (process injection, lateral movement, exfiltration) at the host /
process level — distinct from log-centric SIEMs (Splunk, Microsoft
Sentinel) shipped in earlier waves. This importer parses Falcon Streaming
API JSON exports (DetectionSummaryEvent, IncidentSummaryEvent,
AuthActivityAuditEvent, UserActivityAuditEvent, FalconHostInformation) and
emits an ``EvaluationResult`` per event plus synthetic cross-event signals.

Mapping (see ``shared/mappings/crowdstrike-aksi-controls.json``):

  - severity_label=Critical + status in {new, in_progress, true_positive}
                                                       → DE-01 FAIL
  - severity_label=High     + status in {new, in_progress, true_positive}
                                                       → DE-01 FAIL
  - severity_label=High     + status=closed
    + status=true_positive                             → PR-05 FAIL
  - severity_label=High     + status=false_positive    → PR-05 PASS
  - severity_label=Medium   + open status              → PR-05 FLAG
  - tactic=Exfiltration                                → PR-04 FAIL
  - tactic="Credential Access"                         → PR-01 FAIL
  - tactic="Privilege Escalation"                      → PR-02 FAIL
  - tactic="Initial Access" + severity in {High, Critical}
                                                       → PR-01 FAIL
  - tactic="Lateral Movement"                          → PR-02 FAIL
  - tactic="Impact"                                    → DE-01 FAIL
  - technique in {T1078,T1110,T1003,T1056}             → PR-01 FAIL
  - technique in {T1041,T1567,T1011}                   → PR-04 FAIL
  - technique in {T1059,T1106,T1620}                   → PR-03 FAIL
  - confidence < threshold (50) on autonomous response → PR-03 FLAG
  - actions_taken contains isolate_host
    + is_authorized_response=false                     → PR-02 FAIL
  - actions_taken contains quarantine_file             → captured PR-05 PASS
  - is_managed_endpoint=false on production-named host → PR-01 FLAG
  - event_type=AuthActivityAuditEvent
    + severity_label in {High, Critical}               → PR-01 FAIL

Synthetic cross-event signals:

  - same detection_id/scenario across > N hostnames in 7d window (default 3)
                                                       → DE-01 FAIL synthetic (worm/spread)
  - same behavior name with > N false_positive in 7d (default 30)
                                                       → PR-03 FLAG synthetic
  - same behavior with > N true_positive in 7d (default 5)
                                                       → DE-01 FLAG synthetic

Sanitization:

* ``hostname`` — length + sha256; raw never stored (hostnames can encode
  tenant info).
* ``user_name`` — length + sha256; raw never stored.
* ``command_line`` — length only via ``command_line_length``; the full text
  is never stored, and any field literally named ``command_line`` is
  redacted to length only.
* ``ioc_value`` — length + sha256; raw never stored.
* ``behaviors[].scenario`` — length + sha256; raw never stored (scenarios
  can describe sensitive content).
* ``user_id`` — last 8 chars only.
* ``sensor_id`` — last 8 chars only.
* ``external_ip`` / ``local_ip`` — masked (last octet zeroed for IPv4;
  /48 prefix for IPv6).
* ``aid``, ``cid``, ``machine_domain``, ``platform``, ``event_type``,
  ``severity_label``, ``status``, ``tactic``, ``technique``,
  ``actions_taken``, ``is_authorized_response``, ``is_managed_endpoint``,
  ``process_name``, ``parent_process_name``, ``behaviors[].name``,
  ``behaviors[].confidence`` — verbatim (vendor-supplied + structured,
  pseudonymous or low-PII risk). ``machine_domain`` longer than 80 chars
  is hashed.

The SDK is importable without ``crowdstrike-falconpy`` installed; this
importer parses the Falcon Streaming API JSON schema directly.
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

_MAPPING_FILENAME = "crowdstrike-aksi-controls.json"


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
    "critical_open": "DE-01",
    "high_open": "DE-01",
    "high_closed_true_positive": "PR-05",
    "high_closed_false_positive": "PR-05",
    "medium_open": "PR-05",
    "tactic_exfiltration": "PR-04",
    "tactic_credential_access": "PR-01",
    "tactic_privilege_escalation": "PR-02",
    "tactic_initial_access_high": "PR-01",
    "tactic_lateral_movement": "PR-02",
    "tactic_impact": "DE-01",
    "mitre_technique_pr01": "PR-01",
    "mitre_technique_pr04": "PR-04",
    "mitre_technique_pr03": "PR-03",
    "low_confidence_autonomous": "PR-03",
    "isolate_host_no_authz": "PR-02",
    "quarantine_file_captured": "PR-05",
    "unmanaged_production_endpoint": "PR-01",
    "identity_protection_high": "PR-01",
    "cross_host_attack_synthetic": "DE-01",
    "repeated_fp_synthetic": "PR-03",
    "recurring_tp_synthetic": "DE-01",
}

_DEFAULT_SIGNAL_RESULT: dict[str, str] = {
    "critical_open": "FAIL",
    "high_open": "FAIL",
    "high_closed_true_positive": "FAIL",
    "high_closed_false_positive": "PASS",
    "medium_open": "FLAG",
    "tactic_exfiltration": "FAIL",
    "tactic_credential_access": "FAIL",
    "tactic_privilege_escalation": "FAIL",
    "tactic_initial_access_high": "FAIL",
    "tactic_lateral_movement": "FAIL",
    "tactic_impact": "FAIL",
    "mitre_technique_pr01": "FAIL",
    "mitre_technique_pr04": "FAIL",
    "mitre_technique_pr03": "FAIL",
    "low_confidence_autonomous": "FLAG",
    "isolate_host_no_authz": "FAIL",
    "quarantine_file_captured": "PASS",
    "unmanaged_production_endpoint": "FLAG",
    "identity_protection_high": "FAIL",
    "cross_host_attack_synthetic": "FAIL",
    "repeated_fp_synthetic": "FLAG",
    "recurring_tp_synthetic": "FLAG",
}

_DEFAULT_CROSS_HOST_THRESHOLD = 3
_DEFAULT_REPEATED_FP_THRESHOLD = 30
_DEFAULT_RECURRING_TP_THRESHOLD = 5
_DEFAULT_LOW_CONFIDENCE_THRESHOLD = 50

_DEFAULT_PRODUCTION_HOST_PATTERNS: list[str] = [
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
    "T1011": "PR-04",
    "T1059": "PR-03",
    "T1106": "PR-03",
    "T1620": "PR-03",
}

_OPEN_DETECTION_STATUSES = {"new", "in_progress", "true_positive"}
_CLOSED_STATUSES = {"closed", "true_positive", "false_positive"}

_MACHINE_DOMAIN_MAX_CHARS = 80
_BEHAVIOR_NAME_MAX_CHARS = 60

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
    list[str],
    dict[str, str],
]:
    """Return (signal_to_control, signal_result, cross_host_thr,
    repeated_fp_thr, recurring_tp_thr, low_confidence_thr,
    production_host_patterns, mitre_technique_to_control)."""
    signal_to_control: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    signal_result: dict[str, str] = dict(_DEFAULT_SIGNAL_RESULT)
    cross_host_thr = _DEFAULT_CROSS_HOST_THRESHOLD
    repeated_fp_thr = _DEFAULT_REPEATED_FP_THRESHOLD
    recurring_tp_thr = _DEFAULT_RECURRING_TP_THRESHOLD
    low_confidence_thr = _DEFAULT_LOW_CONFIDENCE_THRESHOLD
    production_patterns = list(_DEFAULT_PRODUCTION_HOST_PATTERNS)
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
            low_confidence_thr,
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
            lc = meta.get("low_confidence_threshold")
            if isinstance(lc, (int, float)):
                low_confidence_thr = int(lc)
            pp = meta.get("production_host_patterns")
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
        low_confidence_thr,
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
    """Hostname / user_name / ioc_value / scenario — store length + sha256
    only. Raw text is NEVER preserved."""
    if text is None or text == "":
        return {"present": False}
    s = str(text)
    return {
        "present": True,
        "length": len(s),
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _truncate_or_hash(
    text: str | None, *, max_chars: int = _MACHINE_DOMAIN_MAX_CHARS
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


def _normalize_severity_label(value: Any) -> str:
    if value is None:
        return "unknown"
    return str(value).strip().lower()


def _normalize_status(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalize_tactic(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


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


def _matches_production_pattern(hostname: str, patterns: list[str]) -> str | None:
    if not hostname:
        return None
    h = hostname.strip().lower()
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


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

class CrowdStrikeImporter:
    """Parse CrowdStrike Falcon Streaming API event exports and convert each
    event into an ``EvaluationResult``.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        cross_host_threshold: distinct hostnames per detection_id/scenario in
            a 7-day window above which a DE-01 synthetic FAIL is emitted
            (default from mapping metadata, falling back to 3).
        repeated_fp_threshold: false_positive count per behavior name in a
            7-day window above which a PR-03 synthetic FLAG is emitted
            (default 30).
        recurring_tp_threshold: true_positive count per behavior name in a
            7-day window above which a DE-01 synthetic FLAG is emitted
            (default 5).
        low_confidence_threshold: behavior confidence below which an
            autonomous-response action triggers a PR-03 FLAG (default 50).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        cross_host_threshold: int | None = None,
        repeated_fp_threshold: int | None = None,
        recurring_tp_threshold: int | None = None,
        low_confidence_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._signal_to_control,
            self._signal_result,
            cross_host_thr,
            repeated_fp_thr,
            recurring_tp_thr,
            low_confidence_thr,
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
        self.low_confidence_threshold = (
            int(low_confidence_threshold)
            if low_confidence_threshold is not None
            else low_confidence_thr
        )

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a CrowdStrike Falcon export (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = list(self._extract_events(text))
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse CrowdStrike Falcon export content from a string."""
        events = list(self._extract_events(content))
        return self._build_results(events, file_sha256=None)

    # -- Internals --------------------------------------------------------

    def _extract_events(self, content: str) -> Iterable[dict[str, Any]]:
        if not content.strip():
            return []
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            return list(_iter_jsonl(content))

        if isinstance(doc, dict):
            for key in ("events", "data", "resources"):
                value = doc.get(key)
                if isinstance(value, list):
                    return [e for e in value if isinstance(e, dict)]
                if isinstance(value, dict):
                    return [value]
            # Bare event-shaped object.
            if any(
                k in doc
                for k in ("event_id", "event_type", "detection_id", "aid", "cid")
            ):
                return [doc]
            return []
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        return []

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "crowdstrike_falcon",
            "source_tool_name": "crowdstrike_falcon",
            "source_tool_version": "v0",
            "spec_url": "https://www.crowdstrike.com/blog/tech-center/intro-streaming-api/",
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
        results = [
            self._build_event_result(e, file_sha256=file_sha256) for e in events
        ]
        synthetics = self._build_synthetic_results(events, file_sha256=file_sha256)
        results.extend(synthetics)
        return results

    # ---- per-event evaluation -------------------------------------------

    def _build_event_result(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        provenance = self._source_provenance(file_sha256=file_sha256)
        evidence_data = self._common_evidence(event, provenance)

        event_id = str(event.get("event_id") or event.get("detection_id") or "")
        event_type = str(event.get("event_type") or "").strip()
        severity_label = _normalize_severity_label(event.get("severity_label"))
        status = _normalize_status(event.get("status"))
        tactic = _normalize_tactic(event.get("tactic"))
        technique_raw = str(event.get("technique") or "").strip().upper()
        is_authorized_response = _coerce_bool(event.get("is_authorized_response"))
        is_managed_endpoint = _coerce_bool(event.get("is_managed_endpoint"))
        actions_taken = [
            str(a).strip().lower()
            for a in (event.get("actions_taken") or [])
            if isinstance(a, (str, int))
        ]
        hostname_raw = str(event.get("hostname") or "")

        behaviors_raw = event.get("behaviors")
        behaviors: list[dict[str, Any]] = (
            [b for b in behaviors_raw if isinstance(b, dict)]
            if isinstance(behaviors_raw, list)
            else []
        )

        # Aggregate behavior techniques + tactics (in addition to top-level fields).
        behavior_techniques: list[str] = [technique_raw] if technique_raw else []
        behavior_tactics: list[str] = [tactic] if tactic else []
        for b in behaviors:
            t = b.get("technique")
            if t:
                behavior_techniques.append(str(t).strip().upper())
            tac = b.get("tactic")
            if tac:
                behavior_tactics.append(str(tac).strip().lower())
        behavior_techniques = sorted(
            {t for t in behavior_techniques if t}
        )
        behavior_tactics_set = {t for t in behavior_tactics if t}

        # Track behavior confidence used for low-confidence-autonomous signal.
        behavior_confidences = [
            _coerce_int(b.get("confidence"))
            for b in behaviors
            if _coerce_int(b.get("confidence")) is not None
        ]
        min_confidence = min(behavior_confidences) if behavior_confidences else None

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

        # 1. Severity + status baseline.
        if severity_label == "critical" and status in _OPEN_DETECTION_STATUSES:
            _emit(
                "critical_open",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} severity=Critical "
                    f"status={status} (open critical detection)"
                ),
            )
        elif severity_label == "high" and status in _OPEN_DETECTION_STATUSES:
            _emit(
                "high_open",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} severity=High "
                    f"status={status} (open high detection)"
                ),
            )
        elif severity_label == "high" and status == "closed":
            # closed without resolution status — treat as informational
            pass

        # closed + true_positive / false_positive routing for High.
        if severity_label == "high" and status == "true_positive":
            # already routed above as open via _OPEN_DETECTION_STATUSES; still
            # emit closed-true-positive when the export marks it as closed.
            pass
        if (
            severity_label == "high"
            and status == "closed"
            and _normalize_status(event.get("disposition") or event.get("resolution"))
            == "true_positive"
        ):
            _emit(
                "high_closed_true_positive",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} severity=High "
                    f"status=closed disposition=true_positive "
                    f"(confirmed real — audit-trail closure)"
                ),
            )
        if severity_label == "high" and status == "false_positive":
            _emit(
                "high_closed_false_positive",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} severity=High "
                    f"status=false_positive (audit)"
                ),
            )

        if severity_label == "medium" and status in _OPEN_DETECTION_STATUSES:
            _emit(
                "medium_open",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} severity=Medium "
                    f"status={status}"
                ),
            )

        # 2. Tactic-based controls.
        if "exfiltration" in behavior_tactics_set:
            _emit(
                "tactic_exfiltration",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} tactic=Exfiltration "
                    f"(top-priority data-loss tactic)"
                ),
                extra={"tactics": sorted(behavior_tactics_set)},
            )
        if "credential access" in behavior_tactics_set:
            _emit(
                "tactic_credential_access",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} tactic='Credential Access'"
                ),
                extra={"tactics": sorted(behavior_tactics_set)},
            )
        if "privilege escalation" in behavior_tactics_set:
            _emit(
                "tactic_privilege_escalation",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} tactic='Privilege Escalation'"
                ),
                extra={"tactics": sorted(behavior_tactics_set)},
            )
        if (
            "initial access" in behavior_tactics_set
            and severity_label in ("high", "critical")
        ):
            _emit(
                "tactic_initial_access_high",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} tactic='Initial Access' "
                    f"severity={severity_label} (active intrusion)"
                ),
                extra={"tactics": sorted(behavior_tactics_set)},
            )
        if "lateral movement" in behavior_tactics_set:
            _emit(
                "tactic_lateral_movement",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} tactic='Lateral Movement' "
                    f"(post-compromise spread)"
                ),
                extra={"tactics": sorted(behavior_tactics_set)},
            )
        if "impact" in behavior_tactics_set:
            _emit(
                "tactic_impact",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} tactic='Impact'"
                ),
                extra={"tactics": sorted(behavior_tactics_set)},
            )

        # 3. MITRE technique-based controls.
        techniques_by_control: dict[str, list[str]] = defaultdict(list)
        for tech in behavior_techniques:
            ctl = self._mitre_technique_to_control.get(tech)
            if ctl:
                techniques_by_control[ctl].append(tech)

        for ctl, techs in techniques_by_control.items():
            if ctl == "PR-01":
                _emit(
                    "mitre_technique_pr01",
                    detail=(
                        f"CrowdStrike detection {event_id or '?'} technique="
                        f"{','.join(sorted(set(techs)))} → PR-01 (credential)"
                    ),
                    extra={"mitre_techniques": sorted(set(techs)), "mitre_control": ctl},
                )
            elif ctl == "PR-04":
                _emit(
                    "mitre_technique_pr04",
                    detail=(
                        f"CrowdStrike detection {event_id or '?'} technique="
                        f"{','.join(sorted(set(techs)))} → PR-04 (exfil)"
                    ),
                    extra={"mitre_techniques": sorted(set(techs)), "mitre_control": ctl},
                )
            elif ctl == "PR-03":
                _emit(
                    "mitre_technique_pr03",
                    detail=(
                        f"CrowdStrike detection {event_id or '?'} technique="
                        f"{','.join(sorted(set(techs)))} → PR-03 (interpreter abuse)"
                    ),
                    extra={"mitre_techniques": sorted(set(techs)), "mitre_control": ctl},
                )

        # 4. Autonomous-response governance.
        if "isolate_host" in actions_taken and is_authorized_response is False:
            _emit(
                "isolate_host_no_authz",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} actions_taken contains "
                    f"isolate_host but is_authorized_response=false "
                    f"(autonomous high-impact action without authorization)"
                ),
                extra={
                    "actions_taken": actions_taken,
                    "is_authorized_response": False,
                },
            )

        # Low-confidence autonomous response — any auto-action with confidence
        # below threshold is a PR-03 FLAG.
        if (
            actions_taken
            and is_authorized_response is True
            and min_confidence is not None
            and min_confidence < self.low_confidence_threshold
        ):
            _emit(
                "low_confidence_autonomous",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} autonomous response "
                    f"(actions_taken={actions_taken}) at confidence={min_confidence} "
                    f"< threshold {self.low_confidence_threshold}"
                ),
                extra={
                    "min_behavior_confidence": min_confidence,
                    "low_confidence_threshold": self.low_confidence_threshold,
                    "actions_taken": actions_taken,
                },
            )

        if "quarantine_file" in actions_taken:
            _emit(
                "quarantine_file_captured",
                detail=(
                    f"CrowdStrike detection {event_id or '?'} actions_taken contains "
                    f"quarantine_file (response captured)"
                ),
                extra={"actions_taken": actions_taken},
            )

        # 5. Unmanaged production endpoint.
        prod_pattern = _matches_production_pattern(
            hostname_raw, self._production_patterns
        )
        if prod_pattern and is_managed_endpoint is False:
            _emit(
                "unmanaged_production_endpoint",
                detail=(
                    f"CrowdStrike host matching production pattern "
                    f"'{prod_pattern}' is_managed_endpoint=false "
                    f"(unmanaged endpoint exposure)"
                ),
                extra={
                    "production_pattern_matched": prod_pattern,
                    "is_managed_endpoint": False,
                },
            )

        # 6. Identity Protection (Falcon Identity).
        if (
            event_type == "AuthActivityAuditEvent"
            and severity_label in ("high", "critical")
        ):
            _emit(
                "identity_protection_high",
                detail=(
                    f"CrowdStrike Falcon Identity Protection event {event_id or '?'} "
                    f"severity={severity_label} (identity-layer detection)"
                ),
                extra={"event_type": event_type},
            )

        # Stamp aggregated metadata + layered_findings.
        for cr in control_results:
            cr.evidence_data["mitre_techniques"] = behavior_techniques
            cr.evidence_data["tactics"] = sorted(behavior_tactics_set)
            cr.evidence_data["actions_taken"] = actions_taken
            cr.evidence_data["layered_findings"] = layered_findings

        # Guarantee at least one control result.
        if not control_results:
            cr = ControlResult(
                control_id="PR-05",
                control_name=_CONTROL_NAMES["PR-05"],
                result="PASS",
                detail=(
                    f"CrowdStrike event {event_id or '?'} type={event_type or 'unknown'} "
                    f"severity={severity_label} status={status or 'unknown'} "
                    f"(no signals matched)"
                ),
                evidence_data={
                    **evidence_data,
                    "signal": "default",
                    "mitre_techniques": behavior_techniques,
                    "tactics": sorted(behavior_tactics_set),
                    "actions_taken": actions_taken,
                    "layered_findings": layered_findings,
                },
            )
            control_results.append(cr)

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst, "ALLOW")

        timestamp_iso = self._normalize_timestamp(event.get("event_time"))

        action_id_seed = event_id or uuid.uuid4().hex
        action_id = f"crowdstrike-{action_id_seed[:16]}"

        decision_reason_parts = [
            f"CrowdStrike {event_type or 'event'} {event_id or '?'}",
            f"severity={severity_label}",
            f"status={status or 'unknown'}",
        ]
        if behavior_tactics_set:
            decision_reason_parts.append(
                "tactics=" + ",".join(sorted(behavior_tactics_set))
            )
        if behavior_techniques:
            decision_reason_parts.append(
                "techniques=" + ",".join(behavior_techniques)
            )
        if actions_taken:
            decision_reason_parts.append("actions=" + ",".join(actions_taken))
        decision_reason = " ".join(decision_reason_parts)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="crowdstrike_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=event_id or None,
        )

    def _common_evidence(
        self,
        event: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        # Sanitize behaviors[].
        behaviors_summary: list[dict[str, Any]] = []
        if isinstance(event.get("behaviors"), list):
            for b in event["behaviors"]:
                if not isinstance(b, dict):
                    continue
                behaviors_summary.append(
                    {
                        "behavior_id": b.get("behavior_id"),
                        "name": _truncate_or_hash(
                            b.get("name"), max_chars=_BEHAVIOR_NAME_MAX_CHARS
                        ),
                        "tactic": b.get("tactic"),
                        "technique": (
                            str(b.get("technique")).upper()
                            if b.get("technique")
                            else None
                        ),
                        "scenario_redacted": _redact_with_hash(b.get("scenario")),
                        "objective": b.get("objective"),
                        "confidence": _coerce_int(b.get("confidence")),
                    }
                )

        actions_taken = [
            str(a).strip().lower()
            for a in (event.get("actions_taken") or [])
            if isinstance(a, (str, int))
        ]

        return {
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "event_time": event.get("event_time"),
            "cid": event.get("cid"),
            "aid": event.get("aid"),
            "hostname_redacted": _redact_with_hash(event.get("hostname")),
            "platform": event.get("platform"),
            "severity": _coerce_int(event.get("severity")),
            "severity_label": _normalize_severity_label(event.get("severity_label")),
            "tactic": event.get("tactic"),
            "technique": (
                str(event.get("technique")).upper() if event.get("technique") else None
            ),
            "detection_id": event.get("detection_id"),
            "status": _normalize_status(event.get("status")),
            "user_name_redacted": _redact_with_hash(event.get("user_name")),
            "user_id_last8": _last_n(event.get("user_id"), 8),
            "ioc_type": event.get("ioc_type"),
            "ioc_value_length": _coerce_int(event.get("ioc_value_length")),
            "ioc_value_redacted": _redact_with_hash(event.get("ioc_value")),
            "command_line_length": _coerce_int(event.get("command_line_length")),
            "command_line_redacted": _redact_with_hash(event.get("command_line")),
            "process_name": event.get("process_name"),
            "parent_process_name": event.get("parent_process_name"),
            "is_managed_endpoint": _coerce_bool(event.get("is_managed_endpoint")),
            "is_authorized_response": _coerce_bool(event.get("is_authorized_response")),
            "actions_taken": actions_taken,
            "machine_domain": _truncate_or_hash(event.get("machine_domain")),
            "external_ip_masked": _mask_ip(event.get("external_ip")),
            "local_ip_masked": _mask_ip(event.get("local_ip")),
            "sensor_id_last8": _last_n(event.get("sensor_id"), 8),
            "behaviors": behaviors_summary,
            "source_tool": "crowdstrike_falcon",
            "source_provenance": provenance,
        }

    # ---- synthetic cross-event evaluation -------------------------------

    def _build_synthetic_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []
        results.extend(
            self._cross_host_attack_synthetics(events, file_sha256=file_sha256)
        )
        results.extend(
            self._repeated_fp_synthetics(events, file_sha256=file_sha256)
        )
        results.extend(
            self._recurring_tp_synthetics(events, file_sha256=file_sha256)
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
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Bucket detections by (detection_id-or-scenario, 7d-window) and emit
        a DE-01 FAIL synthetic when distinct hostnames > threshold."""
        buckets: dict[tuple[str, datetime], set[str]] = defaultdict(set)
        for ev in events:
            key_id = (
                str(ev.get("detection_id") or "").strip()
                or self._scenario_key(ev)
            )
            if not key_id:
                continue
            host = str(ev.get("hostname") or "").strip()
            if not host:
                continue
            week_start = self._week_bucket(ev.get("event_time"))
            buckets[(key_id, week_start)].add(host)

        out: list[EvaluationResult] = []
        for (key_id, week_start), hosts in buckets.items():
            if len(hosts) <= self.cross_host_threshold:
                continue
            out.append(
                self._make_synthetic_result(
                    signal="cross_host_attack_synthetic",
                    detail=(
                        f"CrowdStrike detection key '{key_id[:16]}' observed across "
                        f"{len(hosts)} distinct hosts in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.cross_host_threshold}) — worm/spread pattern"
                    ),
                    evidence_extra={
                        "detection_key_sha256": hashlib.sha256(
                            key_id.encode("utf-8")
                        ).hexdigest(),
                        "distinct_host_count": len(hosts),
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "cross_host_threshold": self.cross_host_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"crowdstrike-synthetic-spread-{key_id[:16]}",
                )
            )
        return out

    def _scenario_key(self, event: dict[str, Any]) -> str:
        behaviors = event.get("behaviors")
        if isinstance(behaviors, list):
            for b in behaviors:
                if isinstance(b, dict) and b.get("scenario"):
                    return hashlib.sha256(
                        str(b["scenario"]).encode("utf-8")
                    ).hexdigest()[:32]
        return ""

    def _behavior_name_buckets(
        self,
        events: list[dict[str, Any]],
        *,
        status_filter: str,
    ) -> dict[tuple[str, datetime], int]:
        buckets: dict[tuple[str, datetime], int] = defaultdict(int)
        for ev in events:
            if _normalize_status(ev.get("status")) != status_filter:
                continue
            week_start = self._week_bucket(ev.get("event_time"))
            behaviors = ev.get("behaviors")
            seen_names: set[str] = set()
            if isinstance(behaviors, list):
                for b in behaviors:
                    if not isinstance(b, dict):
                        continue
                    name = b.get("name")
                    if not name:
                        continue
                    key = str(name)
                    if key in seen_names:
                        continue
                    seen_names.add(key)
                    buckets[(key, week_start)] += 1
        return buckets

    def _repeated_fp_synthetics(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        buckets = self._behavior_name_buckets(events, status_filter="false_positive")
        out: list[EvaluationResult] = []
        for (behavior_name, week_start), count in buckets.items():
            if count <= self.repeated_fp_threshold:
                continue
            name_redacted = _redact_with_hash(behavior_name)
            out.append(
                self._make_synthetic_result(
                    signal="repeated_fp_synthetic",
                    detail=(
                        f"CrowdStrike behavior '{behavior_name[:_BEHAVIOR_NAME_MAX_CHARS]}' "
                        f"produced {count} false_positive detections in 7-day window "
                        f"starting {week_start.isoformat()} (> threshold "
                        f"{self.repeated_fp_threshold}) — rule needs tuning"
                    ),
                    evidence_extra={
                        "behavior_name_redacted": name_redacted,
                        "false_positive_count": count,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "repeated_fp_threshold": self.repeated_fp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"crowdstrike-synthetic-fp-{behavior_name[:16]}",
                )
            )
        return out

    def _recurring_tp_synthetics(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        buckets = self._behavior_name_buckets(events, status_filter="true_positive")
        out: list[EvaluationResult] = []
        for (behavior_name, week_start), count in buckets.items():
            if count <= self.recurring_tp_threshold:
                continue
            name_redacted = _redact_with_hash(behavior_name)
            out.append(
                self._make_synthetic_result(
                    signal="recurring_tp_synthetic",
                    detail=(
                        f"CrowdStrike behavior '{behavior_name[:_BEHAVIOR_NAME_MAX_CHARS]}' "
                        f"produced {count} true_positive detections in 7-day window "
                        f"starting {week_start.isoformat()} (> threshold "
                        f"{self.recurring_tp_threshold}) — recurring real attack"
                    ),
                    evidence_extra={
                        "behavior_name_redacted": name_redacted,
                        "true_positive_count": count,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "recurring_tp_threshold": self.recurring_tp_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"crowdstrike-synthetic-tp-{behavior_name[:16]}",
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
                "source_tool": "crowdstrike_falcon",
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
            source_type="crowdstrike_import",
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
            detail="Empty CrowdStrike Falcon export (no events)",
            evidence_data={"source_provenance": provenance, "event_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"crowdstrike-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="crowdstrike_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty CrowdStrike Falcon export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
