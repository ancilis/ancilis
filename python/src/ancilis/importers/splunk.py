"""Splunk notable-event importer — converts Splunk notable / search-job results to AKSI EvaluationResults.

Splunk (https://www.splunk.com) is the reference SIEM/SOC platform for regulated
enterprises. Splunk's ``/services/search/jobs/{sid}/results`` endpoint and
Enterprise Security ``Notable Events`` framework expose security incidents,
audit-log relays, and (increasingly) the actions taken by Splunk AI Assistant
for SecOps. This importer parses that JSON / JSONL output and converts each
notable event into an ``EvaluationResult``.

Mapping (see ``shared/mappings/splunk-aksi-controls.json``):

  - severity=critical + status in {new, in_progress}                 → DE-01 FAIL  (open critical incident)
  - severity=critical + status=resolved + disposition=true_positive  → PR-05 FAIL  (confirmed real — audit-trail closure)
  - severity=critical + status=resolved + disposition=false_positive → PR-05 PASS
  - severity=high    + status in {new, in_progress}                  → DE-01 FAIL
  - severity=medium  + status in {new, in_progress}                  → PR-05 FLAG
  - severity=low or informational                                    → PR-05 PASS  (audit trail)
  - category=AI/ML severity in {high, critical}                      → DE-01 FAIL with ai_agent_id captured
  - disposition=security_test                                        → PR-05 PASS  (test data)
  - ai_runbook_executed=true + user_decision=null                    → PR-02 FLAG  (autonomous SOC action)
  - ai_runbook_executed=true + user_decision=approved                → PR-05 PASS
  - ai_runbook_executed=true + user_decision=rejected                → PR-02 FAIL  (auto-action user rejected)
  - ai_action_taken in {isolate_host, block_user, quarantine,
    disable_account} + user_decision=null                            → PR-02 FAIL  (high-impact autonomy)
  - ai_confidence_score < threshold (default 0.7) AND
    ai_runbook_executed=true                                         → PR-03 FLAG  (low-confidence autonomy)
  - rule_action contains "quarantine" + user_decision=null           → PR-02 FAIL
  - _count_distinct_users > broad_impact threshold (default 50)      → PR-04 FLAG
  - sourcetype WinEventLog:Security / linux_audit                    → captured (OS audit relayed)

Synthetic cross-event signals:

  - same ai_agent_id with > N notables in 24h (default 100)          → PR-04 FLAG synthetic
  - same rule_name with > N false_positive dispositions in 7d
    (default 20)                                                     → PR-03 FLAG synthetic (rule needs tuning)

Sanitization:

* ``_raw`` text is NEVER stored — only ``_raw_length`` is preserved.
* ``source`` path is reduced to ``parent_dir/basename`` (full path dropped).
* ``search_id`` is truncated to its last 8 characters.
* ``host`` — first 30 chars + sha256 (host names can leak topology).
* ``user`` — verbatim if it matches a service-account pattern (``*-svc``,
  ``svc-*``, ``*_service``); otherwise first 30 chars + sha256.
* ``src_ip`` / ``dest_ip`` — masked to /16 (e.g. ``10.0.0.0/16``).

The SDK is importable without ``splunk-sdk`` installed; this importer parses
the JSON schema directly.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
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

_MAPPING_FILENAME = "splunk-aksi-controls.json"


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
    "critical_resolved_true_positive": "PR-05",
    "critical_false_positive": "PR-05",
    "high_open": "DE-01",
    "medium_open": "PR-05",
    "low_severity": "PR-05",
    "informational": "PR-05",
    "ai_ml_high_severity": "DE-01",
    "autonomous_runbook_no_review": "PR-02",
    "runbook_user_approved": "PR-05",
    "runbook_user_rejected": "PR-02",
    "high_impact_action_no_decision": "PR-02",
    "low_confidence_autonomous": "PR-03",
    "quarantine_no_decision": "PR-02",
    "broad_impact_user_count": "PR-04",
    "high_volume_ai_synthetic": "PR-04",
    "repeated_false_positive_synthetic": "PR-03",
    "security_test_disposition": "PR-05",
}

_DEFAULT_SIGNAL_RESULT: dict[str, str] = {
    "critical_open": "FAIL",
    "critical_resolved_true_positive": "FAIL",
    "critical_false_positive": "PASS",
    "high_open": "FAIL",
    "medium_open": "FLAG",
    "low_severity": "PASS",
    "informational": "PASS",
    "ai_ml_high_severity": "FAIL",
    "autonomous_runbook_no_review": "FLAG",
    "runbook_user_approved": "PASS",
    "runbook_user_rejected": "FAIL",
    "high_impact_action_no_decision": "FAIL",
    "low_confidence_autonomous": "FLAG",
    "quarantine_no_decision": "FAIL",
    "broad_impact_user_count": "FLAG",
    "high_volume_ai_synthetic": "FLAG",
    "repeated_false_positive_synthetic": "FLAG",
    "security_test_disposition": "PASS",
}

_DEFAULT_AI_CONFIDENCE_THRESHOLD = 0.7
_DEFAULT_BROAD_IMPACT_USER_COUNT = 50
_DEFAULT_AI_VOLUME_PER_DAY = 100
_DEFAULT_FALSE_POSITIVE_PATTERN_THRESHOLD = 20
_DEFAULT_HIGH_IMPACT_ACTIONS: list[str] = [
    "isolate_host",
    "block_user",
    "quarantine",
    "disable_account",
]
_DEFAULT_AUDIT_RELAYED_SOURCETYPES: list[str] = [
    "WinEventLog:Security",
    "linux_audit",
]

_OPEN_STATUSES = {"new", "in_progress", "unassigned", "pending"}

_SERVICE_ACCOUNT_PATTERNS: list[str] = [
    "*-svc",
    "svc-*",
    "*-svc-*",
    "*_service",
    "service_*",
    "*-service",
    "service-*",
    "system",
    "root",
]

_FIELD_PREVIEW_MAX = 30

_RESULT_SEVERITY = {"PASS": 0, "FLAG": 1, "FAIL": 2}


def _max_result(a: str, b: str) -> str:
    return a if _RESULT_SEVERITY.get(a, 0) >= _RESULT_SEVERITY.get(b, 0) else b


def _load_mapping_table() -> tuple[
    dict[str, str],
    dict[str, str],
    float,
    int,
    int,
    int,
    list[str],
    list[str],
]:
    """Return (signal_to_control, signal_result, ai_conf_thr, broad_user_thr,
    ai_vol_per_day, fp_pattern_thr, high_impact_actions, audit_sourcetypes)."""
    signal_to_control: dict[str, str] = dict(_DEFAULT_SIGNAL_TO_CONTROL)
    signal_result: dict[str, str] = dict(_DEFAULT_SIGNAL_RESULT)
    ai_conf_thr = _DEFAULT_AI_CONFIDENCE_THRESHOLD
    broad_user_thr = _DEFAULT_BROAD_IMPACT_USER_COUNT
    ai_vol_per_day = _DEFAULT_AI_VOLUME_PER_DAY
    fp_pattern_thr = _DEFAULT_FALSE_POSITIVE_PATTERN_THRESHOLD
    high_impact_actions = list(_DEFAULT_HIGH_IMPACT_ACTIONS)
    audit_sourcetypes = list(_DEFAULT_AUDIT_RELAYED_SOURCETYPES)

    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return (
            signal_to_control,
            signal_result,
            ai_conf_thr,
            broad_user_thr,
            ai_vol_per_day,
            fp_pattern_thr,
            high_impact_actions,
            audit_sourcetypes,
        )

    if isinstance(data, dict):
        raw = data.get("mappings", {})
        if isinstance(raw, dict):
            for key, value in raw.items():
                signal_to_control[str(key)] = str(value)
        meta = data.get("_metadata", {})
        if isinstance(meta, dict):
            ct = meta.get("default_ai_confidence_threshold")
            if isinstance(ct, (int, float)):
                ai_conf_thr = float(ct)
            bc = meta.get("default_broad_impact_user_count")
            if isinstance(bc, (int, float)):
                broad_user_thr = int(bc)
            av = meta.get("default_ai_volume_per_day")
            if isinstance(av, (int, float)):
                ai_vol_per_day = int(av)
            fp = meta.get("default_false_positive_pattern_threshold")
            if isinstance(fp, (int, float)):
                fp_pattern_thr = int(fp)
            ha = meta.get("high_impact_actions")
            if isinstance(ha, list) and ha:
                high_impact_actions = [str(a).lower() for a in ha]
            ast_ = meta.get("audit_relayed_sourcetypes")
            if isinstance(ast_, list) and ast_:
                audit_sourcetypes = [str(s) for s in ast_]
            results_meta = meta.get("result_levels")
            if isinstance(results_meta, dict):
                for k, v in results_meta.items():
                    signal_result[str(k)] = str(v).upper()

    return (
        signal_to_control,
        signal_result,
        ai_conf_thr,
        broad_user_thr,
        ai_vol_per_day,
        fp_pattern_thr,
        high_impact_actions,
        audit_sourcetypes,
    )


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

def _coerce_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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


def _truncate_with_hash(text: str | None, *, max_chars: int = _FIELD_PREVIEW_MAX) -> dict[str, Any]:
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


def _normalize_source_path(source: Any) -> str | None:
    """Reduce a Splunk ``source`` path to ``parent_dir/basename``.

    Splunk source paths often encode hostname, container ID, or username in the
    intermediate directories. We retain only the immediate parent directory
    and the file basename so evidence preserves enough context to know where
    the log came from without leaking the full path.
    """
    if source is None or source == "":
        return None
    s = str(source).strip()
    if not s:
        return None
    p = Path(s)
    parts = p.parts
    if len(parts) <= 1:
        return p.name or s
    parent = parts[-2]
    basename = parts[-1]
    # Normalize Windows-style drive markers that pollute parent.
    if parent.endswith(":"):
        return basename
    return f"{parent}/{basename}"


def _truncate_search_id(search_id: Any) -> str | None:
    """Keep only the last 8 characters of a search_id."""
    if search_id is None:
        return None
    s = str(search_id)
    if not s:
        return None
    return s[-8:] if len(s) >= 8 else s


def _is_service_account(user: str) -> bool:
    u = user.strip().lower()
    if not u:
        return False
    return any(fnmatch.fnmatch(u, pat) for pat in _SERVICE_ACCOUNT_PATTERNS)


def _redact_user(user: Any) -> dict[str, Any]:
    """Service accounts are stored verbatim; human-shaped usernames are hashed."""
    if user is None or user == "":
        return {"present": False}
    s = str(user)
    if _is_service_account(s):
        return {
            "present": True,
            "kind": "service_account",
            "value": s,
        }
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return {
        "present": True,
        "kind": "user",
        "preview": s[:_FIELD_PREVIEW_MAX],
        "sha256": digest,
        "truncated": len(s) > _FIELD_PREVIEW_MAX,
        "length": len(s),
    }


def _mask_ip(ip: Any) -> str | None:
    """Mask an IP address to its /16 network (or /48 for IPv6)."""
    if ip is None or ip == "":
        return None
    s = str(ip).strip()
    if not s:
        return None
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{addr}/16", strict=False)
        return str(net)
    # IPv6 — preserve /48
    net = ipaddress.ip_network(f"{addr}/48", strict=False)
    return str(net)


def _normalize_severity(severity: Any) -> str:
    """Splunk severities can be string ('critical', 'high', 'medium', 'low',
    'informational') or numeric (1–5 / 0–10). Normalize to string form."""
    if severity is None:
        return "unknown"
    if isinstance(severity, str):
        return severity.strip().lower()
    if isinstance(severity, bool):
        return "unknown"
    if isinstance(severity, (int, float)):
        n = float(severity)
        if n >= 9:
            return "critical"
        if n >= 7:
            return "high"
        if n >= 4:
            return "medium"
        if n >= 1:
            return "low"
        return "informational"
    return "unknown"


def _to_list(value: Any) -> list[str]:
    """Splunk multi-valued fields can arrive as list, str, or comma-separated."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    if isinstance(value, str):
        if "," in value:
            return [p.strip() for p in value.split(",") if p.strip()]
        return [value.strip()] if value.strip() else []
    return [str(value)]


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
    """Parse Splunk ``_time`` (ISO-8601 string or epoch numeric)."""
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

class SplunkImporter:
    """Parse Splunk notable-event / search-job exports and convert each event
    into an ``EvaluationResult``.

    Args:
        agent_id: agent identifier stamped on every emitted EvaluationResult.
        mode: ``audit`` (default) or ``enforce``.
        ai_confidence_threshold: ``ai_confidence_score`` value below which a
            runbook execution emits a PR-03 FLAG (default from mapping
            metadata, falling back to 0.7).
        broad_impact_user_count: ``_count_distinct_users`` floor that triggers
            a PR-04 broad-impact FLAG (default 50).
        ai_volume_per_day: notables-per-ai_agent_id-per-24h floor that
            triggers a PR-04 high-volume synthetic FLAG (default 100).
        false_positive_pattern_threshold: false_positive count per rule_name
            in a 7-day window above which we emit a PR-03 rule-tuning
            synthetic FLAG (default 20).
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        ai_confidence_threshold: float | None = None,
        broad_impact_user_count: int | None = None,
        ai_volume_per_day: int | None = None,
        false_positive_pattern_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        (
            self._signal_to_control,
            self._signal_result,
            ai_conf_thr,
            broad_user_thr,
            ai_vol_per_day,
            fp_pattern_thr,
            self._high_impact_actions,
            self._audit_sourcetypes,
        ) = _load_mapping_table()
        self.ai_confidence_threshold = (
            float(ai_confidence_threshold)
            if ai_confidence_threshold is not None
            else ai_conf_thr
        )
        self.broad_impact_user_count = (
            int(broad_impact_user_count)
            if broad_impact_user_count is not None
            else broad_user_thr
        )
        self.ai_volume_per_day = (
            int(ai_volume_per_day) if ai_volume_per_day is not None else ai_vol_per_day
        )
        self.false_positive_pattern_threshold = (
            int(false_positive_pattern_threshold)
            if false_positive_pattern_threshold is not None
            else fp_pattern_thr
        )

    # -- Public API -------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Splunk export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = list(self._extract_events(text))
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Splunk export content from a string (no file hash recorded)."""
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
            for key in ("events", "results", "data"):
                value = doc.get(key)
                if isinstance(value, list):
                    return [e for e in value if isinstance(e, dict)]
                if isinstance(value, dict):
                    return [value]
            # Bare event-shaped object.
            if any(k in doc for k in ("_time", "search_name", "rule_name", "severity", "host")):
                return [doc]
            return []
        if isinstance(doc, list):
            return [e for e in doc if isinstance(e, dict)]
        return []

    def _source_provenance(self, *, file_sha256: str | None) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "splunk",
            "source_tool_name": "splunk",
            "source_tool_version": "v0",
            "spec_url": "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch",
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

        severity = _normalize_severity(event.get("severity"))
        status = str(event.get("status") or "").strip().lower()
        disposition = str(event.get("disposition") or "").strip().lower() or None
        category = str(event.get("category") or "").strip()
        category_lower = category.lower()
        sourcetype = str(event.get("sourcetype") or "")
        rule_action = [a.lower() for a in _to_list(event.get("rule_action"))]
        ai_runbook_executed = _coerce_bool(event.get("ai_runbook_executed"))
        ai_action_taken = (
            str(event.get("ai_action_taken") or "").strip().lower() or None
        )
        user_decision_raw = event.get("user_decision")
        user_decision = (
            str(user_decision_raw).strip().lower()
            if user_decision_raw not in (None, "")
            else None
        )
        ai_confidence_score = _coerce_float(event.get("ai_confidence_score"))
        count_distinct_users = _coerce_int(event.get("_count_distinct_users"))
        ai_agent_id = event.get("ai_agent_id")
        event_id = str(
            event.get("event_id")
            or event.get("id")
            or event.get("search_id")
            or ""
        )

        control_results: list[ControlResult] = []
        layered_findings: list[dict[str, Any]] = []
        worst = "PASS"

        def _emit(signal: str, *, detail: str, extra: dict[str, Any] | None = None) -> None:
            nonlocal worst
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

        # 1. Severity + status + disposition baseline.
        if severity == "critical":
            if status in _OPEN_STATUSES:
                _emit(
                    "critical_open",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=critical "
                        f"status={status} (open critical incident)"
                    ),
                )
            elif status == "resolved" and disposition == "true_positive":
                _emit(
                    "critical_resolved_true_positive",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=critical "
                        f"status=resolved disposition=true_positive "
                        f"(confirmed real incident — audit-trail closure)"
                    ),
                )
            elif status == "resolved" and disposition == "false_positive":
                _emit(
                    "critical_false_positive",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=critical "
                        f"status=resolved disposition=false_positive"
                    ),
                )
            else:
                # Other resolved/closed statuses without a disposition fall back
                # to the audit-trail PASS so downstream evidence still records
                # the event.
                _emit(
                    "informational",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=critical "
                        f"status={status or 'unknown'} disposition={disposition or 'none'}"
                    ),
                )
        elif severity == "high":
            if status in _OPEN_STATUSES:
                _emit(
                    "high_open",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=high "
                        f"status={status}"
                    ),
                )
            else:
                _emit(
                    "informational",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=high "
                        f"status={status or 'unknown'}"
                    ),
                )
        elif severity == "medium":
            if status in _OPEN_STATUSES:
                _emit(
                    "medium_open",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=medium "
                        f"status={status}"
                    ),
                )
            else:
                _emit(
                    "informational",
                    detail=(
                        f"Splunk notable {event_id or '?'} severity=medium "
                        f"status={status or 'unknown'}"
                    ),
                )
        elif severity == "low":
            _emit(
                "low_severity",
                detail=f"Splunk notable {event_id or '?'} severity=low (audit trail)",
            )
        elif severity == "informational":
            _emit(
                "informational",
                detail=f"Splunk notable {event_id or '?'} severity=informational",
            )
        else:
            _emit(
                "informational",
                detail=(
                    f"Splunk notable {event_id or '?'} severity={severity} "
                    f"(unknown — audit trail)"
                ),
            )

        # 2. AI/ML category at high/critical severity.
        if category_lower == "ai/ml" and severity in ("high", "critical"):
            _emit(
                "ai_ml_high_severity",
                detail=(
                    f"Splunk AI/ML category notable {event_id or '?'} severity={severity} "
                    f"ai_agent_id={ai_agent_id or '-'}"
                ),
                extra={"ai_agent_id": ai_agent_id},
            )

        # 3. security_test disposition (test data — always PASS).
        if disposition == "security_test":
            _emit(
                "security_test_disposition",
                detail=(
                    f"Splunk notable {event_id or '?'} disposition=security_test "
                    f"(test data — audit only)"
                ),
            )

        # 4. AI Assistant runbook governance.
        runbook_high_impact_emitted = False
        if ai_runbook_executed is True:
            if user_decision is None:
                _emit(
                    "autonomous_runbook_no_review",
                    detail=(
                        f"Splunk AI Assistant runbook executed on notable "
                        f"{event_id or '?'} without user_decision — autonomous "
                        f"SOC action requires governance review"
                    ),
                    extra={
                        "ai_action_taken": ai_action_taken,
                        "ai_confidence_score": ai_confidence_score,
                    },
                )
            elif user_decision == "approved":
                _emit(
                    "runbook_user_approved",
                    detail=(
                        f"Splunk AI Assistant runbook on notable {event_id or '?'} "
                        f"approved by user (approved automation)"
                    ),
                )
            elif user_decision == "rejected":
                _emit(
                    "runbook_user_rejected",
                    detail=(
                        f"Splunk AI Assistant runbook on notable {event_id or '?'} "
                        f"rejected by user — auto-action contradicted by human review"
                    ),
                    extra={"ai_action_taken": ai_action_taken},
                )

            # Low-confidence autonomous run.
            if (
                ai_confidence_score is not None
                and ai_confidence_score < self.ai_confidence_threshold
            ):
                _emit(
                    "low_confidence_autonomous",
                    detail=(
                        f"Splunk AI Assistant runbook on notable {event_id or '?'} "
                        f"confidence={ai_confidence_score:.3f} below threshold "
                        f"{self.ai_confidence_threshold:.3f}"
                    ),
                    extra={
                        "ai_confidence_score": ai_confidence_score,
                        "ai_confidence_threshold": self.ai_confidence_threshold,
                    },
                )

        # 5. High-impact action without user decision.
        if (
            ai_action_taken
            and ai_action_taken in self._high_impact_actions
            and user_decision is None
        ):
            _emit(
                "high_impact_action_no_decision",
                detail=(
                    f"Splunk AI Assistant high-impact action='{ai_action_taken}' on "
                    f"notable {event_id or '?'} executed without user_decision"
                ),
                extra={"ai_action_taken": ai_action_taken},
            )
            runbook_high_impact_emitted = True

        # 6. rule_action containing 'quarantine' without user decision.
        if (
            "quarantine" in rule_action
            and user_decision is None
            and not runbook_high_impact_emitted
        ):
            _emit(
                "quarantine_no_decision",
                detail=(
                    f"Splunk notable {event_id or '?'} rule_action contains "
                    f"'quarantine' without user_decision"
                ),
                extra={"rule_action": rule_action},
            )

        # 7. Broad-impact alert (_count_distinct_users).
        if (
            count_distinct_users is not None
            and count_distinct_users > self.broad_impact_user_count
        ):
            _emit(
                "broad_impact_user_count",
                detail=(
                    f"Splunk notable {event_id or '?'} affects "
                    f"{count_distinct_users} distinct users (> threshold "
                    f"{self.broad_impact_user_count})"
                ),
                extra={
                    "_count_distinct_users": count_distinct_users,
                    "broad_impact_user_count_threshold": self.broad_impact_user_count,
                },
            )

        # 8. OS-audit relayed sourcetype (captured, no separate signal control).
        if any(s in sourcetype for s in self._audit_sourcetypes):
            for cr in control_results:
                cr.evidence_data["os_audit_relayed"] = sourcetype

        # Stamp layered_findings on every emitted control result.
        for cr in control_results:
            cr.evidence_data["layered_findings"] = layered_findings

        decision = {
            "FAIL": "BLOCK" if self.mode == "enforce" else "FLAG",
            "FLAG": "FLAG",
            "PASS": "ALLOW",
        }.get(worst, "ALLOW")

        # Timestamp normalization.
        timestamp_iso = self._normalize_timestamp(event.get("_time"))

        action_id_seed = (
            event_id
            or str(event.get("search_id") or "")
            or uuid.uuid4().hex
        )
        action_id = f"splunk-{action_id_seed[:16]}"

        decision_reason_parts = [
            f"Splunk notable {event_id or '?'}",
            f"severity={severity}",
            f"status={status or 'unknown'}",
        ]
        if disposition:
            decision_reason_parts.append(f"disposition={disposition}")
        if category:
            decision_reason_parts.append(f"category={category}")
        if ai_runbook_executed is True:
            decision_reason_parts.append("ai_runbook=executed")
        if ai_action_taken:
            decision_reason_parts.append(f"ai_action={ai_action_taken}")
        if user_decision:
            decision_reason_parts.append(f"user_decision={user_decision}")
        decision_reason = " ".join(decision_reason_parts)

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=action_id,
            timestamp=timestamp_iso,
            agent_id=self.agent_id,
            source_type="splunk_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=str(ai_agent_id) if ai_agent_id else None,
        )

    def _common_evidence(
        self,
        event: dict[str, Any],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        host_redacted = _truncate_with_hash(event.get("host"))
        user_redacted = _redact_user(event.get("user"))
        src_ip_masked = _mask_ip(event.get("src_ip"))
        dest_ip_masked = _mask_ip(event.get("dest_ip"))
        source_normalized = _normalize_source_path(event.get("source"))
        search_id_short = _truncate_search_id(event.get("search_id"))

        raw_length = _coerce_int(event.get("_raw_length"))
        # If the export accidentally included _raw, drop it but record length.
        raw = event.get("_raw")
        if raw_length is None and isinstance(raw, str):
            raw_length = len(raw)

        return {
            "severity": _normalize_severity(event.get("severity")),
            "status": str(event.get("status") or "").strip().lower(),
            "disposition": (str(event.get("disposition") or "").strip().lower() or None),
            "category": event.get("category"),
            "rule_name": event.get("rule_name"),
            "search_name": event.get("search_name"),
            "search_id_short": search_id_short,
            "sourcetype": event.get("sourcetype"),
            "index": event.get("index"),
            "host_redacted": host_redacted,
            "user_redacted": user_redacted,
            "src_ip_masked": src_ip_masked,
            "dest_ip_masked": dest_ip_masked,
            "dest_port": _coerce_int(event.get("dest_port")),
            "ai_agent_id": event.get("ai_agent_id"),
            "ai_confidence_score": _coerce_float(event.get("ai_confidence_score")),
            "ai_runbook_executed": _coerce_bool(event.get("ai_runbook_executed")),
            "ai_action_taken": event.get("ai_action_taken"),
            "user_decision": event.get("user_decision"),
            "rule_action": _to_list(event.get("rule_action")),
            "_count_distinct_users": _coerce_int(event.get("_count_distinct_users")),
            "_count_distinct_src_ips": _coerce_int(event.get("_count_distinct_src_ips")),
            "_raw_length": raw_length,
            "source_normalized": source_normalized,
            "owner": event.get("owner"),
            "indexed_at": event.get("indexed_at"),
            "source_tool": "splunk",
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
        results.extend(self._high_volume_ai_synthetics(events, file_sha256=file_sha256))
        results.extend(
            self._repeated_false_positive_synthetics(events, file_sha256=file_sha256)
        )
        return results

    def _high_volume_ai_synthetics(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Bucket events by (ai_agent_id, 24h-window) and emit a PR-04 FLAG when
        any bucket exceeds the configured threshold."""
        buckets: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)
        for e in events:
            agent_id = e.get("ai_agent_id")
            if not agent_id:
                continue
            ts = _parse_time(e.get("_time"))
            if ts is None:
                ts = datetime.now(timezone.utc)
            # Bucket by UTC calendar day.
            day_start = ts.astimezone(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            buckets[(str(agent_id), day_start)].append(e)

        out: list[EvaluationResult] = []
        for (agent_id, day_start), bucket in buckets.items():
            if len(bucket) <= self.ai_volume_per_day:
                continue
            out.append(
                self._make_synthetic_result(
                    signal="high_volume_ai_synthetic",
                    detail=(
                        f"Splunk AI agent '{agent_id}' produced {len(bucket)} notables "
                        f"in 24h window starting {day_start.isoformat()} "
                        f"(> threshold {self.ai_volume_per_day})"
                    ),
                    evidence_extra={
                        "ai_agent_id": agent_id,
                        "window_start": day_start.isoformat(),
                        "window_end": (day_start + timedelta(days=1)).isoformat(),
                        "notable_count": len(bucket),
                        "ai_volume_per_day_threshold": self.ai_volume_per_day,
                    },
                    file_sha256=file_sha256,
                    action_id=f"splunk-synthetic-aivol-{agent_id[:16]}",
                )
            )
        return out

    def _repeated_false_positive_synthetics(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Bucket false_positive events by (rule_name, 7d-window) and emit a
        PR-03 FLAG when any bucket exceeds the configured threshold."""
        buckets: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)
        for e in events:
            disposition = str(e.get("disposition") or "").strip().lower()
            if disposition != "false_positive":
                continue
            rule_name = e.get("rule_name")
            if not rule_name:
                continue
            ts = _parse_time(e.get("_time"))
            if ts is None:
                ts = datetime.now(timezone.utc)
            ts_utc = ts.astimezone(timezone.utc)
            # Bucket into ISO weekly windows (7-day buckets aligned to epoch
            # day 0 modulo 7) — gives stable grouping across exports.
            day_index = (ts_utc - datetime(1970, 1, 1, tzinfo=timezone.utc)).days
            week_start_day = day_index - (day_index % 7)
            week_start = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                days=week_start_day
            )
            buckets[(str(rule_name), week_start)].append(e)

        out: list[EvaluationResult] = []
        for (rule_name, week_start), bucket in buckets.items():
            if len(bucket) <= self.false_positive_pattern_threshold:
                continue
            out.append(
                self._make_synthetic_result(
                    signal="repeated_false_positive_synthetic",
                    detail=(
                        f"Splunk rule '{rule_name}' produced {len(bucket)} "
                        f"false_positive dispositions in 7-day window starting "
                        f"{week_start.isoformat()} (> threshold "
                        f"{self.false_positive_pattern_threshold}) — rule needs tuning"
                    ),
                    evidence_extra={
                        "rule_name": rule_name,
                        "window_start": week_start.isoformat(),
                        "window_end": (week_start + timedelta(days=7)).isoformat(),
                        "false_positive_count": len(bucket),
                        "false_positive_pattern_threshold": self.false_positive_pattern_threshold,
                    },
                    file_sha256=file_sha256,
                    action_id=f"splunk-synthetic-fp-{rule_name[:16]}",
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
                "source_tool": "splunk",
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
            source_type="splunk_import",
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
            detail="Empty Splunk export (no events)",
            evidence_data={"source_provenance": provenance, "event_count": 0},
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"splunk-empty-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="splunk_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason="Empty Splunk export ingested",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
        )
