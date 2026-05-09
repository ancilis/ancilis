"""Salesforce Event Monitoring importer — maps Agentforce/Einstein CRM activity to AKSI controls.

Salesforce (https://salesforce.com) is the dominant enterprise CRM. Salesforce
Agentforce, Service Cloud Einstein, and custom AI agents all read and mutate
customer records (Contact, Account, Lead, Opportunity, Case). The Event
Monitoring API exports ``EventLogFile`` records (one CSV per event type per
hour) and ``RealTimeEventMonitoring`` objects — together the system-of-record
for who-did-what across the entire Salesforce org.

This importer ingests Salesforce Event Monitoring exports in three on-disk
shapes:

  1. ``{"events": [...]}`` — primary event-export envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one event per line

Signal mapping (see shared/mappings/salesforce-aksi-controls.json):
  * EVENT_TYPE=Login + BLOCKED_REASON=null              → PR-01 PASS
  * EVENT_TYPE=Login + BLOCKED_REASON set                → PR-01 FLAG
  * EVENT_TYPE=LoginAs (admin impersonating user)        → PR-01 FAIL
  * EVENT_TYPE=ApiTotalUsage IS_AGENTFORCE=true
    ROWS_RETURNED > threshold (default 1000)             → PR-04 FLAG
  * EVENT_TYPE=DataExport                                → PR-04 FLAG
    (escalate to PR-04 FAIL when FILE_SIZE_BYTES >
    threshold — default 100MB)
  * EVENT_TYPE=ReportExport IS_AGENTFORCE=true           → PR-04 FLAG
  * EVENT_TYPE=FileDownload IS_AGENTFORCE=true on a
    sensitive OBJECT_TYPE                                → PR-04 FLAG
  * EVENT_TYPE=BulkApiV2Request ROWS_PROCESSED >
    threshold (default 10000)                            → PR-04 FLAG
  * EVENT_TYPE=BulkApiV2Request REQUEST_METHOD=DELETE    → PR-02 FAIL
    (irreversible mass-delete)
  * EVENT_TYPE=WaveDownload (CRM Analytics export)       → PR-04 FLAG
  * EVENT_TYPE=InsecureExternalAssets                    → PR-04 FLAG
  * EVENT_TYPE=ApexUnexpectedException                   → DE-01 FAIL
  * EVENT_TYPE=ApexExecution RUN_TIME > threshold        → PR-02 FLAG
  * EVENT_TYPE=EinsteinPrediction PREDICTION_CONFIDENCE
    < threshold (default 0.5)                            → PR-03 FLAG
  * USER_TYPE=PlatformIntegrationUser AND OBJECT_TYPE in
    sensitive set                                        → PR-02 FLAG
  * TLS_VERSION in {TLSv1.0, TLSv1.1}                    → PR-04 FAIL
  * BLOCKED_REASON=Field-level security on Agentforce    → PR-02 PASS
    (audit trail of governance functioning)
  * API_RESPONSE_TIME_MS > threshold (default 60000)     → PR-03 FLAG
  * cross-object pattern: same USER_ID Agentforce
    touching > N OBJECT_TYPEs                            → PR-04 FLAG synthetic
  * high-volume agent: same AGENT_NAME making > N API
    calls                                                → PR-04 FLAG synthetic

Sanitization (security-critical — Salesforce events can contain customer PII
in URIs, full usernames, source IPs, SOQL row IDs, and session keys):
  * ``USERNAME`` is reduced to the email domain only (``svc@acme.com`` → ``acme.com``).
  * ``CLIENT_IP`` IPv4 is reduced to a ``/16`` pattern; RFC1918 / loopback
    are preserved verbatim; IPv6 reduced to a ``/32`` pattern.
  * ``URI`` is path-normalized: query strings are dropped, and any path
    segment longer than 18 chars (the SOQL row-ID surface) is truncated
    to its last 8 chars with an ``id:`` prefix.
  * ``URI_ID_DERIVED`` is reduced to last-8 only (these are record IDs
    that imply a specific data lookup).
  * ``SESSION_KEY`` is reduced to last-8 only.
  * ``QUERY_LENGTH`` is captured as length only (Salesforce already
    exports the length; the SOQL text itself is never present).
  * ``USER_ID`` (and the other Salesforce 15/18-char IDs) is captured
    verbatim — Salesforce IDs are pseudonymous and have no value outside
    the org.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``simple-salesforce``; Salesforce Event Monitoring
exports are parsed with the standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/salesforce.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "salesforce-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_SENSITIVE_OBJECTS: frozenset[str] = frozenset(
    {"Contact", "Account", "Lead", "Opportunity", "Case"}
)
_DEFAULT_LEGACY_TLS: frozenset[str] = frozenset({"TLSv1.0", "TLSv1.1"})

_DEFAULT_ROWS_RETURNED_THRESHOLD = 1000
_DEFAULT_ROWS_PROCESSED_THRESHOLD = 10000
_DEFAULT_FILE_SIZE_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100 MB
_DEFAULT_APEX_RUN_TIME_THRESHOLD_MS = 30000
_DEFAULT_API_RESPONSE_TIME_THRESHOLD_MS = 60000
_DEFAULT_CROSS_OBJECT_THRESHOLD = 8
_DEFAULT_HIGH_VOLUME_AGENT_THRESHOLD = 5000
_DEFAULT_EINSTEIN_CONFIDENCE_THRESHOLD = 0.5


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the salesforce-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
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


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _username_domain(username: str | None) -> str | None:
    """Reduce a Salesforce USERNAME to the domain only.

    Salesforce usernames are email-like (``agent-svc@example.com``). We retain
    only the domain so an analyst can correlate by org/tenant without storing
    the full identifier.
    """
    if not isinstance(username, str):
        return None
    u = username.strip()
    if not u or "@" not in u:
        return None
    return u.split("@", 1)[1].lower() or None


def _classify_source_ip(source_ip: str | None) -> str | None:
    """Normalize CLIENT_IP to a privacy-aware form.

    * RFC1918 / loopback / link-local preserved verbatim.
    * Public IPv4 reduced to ``A.B.0.0/16``.
    * Public IPv6 reduced to first 32 bits + ``::/32``.
    * Hostnames preserved verbatim.
    """
    if not isinstance(source_ip, str):
        return None
    ip = source_ip.strip()
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return ip
        octets = ip.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.0.0/16"
        return ip
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _normalize_uri(uri: str | None) -> str | None:
    """Path-normalize a Salesforce URI.

    * Drop the query string entirely (it can carry SOQL fragments + IDs).
    * For each path segment that looks like a Salesforce row ID
      (15 or 18 chars, alphanumeric), replace with ``id:<last-8>``.
      Salesforce IDs are not secrets, but they imply a specific record
      lookup; storing only the last 8 lets analysts correlate without
      exposing which records were touched.
    """
    if not isinstance(uri, str):
        return None
    raw = uri.strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    path = parts.path or raw
    segments = path.split("/")
    normalized: list[str] = []
    for seg in segments:
        # Salesforce 15- or 18-char alphanumeric row IDs are the SOQL row-ID
        # surface. Anything longer than 18 chars is also collapsed.
        if (len(seg) in (15, 18) and seg.isalnum()) or len(seg) > 18:
            normalized.append(f"id:{seg[-8:]}")
        else:
            normalized.append(seg)
    return "/".join(normalized)


def _last_8(value: Any) -> str | None:
    """Return last-8 chars of a string-like identifier, or None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    if len(v) <= 8:
        return v
    return v[-8:]


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SalesforceImporter:
    """Parse a Salesforce Event Monitoring export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        rows_returned_threshold: int | None = None,
        rows_processed_threshold: int | None = None,
        file_size_bytes_threshold: int | None = None,
        apex_run_time_threshold_ms: int | None = None,
        api_response_time_threshold_ms: int | None = None,
        cross_object_threshold: int | None = None,
        high_volume_agent_threshold: int | None = None,
        einstein_confidence_threshold: float | None = None,
        sensitive_object_types: Iterable[str] | None = None,
        legacy_tls_versions: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        thresholds = meta.get("threshold_metadata", {}) if isinstance(meta, dict) else {}
        if not isinstance(thresholds, dict):
            thresholds = {}

        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Threshold precedence: explicit arg > mapping metadata > default.
        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            value = thresholds.get(key)
            if isinstance(value, (int, float)):
                return int(value)
            return default

        def _resolve_float(arg: float | None, key: str, default: float) -> float:
            if arg is not None:
                return float(arg)
            value = meta.get(key) if isinstance(meta, dict) else None
            if isinstance(value, (int, float)):
                return float(value)
            return default

        self.rows_returned_threshold = _resolve_int(
            rows_returned_threshold,
            "rows_returned_threshold",
            _DEFAULT_ROWS_RETURNED_THRESHOLD,
        )
        self.rows_processed_threshold = _resolve_int(
            rows_processed_threshold,
            "rows_processed_threshold",
            _DEFAULT_ROWS_PROCESSED_THRESHOLD,
        )
        self.file_size_bytes_threshold = _resolve_int(
            file_size_bytes_threshold,
            "file_size_bytes_threshold",
            _DEFAULT_FILE_SIZE_BYTES_THRESHOLD,
        )
        self.apex_run_time_threshold_ms = _resolve_int(
            apex_run_time_threshold_ms,
            "apex_run_time_threshold_ms",
            _DEFAULT_APEX_RUN_TIME_THRESHOLD_MS,
        )
        self.api_response_time_threshold_ms = _resolve_int(
            api_response_time_threshold_ms,
            "api_response_time_threshold_ms",
            _DEFAULT_API_RESPONSE_TIME_THRESHOLD_MS,
        )
        self.cross_object_threshold = _resolve_int(
            cross_object_threshold,
            "cross_object_threshold",
            _DEFAULT_CROSS_OBJECT_THRESHOLD,
        )
        self.high_volume_agent_threshold = _resolve_int(
            high_volume_agent_threshold,
            "high_volume_agent_threshold",
            _DEFAULT_HIGH_VOLUME_AGENT_THRESHOLD,
        )
        self.einstein_confidence_threshold = _resolve_float(
            einstein_confidence_threshold,
            "einstein_confidence_threshold",
            _DEFAULT_EINSTEIN_CONFIDENCE_THRESHOLD,
        )

        if sensitive_object_types is not None:
            self.sensitive_object_types = frozenset(
                str(o) for o in sensitive_object_types
            )
        else:
            meta_sens = meta.get("sensitive_object_types")
            if isinstance(meta_sens, list) and meta_sens:
                self.sensitive_object_types = frozenset(str(o) for o in meta_sens)
            else:
                self.sensitive_object_types = _DEFAULT_SENSITIVE_OBJECTS

        if legacy_tls_versions is not None:
            self.legacy_tls_versions = frozenset(str(t) for t in legacy_tls_versions)
        else:
            meta_tls = meta.get("legacy_tls_versions")
            if isinstance(meta_tls, list) and meta_tls:
                self.legacy_tls_versions = frozenset(str(t) for t in meta_tls)
            else:
                self.legacy_tls_versions = _DEFAULT_LEGACY_TLS

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Salesforce Event Monitoring export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Salesforce Event Monitoring content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events": [...]}`` / ``{"data": [...]}`` / JSONL / single event."""
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
                if "events" in doc and isinstance(doc["events"], list):
                    return [e for e in doc["events"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass: aggregate object_types per Agentforce user, and api-call counts per agent.
        user_objects: dict[str, set[str]] = defaultdict(set)
        agent_call_counts: dict[str, int] = defaultdict(int)
        for ev in events:
            user_id = ev.get("USER_ID")
            object_type = ev.get("OBJECT_TYPE")
            is_agentforce = bool(ev.get("IS_AGENTFORCE"))
            if (
                isinstance(user_id, str)
                and user_id
                and isinstance(object_type, str)
                and object_type
                and is_agentforce
            ):
                user_objects[user_id].add(object_type)
            agent_name = ev.get("AGENT_NAME")
            event_type = str(ev.get("EVENT_TYPE") or "")
            if (
                isinstance(agent_name, str)
                and agent_name
                and event_type in {"ApiTotalUsage", "BulkApiV2Request"}
            ):
                agent_call_counts[agent_name] += 1

        cross_object_users = {
            uid: sorted(objs)
            for uid, objs in user_objects.items()
            if len(objs) > self.cross_object_threshold
        }
        high_volume_agents = {
            agent: count
            for agent, count in agent_call_counts.items()
            if count > self.high_volume_agent_threshold
        }

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_object_users=cross_object_users,
            )
            for ev in events
        ]

        # Synthetic per-user cross-object findings.
        for uid, objs in sorted(cross_object_users.items()):
            results.append(
                self._synthetic_cross_object_result(
                    user_id=uid,
                    object_types=objs,
                    file_sha256=file_sha256,
                )
            )
        # Synthetic per-agent high-volume findings.
        for agent, count in sorted(high_volume_agents.items()):
            results.append(
                self._synthetic_high_volume_agent_result(
                    agent_name=agent,
                    api_call_count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "salesforce_event_monitoring",
            "source_tool_name": "salesforce_event_monitoring",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_object_users: dict[str, list[str]],
    ) -> EvaluationResult:
        event_id = str(event.get("event_id") or uuid.uuid4())
        event_type = str(event.get("EVENT_TYPE") or "Unknown")
        timestamp = str(
            event.get("TIMESTAMP_DERIVED")
            or event.get("EVENT_DATE")
            or datetime.now(timezone.utc).isoformat()
        )

        # -- Identity / actor ----------------------------------------------
        user_id_raw = event.get("USER_ID")
        user_id = str(user_id_raw) if isinstance(user_id_raw, str) else None
        username_domain = _username_domain(event.get("USERNAME"))
        user_type = (
            str(event.get("USER_TYPE")) if isinstance(event.get("USER_TYPE"), str) else None
        )
        client_ip = _classify_source_ip(event.get("CLIENT_IP"))
        organization_id = (
            str(event.get("ORGANIZATION_ID"))
            if isinstance(event.get("ORGANIZATION_ID"), str)
            else None
        )

        # -- Request shape -------------------------------------------------
        uri_normalized = _normalize_uri(event.get("URI"))
        uri_id_last8 = _last_8(event.get("URI_ID_DERIVED"))
        session_key_last8 = _last_8(event.get("SESSION_KEY"))
        request_method = (
            str(event.get("REQUEST_METHOD")).upper()
            if isinstance(event.get("REQUEST_METHOD"), str)
            else None
        )
        api_type = (
            str(event.get("API_TYPE"))
            if isinstance(event.get("API_TYPE"), str)
            else None
        )
        object_type = (
            str(event.get("OBJECT_TYPE"))
            if isinstance(event.get("OBJECT_TYPE"), str)
            else None
        )

        # -- Volume / size -------------------------------------------------
        try:
            rows_returned = int(event.get("ROWS_RETURNED") or 0)
        except (TypeError, ValueError):
            rows_returned = 0
        try:
            rows_processed = int(event.get("ROWS_PROCESSED") or 0)
        except (TypeError, ValueError):
            rows_processed = 0
        try:
            file_size_bytes = int(event.get("FILE_SIZE_BYTES") or 0)
        except (TypeError, ValueError):
            file_size_bytes = 0
        try:
            run_time = int(event.get("RUN_TIME") or 0)
        except (TypeError, ValueError):
            run_time = 0
        try:
            api_response_time_ms = int(event.get("API_RESPONSE_TIME_MS") or 0)
        except (TypeError, ValueError):
            api_response_time_ms = 0
        try:
            query_length = int(event.get("QUERY_LENGTH") or 0)
        except (TypeError, ValueError):
            query_length = 0

        file_type = (
            str(event.get("FILE_TYPE"))
            if isinstance(event.get("FILE_TYPE"), str)
            else None
        )

        # -- Agentforce ----------------------------------------------------
        is_agentforce = bool(event.get("IS_AGENTFORCE"))
        agent_name = (
            str(event.get("AGENT_NAME"))
            if isinstance(event.get("AGENT_NAME"), str)
            else None
        )

        # -- Outcome / governance -----------------------------------------
        blocked_reason_raw = event.get("BLOCKED_REASON")
        blocked_reason = (
            str(blocked_reason_raw).strip()
            if isinstance(blocked_reason_raw, str) and blocked_reason_raw.strip()
            else None
        )
        tls_version = (
            str(event.get("TLS_VERSION"))
            if isinstance(event.get("TLS_VERSION"), str)
            else None
        )

        # -- Apex / Einstein ----------------------------------------------
        exception_type = (
            str(event.get("EXCEPTION_TYPE"))
            if isinstance(event.get("EXCEPTION_TYPE"), str)
            else None
        )
        einstein_model_id = (
            str(event.get("EINSTEIN_MODEL_ID"))
            if isinstance(event.get("EINSTEIN_MODEL_ID"), str)
            else None
        )
        prediction_confidence_raw = event.get("PREDICTION_CONFIDENCE")
        try:
            prediction_confidence: float | None = (
                float(prediction_confidence_raw)
                if prediction_confidence_raw is not None
                else None
            )
        except (TypeError, ValueError):
            prediction_confidence = None

        # -- Misc ----------------------------------------------------------
        report_id = (
            str(event.get("REPORT_ID_DERIVED"))
            if isinstance(event.get("REPORT_ID_DERIVED"), str)
            else None
        )
        dashboard_id = (
            str(event.get("DASHBOARD_ID_DERIVED"))
            if isinstance(event.get("DASHBOARD_ID_DERIVED"), str)
            else None
        )
        api_version = (
            str(event.get("EVENT_LOG_FILE_API_VERSION"))
            if isinstance(event.get("EVENT_LOG_FILE_API_VERSION"), str)
            else None
        )

        common_evidence: dict[str, Any] = {
            "salesforce_event_id": event_id,
            "event_type": event_type,
            "event_time": timestamp,
            "user_id": user_id,
            "username_domain": username_domain,
            "user_type": user_type,
            "client_ip_redacted": client_ip,
            "organization_id": organization_id,
            "uri_normalized": uri_normalized,
            "uri_id_last8": uri_id_last8,
            "session_key_last8": session_key_last8,
            "request_method": request_method,
            "api_type": api_type,
            "api_version": api_version,
            "object_type": object_type,
            "rows_returned": rows_returned,
            "rows_processed": rows_processed,
            "file_type": file_type,
            "file_size_bytes": file_size_bytes,
            "run_time_ms": run_time,
            "api_response_time_ms": api_response_time_ms,
            "query_length": query_length,
            "is_agentforce": is_agentforce,
            "agent_name": agent_name,
            "blocked_reason": blocked_reason,
            "tls_version": tls_version,
            "exception_type": exception_type,
            "einstein_model_id": einstein_model_id,
            "prediction_confidence": prediction_confidence,
            "report_id_derived": report_id,
            "dashboard_id_derived": dashboard_id,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "salesforce_event_monitoring",
        }

        control_results: list[ControlResult] = []
        primary_emitted = False

        # ------------------------------------------------------------------
        # 1. Login / LoginAs
        # ------------------------------------------------------------------
        if event_type == "Login":
            if blocked_reason is None:
                signal = "login_pass"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Salesforce event {event_id} Login by user {user_id} "
                            f"succeeded (no BLOCKED_REASON)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "login_blocked"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} Login by user {user_id} "
                            f"blocked (reason={blocked_reason!r})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            primary_emitted = True
        elif event_type == "LoginAs":
            signal = "login_as_admin_impersonation"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Salesforce event {event_id} LoginAs by admin {user_id} — "
                        f"admin impersonating another user (high-priority audit)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 2. ApiTotalUsage — large Agentforce query
        # ------------------------------------------------------------------
        elif event_type == "ApiTotalUsage":
            if is_agentforce and rows_returned > self.rows_returned_threshold:
                signal = "agentforce_large_query"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} Agentforce ApiTotalUsage "
                            f"returned {rows_returned} rows (> threshold "
                            f"{self.rows_returned_threshold})"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "rows_returned_threshold": self.rows_returned_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 3. DataExport — always FLAG, escalate to FAIL when large.
        # ------------------------------------------------------------------
        elif event_type == "DataExport":
            if file_size_bytes > self.file_size_bytes_threshold:
                signal = "data_export_large"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Salesforce event {event_id} DataExport "
                            f"file_size_bytes={file_size_bytes} exceeds threshold "
                            f"{self.file_size_bytes_threshold} (large bulk exfil surface)"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "file_size_bytes_threshold": self.file_size_bytes_threshold,
                        },
                    )
                )
            else:
                signal = "data_export"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} DataExport "
                            f"file_size_bytes={file_size_bytes} (exfil surface)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 4. ReportExport by Agentforce
        # ------------------------------------------------------------------
        elif event_type == "ReportExport":
            if is_agentforce:
                signal = "report_export_agentforce"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} Agentforce ReportExport "
                            f"(report_id={report_id!r})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 5. FileDownload by Agentforce on a sensitive object
        # ------------------------------------------------------------------
        elif event_type == "FileDownload":
            if (
                is_agentforce
                and object_type is not None
                and object_type in self.sensitive_object_types
            ):
                signal = "file_download_agentforce_sensitive"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} Agentforce FileDownload "
                            f"on sensitive object_type={object_type!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 6. BulkApiV2Request — bulk modification or bulk delete.
        # ------------------------------------------------------------------
        elif event_type == "BulkApiV2Request":
            if request_method == "DELETE":
                signal = "bulk_delete"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Salesforce event {event_id} BulkApiV2Request DELETE "
                            f"(rows_processed={rows_processed}) — irreversible mass "
                            f"action on object_type={object_type!r}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True
            elif rows_processed > self.rows_processed_threshold:
                signal = "bulk_modification"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} BulkApiV2Request "
                            f"{request_method or 'UNKNOWN'} processed "
                            f"{rows_processed} rows (> threshold "
                            f"{self.rows_processed_threshold})"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "rows_processed_threshold": self.rows_processed_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 7. WaveDownload — CRM Analytics export.
        # ------------------------------------------------------------------
        elif event_type == "WaveDownload":
            signal = "wave_download"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Salesforce event {event_id} WaveDownload — CRM Analytics "
                        f"export is a bulk data exfiltration surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 8. InsecureExternalAssets
        # ------------------------------------------------------------------
        elif event_type == "InsecureExternalAssets":
            signal = "insecure_external_assets"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Salesforce event {event_id} InsecureExternalAssets — "
                        f"org has insecure external content configuration"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 9. ApexUnexpectedException
        # ------------------------------------------------------------------
        elif event_type == "ApexUnexpectedException":
            signal = "apex_unexpected_exception"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Salesforce event {event_id} ApexUnexpectedException "
                        f"exception_type={exception_type!r} — uncaught Apex error "
                        f"in production"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 10. ApexExecution — long-running.
        # ------------------------------------------------------------------
        elif event_type == "ApexExecution":
            if run_time > self.apex_run_time_threshold_ms:
                signal = "long_running_apex"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} ApexExecution run_time={run_time}ms "
                            f"exceeds threshold {self.apex_run_time_threshold_ms}ms"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "apex_run_time_threshold_ms": self.apex_run_time_threshold_ms,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 11. EinsteinPrediction — low confidence acted upon.
        # ------------------------------------------------------------------
        elif event_type == "EinsteinPrediction":
            if (
                prediction_confidence is not None
                and prediction_confidence < self.einstein_confidence_threshold
            ):
                signal = "low_confidence_einstein"
                control_id = _control_for(signal, self._mappings, "PR-03")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Salesforce event {event_id} EinsteinPrediction "
                            f"model={einstein_model_id!r} confidence={prediction_confidence} "
                            f"below threshold {self.einstein_confidence_threshold} "
                            f"— low-confidence AI output may be acted upon"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "einstein_confidence_threshold": self.einstein_confidence_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: BLOCKED_REASON=Field-level security on Agentforce.
        # Audit trail of governance functioning. Emitted in addition to any
        # primary signal, but if no primary fired we mark this as primary so
        # the event is not orphaned.
        # ------------------------------------------------------------------
        if (
            blocked_reason == "Field-level security"
            and is_agentforce
        ):
            signal = "blocked_by_fls_governance"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Salesforce event {event_id} Agentforce access correctly "
                        f"blocked by Field-level security — audit trail of governance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: Integration user touching customer records.
        # ------------------------------------------------------------------
        if (
            user_type == "PlatformIntegrationUser"
            and object_type is not None
            and object_type in self.sensitive_object_types
        ):
            signal = "integration_user_customer_data"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Salesforce event {event_id} PlatformIntegrationUser {user_id} "
                        f"touched sensitive object_type={object_type!r} — verify scope"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: Legacy TLS — independent of event type.
        # ------------------------------------------------------------------
        if tls_version is not None and tls_version in self.legacy_tls_versions:
            signal = "legacy_tls"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Salesforce event {event_id} {event_type} negotiated "
                        f"legacy {tls_version} — fails modern crypto controls"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: API_RESPONSE_TIME_MS over threshold.
        # ------------------------------------------------------------------
        if api_response_time_ms > self.api_response_time_threshold_ms:
            signal = "api_response_time_slow"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Salesforce event {event_id} {event_type} api_response_time_ms="
                        f"{api_response_time_ms} exceeds threshold "
                        f"{self.api_response_time_threshold_ms}ms (timeout window)"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "api_response_time_threshold_ms": self.api_response_time_threshold_ms,
                    },
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: per-event cross-object pattern marker (for traceability).
        # ------------------------------------------------------------------
        if (
            is_agentforce
            and isinstance(user_id, str)
            and user_id in cross_object_users
        ):
            signal = "cross_object_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Salesforce event {event_id} Agentforce user {user_id} "
                        f"is part of a cross-object pattern "
                        f"({len(cross_object_users[user_id])} object types > "
                        f"threshold {self.cross_object_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_object_object_types": cross_object_users[user_id],
                        "cross_object_threshold": self.cross_object_threshold,
                    },
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Fallback: unrecognized / unmatched event — surface as PR-05 FLAG.
        # ------------------------------------------------------------------
        if not primary_emitted:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Salesforce event {event_id} EVENT_TYPE={event_type!r} "
                        f"did not match any classified pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": "unknown_event"},
                )
            )

        # Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Salesforce Event Monitoring: event_type={event_type} "
            f"user_id={user_id or 'unknown'} "
            f"object_type={object_type or 'none'} "
            f"is_agentforce={is_agentforce} "
            f"blocked_reason={blocked_reason or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"salesforce-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="salesforce_event_monitoring_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=float(run_time or 0),
            session_id=session_key_last8,
        )

    # ------------------------------------------------------------------
    # Synthetic findings
    # ------------------------------------------------------------------

    def _synthetic_cross_object_result(
        self,
        *,
        user_id: str,
        object_types: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_object_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"salesforce-cross-object-{user_id}"
        evidence: dict[str, Any] = {
            "salesforce_event_id": synthetic_id,
            "user_id": user_id,
            "cross_object_object_types": object_types,
            "cross_object_object_count": len(object_types),
            "cross_object_threshold": self.cross_object_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "salesforce_event_monitoring",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Salesforce synthetic finding: Agentforce user {user_id} touched "
                f"{len(object_types)} object types in this export "
                f"({', '.join(object_types)}) — exceeds cross-object threshold "
                f"{self.cross_object_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="salesforce_event_monitoring_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Salesforce Event Monitoring: synthetic cross-object "
                f"pattern for user_id={user_id} "
                f"object_types={len(object_types)}>threshold="
                f"{self.cross_object_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_high_volume_agent_result(
        self,
        *,
        agent_name: str,
        api_call_count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_volume_agent"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"salesforce-high-volume-{agent_name}"
        evidence: dict[str, Any] = {
            "salesforce_event_id": synthetic_id,
            "agent_name": agent_name,
            "api_call_count": api_call_count,
            "high_volume_agent_threshold": self.high_volume_agent_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "salesforce_event_monitoring",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Salesforce synthetic finding: agent {agent_name} made "
                f"{api_call_count} API calls in this export — exceeds "
                f"high-volume threshold {self.high_volume_agent_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="salesforce_event_monitoring_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Salesforce Event Monitoring: synthetic high-volume "
                f"agent finding for agent_name={agent_name} "
                f"api_calls={api_call_count}>threshold={self.high_volume_agent_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
