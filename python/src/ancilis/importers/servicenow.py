# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""ServiceNow audit-record importer — maps Now Assist activity to AKSI controls.

ServiceNow (https://servicenow.com) is the dominant ITSM platform: incidents,
change requests, problems, requested items, knowledge articles, and the user/
role/ACL configuration that governs them. Now Assist — ServiceNow's AI-agent
surface — creates incidents, drafts and publishes knowledge articles,
qualifies records, and (when enabled) auto-resolves and auto-implements
records. The ``sys_audit`` and ``sys_security_audit_history`` tables are the
canonical evidence source for every field-level mutation: the ``reason``
column distinguishes ``web`` / ``api`` / ``workflow`` / ``now_assist`` /
``automation`` / ``system``, while ``is_now_assist`` and
``now_assist_capability`` mark AI-attributed events.

This importer ingests audit exports in three on-disk shapes:

  1. ``{"audits": [...]}`` — primary sys_audit envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                 — one record per line

Signal mapping (see shared/mappings/servicenow-aksi-controls.json):

  * tablename=incident action=INSERTED reason=now_assist
                                                    → PR-01 FLAG (Now Assist
                                                      creating incidents)
  * tablename=incident action=UPDATED field=state new_value→Resolved/Closed
    reason=now_assist                               → PR-02 FAIL (autonomous
                                                      incident resolution)
  * tablename=incident action=DELETED               → PR-02 FLAG (audit
                                                      destruction surface)
  * tablename=change_request action=UPDATED field=state new_value→Implemented
    reason=now_assist + approval_state≠approved    → PR-02 FAIL (autonomous
                                                      change-implementation
                                                      without approval)
  * tablename=change_request action=INSERTED with approval_state=not_requested
                                                    → PR-02 FLAG (CR without
                                                      approval workflow)
  * tablename=problem field=root_cause changed by now_assist
                                                    → PR-05 FLAG (AI-attributed
                                                      root-cause)
  * tablename=kb_knowledge action=INSERTED reason=now_assist
                                                    → PR-04 FLAG (AI-drafted
                                                      KB article — accuracy)
  * tablename=kb_knowledge action=UPDATED field=published_state
    new_value=published reason=now_assist          → PR-04 FAIL (autonomous
                                                      KB publishing)
  * tablename=sys_user action=INSERTED              → PR-02 FLAG (user
                                                      provisioning)
  * tablename=sys_user_role action=INSERTED with role pattern admin*
                                                    → PR-02 FAIL (admin
                                                      role grant)
  * tablename=sys_security_acl action in
    {INSERTED,UPDATED,DELETED}                      → PR-02 FAIL (ACL change)
  * is_sensitive_field=true changed by now_assist  → PR-04 FLAG (AI editing
                                                      a sensitive field)
  * reason=workflow                                 → PR-05 PASS
  * reason=automation                               → PR-05 PASS
  * reason=system                                   → PR-05 PASS (captured)
  * auth_method=basic                               → PR-04 FAIL (legacy auth)
  * approval_state=rejected on action=UPDATED       → PR-05 PASS (correctly
                                                      rejected)
  * Now-Assist velocity: > N now_assist events from
    one user in 1h (default 50)                    → PR-04 FLAG synthetic
  * Cross-table: same user touching > N tablenames
    in 1h (default 5)                              → captured synthetic
  * Sensitive-field-burst: same actor changing > N
    is_sensitive_field=true fields in 1h (default 20) → PR-04 FAIL synthetic

Sanitization (security-critical — sys_audit rows are dense with tenant
identifiers, customer data, and free-text. Old/new values themselves are
NEVER persisted by this importer — only the field name and the lengths
ServiceNow already exports):

  * ``old_value``/``new_value`` raw text is NEVER stored. ServiceNow already
    surfaces ``old_value_length`` and ``new_value_length``; we keep those
    integers only. (Exception: ``new_value`` is inspected in-flight to
    classify state-transition signals — e.g. ``Resolved`` — but the raw
    string is not persisted to evidence.)
  * ``user_id``, ``sys_id``, and ``record_id`` are reduced to last-8 chars.
    These are GUID-like opaque IDs; last-8 lets analysts correlate without
    storing the full identifier.
  * ``user`` (the username) is kept verbatim — ServiceNow usernames are
    pseudonymous service-account / sys-user names, not PII.
  * ``client_ip`` IPv4 is reduced to ``A.B.0.0/16``; RFC1918, loopback, and
    link-local IPs are preserved verbatim. IPv6 reduced to a /32 hextet
    pattern.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``pysnow``; sys_audit JSON exports are parsed
with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/servicenow.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "servicenow-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_ADMIN_ROLE_PATTERNS: tuple[str, ...] = (
    "admin",
    "admin_*",
    "*_admin",
    "*_admin_*",
    "security_admin",
    "user_admin",
    "itil_admin",
    "knowledge_admin",
)
_DEFAULT_RESOLVED_STATES: frozenset[str] = frozenset(
    {"resolved", "closed", "closed complete", "closed incomplete", "solved"}
)
_DEFAULT_IMPLEMENTED_STATES: frozenset[str] = frozenset(
    {"implemented", "closed", "review", "closed complete"}
)
_DEFAULT_OK_APPROVAL_STATES: frozenset[str] = frozenset({"approved"})
_DEFAULT_WEAK_AUTH_METHODS: frozenset[str] = frozenset({"basic"})

_DEFAULT_NOW_ASSIST_VELOCITY_THRESHOLD = 50
_DEFAULT_NOW_ASSIST_VELOCITY_WINDOW_SECONDS = 3600
_DEFAULT_CROSS_TABLE_THRESHOLD = 5
_DEFAULT_CROSS_TABLE_WINDOW_SECONDS = 3600
_DEFAULT_SENSITIVE_BURST_THRESHOLD = 20
_DEFAULT_SENSITIVE_BURST_WINDOW_SECONDS = 3600


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load servicenow-aksi-controls.json; tolerate missing file."""
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


def _classify_client_ip(client_ip: str | None) -> str | None:
    """Reduce a client_ip to a /16 IPv4 or /32-hextet IPv6 pattern."""
    if not client_ip or not isinstance(client_ip, str):
        return None
    ip = client_ip.strip()
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


def _last_8(value: Any) -> str | None:
    """Return last-8 chars of a string-like identifier, or None."""
    if not isinstance(value, str):
        if isinstance(value, int):
            value = str(value)
        else:
            return None
    v = value.strip()
    if not v:
        return None
    if len(v) <= 8:
        return v
    return v[-8:]


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from int (epoch ms or s) or ISO 8601 string."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            v = v / 1000.0
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        # ServiceNow's sys_created_on is "YYYY-MM-DD HH:MM:SS" (UTC).
        if " " in v and "T" not in v and "+" not in v and "-" not in v[10:]:
            v = v.replace(" ", "T", 1) + "+00:00"
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None
    return None


def _format_timestamp(value: Any) -> str:
    dt = _parse_iso_timestamp(value)
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _role_matches_admin(role_value: str | None, patterns: Iterable[str]) -> bool:
    """Return True if ``role_value`` matches any admin-role pattern (case-insensitive)."""
    if not isinstance(role_value, str):
        return False
    rv = role_value.strip().lower()
    if not rv:
        return False
    return any(fnmatch.fnmatchcase(rv, pattern.lower()) for pattern in patterns)


def _str_or_none(value: Any) -> str | None:
    if isinstance(value, str):
        v = value.strip()
        return v or None
    return None


def _normalize_state(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower()


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class ServiceNowImporter:
    """Parse a ServiceNow sys_audit export and convert each row to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        admin_role_patterns: Iterable[str] | None = None,
        resolved_states: Iterable[str] | None = None,
        implemented_states: Iterable[str] | None = None,
        ok_approval_states: Iterable[str] | None = None,
        weak_auth_methods: Iterable[str] | None = None,
        now_assist_velocity_threshold: int | None = None,
        now_assist_velocity_window_seconds: int | None = None,
        cross_table_threshold: int | None = None,
        cross_table_window_seconds: int | None = None,
        sensitive_field_burst_threshold: int | None = None,
        sensitive_field_burst_window_seconds: int | None = None,
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

        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            value = thresholds.get(key)
            if isinstance(value, (int, float)):
                return int(value)
            return default

        self.now_assist_velocity_threshold = _resolve_int(
            now_assist_velocity_threshold,
            "now_assist_velocity_threshold",
            _DEFAULT_NOW_ASSIST_VELOCITY_THRESHOLD,
        )
        self.now_assist_velocity_window_seconds = _resolve_int(
            now_assist_velocity_window_seconds,
            "now_assist_velocity_window_seconds",
            _DEFAULT_NOW_ASSIST_VELOCITY_WINDOW_SECONDS,
        )
        self.cross_table_threshold = _resolve_int(
            cross_table_threshold,
            "cross_table_threshold",
            _DEFAULT_CROSS_TABLE_THRESHOLD,
        )
        self.cross_table_window_seconds = _resolve_int(
            cross_table_window_seconds,
            "cross_table_window_seconds",
            _DEFAULT_CROSS_TABLE_WINDOW_SECONDS,
        )
        self.sensitive_field_burst_threshold = _resolve_int(
            sensitive_field_burst_threshold,
            "sensitive_field_burst_threshold",
            _DEFAULT_SENSITIVE_BURST_THRESHOLD,
        )
        self.sensitive_field_burst_window_seconds = _resolve_int(
            sensitive_field_burst_window_seconds,
            "sensitive_field_burst_window_seconds",
            _DEFAULT_SENSITIVE_BURST_WINDOW_SECONDS,
        )

        if admin_role_patterns is not None:
            self.admin_role_patterns: tuple[str, ...] = tuple(
                str(p) for p in admin_role_patterns
            )
        else:
            meta_admin = meta.get("admin_role_patterns")
            if isinstance(meta_admin, list) and meta_admin:
                self.admin_role_patterns = tuple(str(p) for p in meta_admin)
            else:
                self.admin_role_patterns = _DEFAULT_ADMIN_ROLE_PATTERNS

        if resolved_states is not None:
            self.resolved_states: frozenset[str] = frozenset(
                str(s).strip().lower() for s in resolved_states
            )
        else:
            meta_resolved = meta.get("sensitive_resolved_states")
            if isinstance(meta_resolved, list) and meta_resolved:
                self.resolved_states = frozenset(
                    str(s).strip().lower() for s in meta_resolved
                )
            else:
                self.resolved_states = _DEFAULT_RESOLVED_STATES

        if implemented_states is not None:
            self.implemented_states: frozenset[str] = frozenset(
                str(s).strip().lower() for s in implemented_states
            )
        else:
            meta_impl = meta.get("implemented_states")
            if isinstance(meta_impl, list) and meta_impl:
                self.implemented_states = frozenset(
                    str(s).strip().lower() for s in meta_impl
                )
            else:
                self.implemented_states = _DEFAULT_IMPLEMENTED_STATES

        if ok_approval_states is not None:
            self.ok_approval_states: frozenset[str] = frozenset(
                str(s).strip().lower() for s in ok_approval_states
            )
        else:
            meta_ok = meta.get("approval_states_ok")
            if isinstance(meta_ok, list) and meta_ok:
                self.ok_approval_states = frozenset(
                    str(s).strip().lower() for s in meta_ok
                )
            else:
                self.ok_approval_states = _DEFAULT_OK_APPROVAL_STATES

        if weak_auth_methods is not None:
            self.weak_auth_methods: frozenset[str] = frozenset(
                str(s).strip().lower() for s in weak_auth_methods
            )
        else:
            meta_weak = meta.get("weak_auth_methods")
            if isinstance(meta_weak, list) and meta_weak:
                self.weak_auth_methods = frozenset(
                    str(s).strip().lower() for s in meta_weak
                )
            else:
                self.weak_auth_methods = _DEFAULT_WEAK_AUTH_METHODS

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a ServiceNow sys_audit export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse ServiceNow sys_audit content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"audits": [...]}`` / ``{"data": [...]}`` / JSONL / single record."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [r for r in doc if isinstance(r, dict)]
            if isinstance(doc, dict):
                for key in ("audits", "records", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [r for r in doc[key] if isinstance(r, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        records: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # Pass 1: aggregate timestamps/tablenames per actor for the three
        # synthetic-finding patterns.
        now_assist_actor_ts: dict[str, list[datetime]] = defaultdict(list)
        cross_table_actor: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        sensitive_burst_actor_ts: dict[str, list[datetime]] = defaultdict(list)

        for rec in records:
            user = _str_or_none(rec.get("user"))
            if not user:
                continue
            ts = _parse_iso_timestamp(rec.get("sys_created_on"))
            if ts is None:
                continue
            tablename = _str_or_none(rec.get("tablename"))
            reason = _str_or_none(rec.get("reason"))
            is_now_assist = bool(rec.get("is_now_assist")) or (
                reason == "now_assist"
            )
            is_sensitive = bool(rec.get("is_sensitive_field"))
            if is_now_assist:
                now_assist_actor_ts[user].append(ts)
                if is_sensitive:
                    sensitive_burst_actor_ts[user].append(ts)
            if tablename:
                cross_table_actor[user].append((ts, tablename))

        now_assist_velocity_actors: dict[str, int] = self._sliding_window_max(
            now_assist_actor_ts,
            self.now_assist_velocity_threshold,
            self.now_assist_velocity_window_seconds,
        )
        sensitive_burst_actors: dict[str, int] = self._sliding_window_max(
            sensitive_burst_actor_ts,
            self.sensitive_field_burst_threshold,
            self.sensitive_field_burst_window_seconds,
        )
        cross_table_actors: dict[str, list[str]] = (
            self._cross_table_distinct(
                cross_table_actor,
                self.cross_table_threshold,
                self.cross_table_window_seconds,
            )
        )

        results: list[EvaluationResult] = [
            self._parse_record(
                rec,
                file_sha256=file_sha256,
                now_assist_velocity_actors=now_assist_velocity_actors,
                cross_table_actors=cross_table_actors,
                sensitive_burst_actors=sensitive_burst_actors,
            )
            for rec in records
        ]

        for user, count in sorted(now_assist_velocity_actors.items()):
            results.append(
                self._synthetic_now_assist_velocity(
                    user=user,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for user, tables in sorted(cross_table_actors.items()):
            results.append(
                self._synthetic_cross_table(
                    user=user,
                    tables=tables,
                    file_sha256=file_sha256,
                )
            )
        for user, count in sorted(sensitive_burst_actors.items()):
            results.append(
                self._synthetic_sensitive_burst(
                    user=user,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    @staticmethod
    def _sliding_window_max(
        actor_ts: dict[str, list[datetime]],
        threshold: int,
        window: int,
    ) -> dict[str, int]:
        """Return ``{actor: max_count}`` where ``max_count > threshold`` in the window."""
        result: dict[str, int] = {}
        for actor, timestamps in actor_ts.items():
            if len(timestamps) <= threshold:
                continue
            sorted_ts = sorted(timestamps)
            left = 0
            max_in_window = 0
            for right in range(len(sorted_ts)):
                while (
                    sorted_ts[right] - sorted_ts[left]
                ).total_seconds() > window:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
            if max_in_window > threshold:
                result[actor] = max_in_window
        return result

    @staticmethod
    def _cross_table_distinct(
        actor_events: dict[str, list[tuple[datetime, str]]],
        threshold: int,
        window: int,
    ) -> dict[str, list[str]]:
        """Return ``{actor: sorted_tablenames}`` where distinct tables in any
        sliding window exceed ``threshold``."""
        result: dict[str, list[str]] = {}
        for actor, events in actor_events.items():
            sorted_events = sorted(events, key=lambda x: x[0])
            best: set[str] = set()
            left = 0
            current: dict[str, int] = defaultdict(int)
            for right in range(len(sorted_events)):
                t_right, tn_right = sorted_events[right]
                current[tn_right] += 1
                while (t_right - sorted_events[left][0]).total_seconds() > window:
                    t_left, tn_left = sorted_events[left]
                    current[tn_left] -= 1
                    if current[tn_left] == 0:
                        del current[tn_left]
                    left += 1
                if len(current) > threshold and len(current) > len(best):
                    best = set(current.keys())
            if best:
                result[actor] = sorted(best)
        return result

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "servicenow_audit",
            "source_tool_name": "servicenow",
            "source_tool_version": "",
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-record parsing
    # ------------------------------------------------------------------

    def _parse_record(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        now_assist_velocity_actors: dict[str, int],
        cross_table_actors: dict[str, list[str]],
        sensitive_burst_actors: dict[str, int],
    ) -> EvaluationResult:
        sys_id_full = _str_or_none(record.get("sys_id"))
        sys_id_last8 = _last_8(sys_id_full)
        record_id_full = _str_or_none(record.get("record_id"))
        record_id_last8 = _last_8(record_id_full)
        user_id_full = _str_or_none(record.get("user_id"))
        user_id_last8 = _last_8(user_id_full)
        evaluation_record_id = sys_id_full or str(uuid.uuid4())

        tablename = _str_or_none(record.get("tablename"))
        action = (
            record.get("action").upper()
            if isinstance(record.get("action"), str)
            else None
        )
        field = _str_or_none(record.get("field"))
        user = _str_or_none(record.get("user"))
        reason = _str_or_none(record.get("reason"))
        is_now_assist_flag = bool(record.get("is_now_assist"))
        is_now_assist = is_now_assist_flag or reason == "now_assist"
        now_assist_capability = _str_or_none(record.get("now_assist_capability"))
        internal_type = _str_or_none(record.get("internal_type"))
        auth_method = _str_or_none(record.get("auth_method"))
        domain = _str_or_none(record.get("domain"))
        approval_state_raw = _str_or_none(record.get("approval_state"))
        approval_state = approval_state_raw.lower() if approval_state_raw else None
        is_sensitive_field = bool(record.get("is_sensitive_field"))
        client_ip_redacted = _classify_client_ip(
            record.get("client_ip")
            if isinstance(record.get("client_ip"), str)
            else None
        )
        try:
            old_value_length = int(record.get("old_value_length") or 0)
        except (TypeError, ValueError):
            old_value_length = 0
        try:
            new_value_length = int(record.get("new_value_length") or 0)
        except (TypeError, ValueError):
            new_value_length = 0

        # In-flight only: read the raw new_value to classify state transitions.
        # Never persisted to evidence.
        raw_new_value = (
            record.get("new_value")
            if isinstance(record.get("new_value"), str)
            else ""
        )
        new_value_normalized = _normalize_state(raw_new_value)

        timestamp = _format_timestamp(record.get("sys_created_on"))

        common_evidence: dict[str, Any] = {
            "servicenow_record_id": evaluation_record_id,
            "sys_id_last8": sys_id_last8,
            "record_id_last8": record_id_last8,
            "user_id_last8": user_id_last8,
            "user": user,
            "tablename": tablename,
            "action": action,
            "field": field,
            "reason": reason,
            "is_now_assist": is_now_assist,
            "now_assist_capability": now_assist_capability,
            "internal_type": internal_type,
            "auth_method": auth_method,
            "domain": domain,
            "approval_state": approval_state,
            "is_sensitive_field": is_sensitive_field,
            "client_ip_redacted": client_ip_redacted,
            "old_value_length": old_value_length,
            "new_value_length": new_value_length,
            "event_time": timestamp,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=evaluation_record_id,
            ),
            "source_tool": "servicenow",
        }

        control_results: list[ControlResult] = []

        # ------------------------------------------------------------------
        # 1. Per-table primary signals.
        # ------------------------------------------------------------------
        if tablename == "incident":
            if action == "INSERTED" and is_now_assist:
                control_results.append(
                    self._cr(
                        signal="now_assist_creates_incident",
                        default="PR-01",
                        result="FLAG",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} Now Assist "
                            f"created incident (record_id_last8={record_id_last8!r}) "
                            f"— review AI-authored intake"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if (
                action == "UPDATED"
                and field == "state"
                and is_now_assist
                and new_value_normalized in self.resolved_states
            ):
                control_results.append(
                    self._cr(
                        signal="now_assist_resolves_incident",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} Now Assist "
                            f"transitioned incident "
                            f"(record_id_last8={record_id_last8!r}) state to a "
                            f"resolved/closed value — autonomous resolution"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if action == "DELETED":
                control_results.append(
                    self._cr(
                        signal="incident_deletion",
                        default="PR-02",
                        result="FLAG",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} incident "
                            f"deletion (record_id_last8={record_id_last8!r}) — "
                            f"audit-destruction surface"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        elif tablename == "change_request":
            if (
                action == "UPDATED"
                and field == "state"
                and is_now_assist
                and new_value_normalized in self.implemented_states
                and approval_state not in self.ok_approval_states
            ):
                control_results.append(
                    self._cr(
                        signal="now_assist_implements_change_unapproved",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} Now Assist "
                            f"implemented change_request "
                            f"(record_id_last8={record_id_last8!r}) without "
                            f"approval (approval_state={approval_state!r})"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if (
                action == "INSERTED"
                and approval_state == "not_requested"
            ):
                control_results.append(
                    self._cr(
                        signal="change_request_no_approval",
                        default="PR-02",
                        result="FLAG",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} change_request "
                            f"inserted without approval workflow "
                            f"(record_id_last8={record_id_last8!r})"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        elif tablename == "problem":
            if field == "root_cause" and is_now_assist:
                control_results.append(
                    self._cr(
                        signal="now_assist_root_cause",
                        default="PR-05",
                        result="FLAG",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} Now Assist "
                            f"set problem.root_cause "
                            f"(record_id_last8={record_id_last8!r}) — AI-attributed "
                            f"root cause warrants review"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        elif tablename == "kb_knowledge":
            if action == "INSERTED" and is_now_assist:
                control_results.append(
                    self._cr(
                        signal="kb_drafted_by_now_assist",
                        default="PR-04",
                        result="FLAG",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} Now Assist "
                            f"drafted KB article "
                            f"(record_id_last8={record_id_last8!r}) — AI-drafted "
                            f"content needs accuracy review"
                        ),
                        common_evidence=common_evidence,
                    )
                )
            if (
                action == "UPDATED"
                and field == "published_state"
                and is_now_assist
                and new_value_normalized == "published"
            ):
                control_results.append(
                    self._cr(
                        signal="kb_published_by_now_assist",
                        default="PR-04",
                        result="FAIL",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} Now Assist "
                            f"autonomously published KB article "
                            f"(record_id_last8={record_id_last8!r})"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        elif tablename == "sys_user":
            if action == "INSERTED":
                control_results.append(
                    self._cr(
                        signal="user_provisioning",
                        default="PR-02",
                        result="FLAG",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} sys_user "
                            f"provisioned (record_id_last8={record_id_last8!r}) — "
                            f"verify approval"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        elif tablename == "sys_user_role":
            if action == "INSERTED" and _role_matches_admin(
                raw_new_value, self.admin_role_patterns
            ):
                control_results.append(
                    self._cr(
                        signal="admin_role_grant",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} sys_user_role "
                            f"INSERTED with admin role pattern — privileged grant "
                            f"requires governance approval"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        elif tablename == "sys_security_acl":
            if action in {"INSERTED", "UPDATED", "DELETED"}:
                control_results.append(
                    self._cr(
                        signal="acl_modification",
                        default="PR-02",
                        result="FAIL",
                        detail=(
                            f"ServiceNow record {evaluation_record_id} "
                            f"sys_security_acl {action} "
                            f"(record_id_last8={record_id_last8!r}) — ACL "
                            f"modifications change the platform authorization model"
                        ),
                        common_evidence=common_evidence,
                    )
                )

        # ------------------------------------------------------------------
        # 2. Cross-cutting additive signals.
        # ------------------------------------------------------------------
        if is_sensitive_field and is_now_assist:
            control_results.append(
                self._cr(
                    signal="sensitive_field_now_assist",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} Now Assist "
                        f"modified sensitive field {field!r} on table "
                        f"{tablename!r} — AI editing high-classification data"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if auth_method and auth_method.lower() in self.weak_auth_methods:
            control_results.append(
                self._cr(
                    signal="basic_auth",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} "
                        f"auth_method={auth_method!r} — legacy basic auth on "
                        f"production ServiceNow fails modern crypto controls"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if approval_state == "rejected" and action == "UPDATED":
            control_results.append(
                self._cr(
                    signal="approval_rejected",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} change correctly "
                        f"rejected (approval_state=rejected) — governance functioning"
                    ),
                    common_evidence=common_evidence,
                )
            )

        if reason == "workflow":
            control_results.append(
                self._cr(
                    signal="workflow_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} reason=workflow "
                        f"— automation audit trail captured"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif reason == "automation":
            control_results.append(
                self._cr(
                    signal="automation_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} reason=automation "
                        f"— automation audit trail captured"
                    ),
                    common_evidence=common_evidence,
                )
            )
        elif reason == "system":
            control_results.append(
                self._cr(
                    signal="system_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} reason=system "
                        f"— system-level audit trail captured"
                    ),
                    common_evidence=common_evidence,
                )
            )

        # ------------------------------------------------------------------
        # 3. Per-record markers for synthetic patterns (traceability).
        # ------------------------------------------------------------------
        if user and user in now_assist_velocity_actors:
            count = now_assist_velocity_actors[user]
            control_results.append(
                self._cr(
                    signal="now_assist_velocity",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} actor {user!r} "
                        f"is part of a Now-Assist velocity pattern "
                        f"({count} actions > threshold "
                        f"{self.now_assist_velocity_threshold} in "
                        f"{self.now_assist_velocity_window_seconds}s window)"
                    ),
                    common_evidence={
                        **common_evidence,
                        "now_assist_velocity_count": count,
                        "now_assist_velocity_threshold": (
                            self.now_assist_velocity_threshold
                        ),
                        "now_assist_velocity_window_seconds": (
                            self.now_assist_velocity_window_seconds
                        ),
                    },
                )
            )
        if user and user in cross_table_actors:
            tables = cross_table_actors[user]
            control_results.append(
                self._cr(
                    signal="cross_table_pattern",
                    default="PR-05",
                    result="FLAG",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} actor {user!r} "
                        f"is part of a cross-table pattern "
                        f"({len(tables)} tablenames > threshold "
                        f"{self.cross_table_threshold} in "
                        f"{self.cross_table_window_seconds}s window)"
                    ),
                    common_evidence={
                        **common_evidence,
                        "cross_table_tables": tables,
                        "cross_table_threshold": self.cross_table_threshold,
                        "cross_table_window_seconds": (
                            self.cross_table_window_seconds
                        ),
                    },
                )
            )
        if user and user in sensitive_burst_actors:
            count = sensitive_burst_actors[user]
            control_results.append(
                self._cr(
                    signal="sensitive_field_burst",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} actor {user!r} "
                        f"is part of a sensitive-field burst "
                        f"({count} sensitive-field changes > threshold "
                        f"{self.sensitive_field_burst_threshold} in "
                        f"{self.sensitive_field_burst_window_seconds}s window)"
                    ),
                    common_evidence={
                        **common_evidence,
                        "sensitive_field_burst_count": count,
                        "sensitive_field_burst_threshold": (
                            self.sensitive_field_burst_threshold
                        ),
                        "sensitive_field_burst_window_seconds": (
                            self.sensitive_field_burst_window_seconds
                        ),
                    },
                )
            )

        # ------------------------------------------------------------------
        # Fallback: nothing matched — surface as PR-05 PASS audit-captured.
        # ------------------------------------------------------------------
        if not control_results:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="PASS",
                    detail=(
                        f"ServiceNow record {evaluation_record_id} table="
                        f"{tablename!r} action={action!r} captured — no "
                        f"pattern-specific signal matched"
                    ),
                    evidence_data={**common_evidence, "signal": "audit_captured"},
                )
            )

        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from ServiceNow sys_audit: tablename={tablename or 'unknown'} "
            f"action={action or 'unknown'} field={field or 'none'} "
            f"reason={reason or 'unknown'} is_now_assist={is_now_assist} "
            f"user={user or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"servicenow-{evaluation_record_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="servicenow_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=user or None,
        )

    def _cr(
        self,
        *,
        signal: str,
        default: str,
        result: str,
        detail: str,
        common_evidence: dict[str, Any],
    ) -> ControlResult:
        control_id = _control_for(signal, self._mappings, default)
        return ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result=result,
            detail=detail,
            evidence_data={**common_evidence, "signal": signal},
        )

    # ------------------------------------------------------------------
    # Synthetic findings
    # ------------------------------------------------------------------

    def _synthetic_now_assist_velocity(
        self,
        *,
        user: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "now_assist_velocity"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"servicenow-now-assist-velocity-{user}"
        evidence: dict[str, Any] = {
            "servicenow_record_id": synthetic_id,
            "user": user,
            "now_assist_velocity_count": count,
            "now_assist_velocity_threshold": self.now_assist_velocity_threshold,
            "now_assist_velocity_window_seconds": (
                self.now_assist_velocity_window_seconds
            ),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "servicenow",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"ServiceNow synthetic finding: actor {user} executed {count} "
                f"Now-Assist actions in a "
                f"{self.now_assist_velocity_window_seconds}s window — exceeds "
                f"threshold {self.now_assist_velocity_threshold} (verify "
                f"capacity and audit completeness)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="servicenow_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from ServiceNow sys_audit: synthetic Now-Assist velocity "
                f"pattern for user={user} count={count}>threshold="
                f"{self.now_assist_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=user or None,
        )

    def _synthetic_cross_table(
        self,
        *,
        user: str,
        tables: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_table_pattern"
        control_id = _control_for(signal, self._mappings, "PR-05")
        synthetic_id = f"servicenow-cross-table-{user}"
        evidence: dict[str, Any] = {
            "servicenow_record_id": synthetic_id,
            "user": user,
            "cross_table_tables": tables,
            "cross_table_count": len(tables),
            "cross_table_threshold": self.cross_table_threshold,
            "cross_table_window_seconds": self.cross_table_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "servicenow",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"ServiceNow synthetic finding: actor {user} touched "
                f"{len(tables)} tablenames in a "
                f"{self.cross_table_window_seconds}s window "
                f"({', '.join(tables)}) — exceeds cross-table threshold "
                f"{self.cross_table_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="servicenow_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from ServiceNow sys_audit: synthetic cross-table pattern "
                f"for user={user} tables={len(tables)}>threshold="
                f"{self.cross_table_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=user or None,
        )

    def _synthetic_sensitive_burst(
        self,
        *,
        user: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "sensitive_field_burst"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"servicenow-sensitive-burst-{user}"
        evidence: dict[str, Any] = {
            "servicenow_record_id": synthetic_id,
            "user": user,
            "sensitive_field_burst_count": count,
            "sensitive_field_burst_threshold": (
                self.sensitive_field_burst_threshold
            ),
            "sensitive_field_burst_window_seconds": (
                self.sensitive_field_burst_window_seconds
            ),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "servicenow",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"ServiceNow synthetic finding: actor {user} changed {count} "
                f"sensitive fields in a "
                f"{self.sensitive_field_burst_window_seconds}s window — "
                f"exceeds sensitive-field-burst threshold "
                f"{self.sensitive_field_burst_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="servicenow_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from ServiceNow sys_audit: synthetic sensitive-field "
                f"burst for user={user} count={count}>threshold="
                f"{self.sensitive_field_burst_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=user or None,
        )
