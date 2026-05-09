"""MongoDB Atlas audit-event importer — maps Atlas database-audit JSON to AKSI controls.

MongoDB Atlas (https://www.mongodb.com/atlas) is the dominant managed NoSQL
database. AI applications storing semi-structured data (chat history,
embeddings, agent memory, JSON documents) commonly sit on top of Atlas. The
audit log captures every database operation — find/insert/update/remove,
DDL (createCollection / dropCollection / dropDatabase), user/role lifecycle,
authentication, and Atlas-management actions.

This importer ingests the Atlas audit JSON exports in four on-disk shapes:

  1. ``{"events": [...]}``     — canonical Atlas wrapper
  2. ``{"data": [...]}``       — generic envelope
  3. ``[{...}, ...]``          — bare array
  4. JSONL                      — one event per line

atype mapping (see shared/mappings/mongodb-atlas-aksi-controls.json):

  * find / aggregate result=0                                   → PR-04 PASS (ns_read)
  * find on sensitive ns + result=0                             → PR-04 FLAG (ns_read_sensitive)
  * find on sensitive ns *without filter_keys* (full-coll scan) → PR-04 FAIL (un-scoped sensitive read)
  * insert / update / remove on sensitive ns                    → PR-03 PASS (ns_write_sensitive — captured)
  * remove with doc_count > threshold                           → PR-02 FLAG (mass-delete)
  * remove on sensitive ns                                      → PR-02 FAIL (ns_delete_sensitive)
  * dropCollection / dropDatabase                               → PR-02 FAIL (schema_destruction)
  * createDatabase / createCollection                           → PR-05 PASS (ns_create)
  * renameCollection                                            → PR-05 FLAG (ns_rename — audit completeness)
  * createUser / grantRolesToUser                               → PR-02 FLAG
  * grantRolesToUser containing admin role                      → PR-02 FAIL (role_grant_admin)
  * dropAllUsersFromDatabase                                    → PR-02 FAIL (mass_user_removal)
  * createRole / updateRole with anyResource / anyAction        → PR-02 FAIL (role_overbroad)
  * authenticate result=0 / 18                                  → PR-01 PASS / FLAG
  * authCheck result=13                                         → PR-02 PASS (correctly denied)
  * command param.command=eval                                  → PR-03 FAIL (server-side eval is dangerous)
  * killOp / killCursors                                        → PR-05 FLAG
  * shutdown                                                    → PR-02 FAIL
  * rotateLogs                                                  → PR-05 PASS
  * atype starts with "encryption"                              → PR-04 PASS (encryption lifecycle)
  * tls_used=false                                              → PR-04 FAIL (tls_disabled)
  * tls_protocol in {TLSv1.0, TLSv1.1}                          → PR-04 FAIL (tls_weak)
  * is_atlas_admin_action=true                                  → captured (atlas_admin_action)
  * users[].db=admin AND read on non-admin ns                   → PR-02 FLAG (admin_user_on_app_data)

Cross-record patterns:

  * Same user touching > N namespaces in 1h               → PR-02 FLAG synthetic
  * Same remote.ip with > N AuthenticationFailed in 1h    → PR-01 FAIL synthetic (brute force)
  * Same user with > N sensitive-collection finds in 1h   → PR-04 FAIL synthetic (mass-sensitive-read)

Sanitization (security-critical — Atlas exports can leak query filters,
collection names, IPs, and session IDs):

  * ``param.args`` is **never stored** — query filters can carry PII (email
    addresses, customer IDs, free-form text). Only the *top-level filter
    keys* (which Atlas already extracts into ``param.filter_keys``) are
    surfaced.
  * ``local.ip`` and ``remote.ip`` masked to ``X.Y.0.0/16`` (IPv4) /
    ``HHHH:HHHH::/32`` (IPv6). RFC1918 / loopback preserved.
  * ``session_id`` reduced to last 8 characters.
  * Full ``param.ns`` is replaced with ``"ns_sensitivity:high"`` when the
    namespace matches a sensitive pattern; the database half (``db.``)
    plus a sensitivity bucket are still surfaced for triage.
  * The original file is hashed (sha256) for source-provenance.

The SDK does **not** depend on ``pymongo``; exports are parsed with the
standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "mongodb-atlas-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallbacks — mirror ``_metadata`` in the canonical JSON.
_DEFAULT_ATYPE_PATTERNS: dict[str, dict[str, str]] = {
    "find":                     {"signal": "ns_read",            "result": "PASS", "control": "PR-04"},
    "aggregate":                {"signal": "ns_read",            "result": "PASS", "control": "PR-04"},
    "count":                    {"signal": "ns_read",            "result": "PASS", "control": "PR-04"},
    "distinct":                 {"signal": "ns_read",            "result": "PASS", "control": "PR-04"},
    "insert":                   {"signal": "ns_write",           "result": "PASS", "control": "PR-03"},
    "update":                   {"signal": "ns_write",           "result": "PASS", "control": "PR-03"},
    "remove":                   {"signal": "ns_delete",          "result": "PASS", "control": "PR-05"},
    "createCollection":         {"signal": "ns_create",          "result": "PASS", "control": "PR-05"},
    "createDatabase":           {"signal": "ns_create",          "result": "PASS", "control": "PR-05"},
    "createView":               {"signal": "ns_create",          "result": "PASS", "control": "PR-05"},
    "createIndex":              {"signal": "ns_index_create",    "result": "PASS", "control": "PR-05"},
    "dropIndex":                {"signal": "ns_index_drop",      "result": "FLAG", "control": "PR-05"},
    "dropCollection":           {"signal": "schema_destruction", "result": "FAIL", "control": "PR-02"},
    "dropDatabase":             {"signal": "schema_destruction", "result": "FAIL", "control": "PR-02"},
    "renameCollection":         {"signal": "ns_rename",          "result": "FLAG", "control": "PR-05"},
    "createUser":               {"signal": "user_create",        "result": "FLAG", "control": "PR-02"},
    "dropUser":                 {"signal": "user_drop",          "result": "FLAG", "control": "PR-02"},
    "grantRolesToUser":         {"signal": "role_grant",         "result": "FLAG", "control": "PR-02"},
    "revokeRolesFromUser":      {"signal": "role_revoke",        "result": "PASS", "control": "PR-05"},
    "createRole":               {"signal": "role_create",        "result": "FLAG", "control": "PR-02"},
    "updateRole":               {"signal": "role_update",        "result": "FLAG", "control": "PR-02"},
    "dropRole":                 {"signal": "role_drop",          "result": "FLAG", "control": "PR-02"},
    "dropAllUsersFromDatabase": {"signal": "mass_user_removal",  "result": "FAIL", "control": "PR-02"},
    "directAuthMutation":       {"signal": "auth_mutation",      "result": "FLAG", "control": "PR-02"},
    "authenticate":             {"signal": "auth_success",       "result": "PASS", "control": "PR-01"},
    "authCheck":                {"signal": "auth_check",         "result": "PASS", "control": "PR-02"},
    "logout":                   {"signal": "session_logout",     "result": "PASS", "control": "PR-05"},
    "applicationMessage":       {"signal": "application_message","result": "PASS", "control": "PR-05"},
    "command":                  {"signal": "command",            "result": "PASS", "control": "PR-05"},
    "killCursors":              {"signal": "operation_terminated","result":"FLAG", "control": "PR-05"},
    "killOp":                   {"signal": "operation_terminated","result":"FLAG", "control": "PR-05"},
    "shutdown":                 {"signal": "database_shutdown",  "result": "FAIL", "control": "PR-02"},
    "rotateLogs":               {"signal": "log_rotation",       "result": "PASS", "control": "PR-05"},
}

_DEFAULT_NS_SENSITIVE_PATTERNS: tuple[str, ...] = (
    "*.customers", "*.users", "*.payroll", "*.pii",
    "*.embeddings", "*.audit_log", "*.secrets", "*.credentials",
)
_DEFAULT_ADMIN_ROLE_PATTERNS: tuple[str, ...] = (
    "*Admin*", "root", "userAdminAnyDatabase", "dbAdminAnyDatabase",
    "readWriteAnyDatabase", "clusterAdmin", "hostManager", "backup", "restore",
)
_DEFAULT_WEAK_TLS_PROTOCOLS: frozenset[str] = frozenset({"TLSv1.0", "TLSv1.1"})

_DEFAULT_MASS_REMOVE_THRESHOLD = 1000
_DEFAULT_CROSS_NAMESPACE_THRESHOLD = 5
_DEFAULT_HIGH_VOLUME_SENSITIVE_READ_THRESHOLD = 100
_DEFAULT_HIGH_VOLUME_SENSITIVE_READ_WINDOW_SECONDS = 3600
_DEFAULT_FAILED_AUTH_BURST_THRESHOLD = 10
_DEFAULT_FAILED_AUTH_BURST_WINDOW_SECONDS = 3600

# atypes considered "read" operations for admin-on-app-data detection.
_READ_ATYPES: frozenset[str] = frozenset(
    {"find", "aggregate", "count", "distinct"}
)

# atypes that count as "user-attributable namespace touches" for
# cross-namespace detection.
_NS_TOUCH_ATYPES: frozenset[str] = frozenset(
    {"find", "aggregate", "count", "distinct", "insert", "update", "remove"}
)


# ---------------------------------------------------------------------------
# Mapping loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
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


def _mask_ip(ip_value: str | None) -> str | None:
    """Mask an Atlas client IP (mirrors Snowflake / CloudTrail).

    * RFC1918 / loopback / link-local preserved verbatim.
    * Public IPv4 reduced to ``X.Y.0.0/16``.
    * Public IPv6 reduced to ``HHHH:HHHH::/32``.
    * Hostnames / non-IP markers preserved verbatim.
    """
    if not ip_value or not isinstance(ip_value, str):
        return None
    ip = ip_value.strip()
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


def _short_session_id(session_id: str | None) -> str | None:
    if not session_id or not isinstance(session_id, str):
        return None
    s = session_id.strip()
    if not s:
        return None
    return s if len(s) <= 8 else s[-8:]


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pat) for pat in patterns)


def _classify_ns(
    ns: str, patterns: tuple[str, ...]
) -> dict[str, Any]:
    """Classify a MongoDB namespace ``db.collection`` against sensitive patterns.

    The full ``ns`` is intentionally NOT surfaced when it matches sensitive
    patterns — the collection name itself can leak (e.g. ``prod.pii_lookup``).
    Only the database segment (low-leak) plus a sensitivity bucket are
    returned.
    """
    if not isinstance(ns, str) or not ns:
        return {"sensitivity": "unknown", "db": "", "matched_pattern": None,
                "ns_redacted": "ns_sensitivity:unknown"}
    db_part = ns.split(".", 1)[0] if "." in ns else ns
    matched: str | None = None
    for pat in patterns:
        if fnmatch.fnmatchcase(ns, pat):
            matched = pat
            break
    if matched is not None:
        return {
            "sensitivity": "high",
            "db": db_part,
            "matched_pattern": matched,
            "ns_redacted": "ns_sensitivity:high",
        }
    return {
        "sensitivity": "low",
        "db": db_part,
        "matched_pattern": None,
        "ns_redacted": ns,
    }


def _parse_iso(ts: str) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f %z",
            "%Y-%m-%d %H:%M:%S %z",
        ):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None


def _has_overbroad_privilege(privileges: Any) -> bool:
    """Return True if a role-privileges list mentions ``anyResource``/``anyAction``."""
    if not isinstance(privileges, list):
        return False
    for priv in privileges:
        if not isinstance(priv, dict):
            continue
        # resource: {"anyResource": true} or {"db": "...", "collection": "..."}
        resource = priv.get("resource")
        if isinstance(resource, dict) and bool(resource.get("anyResource")):
            return True
        actions = priv.get("actions")
        if isinstance(actions, list) and any(
            isinstance(a, str) and a == "anyAction" for a in actions
        ):
            return True
    return False


def _max_sliding_window(
    times: list[datetime], window_seconds: int
) -> int:
    """Largest count of timestamps inside any sliding ``window_seconds`` window."""
    times.sort()
    max_count = 0
    j = 0
    for i in range(len(times)):
        while (times[i] - times[j]).total_seconds() > window_seconds:
            j += 1
        count = i - j + 1
        if count > max_count:
            max_count = count
    return max_count


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class MongoDBAtlasImporter:
    """Parse a MongoDB Atlas audit-event export and convert each event to an EvaluationResult."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        mass_remove_threshold: int | None = None,
        cross_namespace_threshold: int | None = None,
        high_volume_sensitive_read_threshold: int | None = None,
        high_volume_sensitive_read_window_seconds: int | None = None,
        failed_auth_burst_threshold: int | None = None,
        failed_auth_burst_window_seconds: int | None = None,
        ns_sensitive_patterns: Iterable[str] | None = None,
        admin_role_patterns: Iterable[str] | None = None,
        weak_tls_protocols: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # atype patterns — table > built-in defaults.
        meta_at = meta.get("atype_patterns")
        if isinstance(meta_at, dict) and meta_at:
            self._atype_patterns: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_at.items()
                if isinstance(v, dict)
            }
        else:
            self._atype_patterns = dict(_DEFAULT_ATYPE_PATTERNS)

        # Sensitive ns patterns.
        if ns_sensitive_patterns is not None:
            self.ns_sensitive_patterns: tuple[str, ...] = tuple(
                str(p) for p in ns_sensitive_patterns
            )
        else:
            meta_pat = meta.get("ns_sensitive_patterns")
            if isinstance(meta_pat, list) and meta_pat:
                self.ns_sensitive_patterns = tuple(str(p) for p in meta_pat)
            else:
                self.ns_sensitive_patterns = _DEFAULT_NS_SENSITIVE_PATTERNS

        # Admin role patterns.
        if admin_role_patterns is not None:
            self.admin_role_patterns: tuple[str, ...] = tuple(
                str(p) for p in admin_role_patterns
            )
        else:
            meta_roles = meta.get("admin_role_patterns")
            if isinstance(meta_roles, list) and meta_roles:
                self.admin_role_patterns = tuple(str(p) for p in meta_roles)
            else:
                self.admin_role_patterns = _DEFAULT_ADMIN_ROLE_PATTERNS

        # Weak TLS set.
        if weak_tls_protocols is not None:
            self.weak_tls_protocols: frozenset[str] = frozenset(
                str(p) for p in weak_tls_protocols
            )
        else:
            meta_tls = meta.get("weak_tls_protocols")
            if isinstance(meta_tls, list) and meta_tls:
                self.weak_tls_protocols = frozenset(str(p) for p in meta_tls)
            else:
                self.weak_tls_protocols = _DEFAULT_WEAK_TLS_PROTOCOLS

        # Numeric thresholds — explicit > meta > default.
        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            v = meta.get(key)
            try:
                return int(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        self.mass_remove_threshold = _resolve_int(
            mass_remove_threshold,
            "mass_remove_threshold",
            _DEFAULT_MASS_REMOVE_THRESHOLD,
        )
        self.cross_namespace_threshold = _resolve_int(
            cross_namespace_threshold,
            "cross_namespace_threshold",
            _DEFAULT_CROSS_NAMESPACE_THRESHOLD,
        )
        self.high_volume_sensitive_read_threshold = _resolve_int(
            high_volume_sensitive_read_threshold,
            "high_volume_sensitive_read_threshold",
            _DEFAULT_HIGH_VOLUME_SENSITIVE_READ_THRESHOLD,
        )
        self.high_volume_sensitive_read_window_seconds = _resolve_int(
            high_volume_sensitive_read_window_seconds,
            "high_volume_sensitive_read_window_seconds",
            _DEFAULT_HIGH_VOLUME_SENSITIVE_READ_WINDOW_SECONDS,
        )
        self.failed_auth_burst_threshold = _resolve_int(
            failed_auth_burst_threshold,
            "failed_auth_burst_threshold",
            _DEFAULT_FAILED_AUTH_BURST_THRESHOLD,
        )
        self.failed_auth_burst_window_seconds = _resolve_int(
            failed_auth_burst_window_seconds,
            "failed_auth_burst_window_seconds",
            _DEFAULT_FAILED_AUTH_BURST_WINDOW_SECONDS,
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an Atlas audit-event export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Atlas audit-event content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events":[]}`` / ``{"data":[]}`` / bare array / single event / JSONL."""
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
                if "events" in doc and isinstance(doc["events"], list):
                    return [r for r in doc["events"] if isinstance(r, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [r for r in doc["data"] if isinstance(r, dict)]
                # Treat as a single event.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    # -- Build phase --------------------------------------------------------

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # ---- First pass: cross-record aggregations.
        user_namespaces: dict[str, set[str]] = {}
        user_sensitive_reads: dict[str, list[datetime]] = {}
        ip_failed_auths: dict[str, list[datetime]] = {}

        for ev in events:
            atype = str(ev.get("atype") or "")
            param = ev.get("param") or {}
            if not isinstance(param, dict):
                param = {}
            ns = str(param.get("ns") or "")
            users = ev.get("users") or []
            primary_user = ""
            primary_user_db = ""
            if isinstance(users, list) and users:
                first = users[0] if isinstance(users[0], dict) else {}
                primary_user = str(first.get("user") or "")
                primary_user_db = str(first.get("db") or "")

            ts = _parse_iso(str(ev.get("ts") or ""))

            if atype in _NS_TOUCH_ATYPES and primary_user and ns:
                user_namespaces.setdefault(primary_user, set()).add(ns)

            if atype == "find" and primary_user and ts is not None:
                cls = _classify_ns(ns, self.ns_sensitive_patterns)
                if cls["sensitivity"] == "high":
                    user_sensitive_reads.setdefault(primary_user, []).append(ts)

            if atype == "authenticate":
                try:
                    rc = int(ev.get("result"))
                except (TypeError, ValueError):
                    rc = -1
                if rc == 18:
                    remote = ev.get("remote") or {}
                    ip = remote.get("ip") if isinstance(remote, dict) else None
                    if isinstance(ip, str) and ip and ts is not None:
                        ip_failed_auths.setdefault(ip, []).append(ts)
            # Unused locals retained for clarity in pre-aggregation code.
            _ = primary_user_db

        cross_ns_users = {
            u: sorted(ns_set)
            for u, ns_set in user_namespaces.items()
            if len(ns_set) > self.cross_namespace_threshold
        }
        high_volume_users: dict[str, int] = {}
        for u, times in user_sensitive_reads.items():
            mx = _max_sliding_window(
                times, self.high_volume_sensitive_read_window_seconds
            )
            if mx > self.high_volume_sensitive_read_threshold:
                high_volume_users[u] = mx
        brute_force_ips: dict[str, int] = {}
        for ip, times in ip_failed_auths.items():
            mx = _max_sliding_window(
                times, self.failed_auth_burst_window_seconds
            )
            if mx > self.failed_auth_burst_threshold:
                brute_force_ips[ip] = mx

        # ---- Per-event results.
        results: list[EvaluationResult] = []
        for ev in events:
            results.append(
                self._parse_event(
                    ev,
                    file_sha256=file_sha256,
                    cross_ns_users=cross_ns_users,
                    high_volume_users=high_volume_users,
                )
            )

        # ---- Synthetic findings.
        for user, namespaces in sorted(cross_ns_users.items()):
            results.append(
                self._synthetic_cross_namespace_result(
                    user_name=user,
                    namespaces=namespaces,
                    file_sha256=file_sha256,
                )
            )
        for user, count in sorted(high_volume_users.items()):
            results.append(
                self._synthetic_high_volume_sensitive_read_result(
                    user_name=user,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for ip, count in sorted(brute_force_ips.items()):
            results.append(
                self._synthetic_failed_auth_burst_result(
                    remote_ip=ip,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        return results

    # -- Provenance ---------------------------------------------------------

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
        record_kind: str = "event",
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "mongodb_atlas",
            "source_tool_name": "mongodb_atlas",
            "source_tool_version": "",
            "record_kind": record_kind,
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ----------------------------------------------------------------------
    # Event parsing
    # ----------------------------------------------------------------------

    def _parse_event(  # noqa: C901 - audit-event mapper has many overlays
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_ns_users: dict[str, list[str]],
        high_volume_users: dict[str, int],
    ) -> EvaluationResult:
        atype = str(record.get("atype") or "")
        ts = str(record.get("ts") or datetime.now(timezone.utc).isoformat())
        try:
            result_code: int | None = (
                int(record["result"])
                if record.get("result") is not None
                else None
            )
        except (TypeError, ValueError):
            result_code = None

        param = record.get("param") or {}
        if not isinstance(param, dict):
            param = {}
        ns = str(param.get("ns") or "")
        ns_classification = _classify_ns(ns, self.ns_sensitive_patterns)
        is_sensitive_ns = ns_classification["sensitivity"] == "high"
        param_command = str(param.get("command") or "")
        filter_keys_raw = param.get("filter_keys")
        filter_keys: list[str] = (
            [str(k) for k in filter_keys_raw if isinstance(k, str)]
            if isinstance(filter_keys_raw, list)
            else []
        )
        try:
            doc_count: int = int(param.get("doc_count") or 0)
        except (TypeError, ValueError):
            doc_count = 0

        # User attribution.
        users_raw = record.get("users") or []
        users: list[dict[str, str]] = []
        if isinstance(users_raw, list):
            for u in users_raw:
                if isinstance(u, dict):
                    users.append(
                        {"user": str(u.get("user") or ""),
                         "db": str(u.get("db") or "")}
                    )
        primary_user = users[0]["user"] if users else ""
        primary_user_db = users[0]["db"] if users else ""

        # Roles attached to the operation.
        roles_raw = record.get("roles") or []
        roles: list[dict[str, str]] = []
        if isinstance(roles_raw, list):
            for r in roles_raw:
                if isinstance(r, dict):
                    roles.append(
                        {"role": str(r.get("role") or ""),
                         "db": str(r.get("db") or "")}
                    )

        # Granted/revoked roles inside the param block (createUser / grantRolesToUser).
        granted_raw = param.get("rolesGranted") or param.get("roles") or []
        granted_roles: list[str] = []
        if isinstance(granted_raw, list):
            for r in granted_raw:
                if isinstance(r, dict):
                    rn = str(r.get("role") or "")
                    if rn:
                        granted_roles.append(rn)
                elif isinstance(r, str):
                    granted_roles.append(r)
        revoked_raw = param.get("rolesRevoked") or []
        revoked_roles: list[str] = []
        if isinstance(revoked_raw, list):
            for r in revoked_raw:
                if isinstance(r, dict):
                    rn = str(r.get("role") or "")
                    if rn:
                        revoked_roles.append(rn)
                elif isinstance(r, str):
                    revoked_roles.append(r)

        privileges = param.get("privileges")

        # IPs (mask) and session id (truncate).
        local = record.get("local") or {}
        local_ip = local.get("ip") if isinstance(local, dict) else None
        remote = record.get("remote") or {}
        remote_ip = remote.get("ip") if isinstance(remote, dict) else None
        local_ip_masked = _mask_ip(local_ip if isinstance(local_ip, str) else None)
        remote_ip_masked = _mask_ip(
            remote_ip if isinstance(remote_ip, str) else None
        )
        session_id_short = _short_session_id(
            record.get("session_id")
            if isinstance(record.get("session_id"), str)
            else None
        )

        # TLS posture.
        tls_used = record.get("tls_used")
        tls_protocol_raw = record.get("tls_protocol")
        tls_protocol = (
            str(tls_protocol_raw) if isinstance(tls_protocol_raw, str) else ""
        )
        is_atlas_admin_action = bool(record.get("is_atlas_admin_action"))

        # Atlas cluster context.
        atlas_event_data = record.get("atlas_event_data") or {}
        if not isinstance(atlas_event_data, dict):
            atlas_event_data = {}
        cluster_name = str(atlas_event_data.get("cluster_name") or "")
        project_id = str(atlas_event_data.get("project_id") or "")
        org_id = str(atlas_event_data.get("org_id") or "")
        version = str(atlas_event_data.get("version") or "")
        is_replica_set = atlas_event_data.get("is_replica_set")
        is_sharded = atlas_event_data.get("is_sharded")

        # Build per-event evidence — note: param.args is NEVER stored.
        common_evidence: dict[str, Any] = {
            "atype": atype,
            "result_code": result_code,
            "ns_redacted": ns_classification["ns_redacted"],
            "ns_sensitivity": ns_classification["sensitivity"],
            "ns_db": ns_classification["db"],
            "ns_matched_pattern": ns_classification["matched_pattern"],
            "filter_keys": filter_keys,
            "doc_count": doc_count,
            "param_command": param_command,
            "users": users,
            "primary_user": primary_user,
            "primary_user_db": primary_user_db,
            "roles": roles,
            "granted_roles": granted_roles,
            "revoked_roles": revoked_roles,
            "local_ip_masked": local_ip_masked,
            "remote_ip_masked": remote_ip_masked,
            "session_id_suffix": session_id_short,
            "tls_used": bool(tls_used) if tls_used is not None else None,
            "tls_protocol": tls_protocol,
            "is_atlas_admin_action": is_atlas_admin_action,
            "cluster_name": cluster_name,
            "project_id": project_id,
            "org_id": org_id,
            "mongodb_version": version,
            "is_replica_set": (
                bool(is_replica_set) if is_replica_set is not None else None
            ),
            "is_sharded": bool(is_sharded) if is_sharded is not None else None,
            "ts": ts,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=session_id_short,
                record_kind="event",
            ),
            "source_tool": "mongodb_atlas",
        }

        control_results: list[ControlResult] = []

        # --------------------------------------------------------------
        # 1. atype-specific overlays (highest-precedence per atype)
        # --------------------------------------------------------------
        self._append_atype_signal(
            control_results,
            common_evidence=common_evidence,
            atype=atype,
            result_code=result_code,
            ns=ns,
            ns_sensitivity_high=is_sensitive_ns,
            param_command=param_command,
            filter_keys=filter_keys,
            doc_count=doc_count,
            granted_roles=granted_roles,
            privileges=privileges,
        )

        # --------------------------------------------------------------
        # 2. authCheck unauthorized result=13 → PR-02 PASS (correctly denied).
        # --------------------------------------------------------------
        if atype == "authCheck" and result_code == 13:
            signal = "auth_denied"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Atlas authCheck on {ns_classification['ns_redacted']} "
                        f"correctly denied (result=13 unauthorized) — RBAC "
                        f"working as designed"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 3. TLS posture overlays.
        # --------------------------------------------------------------
        if tls_used is False:
            signal = "tls_disabled"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Atlas event atype={atype} on cluster {cluster_name!r} "
                        f"used unencrypted transport (tls_used=false)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif tls_protocol and tls_protocol in self.weak_tls_protocols:
            signal = "tls_weak"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Atlas event atype={atype} on cluster {cluster_name!r} "
                        f"negotiated weak TLS protocol {tls_protocol!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 4. Atlas-management surface marker (additive PR-05 PASS).
        # --------------------------------------------------------------
        if is_atlas_admin_action:
            signal = "atlas_admin_action"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Atlas event atype={atype} marked as Atlas-admin action "
                        f"(project_id={project_id!r}) — control-plane evidence "
                        f"captured"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 5. admin-user reading app data (admin db reading non-admin ns).
        # --------------------------------------------------------------
        if (
            atype in _READ_ATYPES
            and primary_user_db == "admin"
            and ns
            and not ns.startswith("admin.")
        ):
            signal = "admin_user_on_app_data"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Atlas {atype} by admin-db user {primary_user!r} on "
                        f"non-admin namespace {ns_classification['ns_redacted']} "
                        f"— admin reading application data"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 6. Cross-record-pattern markers (informational; synthetic added separately).
        # --------------------------------------------------------------
        if primary_user and primary_user in cross_ns_users:
            signal = "cross_namespace_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            namespaces = cross_ns_users[primary_user]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Atlas event atype={atype} user {primary_user!r} is "
                        f"part of a cross-namespace pattern "
                        f"({len(namespaces)} ns > threshold "
                        f"{self.cross_namespace_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_namespace_count": len(namespaces),
                        "cross_namespace_threshold": (
                            self.cross_namespace_threshold
                        ),
                    },
                )
            )
        if primary_user and primary_user in high_volume_users:
            signal = "high_volume_sensitive_read"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Atlas event atype={atype} user {primary_user!r} is "
                        f"part of a high-volume sensitive-read pattern "
                        f"({high_volume_users[primary_user]} reads > "
                        f"threshold {self.high_volume_sensitive_read_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "high_volume_count": high_volume_users[primary_user],
                        "high_volume_threshold": (
                            self.high_volume_sensitive_read_threshold
                        ),
                    },
                )
            )

        # If nothing was emitted, surface unknown_atype FLAG.
        if not control_results:
            signal = "unknown_atype"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Atlas event has unknown atype={atype!r} — surfaced "
                        f"for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        decision = _decision_for(control_results)
        action_id_suffix = session_id_short or uuid.uuid4().hex[:8]
        decision_reason = (
            f"Imported from MongoDB Atlas audit log: atype={atype} "
            f"ns_sensitivity={ns_classification['sensitivity']} "
            f"user={primary_user or 'none'} "
            f"user_db={primary_user_db or 'none'} "
            f"result_code={result_code if result_code is not None else 'none'} "
            f"cluster={cluster_name or 'none'}"
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mongodb-atlas-{atype}-{action_id_suffix}",
            timestamp=ts,
            agent_id=self.agent_id,
            source_type="mongodb_atlas_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=session_id_short,
        )

    def _append_atype_signal(  # noqa: C901 - branching is intentional & flat
        self,
        control_results: list[ControlResult],
        *,
        common_evidence: dict[str, Any],
        atype: str,
        result_code: int | None,
        ns: str,
        ns_sensitivity_high: bool,
        param_command: str,
        filter_keys: list[str],
        doc_count: int,
        granted_roles: list[str],
        privileges: Any,
    ) -> None:
        """Apply the atype → signal/result/control mapping with overlays."""
        # --- Encryption lifecycle (encryption*) ---
        if atype.startswith("encryption"):
            signal = "encryption_lifecycle"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Atlas encryption-lifecycle event atype={atype} — "
                        f"captured for cryptographic-controls audit trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # --- find / aggregate overlays (sensitive ns + un-scoped detection) ---
        if atype == "find" and ns_sensitivity_high and result_code == 0:
            if not filter_keys:
                signal = "ns_read_unscoped_sensitive"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Atlas find on sensitive namespace "
                            f"{common_evidence['ns_redacted']} executed "
                            f"WITHOUT any filter_keys — full-collection "
                            f"scan over sensitive data"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "ns_read_sensitive"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Atlas find on sensitive namespace "
                            f"{common_evidence['ns_redacted']} succeeded "
                            f"(filter_keys={filter_keys})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            return
        # non-sensitive find — fall through to default mapping below.

        # --- remove overlays (mass + sensitive) ---
        if atype == "remove":
            if ns_sensitivity_high:
                signal = "ns_delete_sensitive"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Atlas remove on sensitive namespace "
                            f"{common_evidence['ns_redacted']} "
                            f"(doc_count={doc_count}) — destructive action on "
                            f"sensitive data"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            if doc_count > self.mass_remove_threshold:
                signal = "ns_delete_mass"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Atlas remove on namespace {ns} with "
                            f"doc_count={doc_count} > threshold "
                            f"{self.mass_remove_threshold} — mass delete"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            # fall through to default remove → ns_delete PASS.

        # --- insert / update on sensitive ns — captured but PR-03 PASS ---
        if atype in ("insert", "update") and ns_sensitivity_high:
            signal = "ns_write_sensitive"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Atlas {atype} on sensitive namespace "
                        f"{common_evidence['ns_redacted']} — write captured for "
                        f"provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # --- grantRolesToUser admin-role overlay ---
        if atype == "grantRolesToUser":
            admin_grant = any(
                _matches_any(rn, self.admin_role_patterns)
                for rn in granted_roles
            )
            if admin_grant:
                signal = "role_grant_admin"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Atlas grantRolesToUser granted privileged role(s) "
                            f"{granted_roles} matching admin patterns — "
                            f"admin-level grant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            # else fall through to default role_grant FLAG.

        # --- createRole / updateRole over-broad privilege overlay ---
        if atype in ("createRole", "updateRole") and _has_overbroad_privilege(
            privileges
        ):
            signal = "role_overbroad"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Atlas {atype} defines privileges containing "
                        f"anyResource / anyAction — over-broad role"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # --- command param.command=eval ---
        if atype == "command" and param_command == "eval":
            signal = "command_eval"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        "Atlas command param.command=eval — server-side eval "
                        "is dangerous and deprecated; arbitrary-code surface"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        # --- authenticate result-code overlay ---
        if atype == "authenticate":
            if result_code == 18:
                signal = "auth_failed"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Atlas authenticate failed (result=18 "
                            f"AuthenticationFailed) for user "
                            f"{common_evidence.get('primary_user') or '?'}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            if result_code == 0:
                signal = "auth_success"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Atlas authenticate succeeded for user "
                            f"{common_evidence.get('primary_user') or '?'}"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                return
            # other result codes — fall through to default mapping.

        # --- default per-atype mapping ---
        pattern = self._atype_patterns.get(atype)
        if pattern is None:
            return  # caller will emit unknown_atype if no other signal added
        signal = pattern.get("signal", "unknown_atype")
        control_id = _control_for(
            signal, self._mappings, pattern.get("control", "PR-05")
        )
        result = pattern.get("result", "PASS")
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result=result,
                detail=(
                    f"Atlas event atype={atype} on namespace "
                    f"{common_evidence['ns_redacted']} classified as {signal} "
                    f"({result})"
                ),
                evidence_data={**common_evidence, "signal": signal},
            )
        )

    # ----------------------------------------------------------------------
    # Synthetic findings
    # ----------------------------------------------------------------------

    def _synthetic_cross_namespace_result(
        self,
        *,
        user_name: str,
        namespaces: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_namespace_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"mongodb-atlas-cross-namespace-{user_name}"
        # Surface only sensitivity histogram — full ns list can leak.
        sensitive_count = sum(
            1
            for n in namespaces
            if _classify_ns(n, self.ns_sensitive_patterns)["sensitivity"]
            == "high"
        )
        evidence: dict[str, Any] = {
            "mongodb_synthetic_id": synthetic_id,
            "primary_user": user_name,
            "cross_namespace_count": len(namespaces),
            "cross_namespace_sensitive_count": sensitive_count,
            "cross_namespace_threshold": self.cross_namespace_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "mongodb_atlas",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"MongoDB Atlas synthetic finding: user {user_name!r} touched "
                f"{len(namespaces)} namespaces in this export "
                f"({sensitive_count} sensitive) — exceeds cross-namespace "
                f"threshold {self.cross_namespace_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mongodb_atlas_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from MongoDB Atlas: synthetic cross-namespace "
                f"pattern for user={user_name} ns={len(namespaces)}>threshold="
                f"{self.cross_namespace_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_high_volume_sensitive_read_result(
        self,
        *,
        user_name: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_volume_sensitive_read"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"mongodb-atlas-mass-sensitive-read-{user_name}"
        evidence: dict[str, Any] = {
            "mongodb_synthetic_id": synthetic_id,
            "primary_user": user_name,
            "high_volume_count": count,
            "high_volume_threshold": self.high_volume_sensitive_read_threshold,
            "high_volume_window_seconds": (
                self.high_volume_sensitive_read_window_seconds
            ),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "mongodb_atlas",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"MongoDB Atlas synthetic finding: user {user_name!r} executed "
                f"{count} sensitive-collection finds in "
                f"{self.high_volume_sensitive_read_window_seconds}s "
                f"(> threshold {self.high_volume_sensitive_read_threshold})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mongodb_atlas_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from MongoDB Atlas: synthetic high-volume "
                f"sensitive-read pattern user={user_name} count={count}>"
                f"threshold={self.high_volume_sensitive_read_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_failed_auth_burst_result(
        self,
        *,
        remote_ip: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "failed_auth_burst"
        control_id = _control_for(signal, self._mappings, "PR-01")
        masked = _mask_ip(remote_ip) or remote_ip
        synthetic_id = f"mongodb-atlas-failed-auth-burst-{masked}"
        evidence: dict[str, Any] = {
            "mongodb_synthetic_id": synthetic_id,
            "remote_ip_masked": masked,
            "failed_auth_count": count,
            "failed_auth_threshold": self.failed_auth_burst_threshold,
            "failed_auth_window_seconds": self.failed_auth_burst_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "mongodb_atlas",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"MongoDB Atlas synthetic finding: {count} AuthenticationFailed "
                f"events from masked IP {masked} in "
                f"{self.failed_auth_burst_window_seconds}s "
                f"(> threshold {self.failed_auth_burst_threshold}) — brute-force "
                f"pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mongodb_atlas_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from MongoDB Atlas: synthetic failed-auth burst "
                f"ip={masked} count={count}>threshold="
                f"{self.failed_auth_burst_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Decision helper
# ---------------------------------------------------------------------------


def _decision_for(control_results: list[ControlResult]) -> str:
    """any FAIL → BLOCK; any FLAG → FLAG; else ALLOW."""
    if any(cr.result == "FAIL" for cr in control_results):
        return "BLOCK"
    if any(cr.result == "FLAG" for cr in control_results):
        return "FLAG"
    return "ALLOW"
