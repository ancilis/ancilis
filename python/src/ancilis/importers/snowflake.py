"""Snowflake QUERY_HISTORY / LOGIN_HISTORY / ACCESS_HISTORY importer — maps
Snowflake data-warehouse audit records to AKSI controls.

Snowflake (https://docs.snowflake.com) is the dominant cloud data warehouse.
Agents that query customer data, generate insights, or train on
warehouse-stored corpora hit Snowflake. The platform has a Snowflake Cortex
adapter for inference; this importer covers the **data-plane** side — the
underlying SQL that runs against the warehouse.

Snowflake's ``SNOWFLAKE.ACCOUNT_USAGE`` schema exposes three high-signal
views:

  * ``QUERY_HISTORY``   — every query executed (SELECT, DML, DDL, COPY, …)
  * ``LOGIN_HISTORY``   — authentication / MFA / failed-login events
  * ``ACCESS_HISTORY``  — base / direct objects accessed per query, including
    the policies (masking, row-access) that fired

This importer ingests those views, exported as JSON, in five on-disk shapes:

  1. ``{"queries": [...]}``                 — query records only
  2. ``{"logins": [...]}``                  — login records only
  3. ``{"queries": [...], "logins": [...]}`` — combined export
  4. ``{"data": [...]}``                    — mixed records, auto-detected
     by ``QUERY_ID`` (query) vs ``EVENT_ID`` (login)
  5. JSONL                                   — one record per line

Query mapping (see shared/mappings/snowflake-aksi-controls.json):

  * QUERY_TYPE=SELECT EXECUTION_STATUS=SUCCESS                       → PR-04 PASS
  * QUERY_TYPE=SELECT POLICIES_REFERENCED contains MASKING/ROW_ACCESS → PR-04 PASS (governance enforced)
  * QUERY_TYPE=SELECT BYTES_SCANNED > 1 GB                            → PR-04 FLAG (large scan)
  * QUERY_TYPE=SELECT base table matches sensitive pattern            → PR-04 FLAG
  * QUERY_TYPE=DELETE / TRUNCATE                                      → PR-05 PASS
  * QUERY_TYPE=DELETE / TRUNCATE on sensitive table                   → PR-02 FAIL
  * QUERY_TYPE=DROP                                                   → PR-02 FAIL (schema destruction)
  * QUERY_TYPE=GRANT                                                  → PR-02 FLAG
  * QUERY_TYPE=GRANT to admin role (ACCOUNTADMIN/SECURITYADMIN/SYSADMIN) → PR-02 FAIL
  * QUERY_TYPE=REVOKE                                                 → PR-05 PASS
  * QUERY_TYPE=COPY                                                   → PR-04 FLAG (data ingress)
  * QUERY_TYPE=UNLOAD                                                 → PR-04 FAIL (exfil to external storage)
  * QUERY_TYPE=PUT (upload to internal stage)                         → PR-04 PASS
  * QUERY_TYPE=GET (download from stage)                              → PR-04 FLAG (egress)
  * EXECUTION_STATUS=FAIL ERROR_CODE in privilege range               → PR-02 PASS (correctly denied)
  * EXECUTION_STATUS=FAIL other                                       → DE-01 FLAG
  * ROLE_NAME=ACCOUNTADMIN on routine SELECT                          → PR-02 FLAG (over-privileged)
  * IS_CLIENT_GENERATED=false (system query)                          → PR-05 PASS

Login mapping:

  * LOGIN IS_SUCCESS=YES SECOND_AUTHENTICATION_FACTOR set             → PR-01 PASS (MFA confirmed)
  * LOGIN IS_SUCCESS=YES no MFA, USER_NAME matches agent pattern      → PR-01 PASS (service account)
  * LOGIN IS_SUCCESS=YES PASSWORD-only on human user                  → PR-01 FAIL (no-MFA)
  * LOGIN IS_SUCCESS=NO ERROR_CODE in login-failure list              → PR-01 FLAG
  * AUTHENTICATION_FACTOR_ENROLLED                                    → PR-01 PASS
  * > N failed logins from same IP in 1h                              → PR-01 FAIL synthetic

Cross-record patterns:

  * Same USER_NAME touching > N databases in export                   → PR-02 FLAG synthetic
  * Same USER_NAME with > N sensitive-table queries in 1h             → PR-04 FLAG synthetic

Sanitization (security-critical — Snowflake exports can leak SQL, table
names, customer IDs, agent task descriptions):

  * ``QUERY_TEXT`` itself is **never stored**. Only the QUERY_TEXT_LENGTH
    integer is captured.
  * ``BASE_OBJECTS_ACCESSED`` / ``DIRECT_OBJECTS_ACCESSED`` full lists are
    **never stored** — table names can themselves be PII (e.g.
    ``CUSTOMER_DATA.SSN_LOOKUP``). Only counts plus a per-pattern
    sensitivity-classifier histogram are surfaced.
  * ``QUERY_TAG`` raw value is **never stored**. The tag is parsed as JSON
    when possible; only top-level keys are captured (operationally useful)
    plus a sha256 of the value-string.
  * ``CLIENT_IP`` is masked to a /16 (or RFC1918 preserved).
  * ``CLIENT_APPLICATION_ID`` is truncated to first 30 chars + sha256 of
    the full string.
  * ``ERROR_MESSAGE`` raw is **never stored** (only ERROR_MESSAGE_LENGTH
    given by Snowflake).
  * ``QUERY_ID`` is reduced to the last 8 characters in the action_id
    namespace — Snowflake IDs are high-cardinality UUIDs and storing the
    full ID at scale is unhelpful.
  * The original file is hashed (sha256) for source provenance.

The SDK does **not** depend on ``snowflake-connector-python``; exports are
parsed with the standard library only.
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


# Mapping table lives at <repo>/shared/mappings/snowflake-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/snowflake.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "snowflake-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallbacks if the mapping JSON is missing or malformed. These mirror
# the ``_metadata`` block of the canonical JSON.
_DEFAULT_QUERY_TYPE_PATTERNS: dict[str, dict[str, str]] = {
    "SELECT":   {"signal": "warehouse_read",       "result": "PASS", "control": "PR-04"},
    "INSERT":   {"signal": "warehouse_write",      "result": "PASS", "control": "PR-04"},
    "UPDATE":   {"signal": "warehouse_write",      "result": "PASS", "control": "PR-04"},
    "MERGE":    {"signal": "warehouse_write",      "result": "PASS", "control": "PR-04"},
    "DELETE":   {"signal": "warehouse_delete",     "result": "PASS", "control": "PR-05"},
    "TRUNCATE": {"signal": "warehouse_delete",     "result": "PASS", "control": "PR-05"},
    "DROP":     {"signal": "schema_destruction",   "result": "FAIL", "control": "PR-02"},
    "ALTER":    {"signal": "schema_change",        "result": "FLAG", "control": "PR-02"},
    "CREATE":   {"signal": "schema_change",        "result": "FLAG", "control": "PR-02"},
    "GRANT":    {"signal": "privilege_grant",      "result": "FLAG", "control": "PR-02"},
    "REVOKE":   {"signal": "privilege_revoke",     "result": "PASS", "control": "PR-05"},
    "USE":      {"signal": "session_context",      "result": "PASS", "control": "PR-05"},
    "SHOW":     {"signal": "metadata_read",        "result": "PASS", "control": "PR-05"},
    "COPY":     {"signal": "data_ingress",         "result": "FLAG", "control": "PR-04"},
    "PUT":      {"signal": "stage_upload",         "result": "PASS", "control": "PR-04"},
    "GET":      {"signal": "stage_download",       "result": "FLAG", "control": "PR-04"},
    "UNLOAD":   {"signal": "data_exfiltration",    "result": "FAIL", "control": "PR-04"},
    "CALL":     {"signal": "procedure_call",       "result": "PASS", "control": "PR-05"},
}

_DEFAULT_SENSITIVE_TABLE_PATTERNS: tuple[str, ...] = (
    "CUSTOMER*", "EMPLOYEE*", "FINANCIAL*", "PII*", "PHI*",
    "SSN*", "CREDIT*", "SALARY*",
)
_DEFAULT_PRIVILEGE_ADMIN_ROLES: frozenset[str] = frozenset(
    {"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN"}
)
_DEFAULT_AGENT_USER_PATTERNS: tuple[str, ...] = (
    "*_SVC", "*_AGENT", "AGENT_*", "SVC_*", "BOT_*", "*_BOT",
)
_DEFAULT_LARGE_SCAN_BYTES = 1_000_000_000
_DEFAULT_CROSS_DATABASE_THRESHOLD = 3
_DEFAULT_HIGH_VOLUME_SENSITIVE_READ_THRESHOLD = 50
_DEFAULT_BRUTE_FORCE_THRESHOLD = 5
_DEFAULT_BRUTE_FORCE_WINDOW_SECONDS = 3600
_DEFAULT_LOGIN_FAILURE_ERROR_CODES: frozenset[int] = frozenset(
    {390100, 390101, 390102, 390103, 390104, 390105, 390106, 390108, 390109}
)
_DEFAULT_PRIVILEGE_DENIED_ERROR_CODES: frozenset[int] = frozenset(
    {3001, 3003, 90030}
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the snowflake-aksi-controls.json mapping; tolerate missing file."""
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


def _mask_client_ip(client_ip: str | None) -> str | None:
    """Mask a Snowflake CLIENT_IP to a privacy-aware form (mirrors CloudTrail).

    * RFC1918 / loopback / link-local preserved verbatim (already non-routable).
    * Public IPv4 reduced to ``X.Y.0.0/16``.
    * Public IPv6 reduced to ``HHHH:HHHH::/32``.
    * Hostnames / non-IP markers preserved verbatim.
    """
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
    # IPv6
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _redact_client_application_id(value: str | None) -> dict[str, Any] | None:
    """Return ``{"prefix": <first 30 chars>, "sha256": <hex>}`` or None."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return {
        "prefix": s[:30],
        "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
    }


def _short_query_id(query_id: str) -> str:
    """Reduce a Snowflake QUERY_ID to its last 8 characters for action_id."""
    qid = query_id.strip()
    if len(qid) <= 8:
        return qid
    return qid[-8:]


def _classify_table_sensitivity(
    tables: list[str], patterns: tuple[str, ...]
) -> dict[str, Any]:
    """Run fnmatch over a fully-qualified table list and return a histogram.

    The full list is intentionally NOT returned — table names can themselves
    leak (e.g. ``PROD.CUSTOMER.SSN_LOOKUP``). We surface counts only.
    """
    total = len(tables)
    pattern_hits: dict[str, int] = {p: 0 for p in patterns}
    sensitive_count = 0
    for fq in tables:
        # The fnmatch must be against the unqualified table name (last
        # dotted component). Snowflake fully-qualifies as DB.SCHEMA.TABLE.
        if not isinstance(fq, str):
            continue
        leaf = fq.split(".")[-1].upper()
        for pat in patterns:
            if fnmatch.fnmatchcase(leaf, pat):
                pattern_hits[pat] += 1
                sensitive_count += 1
                break
    return {
        "total": total,
        "sensitive_count": sensitive_count,
        "pattern_hits": {k: v for k, v in pattern_hits.items() if v > 0},
    }


def _redact_query_tag(query_tag: Any) -> dict[str, Any] | None:
    """Parse QUERY_TAG. Surface top-level keys + sha256 of the value-string.

    QUERY_TAG values can carry agent task descriptions, customer IDs, or
    free-form context that the application set. Keys are operationally
    useful (we want to know "this tag exists"); values can be PII.
    """
    if query_tag is None:
        return None
    if isinstance(query_tag, str):
        s = query_tag.strip()
        if not s:
            return None
        sha = hashlib.sha256(s.encode("utf-8")).hexdigest()
        try:
            parsed = json.loads(s)
        except json.JSONDecodeError:
            return {"is_json": False, "value_sha256": sha}
        if isinstance(parsed, dict):
            return {
                "is_json": True,
                "top_level_keys": sorted(str(k) for k in parsed),
                "value_sha256": sha,
            }
        return {"is_json": True, "value_sha256": sha}
    if isinstance(query_tag, dict):
        raw = json.dumps(query_tag, sort_keys=True)
        return {
            "is_json": True,
            "top_level_keys": sorted(str(k) for k in query_tag),
            "value_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        }
    return None


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pat) for pat in patterns)


def _parse_iso(ts: str) -> datetime | None:
    """Best-effort ISO-8601 parse. Returns None for unparseable inputs.

    Snowflake exports timestamps as ``2026-04-01 12:00:00.000 -0700`` or
    ISO-8601. We try the standard library first; we don't fail loudly if
    the timestamp is missing or malformed (the import is best-effort).
    """
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        # Try Snowflake's space-separated format.
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f %z",
            "%Y-%m-%d %H:%M:%S %z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SnowflakeImporter:
    """Parse a Snowflake export and convert each record to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        large_scan_threshold_bytes: int | None = None,
        cross_database_threshold: int | None = None,
        high_volume_sensitive_read_threshold: int | None = None,
        brute_force_threshold: int | None = None,
        brute_force_window_seconds: int | None = None,
        sensitive_table_patterns: Iterable[str] | None = None,
        privilege_admin_roles: Iterable[str] | None = None,
        agent_user_patterns: Iterable[str] | None = None,
        human_user_allowlist: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # Query-type patterns — table > built-in defaults.
        meta_qt = meta.get("query_type_patterns")
        if isinstance(meta_qt, dict) and meta_qt:
            self._query_type_patterns: dict[str, dict[str, str]] = {
                str(k).upper(): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_qt.items()
                if isinstance(v, dict)
            }
        else:
            self._query_type_patterns = dict(_DEFAULT_QUERY_TYPE_PATTERNS)

        # Sensitive table patterns.
        if sensitive_table_patterns is not None:
            self.sensitive_table_patterns = tuple(
                str(p).upper() for p in sensitive_table_patterns
            )
        else:
            meta_pat = meta.get("sensitive_table_patterns")
            if isinstance(meta_pat, list) and meta_pat:
                self.sensitive_table_patterns = tuple(
                    str(p).upper() for p in meta_pat
                )
            else:
                self.sensitive_table_patterns = _DEFAULT_SENSITIVE_TABLE_PATTERNS

        # Privilege admin roles.
        if privilege_admin_roles is not None:
            self.privilege_admin_roles = frozenset(
                str(r).upper() for r in privilege_admin_roles
            )
        else:
            meta_roles = meta.get("privilege_admin_roles")
            if isinstance(meta_roles, list) and meta_roles:
                self.privilege_admin_roles = frozenset(
                    str(r).upper() for r in meta_roles
                )
            else:
                self.privilege_admin_roles = _DEFAULT_PRIVILEGE_ADMIN_ROLES

        # Agent-user patterns (used to distinguish human vs service accounts).
        if agent_user_patterns is not None:
            self.agent_user_patterns = tuple(
                str(p).upper() for p in agent_user_patterns
            )
        else:
            meta_agent = meta.get("agent_user_patterns")
            if isinstance(meta_agent, list) and meta_agent:
                self.agent_user_patterns = tuple(
                    str(p).upper() for p in meta_agent
                )
            else:
                self.agent_user_patterns = _DEFAULT_AGENT_USER_PATTERNS

        # Human-user allowlist (configurable list of usernames where a missing
        # MFA is *not* treated as a no-MFA FAIL — typically empty in tests).
        self.human_user_allowlist = frozenset(
            str(u).upper() for u in (human_user_allowlist or ())
        )

        # Numeric thresholds — explicit > meta > default.
        def _resolve_int(arg: int | None, key: str, default: int) -> int:
            if arg is not None:
                return int(arg)
            v = meta.get(key)
            try:
                return int(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        self.large_scan_threshold_bytes = _resolve_int(
            large_scan_threshold_bytes,
            "large_scan_threshold_bytes",
            _DEFAULT_LARGE_SCAN_BYTES,
        )
        self.cross_database_threshold = _resolve_int(
            cross_database_threshold,
            "cross_database_threshold",
            _DEFAULT_CROSS_DATABASE_THRESHOLD,
        )
        self.high_volume_sensitive_read_threshold = _resolve_int(
            high_volume_sensitive_read_threshold,
            "high_volume_sensitive_read_threshold",
            _DEFAULT_HIGH_VOLUME_SENSITIVE_READ_THRESHOLD,
        )
        self.brute_force_threshold = _resolve_int(
            brute_force_threshold,
            "brute_force_threshold",
            _DEFAULT_BRUTE_FORCE_THRESHOLD,
        )
        self.brute_force_window_seconds = _resolve_int(
            brute_force_window_seconds,
            "brute_force_window_seconds",
            _DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
        )

        # Error-code sets.
        meta_login_err = meta.get("login_failure_error_codes")
        if isinstance(meta_login_err, list) and meta_login_err:
            try:
                self.login_failure_error_codes: frozenset[int] = frozenset(
                    int(c) for c in meta_login_err
                )
            except (TypeError, ValueError):
                self.login_failure_error_codes = _DEFAULT_LOGIN_FAILURE_ERROR_CODES
        else:
            self.login_failure_error_codes = _DEFAULT_LOGIN_FAILURE_ERROR_CODES

        meta_priv_err = meta.get("privilege_denied_error_codes")
        if isinstance(meta_priv_err, list) and meta_priv_err:
            try:
                self.privilege_denied_error_codes: frozenset[int] = frozenset(
                    int(c) for c in meta_priv_err
                )
            except (TypeError, ValueError):
                self.privilege_denied_error_codes = _DEFAULT_PRIVILEGE_DENIED_ERROR_CODES
        else:
            self.privilege_denied_error_codes = _DEFAULT_PRIVILEGE_DENIED_ERROR_CODES

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Snowflake export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        queries, logins = self._records_from_text(text)
        return self._build_results(queries, logins, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Snowflake export content from a JSON or JSONL string."""
        queries, logins = self._records_from_text(content)
        return self._build_results(queries, logins, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(
        self, text: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Detect ``{"queries":[]}`` / ``{"logins":[]}`` / ``{"data":[]}`` / JSONL.

        Returns a (queries, logins) tuple. Mixed envelopes are auto-classified
        by the presence of ``QUERY_ID`` (query) or ``EVENT_ID`` (login).
        """
        stripped = text.lstrip()
        if not stripped:
            return ([], [])
        queries: list[dict[str, Any]] = []
        logins: list[dict[str, Any]] = []

        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                # Fall through to JSONL.
                return self._classify_records(_iter_jsonl(text))

            if isinstance(doc, list):
                return self._classify_records(
                    r for r in doc if isinstance(r, dict)
                )
            if isinstance(doc, dict):
                got_section = False
                if "queries" in doc and isinstance(doc["queries"], list):
                    queries = [r for r in doc["queries"] if isinstance(r, dict)]
                    got_section = True
                if "logins" in doc and isinstance(doc["logins"], list):
                    logins = [r for r in doc["logins"] if isinstance(r, dict)]
                    got_section = True
                if got_section:
                    return (queries, logins)
                if "data" in doc and isinstance(doc["data"], list):
                    return self._classify_records(
                        r for r in doc["data"] if isinstance(r, dict)
                    )
                # Single record — auto-classify.
                return self._classify_records([doc])
            return ([], [])

        return self._classify_records(_iter_jsonl(text))

    @staticmethod
    def _classify_records(
        records: Iterable[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        queries: list[dict[str, Any]] = []
        logins: list[dict[str, Any]] = []
        for r in records:
            if "QUERY_ID" in r:
                queries.append(r)
            elif "EVENT_ID" in r:
                logins.append(r)
            # Records with neither field are dropped — no signal.
        return (queries, logins)

    # -- Build phase --------------------------------------------------------

    def _build_results(
        self,
        queries: list[dict[str, Any]],
        logins: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # ---- First pass over queries: aggregate cross-record patterns.
        user_databases: dict[str, set[str]] = {}
        user_sensitive_reads: dict[str, list[datetime]] = {}
        for q in queries:
            user = q.get("USER_NAME")
            db = q.get("DATABASE_NAME")
            if isinstance(user, str) and user and isinstance(db, str) and db:
                user_databases.setdefault(user, set()).add(db)
            # Sensitive-table reads (only count SELECTs that hit a sensitive
            # base table).
            qtype = str(q.get("QUERY_TYPE") or "").upper()
            if qtype != "SELECT":
                continue
            base = q.get("BASE_OBJECTS_ACCESSED") or []
            if not isinstance(base, list):
                continue
            classified = _classify_table_sensitivity(
                [str(t) for t in base if isinstance(t, str)],
                self.sensitive_table_patterns,
            )
            if classified["sensitive_count"] > 0 and isinstance(user, str):
                ts = _parse_iso(str(q.get("START_TIME") or ""))
                if ts is not None:
                    user_sensitive_reads.setdefault(user, []).append(ts)

        cross_db_users = {
            u: sorted(dbs)
            for u, dbs in user_databases.items()
            if len(dbs) > self.cross_database_threshold
        }

        # High-volume sensitive read: sliding-window count >= threshold.
        high_volume_users: dict[str, int] = {}
        window = self.brute_force_window_seconds  # reuse 1h window
        for user, times in user_sensitive_reads.items():
            times.sort()
            # sliding window
            max_count = 0
            j = 0
            for i in range(len(times)):
                while (times[i] - times[j]).total_seconds() > window:
                    j += 1
                count = i - j + 1
                if count > max_count:
                    max_count = count
            if max_count > self.high_volume_sensitive_read_threshold:
                high_volume_users[user] = max_count

        # ---- First pass over logins: aggregate brute-force pattern by IP.
        ip_failed_logins: dict[str, list[datetime]] = {}
        for log in logins:
            if str(log.get("EVENT_TYPE") or "").upper() != "LOGIN":
                continue
            if str(log.get("IS_SUCCESS") or "").upper() != "NO":
                continue
            ip = log.get("CLIENT_IP")
            ts = _parse_iso(str(log.get("EVENT_TIMESTAMP") or ""))
            if isinstance(ip, str) and ip and ts is not None:
                ip_failed_logins.setdefault(ip, []).append(ts)

        brute_force_ips: dict[str, int] = {}
        for ip, times in ip_failed_logins.items():
            times.sort()
            max_count = 0
            j = 0
            for i in range(len(times)):
                while (times[i] - times[j]).total_seconds() > self.brute_force_window_seconds:
                    j += 1
                count = i - j + 1
                if count > max_count:
                    max_count = count
            if max_count > self.brute_force_threshold:
                brute_force_ips[ip] = max_count

        # ---- Per-record results.
        results: list[EvaluationResult] = []
        for q in queries:
            results.append(
                self._parse_query(
                    q,
                    file_sha256=file_sha256,
                    cross_db_users=cross_db_users,
                    high_volume_users=high_volume_users,
                )
            )
        for log in logins:
            results.append(
                self._parse_login(
                    log,
                    file_sha256=file_sha256,
                    brute_force_ips=brute_force_ips,
                )
            )

        # ---- Synthetic findings.
        for user, dbs in sorted(cross_db_users.items()):
            results.append(
                self._synthetic_cross_database_result(
                    user_name=user, databases=dbs, file_sha256=file_sha256
                )
            )
        for user, count in sorted(high_volume_users.items()):
            results.append(
                self._synthetic_high_volume_sensitive_read_result(
                    user_name=user, count=count, file_sha256=file_sha256
                )
            )
        for ip, count in sorted(brute_force_ips.items()):
            results.append(
                self._synthetic_brute_force_result(
                    client_ip=ip, count=count, file_sha256=file_sha256
                )
            )
        return results

    # -- Provenance ---------------------------------------------------------

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
        record_kind: str = "query",
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "snowflake",
            "source_tool_name": "snowflake",
            "source_tool_version": "",
            "record_kind": record_kind,
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ----------------------------------------------------------------------
    # Query parsing
    # ----------------------------------------------------------------------

    def _parse_query(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_db_users: dict[str, list[str]],
        high_volume_users: dict[str, int],
    ) -> EvaluationResult:
        query_id_raw = str(record.get("QUERY_ID") or uuid.uuid4().hex)
        short_id = _short_query_id(query_id_raw)
        query_type = str(record.get("QUERY_TYPE") or "").upper().strip()
        execution_status = str(record.get("EXECUTION_STATUS") or "").upper().strip()
        database_name = str(record.get("DATABASE_NAME") or "")
        schema_name = str(record.get("SCHEMA_NAME") or "")
        user_name = str(record.get("USER_NAME") or "")
        role_name = str(record.get("ROLE_NAME") or "").upper()
        warehouse_name = str(record.get("WAREHOUSE_NAME") or "")
        warehouse_size = str(record.get("WAREHOUSE_SIZE") or "")

        try:
            error_code: int | None = (
                int(record["ERROR_CODE"])
                if record.get("ERROR_CODE") is not None
                else None
            )
        except (TypeError, ValueError):
            error_code = None
        try:
            bytes_scanned: int = int(record.get("BYTES_SCANNED") or 0)
        except (TypeError, ValueError):
            bytes_scanned = 0
        try:
            rows_produced: int = int(record.get("ROWS_PRODUCED") or 0)
        except (TypeError, ValueError):
            rows_produced = 0
        try:
            rows_inserted: int = int(record.get("ROWS_INSERTED") or 0)
        except (TypeError, ValueError):
            rows_inserted = 0
        try:
            rows_updated: int = int(record.get("ROWS_UPDATED") or 0)
        except (TypeError, ValueError):
            rows_updated = 0
        try:
            rows_deleted: int = int(record.get("ROWS_DELETED") or 0)
        except (TypeError, ValueError):
            rows_deleted = 0
        try:
            objects_accessed_count: int = int(
                record.get("OBJECTS_ACCESSED_COUNT") or 0
            )
        except (TypeError, ValueError):
            objects_accessed_count = 0
        try:
            objects_modified_count: int = int(
                record.get("OBJECTS_MODIFIED_COUNT") or 0
            )
        except (TypeError, ValueError):
            objects_modified_count = 0
        try:
            query_text_length: int = int(record.get("QUERY_TEXT_LENGTH") or 0)
        except (TypeError, ValueError):
            query_text_length = 0
        try:
            error_message_length: int = int(
                record.get("ERROR_MESSAGE_LENGTH") or 0
            )
        except (TypeError, ValueError):
            error_message_length = 0

        start_time = str(record.get("START_TIME") or datetime.now(timezone.utc).isoformat())
        end_time = str(record.get("END_TIME") or "")
        try:
            total_elapsed_ms = float(record.get("TOTAL_ELAPSED_TIME") or 0.0)
        except (TypeError, ValueError):
            total_elapsed_ms = 0.0
        session_id_raw = record.get("SESSION_ID")
        session_id = (
            str(session_id_raw)
            if session_id_raw is not None and str(session_id_raw)
            else None
        )

        # Policies referenced — list of policy names. Useful signal: the
        # presence of "MASKING" or "ROW_ACCESS" in any policy name indicates
        # governance is enforced.
        policies_raw = record.get("POLICIES_REFERENCED") or []
        policies: list[str] = (
            [str(p) for p in policies_raw if isinstance(p, str)]
            if isinstance(policies_raw, list)
            else []
        )
        has_masking = any("MASKING" in p.upper() for p in policies)
        has_row_access = any("ROW_ACCESS" in p.upper() for p in policies)

        # Object lists — counts only, plus per-pattern sensitivity histogram.
        base_objs_raw = record.get("BASE_OBJECTS_ACCESSED") or []
        base_objs: list[str] = (
            [str(t) for t in base_objs_raw if isinstance(t, str)]
            if isinstance(base_objs_raw, list)
            else []
        )
        direct_objs_raw = record.get("DIRECT_OBJECTS_ACCESSED") or []
        direct_objs: list[str] = (
            [str(t) for t in direct_objs_raw if isinstance(t, str)]
            if isinstance(direct_objs_raw, list)
            else []
        )
        base_classification = _classify_table_sensitivity(
            base_objs, self.sensitive_table_patterns
        )
        direct_classification = _classify_table_sensitivity(
            direct_objs, self.sensitive_table_patterns
        )

        # Sanitization: client IP / app ID / query tag.
        client_ip_raw = record.get("CLIENT_IP")
        client_ip_masked = _mask_client_ip(
            client_ip_raw if isinstance(client_ip_raw, str) else None
        )
        client_app_redacted = _redact_client_application_id(
            record.get("CLIENT_APPLICATION_ID")
            if isinstance(record.get("CLIENT_APPLICATION_ID"), str)
            else None
        )
        query_tag_redacted = _redact_query_tag(record.get("QUERY_TAG"))

        is_client_generated = record.get("IS_CLIENT_GENERATED")
        if isinstance(is_client_generated, bool):
            client_generated: bool | None = is_client_generated
        elif isinstance(is_client_generated, str):
            cg = is_client_generated.strip().lower()
            client_generated = cg == "true" if cg in ("true", "false") else None
        else:
            client_generated = None

        common_evidence: dict[str, Any] = {
            "snowflake_query_id_suffix": short_id,
            "query_type": query_type,
            "database_name": database_name,
            "schema_name": schema_name,
            "user_name": user_name,
            "role_name": role_name,
            "warehouse_name": warehouse_name,
            "warehouse_size": warehouse_size,
            "execution_status": execution_status,
            "error_code": error_code,
            "error_message_length": error_message_length,
            "bytes_scanned": bytes_scanned,
            "rows_produced": rows_produced,
            "rows_inserted": rows_inserted,
            "rows_updated": rows_updated,
            "rows_deleted": rows_deleted,
            "objects_accessed_count": objects_accessed_count,
            "objects_modified_count": objects_modified_count,
            "policies_referenced": policies,
            "policies_masking_present": has_masking,
            "policies_row_access_present": has_row_access,
            "base_objects_classification": base_classification,
            "direct_objects_classification": direct_classification,
            "query_text_length": query_text_length,
            "query_tag_redacted": query_tag_redacted,
            "client_application_redacted": client_app_redacted,
            "client_ip_masked": client_ip_masked,
            "is_client_generated": client_generated,
            "start_time": start_time,
            "end_time": end_time,
            "total_elapsed_ms": total_elapsed_ms,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=query_id_raw,
                record_kind="query",
            ),
            "source_tool": "snowflake",
        }

        control_results: list[ControlResult] = []
        sensitive_base_hit = base_classification["sensitive_count"] > 0
        sensitive_direct_hit = direct_classification["sensitive_count"] > 0
        sensitive_hit = sensitive_base_hit or sensitive_direct_hit

        # --------------------------------------------------------------
        # 1. Execution-status failures take precedence over per-type pass.
        # --------------------------------------------------------------
        if execution_status == "FAIL":
            if (
                error_code is not None
                and error_code in self.privilege_denied_error_codes
            ):
                signal = "access_denied"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Snowflake query {short_id} {query_type} on "
                            f"{database_name}.{schema_name} correctly denied "
                            f"by privilege check (error_code={error_code})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "execution_failure"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Snowflake query {short_id} {query_type} on "
                            f"{database_name}.{schema_name} failed "
                            f"(error_code={error_code})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
        else:
            # ----------------------------------------------------------
            # 2. QUERY_TYPE-driven primary classification.
            # ----------------------------------------------------------
            self._append_query_type_signal(
                control_results,
                common_evidence=common_evidence,
                query_type=query_type,
                short_id=short_id,
                database_name=database_name,
                schema_name=schema_name,
                role_name=role_name,
                bytes_scanned=bytes_scanned,
                has_masking=has_masking,
                has_row_access=has_row_access,
                sensitive_base_hit=sensitive_base_hit,
                sensitive_hit=sensitive_hit,
                user_name=user_name,
            )

        # --------------------------------------------------------------
        # 3. Over-privileged role on routine SELECT.
        # ACCOUNTADMIN / SECURITYADMIN running a successful read on a
        # warehouse that is not a DDL/admin workload is a posture issue
        # — DDL by an admin is expected and we do NOT flag those.
        # --------------------------------------------------------------
        if (
            execution_status == "SUCCESS"
            and query_type == "SELECT"
            and role_name in self.privilege_admin_roles
        ):
            signal = "over_privileged_select"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Snowflake query {short_id} SELECT on "
                        f"{database_name}.{schema_name} executed under "
                        f"admin role {role_name!r} — over-privileged for a "
                        f"routine read"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 4. System-generated query — additive PR-05 PASS (audit trail).
        # --------------------------------------------------------------
        if client_generated is False:
            signal = "system_query"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Snowflake query {short_id} is system-generated "
                        f"(IS_CLIENT_GENERATED=false) — internal Snowflake "
                        f"operation, audit trail recorded"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 5. Agent-attribution evidence (QUERY_TAG carries agent_id).
        # --------------------------------------------------------------
        if (
            isinstance(query_tag_redacted, dict)
            and "agent_id" in (query_tag_redacted.get("top_level_keys") or [])
        ):
            signal = "agent_attribution"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Snowflake query {short_id} carries agent attribution "
                        f"in QUERY_TAG (agent_id key present) — strong evidence "
                        f"of agent provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # --------------------------------------------------------------
        # 6. Cross-record-pattern markers (informational; the synthetic
        # finding is added separately).
        # --------------------------------------------------------------
        if user_name and user_name in cross_db_users:
            signal = "cross_database_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Snowflake query {short_id} user {user_name!r} is "
                        f"part of a cross-database pattern "
                        f"({len(cross_db_users[user_name])} dbs > threshold "
                        f"{self.cross_database_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_database_databases": cross_db_users[user_name],
                        "cross_database_threshold": self.cross_database_threshold,
                    },
                )
            )
        if user_name and user_name in high_volume_users:
            signal = "high_volume_sensitive_read"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Snowflake query {short_id} user {user_name!r} is "
                        f"part of a high-volume sensitive-read pattern "
                        f"({high_volume_users[user_name]} reads > threshold "
                        f"{self.high_volume_sensitive_read_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "high_volume_count": high_volume_users[user_name],
                        "high_volume_threshold": (
                            self.high_volume_sensitive_read_threshold
                        ),
                    },
                )
            )

        decision = _decision_for(control_results)
        decision_reason = (
            f"Imported from Snowflake QUERY_HISTORY: query_type={query_type} "
            f"db={database_name} schema={schema_name} user={user_name} "
            f"role={role_name} status={execution_status} "
            f"error_code={error_code if error_code is not None else 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"snowflake-query-{short_id}",
            timestamp=start_time,
            agent_id=self.agent_id,
            source_type="snowflake_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=total_elapsed_ms,
            session_id=session_id,
        )

    def _append_query_type_signal(
        self,
        control_results: list[ControlResult],
        *,
        common_evidence: dict[str, Any],
        query_type: str,
        short_id: str,
        database_name: str,
        schema_name: str,
        role_name: str,
        bytes_scanned: int,
        has_masking: bool,
        has_row_access: bool,
        sensitive_base_hit: bool,
        sensitive_hit: bool,
        user_name: str,
    ) -> None:
        """Apply the QUERY_TYPE → signal/result/control mapping with overlays.

        Overlays:
          * SELECT with masking/row-access policy → governance PASS variant
          * SELECT with bytes_scanned > threshold → large-scan FLAG
          * SELECT on sensitive base table → sensitive FLAG
          * DELETE/TRUNCATE on sensitive table → PR-02 FAIL
          * GRANT to admin role → PR-02 FAIL (admin grant)
        """
        pattern = self._query_type_patterns.get(query_type)

        # SELECT — special handling: governance overlay > large-scan / sensitive flag > base PASS.
        if query_type == "SELECT":
            if has_masking or has_row_access:
                signal = "warehouse_read_governed"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Snowflake query {short_id} SELECT on "
                            f"{database_name}.{schema_name} — masking / "
                            f"row-access policies enforced (governance PASS)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif sensitive_base_hit:
                signal = "warehouse_read_sensitive"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Snowflake query {short_id} SELECT on "
                            f"{database_name}.{schema_name} accesses tables "
                            f"matching sensitive patterns "
                            f"({list(common_evidence['base_objects_classification']['pattern_hits'].keys())}) "
                            f"without masking/row-access policy"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            elif bytes_scanned > self.large_scan_threshold_bytes:
                signal = "warehouse_read_large_scan"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Snowflake query {short_id} SELECT on "
                            f"{database_name}.{schema_name} scanned "
                            f"{bytes_scanned} bytes (> threshold "
                            f"{self.large_scan_threshold_bytes}) — large-scan "
                            f"posture risk"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "warehouse_read"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Snowflake query {short_id} SELECT on "
                            f"{database_name}.{schema_name} succeeded "
                            f"(rows_produced={common_evidence['rows_produced']})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            return

        # DELETE / TRUNCATE — sensitive-table override.
        if query_type in ("DELETE", "TRUNCATE"):
            if sensitive_hit:
                signal = "warehouse_delete_sensitive"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Snowflake query {short_id} {query_type} on "
                            f"{database_name}.{schema_name} targets a table "
                            f"matching a sensitive pattern — destructive "
                            f"action on sensitive data"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "warehouse_delete"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"Snowflake query {short_id} {query_type} on "
                            f"{database_name}.{schema_name} captured for audit "
                            f"trail"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            return

        # GRANT — admin-role override.
        if query_type == "GRANT":
            # Inspect QUERY_TEXT_LENGTH? We don't have query text. Use the
            # role_name as a proxy: if the *executing* role is an admin role
            # AND the grant produced a privileged role to be granted, surface
            # FAIL. We can't see the grantee from the audit log alone, so we
            # use a conservative heuristic: any GRANT executed under or
            # touching admin role context is FAIL when role_name is one of
            # the admin roles. Otherwise GRANT is FLAG.
            #
            # Note: Snowflake's QUERY_HISTORY does not include the granted
            # privilege. The task description treats this signal as
            # "GRANT to ACCOUNTADMIN/SECURITYADMIN" — we approximate by
            # examining the role_name field (which is the role that executed
            # the GRANT — typically itself a superuser role). When the
            # executing role is an admin role, the resulting privilege chain
            # is high-blast-radius; when it's not, GRANT is FLAG.
            if role_name in self.privilege_admin_roles:
                signal = "privilege_grant_admin"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Snowflake query {short_id} GRANT on "
                            f"{database_name}.{schema_name} executed under "
                            f"admin role {role_name!r} — admin-level grant"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "privilege_grant"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Snowflake query {short_id} GRANT on "
                            f"{database_name}.{schema_name} — privilege grant "
                            f"requires review"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            return

        # Generic / unknown query types fall through the table.
        if pattern is None:
            signal = "unknown_query_type"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Snowflake query {short_id} has unknown QUERY_TYPE="
                        f"{query_type!r} — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            return

        signal = pattern.get("signal", "unknown_query_type")
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
                    f"Snowflake query {short_id} {query_type} on "
                    f"{database_name}.{schema_name} classified as {signal} "
                    f"({result})"
                ),
                evidence_data={**common_evidence, "signal": signal},
            )
        )

    # ----------------------------------------------------------------------
    # Login parsing
    # ----------------------------------------------------------------------

    def _parse_login(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        brute_force_ips: dict[str, int],
    ) -> EvaluationResult:
        event_id_raw = record.get("EVENT_ID")
        event_id = (
            str(event_id_raw)
            if event_id_raw is not None and str(event_id_raw)
            else uuid.uuid4().hex
        )
        event_type = str(record.get("EVENT_TYPE") or "").upper().strip()
        event_timestamp = str(
            record.get("EVENT_TIMESTAMP")
            or datetime.now(timezone.utc).isoformat()
        )
        user_name = str(record.get("USER_NAME") or "")
        user_upper = user_name.upper()
        client_ip_raw = record.get("CLIENT_IP")
        client_ip = client_ip_raw if isinstance(client_ip_raw, str) else None
        client_ip_masked = _mask_client_ip(client_ip)
        reported_client_type = str(record.get("REPORTED_CLIENT_TYPE") or "")
        reported_client_version = str(record.get("REPORTED_CLIENT_VERSION") or "")
        first_factor = str(
            record.get("FIRST_AUTHENTICATION_FACTOR") or ""
        ).upper().strip()
        second_factor_raw = record.get("SECOND_AUTHENTICATION_FACTOR")
        second_factor = (
            str(second_factor_raw).upper().strip()
            if isinstance(second_factor_raw, str) and second_factor_raw.strip()
            else None
        )
        is_success = str(record.get("IS_SUCCESS") or "").upper().strip()
        try:
            error_code: int | None = (
                int(record["ERROR_CODE"])
                if record.get("ERROR_CODE") is not None
                else None
            )
        except (TypeError, ValueError):
            error_code = None

        is_agent_user = _matches_any(user_upper, self.agent_user_patterns)

        common_evidence: dict[str, Any] = {
            "snowflake_event_id": event_id,
            "event_type": event_type,
            "event_timestamp": event_timestamp,
            "user_name": user_name,
            "client_ip_masked": client_ip_masked,
            "reported_client_type": reported_client_type,
            "reported_client_version": reported_client_version,
            "first_authentication_factor": first_factor,
            "second_authentication_factor": second_factor,
            "is_success": is_success,
            "error_code": error_code,
            "is_agent_user": is_agent_user,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=event_id,
                record_kind="login",
            ),
            "source_tool": "snowflake",
        }

        control_results: list[ControlResult] = []

        # MFA enrollment — strengthens identity.
        if event_type == "AUTHENTICATION_FACTOR_ENROLLED":
            signal = "mfa_enrolled"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Snowflake login event {event_id} for user {user_name!r} "
                        f"— authentication factor enrolled (identity strengthened)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif event_type == "LOGIN":
            if is_success == "YES":
                if second_factor:
                    signal = "login_mfa"
                    control_id = _control_for(signal, self._mappings, "PR-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="PASS",
                            detail=(
                                f"Snowflake login {event_id} user {user_name!r} "
                                f"succeeded with MFA "
                                f"(first={first_factor}, second={second_factor})"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                elif is_agent_user or first_factor in (
                    "OAUTH",
                    "SAML_ASSERTION",
                    "KEY_PAIR",
                ):
                    # Service account or non-password machine identity — captured
                    # as PASS.
                    signal = "login_service_account"
                    control_id = _control_for(signal, self._mappings, "PR-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="PASS",
                            detail=(
                                f"Snowflake login {event_id} user {user_name!r} "
                                f"succeeded as service account / machine "
                                f"identity (first={first_factor}) — captured"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                elif (
                    first_factor == "PASSWORD"
                    and user_upper not in self.human_user_allowlist
                ):
                    signal = "login_no_mfa"
                    control_id = _control_for(signal, self._mappings, "PR-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FAIL",
                            detail=(
                                f"Snowflake login {event_id} user {user_name!r} "
                                f"succeeded with PASSWORD only — no MFA on a "
                                f"human user is a critical compliance violation"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
                else:
                    # Allowlisted human user OR unrecognized first factor.
                    signal = "login_service_account"
                    control_id = _control_for(signal, self._mappings, "PR-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="PASS",
                            detail=(
                                f"Snowflake login {event_id} user {user_name!r} "
                                f"succeeded (first={first_factor}) — captured "
                                f"under user allowlist / non-password factor"
                            ),
                            evidence_data={**common_evidence, "signal": signal},
                        )
                    )
            else:
                # Failed login.
                signal = "login_failed"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Snowflake login {event_id} user {user_name!r} "
                            f"failed (error_code={error_code})"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

                # Brute-force pattern marker (additive).
                if isinstance(client_ip, str) and client_ip in brute_force_ips:
                    signal = "brute_force_pattern"
                    control_id = _control_for(signal, self._mappings, "PR-01")
                    control_results.append(
                        ControlResult(
                            control_id=control_id,
                            control_name=_CONTROL_NAMES.get(control_id, control_id),
                            result="FAIL",
                            detail=(
                                f"Snowflake login {event_id} from masked IP "
                                f"{client_ip_masked} is part of a brute-force "
                                f"pattern ({brute_force_ips[client_ip]} "
                                f"failed logins > threshold "
                                f"{self.brute_force_threshold} in "
                                f"{self.brute_force_window_seconds}s)"
                            ),
                            evidence_data={
                                **common_evidence,
                                "signal": signal,
                                "brute_force_count": brute_force_ips[client_ip],
                                "brute_force_threshold": self.brute_force_threshold,
                                "brute_force_window_seconds": (
                                    self.brute_force_window_seconds
                                ),
                            },
                        )
                    )
        else:
            # Other LOGIN_HISTORY events (LOGOUT, etc) — capture neutrally.
            signal = "login_service_account"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Snowflake login event {event_id} type={event_type} "
                        f"for user {user_name!r} — captured as audit-trail PASS"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        decision = _decision_for(control_results)
        decision_reason = (
            f"Imported from Snowflake LOGIN_HISTORY: event_type={event_type} "
            f"user={user_name} success={is_success or 'unknown'} "
            f"first={first_factor or 'none'} "
            f"second={second_factor or 'none'} "
            f"error_code={error_code if error_code is not None else 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"snowflake-login-{event_id}",
            timestamp=event_timestamp,
            agent_id=self.agent_id,
            source_type="snowflake_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    # ----------------------------------------------------------------------
    # Synthetic findings
    # ----------------------------------------------------------------------

    def _synthetic_cross_database_result(
        self,
        *,
        user_name: str,
        databases: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_database_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"snowflake-cross-database-{user_name}"
        evidence: dict[str, Any] = {
            "snowflake_synthetic_id": synthetic_id,
            "user_name": user_name,
            "cross_database_databases": databases,
            "cross_database_database_count": len(databases),
            "cross_database_threshold": self.cross_database_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "snowflake",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Snowflake synthetic finding: user {user_name!r} touched "
                f"{len(databases)} databases in this export "
                f"({', '.join(databases)}) — exceeds cross-database threshold "
                f"{self.cross_database_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snowflake_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Snowflake: synthetic cross-database pattern "
                f"for user={user_name} dbs={len(databases)}>threshold="
                f"{self.cross_database_threshold}"
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
        synthetic_id = f"snowflake-high-volume-sensitive-{user_name}"
        evidence: dict[str, Any] = {
            "snowflake_synthetic_id": synthetic_id,
            "user_name": user_name,
            "high_volume_count": count,
            "high_volume_threshold": self.high_volume_sensitive_read_threshold,
            "high_volume_window_seconds": self.brute_force_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "snowflake",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Snowflake synthetic finding: user {user_name!r} executed "
                f"{count} sensitive-table SELECTs in 1h "
                f"(> threshold {self.high_volume_sensitive_read_threshold})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snowflake_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Snowflake: synthetic high-volume sensitive-read "
                f"pattern for user={user_name} count={count}>threshold="
                f"{self.high_volume_sensitive_read_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_brute_force_result(
        self,
        *,
        client_ip: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "brute_force_pattern"
        control_id = _control_for(signal, self._mappings, "PR-01")
        client_ip_masked = _mask_client_ip(client_ip) or client_ip
        synthetic_id = f"snowflake-brute-force-{client_ip_masked}"
        evidence: dict[str, Any] = {
            "snowflake_synthetic_id": synthetic_id,
            "client_ip_masked": client_ip_masked,
            "brute_force_count": count,
            "brute_force_threshold": self.brute_force_threshold,
            "brute_force_window_seconds": self.brute_force_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "snowflake",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"Snowflake synthetic finding: {count} failed logins from "
                f"masked IP {client_ip_masked} in "
                f"{self.brute_force_window_seconds}s "
                f"(> threshold {self.brute_force_threshold}) — brute-force "
                f"pattern"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="snowflake_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from Snowflake: synthetic brute-force pattern "
                f"ip={client_ip_masked} count={count}>threshold="
                f"{self.brute_force_threshold}"
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
