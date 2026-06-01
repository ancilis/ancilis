"""PostgreSQL pgaudit importer — maps pgaudit/CSV-log audit records to AKSI
controls.

PostgreSQL (https://www.postgresql.org) is the dominant open-source relational
database; pgaudit (https://github.com/pgaudit/pgaudit) is the de-facto standard
audit-logging extension. Agents that query application data hit Postgres far
more than they hit warehouses, so the relational-database evidence surface is a
hard requirement for runtime evidence — this importer is the relational peer of
the Snowflake importer (data-warehouse).

pgaudit emits records into Postgres' standard ``csvlog`` (or stderr) and tags
each statement with a class (READ / WRITE / FUNCTION / ROLE / DDL / MISC /
MISC_SET) plus the SQL ``command_tag`` (SELECT, INSERT, GRANT, DROP, COPY, …).
This importer accepts the JSON-converted form of those records — operators are
expected to convert their CSV log into the JSON envelopes below upstream of
Ancilis (or use any pgaudit-aware shipper that does the same).

Accepted on-disk shapes:

  1. ``{"events": [...]}``
  2. ``{"data":   [...]}``
  3. JSONL — one record per line
  4. Single record dict

Mapping (see shared/mappings/postgres-pgaudit-aksi-controls.json):

  * class=READ command_tag=SELECT object_type=TABLE/VIEW (non-sensitive) → PR-04 PASS
  * class=READ on a sensitive-pattern table                               → PR-04 FLAG
  * class=READ on pg_authid / pg_shadow / pg_user_mapping                 → PR-04 FAIL
    (reading password-hash tables = credential exfiltration)
  * class=WRITE INSERT/UPDATE                                             → PR-03 PASS
  * class=WRITE DELETE rows_affected > threshold                          → PR-02 FLAG (mass-delete)
  * class=WRITE DELETE on sensitive table                                 → PR-02 FAIL
  * class=DDL DROP TABLE/DATABASE/SCHEMA                                  → PR-02 FAIL (schema destruction)
  * class=DDL ALTER on sensitive table                                    → PR-02 FLAG
  * class=DDL CREATE …                                                    → PR-05 PASS (audit trail)
  * class=ROLE GRANT/REVOKE/CREATE ROLE/DROP ROLE/ALTER ROLE              → PR-02 FLAG
  * is_superuser=true on routine class=READ/WRITE                         → PR-02 FLAG (over-privileged)
  * is_superuser=true command_tag=DROP ROLE                               → PR-02 FAIL
  * error_severity=FATAL or PANIC                                         → DE-01 FAIL
  * error_severity=ERROR with class=ROLE                                  → PR-02 PASS (denied)
  * error_severity=ERROR with class=READ on sensitive table               → PR-02 PASS (denied)
  * ssl_used=false                                                        → PR-04 FAIL (unencrypted DB connection)
  * ssl_protocol in {TLSv1.0, TLSv1.1}                                    → PR-04 FAIL (legacy TLS)
  * command_tag=COPY on sensitive table                                   → PR-04 FLAG (bulk export)
  * command_tag=COPY ... TO PROGRAM                                       → PR-04 FAIL
    (executing OS commands via SQL — high-impact)
  * client_host external (not RFC1918) on production database             → PR-01 FLAG
  * session_user_name != current_user_name                                → PR-02 FLAG (set_role chain / impersonation)

Cross-record patterns:

  * Same user_name touching > N databases in export                       → PR-02 FLAG synthetic
  * Same user_name with > N sensitive-table SELECTs in 1h                 → PR-04 FAIL synthetic
  * Same user_name with > N DDL operations in 1h                          → PR-02 FLAG synthetic

Sanitization (security-critical — pgaudit records can leak SQL, table names,
customer IDs, error messages):

  * ``statement_text`` is **never stored**. Only the ``statement_text_length``
    integer is captured, and any field that could carry the raw SQL is dropped.
  * ``error_message`` raw is **never stored** (length only).
  * ``object_name`` is captured verbatim *only* when it does NOT match a
    sensitive pattern. Sensitive table names are reduced to match metadata
    (``{matched_pattern, schema_qualified: bool, leaf_sha256, schema_name}``)
    so PII-bearing names like ``app.customers_ssn`` are not stored raw.
  * ``client_host`` is masked to a /16 (IPv4) or /32 (IPv6); RFC1918 / loopback
    / link-local addresses are preserved verbatim.
  * ``application_name`` is reduced to ``{prefix: <first 30>, sha256: <hex>}``.
  * ``session_id`` is reduced to its last 8 characters.
  * The original file is hashed (sha256) for source provenance.

The SDK does **not** depend on ``psycopg2``; exports are parsed with the
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


# Mapping table lives at <repo>/shared/mappings/postgres-pgaudit-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/postgres_pgaudit.py —
# five .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "postgres-pgaudit-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallbacks used if the mapping JSON is missing or malformed.
_DEFAULT_COMMAND_CLASS_PATTERNS: dict[str, dict[str, str]] = {
    "READ":     {"signal": "db_read",          "result": "PASS", "control": "PR-04"},
    "WRITE":    {"signal": "db_write",         "result": "PASS", "control": "PR-03"},
    "FUNCTION": {"signal": "db_function_call", "result": "PASS", "control": "PR-05"},
    "ROLE":     {"signal": "role_change",      "result": "FLAG", "control": "PR-02"},
    "DDL":      {"signal": "schema_change",    "result": "PASS", "control": "PR-05"},
    "MISC":     {"signal": "db_misc",          "result": "PASS", "control": "PR-05"},
    "MISC_SET": {"signal": "session_set",      "result": "PASS", "control": "PR-05"},
}

_DEFAULT_SENSITIVE_TABLE_PATTERNS: tuple[str, ...] = (
    "*customers*", "*employees*", "*payroll*", "*pii*", "*phi*",
    "*ssn*", "*credit*", "*audit_log*", "pg_*shadow*", "pg_*authid*",
)
_DEFAULT_SYSTEM_CATALOG_SECRET_TABLES: frozenset[str] = frozenset(
    {"pg_authid", "pg_shadow", "pg_user_mapping"}
)
_DEFAULT_LEGACY_TLS_PROTOCOLS: frozenset[str] = frozenset({"TLSv1.0", "TLSv1.1"})
_DEFAULT_DDL_DESTRUCTIVE_TARGETS: frozenset[str] = frozenset(
    {"TABLE", "DATABASE", "SCHEMA"}
)
_DEFAULT_ROLE_COMMAND_TAGS: frozenset[str] = frozenset(
    {"GRANT", "REVOKE", "CREATE ROLE", "DROP ROLE", "ALTER ROLE"}
)

_DEFAULT_MASS_DELETE_THRESHOLD = 1000
_DEFAULT_CROSS_DATABASE_THRESHOLD = 3
_DEFAULT_MASS_SENSITIVE_READ_THRESHOLD = 100
_DEFAULT_HIGH_VOLUME_DDL_THRESHOLD = 50
_DEFAULT_PATTERN_WINDOW_SECONDS = 3600


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the postgres-pgaudit-aksi-controls.json mapping; tolerate missing file."""
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


def _mask_client_host(client_host: str | None) -> str | None:
    """Mask a Postgres client_host to a privacy-aware form.

    * RFC1918 / loopback / link-local preserved verbatim (already non-routable).
    * Public IPv4 reduced to ``X.Y.0.0/16``.
    * Public IPv6 reduced to ``HHHH:HHHH::/32``.
    * Hostnames / non-IP markers preserved verbatim.
    """
    if not client_host or not isinstance(client_host, str):
        return None
    ip = client_host.strip()
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


def _is_external_client(client_host: str | None) -> bool:
    """True iff client_host parses as a public (non-RFC1918) IP address.

    Hostnames and unparseable values are conservative-False — callers that
    care about a missing host should check separately.
    """
    if not isinstance(client_host, str) or not client_host.strip():
        return False
    try:
        addr = ipaddress.ip_address(client_host.strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _redact_application_name(value: str | None) -> dict[str, Any] | None:
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


def _short_session_id(session_id: str) -> str:
    """Reduce a Postgres session_id to its last 8 characters."""
    sid = session_id.strip()
    if len(sid) <= 8:
        return sid
    return sid[-8:]


def _split_object_name(object_name: str) -> tuple[str, str]:
    """Split ``schema.table`` into (schema, leaf). Returns ('', name) if bare."""
    s = object_name.strip()
    if not s:
        return ("", "")
    if "." in s:
        head, _, leaf = s.rpartition(".")
        return (head, leaf)
    return ("", s)


def _matches_sensitive(
    object_name: str, patterns: tuple[str, ...]
) -> tuple[bool, str | None]:
    """Match an object_name against sensitive patterns (case-insensitive).

    Patterns are fnmatch globs. We test the raw fully-qualified name and
    the unqualified leaf. Returns (matched, matched_pattern).
    """
    if not object_name:
        return (False, None)
    name_lower = object_name.lower()
    _, leaf = _split_object_name(name_lower)
    for pat in patterns:
        pat_l = pat.lower()
        if fnmatch.fnmatchcase(name_lower, pat_l) or fnmatch.fnmatchcase(
            leaf, pat_l
        ):
            return (True, pat)
    return (False, None)


def _sanitize_object_name(
    object_name: str | None,
    sensitive_patterns: tuple[str, ...],
) -> dict[str, Any]:
    """Return ``{name, sensitive, matched_pattern, schema_name, leaf_sha256}``.

    When the object_name matches a sensitive pattern we reduce it to match
    metadata so the bare table name (which can itself be PII — see
    ``app.customers_ssn``) is not stored raw. Non-sensitive object names are
    captured verbatim.
    """
    if not isinstance(object_name, str) or not object_name.strip():
        return {
            "name": None,
            "sensitive": False,
            "matched_pattern": None,
            "schema_name": None,
            "leaf_sha256": None,
        }
    raw = object_name.strip()
    schema, leaf = _split_object_name(raw)
    is_sensitive, matched = _matches_sensitive(raw, sensitive_patterns)
    if is_sensitive:
        return {
            "name": None,
            "sensitive": True,
            "matched_pattern": matched,
            "schema_name": schema or None,
            "leaf_sha256": hashlib.sha256(leaf.encode("utf-8")).hexdigest(),
        }
    return {
        "name": raw,
        "sensitive": False,
        "matched_pattern": None,
        "schema_name": schema or None,
        "leaf_sha256": None,
    }


def _is_system_catalog_secret(
    object_name: str | None, secret_tables: frozenset[str]
) -> bool:
    """True iff object_name resolves to a catalog table that holds password hashes."""
    if not isinstance(object_name, str) or not object_name.strip():
        return False
    _, leaf = _split_object_name(object_name.strip().lower())
    return leaf in secret_tables


def _statement_contains_to_program(statement_text: str | None) -> bool:
    """Check whether a (post-sanitized) snippet flags as ``COPY ... TO PROGRAM``.

    ``statement_text`` is normally NEVER stored — but pgaudit configs sometimes
    surface a parameter-stripped pseudo-text or a TO-PROGRAM marker field that
    we *can* inspect transiently to make a routing decision. After making the
    decision we drop the snippet and never persist it.
    """
    if not isinstance(statement_text, str) or not statement_text.strip():
        return False
    upper = statement_text.upper()
    return "TO PROGRAM" in upper or "FROM PROGRAM" in upper


def _parse_iso(ts: str) -> datetime | None:
    """Best-effort ISO-8601 parse. Returns None for unparseable inputs."""
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
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


class PostgresPgAuditImporter:
    """Parse a pgaudit-formatted JSON export and convert to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        mass_delete_threshold: int | None = None,
        cross_database_threshold: int | None = None,
        mass_sensitive_read_threshold: int | None = None,
        high_volume_ddl_threshold: int | None = None,
        pattern_window_seconds: int | None = None,
        sensitive_table_patterns: Iterable[str] | None = None,
        system_catalog_secret_tables: Iterable[str] | None = None,
        legacy_tls_protocols: Iterable[str] | None = None,
        production_databases: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }

        # command_class patterns — table > built-in defaults.
        meta_ccp = meta.get("command_class_patterns")
        if isinstance(meta_ccp, dict) and meta_ccp:
            self._command_class_patterns: dict[str, dict[str, str]] = {
                str(k).upper(): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_ccp.items()
                if isinstance(v, dict)
            }
        else:
            self._command_class_patterns = dict(_DEFAULT_COMMAND_CLASS_PATTERNS)

        # Sensitive table patterns.
        if sensitive_table_patterns is not None:
            self.sensitive_table_patterns = tuple(
                str(p) for p in sensitive_table_patterns
            )
        else:
            meta_pat = meta.get("sensitive_table_patterns")
            if isinstance(meta_pat, list) and meta_pat:
                self.sensitive_table_patterns = tuple(str(p) for p in meta_pat)
            else:
                self.sensitive_table_patterns = _DEFAULT_SENSITIVE_TABLE_PATTERNS

        # System-catalog credential tables.
        if system_catalog_secret_tables is not None:
            self.system_catalog_secret_tables = frozenset(
                str(t).lower() for t in system_catalog_secret_tables
            )
        else:
            meta_sec = meta.get("system_catalog_secret_tables")
            if isinstance(meta_sec, list) and meta_sec:
                self.system_catalog_secret_tables = frozenset(
                    str(t).lower() for t in meta_sec
                )
            else:
                self.system_catalog_secret_tables = (
                    _DEFAULT_SYSTEM_CATALOG_SECRET_TABLES
                )

        # Legacy TLS protocol set.
        if legacy_tls_protocols is not None:
            self.legacy_tls_protocols = frozenset(
                str(p) for p in legacy_tls_protocols
            )
        else:
            meta_tls = meta.get("legacy_tls_protocols")
            if isinstance(meta_tls, list) and meta_tls:
                self.legacy_tls_protocols = frozenset(str(p) for p in meta_tls)
            else:
                self.legacy_tls_protocols = _DEFAULT_LEGACY_TLS_PROTOCOLS

        # Production-database allowlist (configurable; empty default => any
        # database name with "prod" prefix or substring is treated as prod —
        # see ``_is_production_database``).
        self.production_databases = frozenset(
            str(d).lower() for d in (production_databases or ())
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

        self.mass_delete_threshold = _resolve_int(
            mass_delete_threshold,
            "mass_delete_threshold",
            _DEFAULT_MASS_DELETE_THRESHOLD,
        )
        self.cross_database_threshold = _resolve_int(
            cross_database_threshold,
            "cross_database_threshold",
            _DEFAULT_CROSS_DATABASE_THRESHOLD,
        )
        self.mass_sensitive_read_threshold = _resolve_int(
            mass_sensitive_read_threshold,
            "mass_sensitive_read_threshold",
            _DEFAULT_MASS_SENSITIVE_READ_THRESHOLD,
        )
        self.high_volume_ddl_threshold = _resolve_int(
            high_volume_ddl_threshold,
            "high_volume_ddl_threshold",
            _DEFAULT_HIGH_VOLUME_DDL_THRESHOLD,
        )
        self.pattern_window_seconds = _resolve_int(
            pattern_window_seconds,
            "pattern_window_seconds",
            _DEFAULT_PATTERN_WINDOW_SECONDS,
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a pgaudit JSON export from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._records_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse pgaudit content from a JSON / JSONL string."""
        events = self._records_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events":[]}`` / ``{"data":[]}`` / list / single / JSONL."""
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
                # Single record envelope.
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
        # ---- First pass: aggregate cross-record patterns.
        user_databases: dict[str, set[str]] = {}
        user_sensitive_reads: dict[str, list[datetime]] = {}
        user_ddls: dict[str, list[datetime]] = {}
        for ev in events:
            user = str(ev.get("user_name") or "")
            db = str(ev.get("database_name") or "")
            if user and db:
                user_databases.setdefault(user, set()).add(db)
            cls = str(ev.get("class") or ev.get("audit_type") or "").upper()
            cmd = str(ev.get("command_tag") or "").upper()
            obj_name = str(ev.get("object_name") or "")
            ts = _parse_iso(str(ev.get("log_time") or ""))
            if cls == "READ" and user and ts is not None:
                is_sens, _ = _matches_sensitive(obj_name, self.sensitive_table_patterns)
                if is_sens:
                    user_sensitive_reads.setdefault(user, []).append(ts)
            if cls == "DDL" and user and ts is not None and cmd:
                user_ddls.setdefault(user, []).append(ts)

        cross_db_users = {
            u: sorted(dbs)
            for u, dbs in user_databases.items()
            if len(dbs) > self.cross_database_threshold
        }

        mass_sensitive_users = self._sliding_window_breaches(
            user_sensitive_reads,
            window_seconds=self.pattern_window_seconds,
            threshold=self.mass_sensitive_read_threshold,
        )
        high_volume_ddl_users = self._sliding_window_breaches(
            user_ddls,
            window_seconds=self.pattern_window_seconds,
            threshold=self.high_volume_ddl_threshold,
        )

        # ---- Per-record results.
        results: list[EvaluationResult] = []
        for ev in events:
            results.append(
                self._parse_event(
                    ev,
                    file_sha256=file_sha256,
                    cross_db_users=cross_db_users,
                    mass_sensitive_users=mass_sensitive_users,
                    high_volume_ddl_users=high_volume_ddl_users,
                )
            )

        # ---- Synthetic findings.
        for user, dbs in sorted(cross_db_users.items()):
            results.append(
                self._synthetic_cross_database_result(
                    user_name=user, databases=dbs, file_sha256=file_sha256
                )
            )
        for user, count in sorted(mass_sensitive_users.items()):
            results.append(
                self._synthetic_mass_sensitive_read_result(
                    user_name=user, count=count, file_sha256=file_sha256
                )
            )
        for user, count in sorted(high_volume_ddl_users.items()):
            results.append(
                self._synthetic_high_volume_ddl_result(
                    user_name=user, count=count, file_sha256=file_sha256
                )
            )
        return results

    @staticmethod
    def _sliding_window_breaches(
        user_times: dict[str, list[datetime]],
        *,
        window_seconds: int,
        threshold: int,
    ) -> dict[str, int]:
        out: dict[str, int] = {}
        for user, times in user_times.items():
            times.sort()
            max_count = 0
            j = 0
            for i in range(len(times)):
                while (times[i] - times[j]).total_seconds() > window_seconds:
                    j += 1
                count = i - j + 1
                if count > max_count:
                    max_count = count
            if max_count > threshold:
                out[user] = max_count
        return out

    # -- Provenance ---------------------------------------------------------

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
        record_kind: str = "event",
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "postgres-pgaudit",
            "source_tool_name": "pgaudit",
            "source_tool_version": "",
            "record_kind": record_kind,
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _is_production_database(self, database_name: str) -> bool:
        """Best-effort: explicit allowlist > ``prod`` substring heuristic."""
        if not database_name:
            return False
        name = database_name.lower()
        if self.production_databases:
            return name in self.production_databases
        return "prod" in name

    # ----------------------------------------------------------------------
    # Event parsing
    # ----------------------------------------------------------------------

    def _parse_event(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_db_users: dict[str, list[str]],
        mass_sensitive_users: dict[str, int],
        high_volume_ddl_users: dict[str, int],
    ) -> EvaluationResult:
        log_time = str(
            record.get("log_time") or datetime.now(timezone.utc).isoformat()
        )
        user_name = str(record.get("user_name") or "")
        database_name = str(record.get("database_name") or "")
        session_id_raw = str(record.get("session_id") or "")
        session_id_short = _short_session_id(session_id_raw) if session_id_raw else ""
        try:
            process_id = int(record.get("process_id") or 0)
        except (TypeError, ValueError):
            process_id = 0
        try:
            session_line_num = int(record.get("session_line_num") or 0)
        except (TypeError, ValueError):
            session_line_num = 0
        command_tag = str(record.get("command_tag") or "").upper().strip()
        audit_type = str(record.get("audit_type") or "").upper().strip()
        cls_raw = str(record.get("class") or audit_type).upper().strip()
        cls = cls_raw or audit_type
        try:
            statement_id = int(record.get("statement_id") or 0)
        except (TypeError, ValueError):
            statement_id = 0
        try:
            substatement_id = int(record.get("substatement_id") or 0)
        except (TypeError, ValueError):
            substatement_id = 0
        object_type = str(record.get("object_type") or "").upper().strip()
        object_name_raw = str(record.get("object_name") or "")
        object_name_redacted = _sanitize_object_name(
            object_name_raw, self.sensitive_table_patterns
        )
        try:
            statement_text_length = int(record.get("statement_text_length") or 0)
        except (TypeError, ValueError):
            statement_text_length = 0
        try:
            parameter_count = int(record.get("parameter_count") or 0)
        except (TypeError, ValueError):
            parameter_count = 0
        session_user_name = str(record.get("session_user_name") or "")
        current_user_name = str(record.get("current_user_name") or "")
        client_host_raw = record.get("client_host")
        client_host = (
            client_host_raw if isinstance(client_host_raw, str) else None
        )
        client_host_masked = _mask_client_host(client_host)
        application_name_redacted = _redact_application_name(
            record.get("application_name")
            if isinstance(record.get("application_name"), str)
            else None
        )
        try:
            duration_ms = float(record.get("duration_ms") or 0.0)
        except (TypeError, ValueError):
            duration_ms = 0.0
        try:
            rows_affected = int(record.get("rows_affected") or 0)
        except (TypeError, ValueError):
            rows_affected = 0
        error_severity_raw = record.get("error_severity")
        error_severity = (
            str(error_severity_raw).upper().strip()
            if isinstance(error_severity_raw, str) and error_severity_raw.strip()
            else None
        )
        try:
            error_message_length = int(record.get("error_message_length") or 0)
        except (TypeError, ValueError):
            error_message_length = 0
        transaction_id_raw = record.get("transaction_id")
        transaction_id: int | None
        try:
            transaction_id = (
                int(transaction_id_raw) if transaction_id_raw is not None else None
            )
        except (TypeError, ValueError):
            transaction_id = None

        ssl_used_raw = record.get("ssl_used")
        if isinstance(ssl_used_raw, bool):
            ssl_used: bool | None = ssl_used_raw
        elif isinstance(ssl_used_raw, str):
            su = ssl_used_raw.strip().lower()
            ssl_used = su == "true" if su in ("true", "false") else None
        else:
            ssl_used = None
        ssl_protocol_raw = record.get("ssl_protocol")
        ssl_protocol = (
            str(ssl_protocol_raw).strip()
            if isinstance(ssl_protocol_raw, str) and ssl_protocol_raw.strip()
            else None
        )
        ssl_cipher_raw = record.get("ssl_cipher")
        ssl_cipher = (
            str(ssl_cipher_raw).strip()
            if isinstance(ssl_cipher_raw, str) and ssl_cipher_raw.strip()
            else None
        )

        is_superuser_raw = record.get("is_superuser")
        if isinstance(is_superuser_raw, bool):
            is_superuser: bool | None = is_superuser_raw
        elif isinstance(is_superuser_raw, str):
            sb = is_superuser_raw.strip().lower()
            is_superuser = sb == "true" if sb in ("true", "false") else None
        else:
            is_superuser = None
        schema_path_raw = record.get("schema_path") or []
        schema_path = (
            [str(p) for p in schema_path_raw if isinstance(p, str)]
            if isinstance(schema_path_raw, list)
            else []
        )

        # Statement-text snippet — used transiently to detect COPY ... TO PROGRAM
        # (which only pgaudit records expose via a ``statement_text`` field at
        # all). After we've made the routing decision we drop the snippet and
        # never persist it; only the length is captured.
        statement_text_snippet = record.get("statement_text")
        copy_to_program = (
            command_tag == "COPY"
            and _statement_contains_to_program(
                statement_text_snippet
                if isinstance(statement_text_snippet, str)
                else None
            )
        )

        sensitive_obj = bool(object_name_redacted.get("sensitive"))
        catalog_secret = _is_system_catalog_secret(
            object_name_raw, self.system_catalog_secret_tables
        )
        external_client = _is_external_client(client_host)

        common_evidence: dict[str, Any] = {
            "log_time": log_time,
            "user_name": user_name,
            "database_name": database_name,
            "session_id_suffix": session_id_short,
            "process_id": process_id,
            "session_line_num": session_line_num,
            "command_tag": command_tag,
            "audit_type": audit_type,
            "class": cls,
            "statement_id": statement_id,
            "substatement_id": substatement_id,
            "object_type": object_type,
            "object_name_redacted": object_name_redacted,
            "statement_text_length": statement_text_length,
            "parameter_count": parameter_count,
            "session_user_name": session_user_name,
            "current_user_name": current_user_name,
            "client_host_masked": client_host_masked,
            "client_host_external": external_client,
            "application_name_redacted": application_name_redacted,
            "duration_ms": duration_ms,
            "rows_affected": rows_affected,
            "error_severity": error_severity,
            "error_message_length": error_message_length,
            "transaction_id": transaction_id,
            "ssl_used": ssl_used,
            "ssl_protocol": ssl_protocol,
            "ssl_cipher": ssl_cipher,
            "is_superuser": is_superuser,
            "schema_path": schema_path,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=session_id_raw or None,
                record_kind="event",
            ),
            "source_tool": "pgaudit",
        }

        control_results: list[ControlResult] = []
        action_id_seed = (
            f"{session_id_short or 'noses'}-{statement_id}-{substatement_id}"
        )

        # ------------------------------------------------------------------
        # 1. Connection-layer FAIL signals (TLS / unencrypted).
        # ------------------------------------------------------------------
        if ssl_used is False:
            self._add(
                control_results,
                signal="unencrypted_connection",
                default_control="PR-04",
                result="FAIL",
                detail=(
                    f"pgaudit event for user {user_name!r} on db "
                    f"{database_name!r} ran on an unencrypted connection "
                    f"(ssl_used=false) — credential and data leakage risk"
                ),
                evidence=common_evidence,
            )
        elif (
            ssl_protocol is not None and ssl_protocol in self.legacy_tls_protocols
        ):
            self._add(
                control_results,
                signal="legacy_tls",
                default_control="PR-04",
                result="FAIL",
                detail=(
                    f"pgaudit event for user {user_name!r} on db "
                    f"{database_name!r} used legacy TLS protocol "
                    f"{ssl_protocol!r}"
                ),
                evidence=common_evidence,
            )

        # ------------------------------------------------------------------
        # 2. COPY ... TO PROGRAM (FAIL — OS command execution via SQL).
        # ------------------------------------------------------------------
        if copy_to_program:
            self._add(
                control_results,
                signal="copy_to_program",
                default_control="PR-04",
                result="FAIL",
                detail=(
                    f"pgaudit event {action_id_seed} COPY by user "
                    f"{user_name!r} executes an external program "
                    f"(TO/FROM PROGRAM) — high-impact OS-command-via-SQL"
                ),
                evidence=common_evidence,
            )

        # ------------------------------------------------------------------
        # 3. Error-severity-driven routing.
        # ------------------------------------------------------------------
        sev = error_severity or ""
        if sev in ("FATAL", "PANIC"):
            self._add(
                control_results,
                signal="fatal_error",
                default_control="DE-01",
                result="FAIL",
                detail=(
                    f"pgaudit event for user {user_name!r} on db "
                    f"{database_name!r} returned {sev} — baseline-detection "
                    f"escalation"
                ),
                evidence=common_evidence,
            )
        elif sev == "ERROR" and cls == "ROLE":
            self._add(
                control_results,
                signal="access_denied_role",
                default_control="PR-02",
                result="PASS",
                detail=(
                    f"pgaudit event {action_id_seed}: ROLE-class command "
                    f"{command_tag!r} correctly denied for user "
                    f"{user_name!r} (audit-trail evidence)"
                ),
                evidence=common_evidence,
            )
        elif sev == "ERROR" and cls == "READ" and sensitive_obj:
            self._add(
                control_results,
                signal="access_denied_sensitive",
                default_control="PR-02",
                result="PASS",
                detail=(
                    f"pgaudit event {action_id_seed}: READ on a sensitive "
                    f"object correctly denied for user {user_name!r} "
                    f"(audit-trail evidence)"
                ),
                evidence=common_evidence,
            )
        else:
            # ------------------------------------------------------------------
            # 4. Class-driven primary classification.
            # ------------------------------------------------------------------
            self._append_class_signal(
                control_results,
                common_evidence=common_evidence,
                cls=cls,
                command_tag=command_tag,
                object_type=object_type,
                sensitive_obj=sensitive_obj,
                catalog_secret=catalog_secret,
                rows_affected=rows_affected,
                action_id_seed=action_id_seed,
                user_name=user_name,
                database_name=database_name,
                is_superuser=bool(is_superuser),
            )

        # ------------------------------------------------------------------
        # 5. Over-privileged superuser on routine READ/WRITE.
        # ------------------------------------------------------------------
        if (
            is_superuser is True
            and cls in ("READ", "WRITE")
            and sev != "ERROR"
            and not catalog_secret
        ):
            self._add(
                control_results,
                signal="over_privileged_routine",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: routine {cls} executed "
                    f"by superuser {user_name!r} — over-privileged for "
                    f"day-to-day workload"
                ),
                evidence=common_evidence,
            )

        # ------------------------------------------------------------------
        # 6. Superuser DROP ROLE (FAIL — superuser target destruction).
        # ------------------------------------------------------------------
        if (
            is_superuser is True
            and command_tag in ("DROP ROLE", "DROP USER")
        ):
            self._add(
                control_results,
                signal="superuser_drop_role",
                default_control="PR-02",
                result="FAIL",
                detail=(
                    f"pgaudit event {action_id_seed}: superuser "
                    f"{user_name!r} executed {command_tag!r} — privilege "
                    f"removal of a superuser is high-blast-radius"
                ),
                evidence=common_evidence,
            )

        # ------------------------------------------------------------------
        # 7. set_role chain / impersonation marker.
        # ------------------------------------------------------------------
        if (
            session_user_name
            and current_user_name
            and session_user_name != current_user_name
        ):
            self._add(
                control_results,
                signal="set_role_chain",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: session_user="
                    f"{session_user_name!r} != current_user="
                    f"{current_user_name!r} — SET ROLE / impersonation "
                    f"detected"
                ),
                evidence=common_evidence,
            )

        # ------------------------------------------------------------------
        # 8. External client on production database.
        # ------------------------------------------------------------------
        if external_client and self._is_production_database(database_name):
            self._add(
                control_results,
                signal="external_client_on_prod",
                default_control="PR-01",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: external client "
                    f"{client_host_masked} on production database "
                    f"{database_name!r}"
                ),
                evidence=common_evidence,
            )

        # ------------------------------------------------------------------
        # 9. Cross-record markers.
        # ------------------------------------------------------------------
        if user_name and user_name in cross_db_users:
            self._add(
                control_results,
                signal="cross_database_pattern",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: user {user_name!r} is "
                    f"part of a cross-database pattern "
                    f"({len(cross_db_users[user_name])} dbs > threshold "
                    f"{self.cross_database_threshold})"
                ),
                evidence={
                    **common_evidence,
                    "cross_database_databases": cross_db_users[user_name],
                    "cross_database_threshold": self.cross_database_threshold,
                },
            )
        if user_name and user_name in mass_sensitive_users:
            self._add(
                control_results,
                signal="mass_sensitive_read",
                default_control="PR-04",
                result="FAIL",
                detail=(
                    f"pgaudit event {action_id_seed}: user {user_name!r} is "
                    f"part of a mass-sensitive-read pattern "
                    f"({mass_sensitive_users[user_name]} reads > threshold "
                    f"{self.mass_sensitive_read_threshold} in "
                    f"{self.pattern_window_seconds}s)"
                ),
                evidence={
                    **common_evidence,
                    "mass_sensitive_count": mass_sensitive_users[user_name],
                    "mass_sensitive_threshold": (
                        self.mass_sensitive_read_threshold
                    ),
                },
            )
        if user_name and user_name in high_volume_ddl_users:
            self._add(
                control_results,
                signal="high_volume_ddl",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: user {user_name!r} is "
                    f"part of a high-volume-DDL pattern "
                    f"({high_volume_ddl_users[user_name]} ops > threshold "
                    f"{self.high_volume_ddl_threshold} in "
                    f"{self.pattern_window_seconds}s)"
                ),
                evidence={
                    **common_evidence,
                    "high_volume_ddl_count": high_volume_ddl_users[user_name],
                    "high_volume_ddl_threshold": self.high_volume_ddl_threshold,
                },
            )

        decision = _decision_for(control_results)
        decision_reason = (
            f"Imported from pgaudit: command_tag={command_tag} class={cls} "
            f"db={database_name} user={user_name} object_type={object_type} "
            f"sev={error_severity or 'none'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"pgaudit-event-{action_id_seed}",
            timestamp=log_time,
            agent_id=self.agent_id,
            source_type="postgres_pgaudit_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=duration_ms,
            session_id=session_id_short or None,
        )

    # -- Class-routing helper ----------------------------------------------

    def _append_class_signal(
        self,
        control_results: list[ControlResult],
        *,
        common_evidence: dict[str, Any],
        cls: str,
        command_tag: str,
        object_type: str,
        sensitive_obj: bool,
        catalog_secret: bool,
        rows_affected: int,
        action_id_seed: str,
        user_name: str,
        database_name: str,
        is_superuser: bool,
    ) -> None:
        # ---- READ
        if cls == "READ":
            if catalog_secret:
                self._add(
                    control_results,
                    signal="db_read_credential_table",
                    default_control="PR-04",
                    result="FAIL",
                    detail=(
                        f"pgaudit event {action_id_seed}: READ on Postgres "
                        f"credential catalog table by user {user_name!r} — "
                        f"password-hash-table access is credential "
                        f"exfiltration"
                    ),
                    evidence=common_evidence,
                )
                return
            if sensitive_obj:
                self._add(
                    control_results,
                    signal="db_read_sensitive",
                    default_control="PR-04",
                    result="FLAG",
                    detail=(
                        f"pgaudit event {action_id_seed}: READ on a "
                        f"sensitive-pattern object by user {user_name!r}"
                    ),
                    evidence=common_evidence,
                )
                return
            self._add(
                control_results,
                signal="db_read",
                default_control="PR-04",
                result="PASS",
                detail=(
                    f"pgaudit event {action_id_seed}: READ {command_tag} on "
                    f"{object_type or 'OBJECT'} by user {user_name!r}"
                ),
                evidence=common_evidence,
            )
            return

        # ---- WRITE
        if cls == "WRITE":
            if command_tag == "DELETE" and sensitive_obj:
                self._add(
                    control_results,
                    signal="db_write_sensitive_delete",
                    default_control="PR-02",
                    result="FAIL",
                    detail=(
                        f"pgaudit event {action_id_seed}: DELETE on a "
                        f"sensitive object by user {user_name!r} "
                        f"(rows_affected={rows_affected})"
                    ),
                    evidence=common_evidence,
                )
                return
            if (
                command_tag == "DELETE"
                and rows_affected > self.mass_delete_threshold
            ):
                self._add(
                    control_results,
                    signal="db_write_mass_delete",
                    default_control="PR-02",
                    result="FLAG",
                    detail=(
                        f"pgaudit event {action_id_seed}: DELETE affected "
                        f"{rows_affected} rows (> threshold "
                        f"{self.mass_delete_threshold}) by user "
                        f"{user_name!r}"
                    ),
                    evidence=common_evidence,
                )
                return
            self._add(
                control_results,
                signal="db_write",
                default_control="PR-03",
                result="PASS",
                detail=(
                    f"pgaudit event {action_id_seed}: WRITE {command_tag} on "
                    f"{object_type or 'OBJECT'} by user {user_name!r} "
                    f"(rows_affected={rows_affected}) — captured for audit "
                    f"trail"
                ),
                evidence=common_evidence,
            )
            return

        # ---- DDL
        if cls == "DDL":
            if (
                command_tag.startswith("DROP ")
                and object_type in _DEFAULT_DDL_DESTRUCTIVE_TARGETS
            ) or command_tag in ("DROP TABLE", "DROP DATABASE", "DROP SCHEMA"):
                self._add(
                    control_results,
                    signal="schema_destruction",
                    default_control="PR-02",
                    result="FAIL",
                    detail=(
                        f"pgaudit event {action_id_seed}: {command_tag} on "
                        f"{object_type or 'OBJECT'} by user {user_name!r} — "
                        f"schema destruction"
                    ),
                    evidence=common_evidence,
                )
                return
            if (
                command_tag.startswith("ALTER ") or command_tag == "ALTER"
            ) and sensitive_obj:
                self._add(
                    control_results,
                    signal="schema_change_sensitive",
                    default_control="PR-02",
                    result="FLAG",
                    detail=(
                        f"pgaudit event {action_id_seed}: ALTER on a "
                        f"sensitive object by user {user_name!r}"
                    ),
                    evidence=common_evidence,
                )
                return
            self._add(
                control_results,
                signal="schema_change",
                default_control="PR-05",
                result="PASS",
                detail=(
                    f"pgaudit event {action_id_seed}: DDL {command_tag} on "
                    f"{object_type or 'OBJECT'} by user {user_name!r} — "
                    f"audit trail recorded"
                ),
                evidence=common_evidence,
            )
            return

        # ---- ROLE
        if cls == "ROLE":
            # COPY override — sensitive table or unconditional FLAG.
            self._add(
                control_results,
                signal="role_change",
                default_control="PR-02",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: ROLE-class command "
                    f"{command_tag!r} by user {user_name!r}"
                ),
                evidence=common_evidence,
            )
            return

        # ---- COPY (special — pgaudit may class as MISC or its own audit_type)
        if command_tag == "COPY" and sensitive_obj:
            self._add(
                control_results,
                signal="copy_sensitive",
                default_control="PR-04",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: COPY on a "
                    f"sensitive object by user {user_name!r}"
                ),
                evidence=common_evidence,
            )
            return

        # ---- Generic / unknown class — fall through the table.
        pattern = self._command_class_patterns.get(cls)
        if pattern is None:
            self._add(
                control_results,
                signal="unknown_class",
                default_control="PR-05",
                result="FLAG",
                detail=(
                    f"pgaudit event {action_id_seed}: unknown class "
                    f"{cls!r} command_tag={command_tag!r} — surfaced for review"
                ),
                evidence=common_evidence,
            )
            return

        signal = pattern.get("signal", "db_misc")
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
                    f"pgaudit event {action_id_seed}: {cls} {command_tag} on "
                    f"{object_type or 'OBJECT'} classified as {signal} "
                    f"({result})"
                ),
                evidence_data={**common_evidence, "signal": signal},
            )
        )

    # -- ControlResult builder helper --------------------------------------

    def _add(
        self,
        control_results: list[ControlResult],
        *,
        signal: str,
        default_control: str,
        result: str,
        detail: str,
        evidence: dict[str, Any],
    ) -> None:
        control_id = _control_for(signal, self._mappings, default_control)
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result=result,
                detail=detail,
                evidence_data={**evidence, "signal": signal},
            )
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
        synthetic_id = f"pgaudit-cross-database-{user_name}"
        evidence: dict[str, Any] = {
            "synthetic_id": synthetic_id,
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
            "source_tool": "pgaudit",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"pgaudit synthetic finding: user {user_name!r} touched "
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
            source_type="postgres_pgaudit_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from pgaudit: synthetic cross-database pattern "
                f"for user={user_name} dbs={len(databases)}>threshold="
                f"{self.cross_database_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_mass_sensitive_read_result(
        self,
        *,
        user_name: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "mass_sensitive_read"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"pgaudit-mass-sensitive-read-{user_name}"
        evidence: dict[str, Any] = {
            "synthetic_id": synthetic_id,
            "user_name": user_name,
            "mass_sensitive_count": count,
            "mass_sensitive_threshold": self.mass_sensitive_read_threshold,
            "mass_sensitive_window_seconds": self.pattern_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "pgaudit",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"pgaudit synthetic finding: user {user_name!r} executed "
                f"{count} sensitive-table SELECTs in "
                f"{self.pattern_window_seconds}s "
                f"(> threshold {self.mass_sensitive_read_threshold}) — "
                f"mass-sensitive-read pattern (likely exfiltration)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="postgres_pgaudit_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from pgaudit: synthetic mass-sensitive-read "
                f"pattern for user={user_name} count={count}>threshold="
                f"{self.mass_sensitive_read_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_high_volume_ddl_result(
        self,
        *,
        user_name: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_volume_ddl"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"pgaudit-high-volume-ddl-{user_name}"
        evidence: dict[str, Any] = {
            "synthetic_id": synthetic_id,
            "user_name": user_name,
            "high_volume_ddl_count": count,
            "high_volume_ddl_threshold": self.high_volume_ddl_threshold,
            "high_volume_ddl_window_seconds": self.pattern_window_seconds,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=synthetic_id,
                record_kind="synthetic",
            ),
            "source_tool": "pgaudit",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"pgaudit synthetic finding: user {user_name!r} executed "
                f"{count} DDL operations in "
                f"{self.pattern_window_seconds}s "
                f"(> threshold {self.high_volume_ddl_threshold})"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="postgres_pgaudit_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from pgaudit: synthetic high-volume-DDL pattern "
                f"for user={user_name} count={count}>threshold="
                f"{self.high_volume_ddl_threshold}"
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
