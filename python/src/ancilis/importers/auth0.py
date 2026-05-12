"""Auth0 tenant log importer — maps identity-event audit records to AKSI controls.

Auth0 (https://auth0.com/docs/api/management/v2/logs) is the second-most-used
enterprise identity provider after Okta — particularly common for B2C and SaaS.
The Management API ``/api/v2/logs`` endpoint exports tenant events: logins,
signups, consent grants, token exchanges, password changes, connection updates,
and Management API operations. CloudTrail covers AWS-internal actions; Okta
SystemLog covers the dominant enterprise SSO surface; Auth0 closes the
identity-provider pair so customers on either platform get equivalent
agent-identity audit coverage.

This importer ingests Auth0 tenant log exports in three on-disk shapes:

  1. ``{"logs": [...]}`` — canonical Auth0 tenant-log envelope
  2. ``{"data":  [...]}`` — generic data envelope
  3. JSONL                 — one log entry per line

Auth0 uses short two-to-five-character ``type`` codes rather than full event
names. The importer maps each code to a human-readable signal name (e.g.
``s`` → ``login_success``, ``ublkd`` → ``user_blocked``) so downstream evidence
is self-describing without forcing analysts to memorize the Auth0 vocabulary.

Signal mapping (see shared/mappings/auth0-aksi-controls.json):
  * type=s (login success)                                 → PR-01 PASS
  * type=f / fp / fu (login failures)                      → PR-01 FLAG
  * type=ublkd (user blocked: multiple failed attempts)    → PR-01 FAIL
  * type=limit_wc (rate limit reached)                     → PR-02 FLAG
  * type=ss (successful signup)                            → PR-01 PASS
  * type=scu (successful connection update)                → PR-02 FLAG
  * type=fcu (failed connection update)                    → PR-02 PASS
  * type=scp (successful password change)                  → PR-01 PASS
  * type=sapi/fapi (Management API ops)                    → PR-02
  * type=sece (successful token exchange) w/ admin scope   → PR-01 FLAG (additive)
  * type=fece (failed token exchange)                      → PR-01 FLAG
  * type=scoa (consent granted)                            → PR-04 PASS
  * type=fcoa (consent denied)                             → PR-04 PASS
  * scope contains admin / read:users / update:users       → PR-02 FLAG (additive)
  * connection=saml or strategy_type=enterprise            → captured (federation)
  * isMobile=true on type=s                                → captured (mobile)
  * details.stats.loginsCount=1 (first-ever login)         → PR-01 captured
  * client_name not in allowlist (configurable)            → PR-01 FLAG
  * cross-country pattern (one user_id touching > N
    distinct country_codes in an export, default 3)        → PR-01 FLAG synthetic

Sanitization (security-critical — Auth0 tenant logs are PII-rich):
  * ``user_id`` is captured verbatim — Auth0 user IDs are pseudonymous by
    design (e.g. ``auth0|abc123``, ``google-oauth2|...``); the prefix carries
    the connection taxonomy which is needed for analysis.
  * ``ip`` is masked to a /16 (public IPv4) or /32 (IPv6); RFC1918 private
    addresses are preserved verbatim.
  * ``user_agent`` is truncated to its first 80 chars and a sha256 of the full
    UA is captured separately. Full UA strings are browser-fingerprintable.
  * ``details.auth.user.email`` is reduced to its email-domain only
    (``alice@corp.example.com`` → ``"@corp.example.com"``). The full email is
    PII; the domain is sufficient to correlate "internal vs external".
  * ``details.auth.user.name`` is reduced to length + sha256 (no plaintext).
  * ``location_info`` is reduced to ``country_code`` only.
    ``city_name`` / ``latitude`` / ``longitude`` are dropped — city-level
    geolocation is too granular for evidence and not needed for posture
    analysis (cross-country and country-of-origin are sufficient signals).
  * ``description`` is truncated to 200 chars (Auth0-managed safe text, but
    truncated as defense-in-depth in case a custom description leaks data).
  * ``details.request`` / ``details.response`` are reduced to top-level keys
    only — values are never stored.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``auth0-python`` package; tenant log JSON
exports are parsed with the standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/auth0.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "auth0-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Built-in fallback if the mapping JSON is missing or malformed. Mirrors the
# canonical `_metadata.type_signals` map in the JSON.
_DEFAULT_TYPE_SIGNALS: dict[str, dict[str, str]] = {
    "s":        {"signal": "login_success",             "result": "PASS", "control": "PR-01"},
    "f":        {"signal": "login_failure",              "result": "FLAG", "control": "PR-01"},
    "fp":       {"signal": "login_failure_password",     "result": "FLAG", "control": "PR-01"},
    "fu":       {"signal": "login_failure_user",         "result": "FLAG", "control": "PR-01"},
    "ublkd":    {"signal": "user_blocked",               "result": "FAIL", "control": "PR-01"},
    "limit_wc": {"signal": "rate_limit_reached",         "result": "FLAG", "control": "PR-02"},
    "ss":       {"signal": "signup_success",             "result": "PASS", "control": "PR-01"},
    "fs":       {"signal": "signup_failure",             "result": "FLAG", "control": "PR-01"},
    "scu":      {"signal": "connection_update_success",  "result": "FLAG", "control": "PR-02"},
    "fcu":      {"signal": "connection_update_failure",  "result": "PASS", "control": "PR-02"},
    "scp":      {"signal": "change_password_success",    "result": "PASS", "control": "PR-01"},
    "sapi":     {"signal": "management_api_success",     "result": "FLAG", "control": "PR-02"},
    "fapi":     {"signal": "management_api_failure",     "result": "PASS", "control": "PR-02"},
    "sece":     {"signal": "token_exchange_success",     "result": "PASS", "control": "PR-01"},
    "fece":     {"signal": "token_exchange_failure",     "result": "FLAG", "control": "PR-01"},
    "scoa":     {"signal": "consent_granted",            "result": "PASS", "control": "PR-04"},
    "fcoa":     {"signal": "consent_denied",             "result": "PASS", "control": "PR-04"},
}

_DEFAULT_TYPE_TO_HUMAN: dict[str, str] = {
    code: meta["signal"] for code, meta in _DEFAULT_TYPE_SIGNALS.items()
}

# Privileged Auth0 scopes — when granted (especially via token exchange),
# raise a PR-02 FLAG so the privilege grant is captured for audit. These
# are exact substrings checked against the space-separated scope string.
_DEFAULT_PRIVILEGED_SCOPE_PATTERNS: tuple[str, ...] = (
    "admin",
    "read:users",
    "update:users",
    "delete:users",
    "create:users",
    "read:clients",
    "update:clients",
    "create:clients",
)

_DEFAULT_CROSS_COUNTRY_THRESHOLD = 3

# Description column is Auth0-managed safe text but truncated as defense-in-depth.
_DESCRIPTION_MAX_LEN = 200

# user_agent prefix length kept verbatim; the full UA is hashed separately.
_USER_AGENT_PREFIX_LEN = 80


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the auth0-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_email_to_domain(value: str | None) -> str | None:
    """Reduce an email-style value to ``"@<domain>"``.

    ``alice@corp.example.com`` → ``"@corp.example.com"``. Non-email strings
    are tagged ``"<non-email>"`` so a username is never accidentally captured.
    """
    if not value or not isinstance(value, str):
        return None
    val = value.strip()
    if not val:
        return None
    if "@" in val:
        domain = val.rsplit("@", 1)[1].strip().lower()
        if domain:
            return f"@{domain}"
        return None
    return "<non-email>"


def _hash_name(name: str | None) -> tuple[int | None, str | None]:
    """Reduce a display name to (length, sha256). Plaintext is never stored."""
    if not name or not isinstance(name, str):
        return None, None
    val = name.strip()
    if not val:
        return None, None
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()
    return len(val), digest


def _classify_ip_address(ip_address: str | None) -> str | None:
    """Mask an Auth0 ``ip`` to a /16 (IPv4) or /32 (IPv6).

    RFC1918 private / loopback / link-local addresses are preserved verbatim.
    """
    if not ip_address or not isinstance(ip_address, str):
        return None
    ip = ip_address.strip()
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


def _redact_user_agent(raw_ua: str | None) -> tuple[str | None, str | None]:
    """Truncate a raw user-agent to first 80 chars and capture sha256 of full."""
    if not raw_ua or not isinstance(raw_ua, str):
        return None, None
    ua = raw_ua.strip()
    if not ua:
        return None, None
    truncated = ua[:_USER_AGENT_PREFIX_LEN]
    digest = hashlib.sha256(ua.encode("utf-8")).hexdigest()
    return truncated, digest


def _truncate_description(description: str | None) -> str | None:
    """Truncate Auth0-managed description text to a defense-in-depth length."""
    if not description or not isinstance(description, str):
        return None
    val = description.strip()
    if not val:
        return None
    if len(val) <= _DESCRIPTION_MAX_LEN:
        return val
    return val[:_DESCRIPTION_MAX_LEN]


def _top_level_keys(value: Any) -> list[str]:
    """Return the sorted top-level keys of a dict (values NEVER captured)."""
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    return []


def _scope_tokens(scope: Any) -> list[str]:
    """Normalize an Auth0 scope value into a list of token strings.

    Auth0 represents scope either as a space-separated string
    (``"openid profile email"``) or as a list of strings. Both shapes are
    accepted; anything else returns an empty list.
    """
    if isinstance(scope, str):
        return [tok for tok in scope.split() if tok]
    if isinstance(scope, list):
        out: list[str] = []
        for tok in scope:
            if isinstance(tok, str):
                stripped = tok.strip()
                if stripped:
                    out.append(stripped)
        return out
    return []


def _scope_has_privileged_pattern(
    scope_tokens: list[str], patterns: tuple[str, ...]
) -> str | None:
    """Return the first matching privileged pattern, or ``None``."""
    if not scope_tokens:
        return None
    # Patterns are substrings (e.g. "admin" matches "admin", "read:admin",
    # and "scope:admin"). Use case-insensitive comparison.
    lowered_tokens = [tok.lower() for tok in scope_tokens]
    for pat in patterns:
        pat_low = pat.lower()
        for tok in lowered_tokens:
            if pat_low in tok:
                return pat
    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class Auth0Importer:
    """Parse an Auth0 tenant log export and convert each entry to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_country_threshold: int | None = None,
        privileged_scope_patterns: Iterable[str] | None = None,
        client_name_allowlist: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Type-code → signal/result/control table.
        meta_types = meta.get("type_signals")
        if isinstance(meta_types, dict) and meta_types:
            self._type_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_types.items()
                if isinstance(v, dict)
            }
        else:
            self._type_signals = {
                k: dict(v) for k, v in _DEFAULT_TYPE_SIGNALS.items()
            }
        # Type-code → human-readable name (for evidence).
        meta_human = meta.get("type_to_human_name")
        if isinstance(meta_human, dict) and meta_human:
            self._type_to_human: dict[str, str] = {
                str(k): str(v) for k, v in meta_human.items()
            }
        else:
            # Derive from type_signals when the mapping omits type_to_human_name.
            self._type_to_human = {
                code: meta_obj.get("signal", code)
                for code, meta_obj in self._type_signals.items()
            }
        # Privileged scope patterns precedence: explicit arg > mapping > default.
        if privileged_scope_patterns is not None:
            self.privileged_scope_patterns: tuple[str, ...] = tuple(
                str(p) for p in privileged_scope_patterns
            )
        else:
            meta_scopes = meta.get("privileged_scope_patterns")
            if isinstance(meta_scopes, list) and meta_scopes:
                self.privileged_scope_patterns = tuple(
                    str(p) for p in meta_scopes
                )
            else:
                self.privileged_scope_patterns = _DEFAULT_PRIVILEGED_SCOPE_PATTERNS
        # Cross-country threshold precedence: explicit arg > mapping > default.
        if cross_country_threshold is not None:
            self.cross_country_threshold = int(cross_country_threshold)
        else:
            self.cross_country_threshold = int(
                meta.get("cross_country_threshold", _DEFAULT_CROSS_COUNTRY_THRESHOLD)
            )
        # Client-name allowlist (optional). When set, any client_name not in
        # the allowlist raises a PR-01 FLAG — supports unknown-OAuth-client
        # detection. ``None`` disables the check.
        if client_name_allowlist is not None:
            self.client_name_allowlist: frozenset[str] | None = frozenset(
                str(c) for c in client_name_allowlist
            )
        else:
            self.client_name_allowlist = None

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an Auth0 tenant log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        logs = self._logs_from_text(text)
        return self._build_results(logs, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Auth0 tenant log content from a JSON or JSONL string."""
        logs = self._logs_from_text(content)
        return self._build_results(logs, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _logs_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"logs": [...]}`` / ``{"data": [...]}`` / JSONL / single log."""
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
                if "logs" in doc and isinstance(doc["logs"], list):
                    return [e for e in doc["logs"] if isinstance(e, dict)]
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Single log entry.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        logs: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-log EvaluationResults plus cross-country synthetic findings."""
        # First pass: aggregate country_codes per user_id for cross-country detection.
        user_countries: dict[str, set[str]] = {}
        for log in logs:
            uid = log.get("user_id")
            location = log.get("location_info") or {}
            if not isinstance(location, dict):
                continue
            country = location.get("country_code")
            if (
                isinstance(uid, str) and uid
                and isinstance(country, str) and country
            ):
                user_countries.setdefault(uid, set()).add(country)

        cross_country_users = {
            uid: sorted(countries)
            for uid, countries in user_countries.items()
            if len(countries) > self.cross_country_threshold
        }

        results = [
            self._parse_log(
                log,
                file_sha256=file_sha256,
                cross_country_users=cross_country_users,
            )
            for log in logs
        ]

        # Synthetic per-user cross-country pattern findings.
        for uid, countries in sorted(cross_country_users.items()):
            results.append(
                self._synthetic_cross_country_result(
                    user_id=uid,
                    countries=countries,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        log_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "auth0_tenant_logs",
            "source_tool_name": "auth0",
            "source_tool_version": "",
        }
        if log_id is not None:
            provenance["log_id"] = log_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-log parsing
    # ------------------------------------------------------------------

    def _parse_log(
        self,
        log: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_country_users: dict[str, list[str]],
    ) -> EvaluationResult:
        # Auth0 uses ``log_id`` and a duplicated ``_id`` field; prefer log_id.
        log_id_raw = log.get("log_id") or log.get("_id") or str(uuid.uuid4())
        log_id = str(log_id_raw)
        type_code = str(log.get("type") or "").strip()
        date = str(log.get("date") or datetime.now(timezone.utc).isoformat())
        description = _truncate_description(
            log.get("description") if isinstance(log.get("description"), str) else None
        )
        connection = str(log.get("connection") or "") or None
        connection_id = str(log.get("connection_id") or "") or None
        client_id = str(log.get("client_id") or "") or None
        client_name = str(log.get("client_name") or "") or None
        tenant_name = str(log.get("tenant_name") or "") or None
        hostname = str(log.get("hostname") or "") or None
        strategy = str(log.get("strategy") or "") or None
        strategy_type = str(log.get("strategy_type") or "") or None
        audience = str(log.get("audience") or "") or None
        user_id_raw = log.get("user_id")
        user_id = str(user_id_raw) if isinstance(user_id_raw, str) and user_id_raw else None

        is_mobile_raw = log.get("isMobile")
        is_mobile: bool | None = (
            bool(is_mobile_raw) if isinstance(is_mobile_raw, bool) else None
        )

        # ---- ip / user_agent (sanitized) ----
        ip_redacted = _classify_ip_address(
            log.get("ip") if isinstance(log.get("ip"), str) else None
        )
        ua_truncated, ua_sha256 = _redact_user_agent(
            log.get("user_agent") if isinstance(log.get("user_agent"), str) else None
        )

        # ---- location_info — country only, drop city / lat / lon ----
        location = log.get("location_info") or {}
        if not isinstance(location, dict):
            location = {}
        country_code = str(location.get("country_code") or "") or None

        # ---- details (sub-tree, sanitized) ----
        details = log.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        request_keys = _top_level_keys(details.get("request"))
        response_keys = _top_level_keys(details.get("response"))
        session_id = details.get("session_id")
        session_id_str = str(session_id) if isinstance(session_id, str) and session_id else None
        # details.scope can override the top-level scope on token-exchange events.
        scope_value = details.get("scope")
        if scope_value is None:
            scope_value = log.get("scope")
        scope_tokens = _scope_tokens(scope_value)
        scope_str = " ".join(scope_tokens) if scope_tokens else None

        # details.auth.user is PII-rich — extract domain + name-hash only.
        auth_obj = details.get("auth") or {}
        if not isinstance(auth_obj, dict):
            auth_obj = {}
        auth_user = auth_obj.get("user") or {}
        if not isinstance(auth_user, dict):
            auth_user = {}
        email_domain = _redact_email_to_domain(
            auth_user.get("email") if isinstance(auth_user.get("email"), str) else None
        )
        name_length, name_sha256 = _hash_name(
            auth_user.get("name") if isinstance(auth_user.get("name"), str) else None
        )

        # details.stats.loginsCount = 1 → first-ever login signal.
        stats = details.get("stats") or {}
        if not isinstance(stats, dict):
            stats = {}
        logins_count_raw = stats.get("loginsCount")
        logins_count: int | None
        if isinstance(logins_count_raw, bool):  # bool is subclass of int — exclude.
            logins_count = None
        elif isinstance(logins_count_raw, int):
            logins_count = logins_count_raw
        else:
            logins_count = None

        # Resolve human-readable signal name for the type code.
        type_human = self._type_to_human.get(type_code)

        common_evidence: dict[str, Any] = {
            "auth0_log_id": log_id,
            "type_code": type_code,
            "type_human": type_human,
            "date": date,
            "description": description,
            "connection": connection,
            "connection_id": connection_id,
            "strategy": strategy,
            "strategy_type": strategy_type,
            "client_id": client_id,
            "client_name": client_name,
            "tenant_name": tenant_name,
            "hostname": hostname,
            "audience": audience,
            "user_id": user_id,
            "is_mobile": is_mobile,
            "client_ip_redacted": ip_redacted,
            "client_user_agent_truncated": ua_truncated,
            "client_user_agent_sha256": ua_sha256,
            "country_code": country_code,
            "details_request_keys": request_keys,
            "details_response_keys": response_keys,
            "details_session_id": session_id_str,
            "details_scope": scope_str,
            "details_auth_user_email_domain": email_domain,
            "details_auth_user_name_length": name_length,
            "details_auth_user_name_sha256": name_sha256,
            "details_stats_logins_count": logins_count,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, log_id=log_id
            ),
            "source_tool": "auth0",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Type-code classification (primary signal).
        # ----------------------------------------------------------------
        type_meta = self._type_signals.get(type_code)
        if type_meta is not None:
            signal = type_meta.get("signal", type_human or "unknown_event")
            control_id = _control_for(
                signal, self._mappings, type_meta.get("control", "PR-05")
            )
            result = type_meta.get("result", "PASS")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Auth0 log {log_id} type={type_code} "
                        f"({signal}) classified as {result}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown type code — surface as PR-05 FLAG so it does not silently pass.
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Auth0 log {log_id} type={type_code!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Privileged scope detection (additive PR-02 FLAG).
        # Fires on any event carrying admin / read:users / update:users etc.
        # in scope. Token exchanges (sece) with admin scope additionally
        # produce an admin_token_exchange PR-01 FLAG (covered below).
        # ----------------------------------------------------------------
        priv_match = _scope_has_privileged_pattern(
            scope_tokens, self.privileged_scope_patterns
        )
        if priv_match is not None:
            signal = "privileged_scope"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Auth0 log {log_id} carries privileged scope "
                        f"matching {priv_match!r} — verify approval trail "
                        f"(scope={scope_str!r})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "privileged_scope_match": priv_match,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 3. Successful token exchange with admin scope → PR-01 FLAG.
        # Token exchange (sece) with admin scope is higher-risk than a plain
        # privileged-scope grant: an admin token has been issued.
        # ----------------------------------------------------------------
        if (
            type_code == "sece"
            and any("admin" in tok.lower() for tok in scope_tokens)
        ):
            signal = "admin_token_exchange"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Auth0 log {log_id} is a successful token exchange "
                        f"that issued an admin-scoped token (scope={scope_str!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. First-ever login (loginsCount=1) on a successful login → PASS.
        # Captured as an audit marker so account-activation events are
        # explicitly recorded for compliance review.
        # ----------------------------------------------------------------
        if type_code == "s" and logins_count == 1:
            signal = "first_ever_login"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Auth0 log {log_id} is the first-ever login for user "
                        f"{user_id!r} (loginsCount=1) — account activation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Mobile session marker on successful login → PASS.
        # ----------------------------------------------------------------
        if type_code == "s" and is_mobile is True:
            signal = "mobile_session"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Auth0 log {log_id} is a successful login from a "
                        f"mobile device — captured for session-channel analysis"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 6. Federation marker — connection=saml or strategy_type=enterprise.
        # ----------------------------------------------------------------
        is_federation = (
            (connection is not None and connection.lower() == "saml")
            or (strategy_type is not None and strategy_type.lower() == "enterprise")
        )
        if is_federation:
            signal = "federation_session"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Auth0 log {log_id} originated from a federated "
                        f"identity source (connection={connection!r}, "
                        f"strategy_type={strategy_type!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 7. Unknown OAuth client (when an allowlist is configured).
        # ----------------------------------------------------------------
        if (
            self.client_name_allowlist is not None
            and client_name is not None
            and client_name not in self.client_name_allowlist
        ):
            signal = "unknown_oauth_client"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Auth0 log {log_id} originated from an OAuth client "
                        f"not in the allowlist (client_name={client_name!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 8. Cross-country pattern — informational per-event marker.
        # The synthetic per-user finding is added separately in the second pass.
        # ----------------------------------------------------------------
        if user_id is not None and user_id in cross_country_users:
            signal = "cross_country_pattern"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Auth0 log {log_id} user {user_id!r} is part of a "
                        f"cross-country pattern "
                        f"({len(cross_country_users[user_id])} countries > "
                        f"threshold {self.cross_country_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_country_country_codes": cross_country_users[user_id],
                        "cross_country_threshold": self.cross_country_threshold,
                    },
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
            f"Imported from Auth0 tenant logs: type={type_code} "
            f"({type_human or 'unknown'}) "
            f"connection={connection or 'unknown'} "
            f"strategy_type={strategy_type or 'unknown'} "
            f"country={country_code or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"auth0-{log_id[:32]}",
            timestamp=date,
            agent_id=self.agent_id,
            source_type="auth0_tenant_logs_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=session_id_str,
        )

    def _synthetic_cross_country_result(
        self,
        *,
        user_id: str,
        countries: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-user cross-country pattern finding."""
        signal = "cross_country_pattern"
        control_id = _control_for(signal, self._mappings, "PR-01")
        # user_id may contain '|' (auth0|abc) which is fine for an action_id.
        synthetic_id = f"auth0-cross-country-{user_id}"
        evidence: dict[str, Any] = {
            "auth0_log_id": synthetic_id,
            "user_id": user_id,
            "cross_country_country_codes": countries,
            "cross_country_country_count": len(countries),
            "cross_country_threshold": self.cross_country_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                log_id=synthetic_id,
            ),
            "source_tool": "auth0",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Auth0 synthetic finding: user {user_id!r} touched "
                f"{len(countries)} countries in this export "
                f"({', '.join(countries)}) — exceeds cross-country threshold "
                f"{self.cross_country_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="auth0_tenant_logs_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Auth0 tenant logs: synthetic cross-country "
                f"pattern for user={user_id!r} "
                f"countries={len(countries)}>threshold="
                f"{self.cross_country_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
