"""Okta SystemLog importer — maps identity-event audit records to AKSI controls.

Okta (https://developer.okta.com/docs/reference/api/system-log/) is the dominant
enterprise identity provider. Its SystemLog API (``/api/v1/logs``) is the
canonical evidence of "who logged in / who consented / who escalated" for any
compliance audit. CloudTrail covers AWS-internal actions; Okta SystemLog covers
the SSO surface — the gap most enterprise agents touch on day one (SAML token
issuance, MFA challenge, admin-app access, API-token lifecycle).

This importer ingests SystemLog exports in three on-disk shapes:

  1. ``{"events": [...]}`` — canonical Okta API envelope
  2. ``{"data":   [...]}`` — generic data envelope
  3. JSONL                  — one event per line

Signal mapping (see shared/mappings/okta-aksi-controls.json):
  * ``user.authentication.*`` & outcome=SUCCESS    → PR-01 PASS
  * ``user.authentication.*`` & outcome=FAILURE    → PR-01 FLAG (failed login)
  * ``user.authentication.*`` & outcome=CHALLENGE  → PR-01 PASS (MFA prompted)
  * ``user.session.start`` & isProxy=true          → PR-01 FLAG (proxy origin)
  * proxy + anonymizer asOrg ("Tor"/"VPN"/...)     → PR-01 FAIL (anonymizer origin)
  * ``user.session.access_admin_app``              → PR-02 FLAG (admin surface)
  * ``user.account.privilege.grant`` / ``*.privilege.*`` → PR-02 FAIL
  * ``system.api_token.create``                    → PR-01 FLAG (token issuance)
  * ``system.api_token.revoke``                    → PR-05 PASS (audit trail)
  * ``application.user_membership.add`` to admin app → PR-02 FLAG
  * ``policy.lifecycle.deactivate``                → PR-02 FAIL (policy weakening)
  * outcome=DENY                                   → PR-02 PASS (correctly denied)
  * ``iwa.exempt.*``                               → PR-01 FLAG (auth bypass)
  * ``user.mfa.factor.deactivate``                 → PR-01 FAIL (security degradation)
  * cross-country pattern (one actor.id touching > N
    distinct countries in an export, default 3)   → PR-01 FLAG synthetic

Sanitization (security-critical — SystemLog rows are PII-rich):
  * ``actor.id`` (Okta IDs like ``00u...``) is redacted to first-4 / last-4 with
    the middle masked: ``00u1...XYZ4``. This preserves the type-prefix taxonomy
    (``00u`` user, ``00o`` org-app, ``0oa`` app-instance) which is not sensitive.
  * ``actor.alternateId`` is reduced to its **email-domain only**
    (``alice@example.com`` → ``"@example.com"``). The full email is PII; the
    domain is sufficient to correlate "internal vs external" without exposing
    the user.
  * ``client.ipAddress`` is masked to a /16 (public IPv4) or /32 (IPv6); RFC1918
    private addresses are preserved verbatim.
  * ``client.userAgent.rawUserAgent`` is truncated to its first 80 chars and a
    sha256 of the full UA is captured separately. Full UA strings are
    browser-fingerprintable.
  * ``debugContext.debugData.requestUri`` is reduced to its path component;
    any query string is dropped (paths can be safe, query strings carry
    tokens / session IDs).
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``okta`` package; SystemLog JSON exports are
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
from urllib.parse import urlparse

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/okta.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "okta-aksi-controls.json"
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
# canonical `_metadata.event_patterns` list in the JSON.
_DEFAULT_EVENT_PATTERNS: tuple[dict[str, Any], ...] = (
    {"event_type": "user.authentication.*", "outcome": "SUCCESS",
     "signal": "auth_success", "result": "PASS", "control": "PR-01"},
    {"event_type": "user.authentication.*", "outcome": "FAILURE",
     "signal": "auth_failure", "result": "FLAG", "control": "PR-01"},
    {"event_type": "user.authentication.*", "outcome": "CHALLENGE",
     "signal": "auth_mfa_challenge", "result": "PASS", "control": "PR-01"},
    {"event_type": "user.session.start",
     "signal": "session_start", "result": "PASS", "control": "PR-01"},
    {"event_type": "user.session.access_admin_app",
     "signal": "admin_app_access", "result": "FLAG", "control": "PR-02"},
    {"event_type": "user.account.privilege.grant",
     "signal": "privilege_grant", "result": "FAIL", "control": "PR-02"},
    {"event_type": "*.privilege.*",
     "signal": "privilege_change", "result": "FAIL", "control": "PR-02"},
    {"event_type": "system.api_token.create",
     "signal": "api_token_create", "result": "FLAG", "control": "PR-01"},
    {"event_type": "system.api_token.revoke",
     "signal": "api_token_revoke", "result": "PASS", "control": "PR-05"},
    {"event_type": "application.user_membership.add",
     "signal": "app_membership_add", "result": "PASS", "control": "PR-02"},
    {"event_type": "policy.lifecycle.deactivate",
     "signal": "policy_deactivate", "result": "FAIL", "control": "PR-02"},
    {"event_type": "iwa.exempt.*",
     "signal": "iwa_exempt", "result": "FLAG", "control": "PR-01"},
    {"event_type": "user.mfa.factor.deactivate",
     "signal": "mfa_factor_deactivate", "result": "FAIL", "control": "PR-01"},
)

_DEFAULT_CROSS_COUNTRY_THRESHOLD = 3
_DEFAULT_ANONYMIZER_PATTERNS: tuple[str, ...] = (
    "*Tor*", "*VPN*", "*anonymous*", "*Anonymizer*", "*Proxy*",
)
_DEFAULT_ADMIN_APP_KEYWORDS: tuple[str, ...] = (
    "admin", "Admin", "ADMIN", "okta-admin", "AdminConsole",
)


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the okta-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_actor_id(actor_id: str | None) -> str | None:
    """Redact an Okta actor ID to ``<first-4>...<last-4>``.

    Okta IDs use a 3-char type prefix (``00u`` user, ``00o`` org, ``0oa`` app
    instance, ``00g`` group, ...) followed by a 17-char random tail. Keeping
    the first four characters preserves the type taxonomy (which is public)
    while masking everything but the last four characters.
    """
    if not actor_id or not isinstance(actor_id, str):
        return None
    aid = actor_id.strip()
    if not aid:
        return None
    if len(aid) <= 8:
        # Short ID — surface the prefix only.
        return aid[:4] + "..." if len(aid) > 4 else aid
    return f"{aid[:4]}...{aid[-4:]}"


def _redact_email_to_domain(alternate_id: str | None) -> str | None:
    """Reduce an email-style alternateId to ``"@<domain>"``.

    ``alice@example.com`` → ``"@example.com"``. Non-email strings are returned
    as a tag rather than the raw value (``"login:alice"`` → ``"<non-email>"``)
    so a username is never accidentally captured.
    """
    if not alternate_id or not isinstance(alternate_id, str):
        return None
    val = alternate_id.strip()
    if not val:
        return None
    if "@" in val:
        # Take the last @ split — handles unusual local parts safely.
        domain = val.rsplit("@", 1)[1].strip().lower()
        if domain:
            return f"@{domain}"
        return None
    return "<non-email>"


def _classify_ip_address(ip_address: str | None) -> str | None:
    """Mask an Okta client.ipAddress to a /16 (IPv4) or /32 (IPv6).

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
    """Truncate a raw user-agent to first 80 chars and capture sha256 of full.

    Full UA strings are browser-fingerprintable; the truncated form preserves
    enough context (browser family + major version) for analyst review while
    the sha256 lets an analyst correlate identical UAs across events without
    recovering the original.
    """
    if not raw_ua or not isinstance(raw_ua, str):
        return None, None
    ua = raw_ua.strip()
    if not ua:
        return None, None
    truncated = ua[:80]
    digest = hashlib.sha256(ua.encode("utf-8")).hexdigest()
    return truncated, digest


def _redact_request_uri(uri: str | None) -> str | None:
    """Strip the query string and fragment from a debugContext.requestUri.

    Path components are typically safe (``/api/v1/users/me``); query strings
    can carry tokens / session IDs / redirect targets.
    """
    if not uri or not isinstance(uri, str):
        return None
    val = uri.strip()
    if not val:
        return None
    try:
        parsed = urlparse(val)
    except ValueError:
        return None
    # If only a path was supplied, urlparse puts it in .path with empty scheme.
    return parsed.path or None


def _matches_event_pattern(
    event_type: str, outcome_result: str, pattern: dict[str, Any]
) -> bool:
    type_pat = str(pattern.get("event_type", ""))
    outcome_filter = pattern.get("outcome")
    if not fnmatch.fnmatchcase(event_type, type_pat):
        return False
    if outcome_filter is None:
        return True
    return outcome_result.upper() == str(outcome_filter).upper()


def _is_anonymizer(as_org: str | None, patterns: tuple[str, ...]) -> bool:
    """Match the ASN-org string against known-anonymizer fnmatch patterns."""
    if not as_org or not isinstance(as_org, str):
        return False
    org = as_org.strip()
    if not org:
        return False
    return any(fnmatch.fnmatchcase(org, pat) for pat in patterns)


def _is_admin_target(
    targets: list[dict[str, Any]], keywords: tuple[str, ...]
) -> bool:
    """Heuristic: any target whose displayName or alternateId contains an admin keyword."""
    for tgt in targets:
        if not isinstance(tgt, dict):
            continue
        for field_name in ("displayName", "alternateId", "type"):
            val = tgt.get(field_name)
            if isinstance(val, str):
                for kw in keywords:
                    if kw in val:
                        return True
    return False


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class OktaImporter:
    """Parse an Okta SystemLog export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_country_threshold: int | None = None,
        anonymizer_patterns: Iterable[str] | None = None,
        admin_app_keywords: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Event patterns precedence: mapping table > built-in defaults.
        meta_patterns = meta.get("event_patterns")
        if isinstance(meta_patterns, list) and meta_patterns:
            self._event_patterns: tuple[dict[str, Any], ...] = tuple(
                p for p in meta_patterns if isinstance(p, dict)
            )
        else:
            self._event_patterns = _DEFAULT_EVENT_PATTERNS
        # Cross-country threshold precedence: explicit arg > mapping metadata > default.
        if cross_country_threshold is not None:
            self.cross_country_threshold = int(cross_country_threshold)
        else:
            self.cross_country_threshold = int(
                meta.get("cross_country_threshold", _DEFAULT_CROSS_COUNTRY_THRESHOLD)
            )
        # Anonymizer patterns precedence: explicit arg > mapping metadata > default.
        if anonymizer_patterns is not None:
            self.anonymizer_patterns: tuple[str, ...] = tuple(
                str(p) for p in anonymizer_patterns
            )
        else:
            meta_anon = meta.get("anonymizer_patterns")
            if isinstance(meta_anon, list) and meta_anon:
                # Allow bare substrings ("Tor") OR fnmatch globs ("*Tor*").
                # Wrap bare substrings with wildcards so matching is forgiving.
                normalized: list[str] = []
                for p in meta_anon:
                    s = str(p)
                    if "*" in s or "?" in s or "[" in s:
                        normalized.append(s)
                    else:
                        normalized.append(f"*{s}*")
                self.anonymizer_patterns = tuple(normalized)
            else:
                self.anonymizer_patterns = _DEFAULT_ANONYMIZER_PATTERNS
        # Admin-app keywords precedence: explicit arg > mapping metadata > default.
        if admin_app_keywords is not None:
            self.admin_app_keywords: tuple[str, ...] = tuple(
                str(k) for k in admin_app_keywords
            )
        else:
            meta_admin = meta.get("admin_app_keywords")
            if isinstance(meta_admin, list) and meta_admin:
                self.admin_app_keywords = tuple(str(k) for k in meta_admin)
            else:
                self.admin_app_keywords = _DEFAULT_ADMIN_APP_KEYWORDS

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an Okta SystemLog export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Okta SystemLog content from a JSON or JSONL string."""
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
                # Single event.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-event EvaluationResults plus cross-country synthetic findings."""
        # First pass: aggregate countries per actor.id for cross-country detection.
        actor_countries: dict[str, set[str]] = {}
        for evt in events:
            actor = evt.get("actor") or {}
            if not isinstance(actor, dict):
                continue
            aid = actor.get("id")
            client = evt.get("client") or {}
            if not isinstance(client, dict):
                continue
            geo = client.get("geographicalContext") or {}
            if not isinstance(geo, dict):
                continue
            country = geo.get("country")
            if (
                isinstance(aid, str) and aid
                and isinstance(country, str) and country
            ):
                actor_countries.setdefault(aid, set()).add(country)

        cross_country_actors = {
            aid: sorted(countries)
            for aid, countries in actor_countries.items()
            if len(countries) > self.cross_country_threshold
        }

        results = [
            self._parse_event(
                evt,
                file_sha256=file_sha256,
                cross_country_actors=cross_country_actors,
            )
            for evt in events
        ]

        # Synthetic per-actor cross-country pattern findings.
        for aid, countries in sorted(cross_country_actors.items()):
            results.append(
                self._synthetic_cross_country_result(
                    actor_id=aid,
                    countries=countries,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        event_uuid: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "okta_systemlog",
            "source_tool_name": "okta",
            "source_tool_version": "",
        }
        if event_uuid is not None:
            provenance["event_uuid"] = event_uuid
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _classify_event(
        self, event_type: str, outcome_result: str
    ) -> dict[str, Any] | None:
        """Find the first event-pattern that matches; ``None`` if no match."""
        for pattern in self._event_patterns:
            if _matches_event_pattern(event_type, outcome_result, pattern):
                return pattern
        return None

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_country_actors: dict[str, list[str]],
    ) -> EvaluationResult:
        event_uuid = str(event.get("uuid") or uuid.uuid4())
        event_type = str(event.get("eventType") or "").strip()
        published = str(
            event.get("published") or datetime.now(timezone.utc).isoformat()
        )
        severity = str(event.get("severity") or "").strip()
        legacy_event_type = str(event.get("legacyEventType") or "").strip()
        display_message = str(event.get("displayMessage") or "").strip()

        # ---- actor (sanitized) ----
        actor = event.get("actor") or {}
        if not isinstance(actor, dict):
            actor = {}
        actor_id_raw = actor.get("id") if isinstance(actor.get("id"), str) else None
        actor_id_redacted = _redact_actor_id(actor_id_raw)
        actor_type = str(actor.get("type") or "")
        actor_alternate_id_raw = actor.get("alternateId")
        actor_alternate_id_domain = _redact_email_to_domain(
            actor_alternate_id_raw
            if isinstance(actor_alternate_id_raw, str)
            else None
        )

        # ---- client (sanitized) ----
        client = event.get("client") or {}
        if not isinstance(client, dict):
            client = {}
        ip_raw = client.get("ipAddress")
        ip_redacted = _classify_ip_address(
            ip_raw if isinstance(ip_raw, str) else None
        )
        user_agent = client.get("userAgent") or {}
        if not isinstance(user_agent, dict):
            user_agent = {}
        ua_raw = user_agent.get("rawUserAgent")
        ua_truncated, ua_sha256 = _redact_user_agent(
            ua_raw if isinstance(ua_raw, str) else None
        )
        ua_os = str(user_agent.get("os") or "") or None
        ua_browser = str(user_agent.get("browser") or "") or None
        device = str(client.get("device") or "") or None
        zone = str(client.get("zone") or "") or None
        geo = client.get("geographicalContext") or {}
        if not isinstance(geo, dict):
            geo = {}
        country = str(geo.get("country") or "") or None

        # ---- outcome ----
        outcome = event.get("outcome") or {}
        if not isinstance(outcome, dict):
            outcome = {}
        outcome_result = str(outcome.get("result") or "").strip().upper()
        outcome_reason = str(outcome.get("reason") or "") or None

        # ---- target list ----
        targets_raw = event.get("target") or []
        targets: list[dict[str, Any]] = (
            [t for t in targets_raw if isinstance(t, dict)]
            if isinstance(targets_raw, list)
            else []
        )
        target_count = len(targets)

        # ---- transaction ----
        transaction = event.get("transaction") or {}
        if not isinstance(transaction, dict):
            transaction = {}
        transaction_type = str(transaction.get("type") or "") or None
        transaction_id = str(transaction.get("id") or "") or None

        # ---- debugContext.debugData (requestUri sanitized) ----
        debug_context = event.get("debugContext") or {}
        if not isinstance(debug_context, dict):
            debug_context = {}
        debug_data = debug_context.get("debugData") or {}
        if not isinstance(debug_data, dict):
            debug_data = {}
        request_uri_path = _redact_request_uri(
            debug_data.get("requestUri")
            if isinstance(debug_data.get("requestUri"), str)
            else None
        )

        # ---- authenticationContext ----
        auth_context = event.get("authenticationContext") or {}
        if not isinstance(auth_context, dict):
            auth_context = {}
        auth_provider = str(auth_context.get("authenticationProvider") or "") or None

        # ---- securityContext ----
        security_context = event.get("securityContext") or {}
        if not isinstance(security_context, dict):
            security_context = {}
        is_proxy = security_context.get("isProxy")
        is_proxy_bool: bool | None = (
            bool(is_proxy) if isinstance(is_proxy, bool) else None
        )
        as_org = str(security_context.get("asOrg") or "") or None
        as_number_raw = security_context.get("asNumber")
        as_number: int | None
        if isinstance(as_number_raw, int) and not isinstance(as_number_raw, bool):
            as_number = as_number_raw
        else:
            as_number = None

        common_evidence: dict[str, Any] = {
            "okta_event_uuid": event_uuid,
            "event_type": event_type,
            "published": published,
            "severity": severity,
            "legacy_event_type": legacy_event_type,
            "display_message": display_message,
            "actor_id_redacted": actor_id_redacted,
            "actor_type": actor_type,
            "actor_alternate_id_domain": actor_alternate_id_domain,
            "client_ip_redacted": ip_redacted,
            "client_user_agent_truncated": ua_truncated,
            "client_user_agent_sha256": ua_sha256,
            "client_user_agent_os": ua_os,
            "client_user_agent_browser": ua_browser,
            "client_device": device,
            "client_zone": zone,
            "client_country": country,
            "outcome_result": outcome_result or None,
            "outcome_reason": outcome_reason,
            "target_count": target_count,
            "transaction_type": transaction_type,
            "transaction_id": transaction_id,
            "debug_request_uri_path": request_uri_path,
            "authentication_provider": auth_provider,
            "security_is_proxy": is_proxy_bool,
            "security_as_org": as_org,
            "security_as_number": as_number,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_uuid=event_uuid
            ),
            "source_tool": "okta",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Event-type pattern classification.
        # ----------------------------------------------------------------
        pattern = self._classify_event(event_type, outcome_result)
        if pattern is not None:
            signal = str(pattern.get("signal", "unknown_event"))
            control_id = _control_for(
                signal, self._mappings, str(pattern.get("control", "PR-05"))
            )
            result = str(pattern.get("result", "PASS"))
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Okta event {event_uuid} eventType={event_type} "
                        f"outcome={outcome_result or 'unknown'} "
                        f"classified as {signal} ({result})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Unknown event type — surface as PR-05 FLAG so it does not silently pass.
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Okta event {event_uuid} eventType={event_type!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Outcome=DENY — additive PR-02 PASS (correctly denied = audit trail).
        # The per-event classification covers SUCCESS/FAILURE/CHALLENGE for auth
        # events; DENY is orthogonal (policy denied an action) and worth a
        # dedicated PR-02 PASS even if the event-type pattern already matched.
        # ----------------------------------------------------------------
        if outcome_result == "DENY":
            signal = "outcome_deny"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Okta event {event_uuid} eventType={event_type} "
                        f"outcome=DENY — policy correctly denied the action"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Proxy / anonymizer detection on session events.
        # Proxy-originated sessions are FLAG; anonymizer (Tor / VPN /
        # anonymous-proxy ASNs) is FAIL. Anonymizer takes precedence over
        # the plain proxy flag.
        # ----------------------------------------------------------------
        if is_proxy_bool is True:
            if _is_anonymizer(as_org, self.anonymizer_patterns):
                signal = "anonymizer_session"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"Okta event {event_uuid} originated from an "
                            f"anonymizing network (asOrg={as_org!r}) — known "
                            f"anonymizer pattern matched"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
            else:
                signal = "proxy_session"
                control_id = _control_for(signal, self._mappings, "PR-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"Okta event {event_uuid} originated from a proxy "
                            f"(asOrg={as_org!r}) — verify origin"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )

        # ----------------------------------------------------------------
        # 4. application.user_membership.add to admin-keyworded target →
        # additive PR-02 FLAG (admin-app membership change). The plain
        # event-type pattern classifies this as PASS; the admin-target
        # heuristic upgrades it.
        # ----------------------------------------------------------------
        if (
            event_type == "application.user_membership.add"
            and _is_admin_target(targets, self.admin_app_keywords)
        ):
            signal = "admin_app_membership"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Okta event {event_uuid} adds membership to an "
                        f"admin/privileged application — verify approval trail"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Cross-country pattern — informational per-event marker. The
        # synthetic per-actor finding is added separately in the second pass.
        # ----------------------------------------------------------------
        if (
            isinstance(actor_id_raw, str)
            and actor_id_raw in cross_country_actors
        ):
            signal = "cross_country_pattern"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Okta event {event_uuid} actor {actor_id_redacted} "
                        f"is part of a cross-country pattern "
                        f"({len(cross_country_actors[actor_id_raw])} countries > "
                        f"threshold {self.cross_country_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_country_countries": cross_country_actors[
                            actor_id_raw
                        ],
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
            f"Imported from Okta SystemLog: eventType={event_type} "
            f"outcome={outcome_result or 'unknown'} "
            f"actor_type={actor_type or 'unknown'} "
            f"auth_provider={auth_provider or 'none'} "
            f"country={country or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"okta-{event_uuid[:32]}",
            timestamp=published,
            agent_id=self.agent_id,
            source_type="okta_systemlog_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=transaction_id,
        )

    def _synthetic_cross_country_result(
        self,
        *,
        actor_id: str,
        countries: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-actor cross-country pattern finding.

        Captures the (redacted) actor.id, the countries it touched, and the
        threshold used so downstream posture analysis can answer "which
        identities are crossing geographic boundaries in this export?".
        """
        signal = "cross_country_pattern"
        control_id = _control_for(signal, self._mappings, "PR-01")
        synthetic_id = f"okta-cross-country-{actor_id}"
        actor_redacted = _redact_actor_id(actor_id) or actor_id
        evidence: dict[str, Any] = {
            "okta_event_uuid": synthetic_id,
            "actor_id_redacted": actor_redacted,
            "cross_country_countries": countries,
            "cross_country_country_count": len(countries),
            "cross_country_threshold": self.cross_country_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_uuid=synthetic_id,
            ),
            "source_tool": "okta",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Okta synthetic finding: actor {actor_redacted} touched "
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
            source_type="okta_systemlog_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Okta SystemLog: synthetic cross-country "
                f"pattern for actor={actor_redacted} "
                f"countries={len(countries)}>threshold="
                f"{self.cross_country_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
