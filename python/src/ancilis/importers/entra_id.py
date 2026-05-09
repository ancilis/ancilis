"""Azure Entra ID sign-in importer — maps identity-event audit records to AKSI controls.

Azure Entra ID (formerly Azure Active Directory) is THE identity provider for
Microsoft 365 + Azure ecosystems and possibly the largest enterprise IdP
overall. Microsoft Graph's ``/auditLogs/signIns`` and
``/auditLogs/directoryAudits`` endpoints export the canonical evidence of
"who signed in / which Conditional-Access policies fired / what risk Microsoft
observed / which authentication method was used". CloudTrail covers
AWS-internal actions; Okta SystemLog and Auth0 tenant logs cover the
non-Microsoft enterprise IdP surface; Entra ID closes the "Big 3 enterprise
IdP" coverage with a fundamentally different log shape (Microsoft Graph
events) and policy model (Conditional Access).

This importer ingests Microsoft Graph sign-in exports in three on-disk shapes:

  1. ``{"value": [...]}`` — canonical Microsoft Graph envelope
  2. ``{"data":  [...]}`` — generic data envelope
  3. JSONL                — one event per line

Signal mapping (see shared/mappings/entra-id-aksi-controls.json):

  * conditionalAccessStatus=success + status.errorCode=0 + risk=none → PR-01 PASS
  * status.errorCode != 0                                            → PR-01 FLAG
  * conditionalAccessStatus=failure                                  → PR-02 FLAG
  * riskLevelDuringSignIn=high or riskLevelAggregated=high           → PR-01 FAIL
  * riskLevelDuringSignIn=medium                                     → PR-01 FLAG
  * riskState=confirmedCompromised                                   → PR-01 FAIL
  * riskState=atRisk                                                 → PR-01 FLAG
  * riskEventTypes_v2 contains leakedCredentials                     → PR-01 FAIL
  * riskEventTypes_v2 contains passwordSpray                         → PR-01 FAIL
  * riskEventTypes_v2 contains anonymizedIPAddress                   → PR-01 FLAG
  * riskEventTypes_v2 contains atypicalTravel                        → PR-01 FLAG
  * clientAppUsed in legacy_auth_clients                             → PR-01 FLAG
  * deviceDetail.isCompliant=false on resource access                → PR-02 FLAG
  * deviceDetail.isManaged=false on privileged resource              → PR-02 FLAG
  * authenticationDetails password-only on privileged resource       → PR-01 FLAG
  * appliedConditionalAccessPolicies result=block                    → PR-02 PASS
  * appId not in known-app-allowlist (when configured)               → PR-01 FLAG
  * signInIdentifierType=phoneNumber                                 → PR-01 PASS
  * cross-country pattern (one userId touching > N countries)        → PR-01 FLAG synthetic
  * multi-app pattern (one userId touching > N appIds)               → PR-01 PASS synthetic

Sanitization (security-critical — Entra sign-in rows are PII-rich):

  * ``userPrincipalName`` is reduced to its **email-domain only**
    (``alice@corp.example.com`` → ``"@corp.example.com"``). The full UPN is PII;
    the domain is sufficient to correlate "internal vs external" without
    exposing the user.
  * ``userDisplayName`` is reduced to (length, sha256). Plaintext is never
    stored — display names are PII (often legal name) and the digest lets an
    analyst correlate identical names across events without recovering the
    original.
  * ``userId`` is captured verbatim — Microsoft Graph object IDs are
    pseudonymous by design (random UUIDs, no PII content).
  * ``ipAddress`` is masked to a /16 (public IPv4) or /32 (IPv6); RFC1918
    private / loopback / link-local addresses are preserved verbatim.
  * ``location`` is reduced to ``countryOrRegion`` only.
    ``city`` / ``state`` / ``geoCoordinates`` are dropped — city-level and
    geo-coordinate data are too granular for evidence and not needed for
    posture analysis (cross-country and country-of-origin are sufficient).
  * ``deviceDetail.deviceId`` is truncated to its last-8 characters. Device
    IDs are pseudo-IDs but truncation reduces inversion risk.
  * ``correlationId`` and ``originalRequestId`` are captured verbatim — they
    are Microsoft-generated request IDs, not user-derived.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``azure-identity`` or ``msgraph-sdk`` packages;
sign-in JSON exports are parsed with the standard library only.
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


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/entra_id.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "entra-id-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Risk-event types from Microsoft Graph riskEventTypes_v2 → (signal, result, control).
_DEFAULT_RISK_EVENT_SIGNALS: dict[str, dict[str, str]] = {
    "leakedCredentials": {
        "signal": "leaked_credentials", "result": "FAIL", "control": "PR-01",
    },
    "passwordSpray": {
        "signal": "password_spray", "result": "FAIL", "control": "PR-01",
    },
    "anonymizedIPAddress": {
        "signal": "anonymized_ip", "result": "FLAG", "control": "PR-01",
    },
    "atypicalTravel": {
        "signal": "atypical_travel", "result": "FLAG", "control": "PR-01",
    },
    "unfamiliarFeatures": {
        "signal": "unfamiliar_features", "result": "FLAG", "control": "PR-01",
    },
    "investigationsThreatIntelligence": {
        "signal": "threat_intelligence", "result": "FAIL", "control": "PR-01",
    },
}

_DEFAULT_PRIVILEGED_RESOURCE_PATTERNS: tuple[str, ...] = (
    "Microsoft Graph",
    "Azure Management",
    "Azure Portal",
    "admin*",
)

_DEFAULT_LEGACY_AUTH_CLIENTS: tuple[str, ...] = (
    "Exchange ActiveSync",
    "IMAP",
    "POP",
    "Authenticated SMTP",
    "Other clients",
)

_DEFAULT_CROSS_COUNTRY_THRESHOLD = 3
_DEFAULT_MULTI_APP_THRESHOLD = 30

# Display-name PII redaction is hash + length only.
# UPN domain redaction yields strings like "@corp.example.com".


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the entra-id-aksi-controls.json mapping; tolerate missing file."""
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


def _redact_upn_to_domain(upn: str | None) -> str | None:
    """Reduce a userPrincipalName to ``"@<domain>"``.

    ``alice@corp.example.com`` → ``"@corp.example.com"``. UPNs without an ``@``
    are tagged ``"<non-upn>"`` so the local part is never accidentally captured.
    """
    if not upn or not isinstance(upn, str):
        return None
    val = upn.strip()
    if not val:
        return None
    if "@" in val:
        domain = val.rsplit("@", 1)[1].strip().lower()
        if domain:
            return f"@{domain}"
        return None
    return "<non-upn>"


def _hash_display_name(name: str | None) -> tuple[int | None, str | None]:
    """Reduce a userDisplayName to (length, sha256). Plaintext is never stored."""
    if not name or not isinstance(name, str):
        return None, None
    val = name.strip()
    if not val:
        return None, None
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()
    return len(val), digest


def _classify_ip_address(ip_address: str | None) -> str | None:
    """Mask an Entra ID ``ipAddress`` to a /16 (IPv4) or /32 (IPv6).

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


def _redact_device_id(device_id: str | None) -> str | None:
    """Truncate a deviceDetail.deviceId to its last 8 chars.

    Device IDs are pseudonymous (random UUIDs) but truncation reduces
    inversion risk if the device-ID space is enumerable.
    """
    if not device_id or not isinstance(device_id, str):
        return None
    val = device_id.strip()
    if not val:
        return None
    if len(val) <= 8:
        return val
    return f"...{val[-8:]}"


def _resource_is_privileged(
    resource_display_name: str | None, patterns: tuple[str, ...]
) -> bool:
    """Match a resourceDisplayName against the privileged-resource patterns."""
    if not resource_display_name or not isinstance(resource_display_name, str):
        return False
    name = resource_display_name.strip()
    if not name:
        return False
    for pat in patterns:
        if "*" in pat or "?" in pat or "[" in pat:
            if fnmatch.fnmatchcase(name, pat):
                return True
        else:
            # Bare strings are case-insensitive substring matches so
            # "Microsoft Graph" matches both itself and "Microsoft Graph API".
            if pat.lower() in name.lower():
                return True
    return False


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class EntraIDImporter:
    """Parse a Microsoft Graph sign-in export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_country_threshold: int | None = None,
        multi_app_threshold: int | None = None,
        privileged_resource_patterns: Iterable[str] | None = None,
        legacy_auth_clients: Iterable[str] | None = None,
        app_id_allowlist: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Risk-event-type → signal/result/control table.
        meta_risk_events = meta.get("risk_event_signals")
        if isinstance(meta_risk_events, dict) and meta_risk_events:
            self._risk_event_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_risk_events.items()
                if isinstance(v, dict)
            }
        else:
            self._risk_event_signals = {
                k: dict(v) for k, v in _DEFAULT_RISK_EVENT_SIGNALS.items()
            }
        # Cross-country threshold precedence: arg > mapping > default.
        if cross_country_threshold is not None:
            self.cross_country_threshold = int(cross_country_threshold)
        else:
            self.cross_country_threshold = int(
                meta.get("cross_country_threshold", _DEFAULT_CROSS_COUNTRY_THRESHOLD)
            )
        # Multi-app threshold precedence: arg > mapping > default.
        if multi_app_threshold is not None:
            self.multi_app_threshold = int(multi_app_threshold)
        else:
            self.multi_app_threshold = int(
                meta.get("multi_app_threshold", _DEFAULT_MULTI_APP_THRESHOLD)
            )
        # Privileged resource patterns precedence: arg > mapping > default.
        if privileged_resource_patterns is not None:
            self.privileged_resource_patterns: tuple[str, ...] = tuple(
                str(p) for p in privileged_resource_patterns
            )
        else:
            meta_priv = meta.get("privileged_resource_patterns")
            if isinstance(meta_priv, list) and meta_priv:
                self.privileged_resource_patterns = tuple(
                    str(p) for p in meta_priv
                )
            else:
                self.privileged_resource_patterns = _DEFAULT_PRIVILEGED_RESOURCE_PATTERNS
        # Legacy-auth clients precedence: arg > mapping > default.
        if legacy_auth_clients is not None:
            self.legacy_auth_clients: frozenset[str] = frozenset(
                str(c) for c in legacy_auth_clients
            )
        else:
            meta_legacy = meta.get("legacy_auth_clients")
            if isinstance(meta_legacy, list) and meta_legacy:
                self.legacy_auth_clients = frozenset(
                    str(c) for c in meta_legacy
                )
            else:
                self.legacy_auth_clients = frozenset(_DEFAULT_LEGACY_AUTH_CLIENTS)
        # appId allowlist (optional). When set, any appId not in the allowlist
        # raises a PR-01 FLAG — supports unknown-app detection. ``None``
        # disables the check.
        if app_id_allowlist is not None:
            self.app_id_allowlist: frozenset[str] | None = frozenset(
                str(a) for a in app_id_allowlist
            )
        else:
            self.app_id_allowlist = None

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an Entra ID sign-in export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Entra ID sign-in content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"value": [...]}`` / ``{"data": [...]}`` / JSONL / single event."""
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
                if "value" in doc and isinstance(doc["value"], list):
                    return [e for e in doc["value"] if isinstance(e, dict)]
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
        """Build per-event EvaluationResults plus synthetic pattern findings."""
        # First pass: aggregate countries and appIds per userId.
        user_countries: dict[str, set[str]] = {}
        user_apps: dict[str, set[str]] = {}
        for evt in events:
            uid = evt.get("userId")
            if not isinstance(uid, str) or not uid:
                continue
            location = evt.get("location") or {}
            if isinstance(location, dict):
                country = location.get("countryOrRegion")
                if isinstance(country, str) and country:
                    user_countries.setdefault(uid, set()).add(country)
            app_id = evt.get("appId")
            if isinstance(app_id, str) and app_id:
                user_apps.setdefault(uid, set()).add(app_id)

        cross_country_users = {
            uid: sorted(countries)
            for uid, countries in user_countries.items()
            if len(countries) > self.cross_country_threshold
        }
        multi_app_users = {
            uid: sorted(apps)
            for uid, apps in user_apps.items()
            if len(apps) > self.multi_app_threshold
        }

        results = [
            self._parse_event(
                evt,
                file_sha256=file_sha256,
                cross_country_users=cross_country_users,
                multi_app_users=multi_app_users,
            )
            for evt in events
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
        # Synthetic per-user multi-app pattern findings (informational, PASS).
        for uid, apps in sorted(multi_app_users.items()):
            results.append(
                self._synthetic_multi_app_result(
                    user_id=uid,
                    app_ids=apps,
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
            "source_format": "entra_id_signins",
            "source_tool_name": "entra_id",
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

    def _parse_event(  # noqa: C901, PLR0912, PLR0915 — single-pass per-event mapper
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_country_users: dict[str, list[str]],
        multi_app_users: dict[str, list[str]],
    ) -> EvaluationResult:
        event_id_raw = event.get("id") or str(uuid.uuid4())
        event_id = str(event_id_raw)
        created = str(
            event.get("createdDateTime") or datetime.now(timezone.utc).isoformat()
        )

        # ---- user (sanitized) ----
        upn_domain = _redact_upn_to_domain(
            event.get("userPrincipalName")
            if isinstance(event.get("userPrincipalName"), str)
            else None
        )
        display_name_length, display_name_sha256 = _hash_display_name(
            event.get("userDisplayName")
            if isinstance(event.get("userDisplayName"), str)
            else None
        )
        user_id_raw = event.get("userId")
        user_id = (
            str(user_id_raw)
            if isinstance(user_id_raw, str) and user_id_raw
            else None
        )

        # ---- app / resource ----
        app_id_raw = event.get("appId")
        app_id = (
            str(app_id_raw) if isinstance(app_id_raw, str) and app_id_raw else None
        )
        app_display_name = str(event.get("appDisplayName") or "") or None
        resource_display_name = str(event.get("resourceDisplayName") or "") or None
        resource_id_raw = event.get("resourceId")
        resource_id = (
            str(resource_id_raw)
            if isinstance(resource_id_raw, str) and resource_id_raw
            else None
        )

        client_app_used = str(event.get("clientAppUsed") or "") or None
        is_interactive_raw = event.get("isInteractive")
        is_interactive: bool | None = (
            bool(is_interactive_raw)
            if isinstance(is_interactive_raw, bool)
            else None
        )
        token_issuer_type = str(event.get("tokenIssuerType") or "") or None
        token_issuer_name = str(event.get("tokenIssuerName") or "") or None
        correlation_id = str(event.get("correlationId") or "") or None
        original_request_id = str(event.get("originalRequestId") or "") or None
        ca_status = str(event.get("conditionalAccessStatus") or "") or None
        sign_in_id_type = str(event.get("signInIdentifierType") or "") or None

        processing_time_raw = event.get("processingTimeInMilliseconds")
        processing_time: int | None
        if isinstance(processing_time_raw, bool):
            processing_time = None
        elif isinstance(processing_time_raw, int):
            processing_time = processing_time_raw
        else:
            processing_time = None

        # ---- ip / location (sanitized) ----
        ip_redacted = _classify_ip_address(
            event.get("ipAddress")
            if isinstance(event.get("ipAddress"), str)
            else None
        )
        location = event.get("location") or {}
        if not isinstance(location, dict):
            location = {}
        country = str(location.get("countryOrRegion") or "") or None

        # ---- risk fields ----
        risk_detail = str(event.get("riskDetail") or "") or None
        risk_level_aggregated = str(event.get("riskLevelAggregated") or "") or None
        risk_level_during = str(event.get("riskLevelDuringSignIn") or "") or None
        risk_state = str(event.get("riskState") or "") or None
        risk_event_types_raw = event.get("riskEventTypes_v2") or []
        risk_event_types: list[str] = (
            [str(r) for r in risk_event_types_raw if isinstance(r, str)]
            if isinstance(risk_event_types_raw, list)
            else []
        )

        # ---- device (sanitized) ----
        device = event.get("deviceDetail") or {}
        if not isinstance(device, dict):
            device = {}
        device_id_redacted = _redact_device_id(
            device.get("deviceId")
            if isinstance(device.get("deviceId"), str)
            else None
        )
        device_display_name = str(device.get("displayName") or "") or None
        device_os = str(device.get("operatingSystem") or "") or None
        device_browser = str(device.get("browser") or "") or None
        is_compliant_raw = device.get("isCompliant")
        is_compliant: bool | None = (
            bool(is_compliant_raw)
            if isinstance(is_compliant_raw, bool)
            else None
        )
        is_managed_raw = device.get("isManaged")
        is_managed: bool | None = (
            bool(is_managed_raw)
            if isinstance(is_managed_raw, bool)
            else None
        )
        device_trust_type = str(device.get("trustType") or "") or None

        # ---- conditional access policies ----
        applied_ca_raw = event.get("appliedConditionalAccessPolicies") or []
        applied_ca: list[dict[str, Any]] = (
            [p for p in applied_ca_raw if isinstance(p, dict)]
            if isinstance(applied_ca_raw, list)
            else []
        )
        ca_policy_names = [
            str(p.get("displayName"))
            for p in applied_ca
            if isinstance(p.get("displayName"), str)
        ]
        ca_policy_count = len(applied_ca)
        ca_block_results = [
            p for p in applied_ca
            if str(p.get("result") or "").lower() == "block"
        ]

        # ---- authentication details ----
        auth_details_raw = event.get("authenticationDetails") or []
        auth_details: list[dict[str, Any]] = (
            [a for a in auth_details_raw if isinstance(a, dict)]
            if isinstance(auth_details_raw, list)
            else []
        )
        auth_methods = [
            str(a.get("authenticationMethod"))
            for a in auth_details
            if isinstance(a.get("authenticationMethod"), str)
            and a.get("authenticationMethod")
        ]
        auth_methods_lower = [m.lower() for m in auth_methods]
        password_only = (
            len(auth_methods) > 0
            and all("password" in m for m in auth_methods_lower)
        )

        # ---- network location details ----
        network_raw = event.get("networkLocationDetails") or []
        network_details: list[dict[str, Any]] = (
            [n for n in network_raw if isinstance(n, dict)]
            if isinstance(network_raw, list)
            else []
        )
        network_types = [
            str(n.get("networkType"))
            for n in network_details
            if isinstance(n.get("networkType"), str)
        ]
        is_trusted_named_location = any(
            t.lower() == "trustednamedlocation" for t in network_types
        )

        # ---- status ----
        status = event.get("status") or {}
        if not isinstance(status, dict):
            status = {}
        status_error_raw = status.get("errorCode")
        status_error_code: int | None
        if isinstance(status_error_raw, bool):
            status_error_code = None
        elif isinstance(status_error_raw, int):
            status_error_code = status_error_raw
        else:
            status_error_code = None
        status_failure_reason = str(status.get("failureReason") or "") or None
        status_additional_details = str(status.get("additionalDetails") or "") or None

        is_privileged_resource = _resource_is_privileged(
            resource_display_name, self.privileged_resource_patterns
        )

        common_evidence: dict[str, Any] = {
            "entra_id_event_id": event_id,
            "created_date_time": created,
            "user_principal_name_domain": upn_domain,
            "user_display_name_length": display_name_length,
            "user_display_name_sha256": display_name_sha256,
            "user_id": user_id,
            "app_id": app_id,
            "app_display_name": app_display_name,
            "resource_display_name": resource_display_name,
            "resource_id": resource_id,
            "client_app_used": client_app_used,
            "is_interactive": is_interactive,
            "token_issuer_type": token_issuer_type,
            "token_issuer_name": token_issuer_name,
            "correlation_id": correlation_id,
            "original_request_id": original_request_id,
            "conditional_access_status": ca_status,
            "sign_in_identifier_type": sign_in_id_type,
            "processing_time_ms": processing_time,
            "client_ip_redacted": ip_redacted,
            "country_or_region": country,
            "risk_detail": risk_detail,
            "risk_level_aggregated": risk_level_aggregated,
            "risk_level_during_signin": risk_level_during,
            "risk_state": risk_state,
            "risk_event_types": risk_event_types,
            "device_id_redacted": device_id_redacted,
            "device_display_name": device_display_name,
            "device_operating_system": device_os,
            "device_browser": device_browser,
            "device_is_compliant": is_compliant,
            "device_is_managed": is_managed,
            "device_trust_type": device_trust_type,
            "applied_ca_policy_count": ca_policy_count,
            "applied_ca_policy_names": ca_policy_names,
            "authentication_methods": auth_methods,
            "network_types": network_types,
            "status_error_code": status_error_code,
            "status_failure_reason": status_failure_reason,
            "status_additional_details": status_additional_details,
            "is_privileged_resource": is_privileged_resource,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "entra_id",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Base sign-in success / failure classification.
        # status.errorCode==0 + ca_status==success + risk==none → PASS.
        # status.errorCode!=0 → FLAG.
        # ----------------------------------------------------------------
        is_clean_success = (
            status_error_code == 0
            and (ca_status or "").lower() == "success"
            and (risk_level_during or "none").lower() in ("none", "")
            and (risk_level_aggregated or "none").lower() in ("none", "", "hidden")
        )
        if is_clean_success:
            signal = "signin_success"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Entra ID sign-in {event_id} succeeded "
                        f"(errorCode=0, ca=success, risk=none)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif status_error_code is not None and status_error_code != 0:
            signal = "signin_failure"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} failed "
                        f"(errorCode={status_error_code} "
                        f"reason={status_failure_reason!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            # Neither a clean success nor a hard failure — surface as
            # unknown_event so the row is not silently dropped. Risk-based
            # signals below may add further controls.
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} has no clean success / "
                        f"failure shape — surfaced for review "
                        f"(errorCode={status_error_code} ca={ca_status!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Conditional Access status overlays.
        # ca=failure → PR-02 FLAG (CA policy denied).
        # ----------------------------------------------------------------
        if (ca_status or "").lower() == "failure":
            signal = "ca_failure"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} blocked by Conditional "
                        f"Access (ca_status=failure)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # CA block result(s) → PR-02 PASS (correctly blocked = audit trail).
        if ca_block_results:
            signal = "ca_block_audit"
            control_id = _control_for(signal, self._mappings, "PR-02")
            block_names = [
                str(p.get("displayName"))
                for p in ca_block_results
                if isinstance(p.get("displayName"), str)
            ]
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Entra ID sign-in {event_id} correctly blocked by "
                        f"{len(ca_block_results)} CA policy/policies "
                        f"({', '.join(block_names) or 'unnamed'})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "ca_block_policy_names": block_names,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 3. Risk-level overlays (Microsoft-assigned risk).
        # ----------------------------------------------------------------
        risk_during_low = (risk_level_during or "").lower()
        risk_agg_low = (risk_level_aggregated or "").lower()
        if risk_during_low == "high" or risk_agg_low == "high":
            signal = "high_risk_signin"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Entra ID sign-in {event_id} flagged high-risk by "
                        f"Microsoft (during={risk_level_during!r} "
                        f"aggregated={risk_level_aggregated!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif risk_during_low == "medium":
            signal = "medium_risk_signin"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} flagged medium-risk "
                        f"during sign-in"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Risk-state overlays.
        # ----------------------------------------------------------------
        risk_state_low = (risk_state or "").lower()
        if risk_state_low == "confirmedcompromised":
            signal = "confirmed_compromised"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Entra ID sign-in {event_id} riskState="
                        f"confirmedCompromised — Microsoft confirmed "
                        f"account compromise"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        elif risk_state_low == "atrisk":
            signal = "at_risk"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} riskState=atRisk — "
                        f"Microsoft flagged the account as currently at risk"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 5. Risk-event-type overlays.
        # leakedCredentials / passwordSpray / threatIntel → FAIL.
        # anonymizedIPAddress / atypicalTravel / unfamiliarFeatures → FLAG.
        # ----------------------------------------------------------------
        for risk_event in risk_event_types:
            meta = self._risk_event_signals.get(risk_event)
            if meta is None:
                continue
            signal = meta.get("signal", risk_event)
            result = meta.get("result", "FLAG")
            control_id = _control_for(
                signal, self._mappings, meta.get("control", "PR-01")
            )
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=result,
                    detail=(
                        f"Entra ID sign-in {event_id} carries risk-event "
                        f"{risk_event!r} → {signal} ({result})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "risk_event_type": risk_event,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 6. Legacy-auth client detection.
        # Microsoft itself recommends blocking legacy authentication via CA.
        # IMAP / POP / Exchange ActiveSync / Authenticated SMTP / Other clients
        # all bypass modern auth (no MFA, no Conditional Access enforcement).
        # ----------------------------------------------------------------
        if client_app_used is not None and client_app_used in self.legacy_auth_clients:
            signal = "legacy_auth_client"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} used legacy auth client "
                        f"{client_app_used!r} — should be blocked by CA policy"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 7. Device compliance / management overlays.
        # isCompliant=false → PR-02 FLAG (Intune compliance failure).
        # isManaged=false on privileged resource → PR-02 FLAG (BYOD on admin).
        # ----------------------------------------------------------------
        if is_compliant is False:
            signal = "non_compliant_device"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} from non-compliant "
                        f"device (deviceId={device_id_redacted}, "
                        f"resource={resource_display_name!r})"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        if is_managed is False and is_privileged_resource:
            signal = "unmanaged_device_privileged"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} from unmanaged device "
                        f"to privileged resource {resource_display_name!r}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 8. Password-only on privileged resource.
        # If authenticationDetails contains ONLY password methods (no MFA
        # factor: no FIDO, OAuth verification, mobile-app push, etc.) and
        # the resource is privileged, raise PR-01 FLAG.
        # ----------------------------------------------------------------
        if password_only and is_privileged_resource:
            signal = "password_only_privileged"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} authenticated with "
                        f"password-only ({auth_methods}) on privileged "
                        f"resource {resource_display_name!r} — no MFA factor"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 9. Unknown-app detection (when an allowlist is configured).
        # ----------------------------------------------------------------
        if (
            self.app_id_allowlist is not None
            and app_id is not None
            and app_id not in self.app_id_allowlist
        ):
            signal = "unknown_app"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Entra ID sign-in {event_id} appId={app_id!r} "
                        f"({app_display_name!r}) not in known-app allowlist"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 10. Passwordless / phone-based sign-in marker.
        # ----------------------------------------------------------------
        if (sign_in_id_type or "").lower() == "phonenumber":
            signal = "passwordless_phone_signin"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Entra ID sign-in {event_id} used phoneNumber "
                        f"identifier (passwordless / SMS-OTP)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 11. Untagged-network marker (no networkLocationDetails, no
        # trustedNamedLocation match). Captured as PASS = informational.
        # ----------------------------------------------------------------
        if not network_details and not is_trusted_named_location:
            signal = "untagged_network"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Entra ID sign-in {event_id} originated from an "
                        f"un-tagged network (no networkLocationDetails)"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 12. Cross-country / multi-app per-event markers.
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
                        f"Entra ID sign-in {event_id} user {user_id!r} part "
                        f"of cross-country pattern "
                        f"({len(cross_country_users[user_id])} countries > "
                        f"threshold {self.cross_country_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_country_countries": cross_country_users[user_id],
                        "cross_country_threshold": self.cross_country_threshold,
                    },
                )
            )
        if user_id is not None and user_id in multi_app_users:
            signal = "multi_app_pattern"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Entra ID sign-in {event_id} user {user_id!r} part "
                        f"of multi-app pattern "
                        f"({len(multi_app_users[user_id])} apps > "
                        f"threshold {self.multi_app_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "multi_app_app_ids": multi_app_users[user_id],
                        "multi_app_threshold": self.multi_app_threshold,
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
            f"Imported from Entra ID sign-ins: errorCode={status_error_code} "
            f"ca={ca_status or 'unknown'} "
            f"risk_during={risk_level_during or 'none'} "
            f"risk_state={risk_state or 'none'} "
            f"client_app={client_app_used or 'unknown'} "
            f"country={country or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"entra-id-{event_id[:32]}",
            timestamp=created,
            agent_id=self.agent_id,
            source_type="entra_id_signins_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=correlation_id,
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
        synthetic_id = f"entra-id-cross-country-{user_id}"
        evidence: dict[str, Any] = {
            "entra_id_event_id": synthetic_id,
            "user_id": user_id,
            "cross_country_countries": countries,
            "cross_country_country_count": len(countries),
            "cross_country_threshold": self.cross_country_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "entra_id",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Entra ID synthetic finding: user {user_id!r} touched "
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
            source_type="entra_id_signins_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Entra ID sign-ins: synthetic cross-country "
                f"pattern for user={user_id!r} "
                f"countries={len(countries)}>threshold="
                f"{self.cross_country_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_multi_app_result(
        self,
        *,
        user_id: str,
        app_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-user multi-app pattern finding (broad consent surface)."""
        signal = "multi_app_pattern"
        control_id = _control_for(signal, self._mappings, "PR-01")
        synthetic_id = f"entra-id-multi-app-{user_id}"
        evidence: dict[str, Any] = {
            "entra_id_event_id": synthetic_id,
            "user_id": user_id,
            "multi_app_app_ids": app_ids,
            "multi_app_app_count": len(app_ids),
            "multi_app_threshold": self.multi_app_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "entra_id",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="PASS",
            detail=(
                f"Entra ID synthetic finding: user {user_id!r} touched "
                f"{len(app_ids)} distinct apps in this export — exceeds "
                f"multi-app threshold {self.multi_app_threshold} "
                f"(broad consent surface, captured for audit)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="entra_id_signins_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason=(
                f"Imported from Entra ID sign-ins: synthetic multi-app "
                f"pattern for user={user_id!r} "
                f"apps={len(app_ids)}>threshold={self.multi_app_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
