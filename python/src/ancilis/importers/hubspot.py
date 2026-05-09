"""HubSpot CRM audit-log importer — maps Breeze AI agent activity to AKSI controls.

HubSpot (https://hubspot.com) is the dominant SMB / mid-market CRM. HubSpot
Breeze (Copilot + Agents) is HubSpot's native AI surface — it reads and
mutates Contacts, Deals, Companies, Tickets, and Engagements (emails, notes,
calls, tasks). Each Breeze action is a tool-using agent operating directly
on the system-of-record for revenue. The Audit Log API and webhook event
stream are the system-of-record for who-did-what across a HubSpot portal.

This importer ingests HubSpot Audit Log / webhook event exports in three
on-disk shapes:

  1. ``{"events": [...]}`` — primary event-export envelope
  2. ``{"data": [...]}``    — generic data envelope
  3. JSONL                   — one event per line

Signal mapping (see shared/mappings/hubspot-aksi-controls.json):
  * ``event_type=contact.creation`` by Breeze agent       → PR-01 FLAG
  * ``event_type=contact.deletion`` by Breeze agent       → PR-02 FAIL
    (autonomous data destruction)
  * ``event_type=contact.propertyChange`` with a sensitive
    property in ``properties_changed`` (ssn / tax_id /
    credit_card / passport / ...)                          → PR-04 FAIL → BLOCK
  * ``event_type=contact.propertyChange`` +
    ``is_breeze_generated=true`` and properties_changed
    contains email / phone                                 → PR-04 FLAG
  * ``event_type=deal.creation`` by Breeze with
    ``breeze_confidence_score < threshold``                → PR-03 FLAG
  * ``event_type=deal.creation.amountChange`` amount over
    threshold (default $50000 = 5,000,000 cents) by Breeze → PR-04 FAIL
  * ``event_type=deal.creation.stageChange`` to "Closed
    Won" by Breeze                                         → PR-02 FAIL
    (autonomous deal closure = direct revenue impact)
  * ``event_type=engagement.email`` is_breeze_generated    → PR-04 FLAG
    (agent-sent email — outbound communication)
  * ``event_type=engagement.note`` is_breeze_generated on
    a contact with internal-note property pattern          → PR-05 FLAG
  * ``event_type=workflow.trigger`` with workflow_id       → PR-05 PASS
  * ``event_type=breeze_copilot.message``                  → captured (audit)
  * ``event_type=breeze_agent.action`` agent_action=
    draft_email                                            → PR-04 FLAG
  * ``event_type=breeze_agent.action`` agent_action=
    qualify_lead                                           → PR-05 PASS
  * ``event_type=export.contacts`` with export_size_bytes
    over threshold (default 10MB)                          → PR-04 FAIL
  * ``event_type=webhook.created`` host not in allowlist   → PR-04 FLAG
  * ``event_type=app.install``                             → PR-01 FLAG
    (new automation surface)
  * ``event_type=user.role.update`` to Super Admin         → PR-02 FAIL
  * ``event_type=property_change.list_membership`` on a
    marketing contact                                      → PR-05 FLAG
  * ``event_type=company.merger`` or ``contact.merger``    → PR-05 FLAG
    (data merge — audit completeness)
  * ``is_bulk=true`` + ``record_count`` over threshold     → PR-04 FLAG
  * cross-object pattern: same Breeze actor touching > N
    object_types in 1 hour (default 4)                     → PR-04 FLAG synthetic
  * bot-velocity: Breeze actor doing > N actions in 1 hour
    (default 100)                                          → PR-04 FLAG synthetic
  * high-touch contact: same target.object_id (contact)
    modified > N times in 1 hour (default 5)               → PR-05 FLAG synthetic

Sanitization (security-critical — HubSpot events can carry full customer PII
in property values, full agent identity in actor.email, full contact IDs in
target.object_id, full webhook URLs):
  * ``actor.user_id`` retains only the last 8 characters (HubSpot user IDs
    are pseudonymous portal-scoped IDs but still re-identifiable).
  * ``actor.email`` is reduced to the email domain only.
  * ``target.object_id`` retains only the last 8 characters — the suffix lets
    analysts correlate without exposing which records were touched.
  * ``properties_changed`` is captured as a KEY LIST ONLY — values are never
    stored. (HubSpot property values frequently carry SSN, tax_id, full names,
    deal amounts.)
  * ``webhook_url`` is reduced to the URL host only.
  * ``client_ip`` IPv4 is reduced to ``/16``; private / loopback / link-local
    are preserved verbatim; IPv6 reduced to a ``/32`` pattern.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on ``hubspot-api-client``; HubSpot audit-log exports
are parsed with the standard library only.
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
#   <repo>/python/src/ancilis/importers/hubspot.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "hubspot-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_SENSITIVE_PROPERTIES: frozenset[str] = frozenset(
    {
        "ssn",
        "tax_id",
        "credit_card",
        "passport",
        "bank_account",
        "national_id",
        "drivers_license",
    }
)
_DEFAULT_CONTACT_INFO_PROPERTIES: frozenset[str] = frozenset(
    {"email", "phone", "mobile_phone"}
)
_DEFAULT_CLOSED_WON_LABELS: frozenset[str] = frozenset(
    {"closedwon", "closed_won", "closed won"}
)
_DEFAULT_SUPER_ADMIN_LABELS: frozenset[str] = frozenset(
    {"super admin", "super_admin", "superadmin"}
)

# Threshold defaults — large_deal is in cents (5,000,000 = $50,000).
_DEFAULT_LARGE_DEAL_THRESHOLD = 5_000_000
_DEFAULT_BULK_EXPORT_THRESHOLD = 10_000_000  # 10 MB
_DEFAULT_BREEZE_CONFIDENCE_THRESHOLD = 0.7
_DEFAULT_CROSS_OBJECT_THRESHOLD = 4
_DEFAULT_BOT_VELOCITY_THRESHOLD = 100
_DEFAULT_HIGH_TOUCH_CONTACT_THRESHOLD = 5
_DEFAULT_BULK_RECORD_THRESHOLD = 1000


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the hubspot-aksi-controls.json mapping; tolerate missing file."""
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


def _email_domain(email: str | None) -> str | None:
    """Reduce an email to the domain only (``svc@acme.com`` → ``acme.com``)."""
    if not isinstance(email, str):
        return None
    e = email.strip()
    if not e or "@" not in e:
        return None
    return e.split("@", 1)[1].lower() or None


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


def _classify_source_ip(source_ip: str | None) -> str | None:
    """Normalize a client IP to a privacy-aware form.

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


def _webhook_host(url: str | None) -> str | None:
    """Reduce a webhook URL to the host portion only."""
    if not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = parts.netloc or parts.path or ""
    host = host.split("/", 1)[0]
    return host.lower() or None


def _coerce_ts_to_hour(timestamp: Any) -> str:
    """Reduce a HubSpot timestamp (epoch ms or ISO string) to an hour bucket.

    Used for the "in 1 hour" synthetic patterns. Returns ``YYYY-MM-DDTHH``.
    """
    if isinstance(timestamp, (int, float)):
        try:
            dt = datetime.fromtimestamp(timestamp / 1000.0, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H")
        except (OverflowError, OSError, ValueError):
            return "unknown"
    if isinstance(timestamp, str) and timestamp.strip():
        # Accept ISO 8601 with or without milliseconds, with Z or +00:00.
        s = timestamp.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            return dt.strftime("%Y-%m-%dT%H")
        except ValueError:
            return timestamp[:13] if len(timestamp) >= 13 else "unknown"
    return "unknown"


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class HubSpotImporter:
    """Parse a HubSpot Audit Log / webhook export and convert to ``EvaluationResult`` records."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        large_deal_threshold: int | None = None,
        bulk_export_threshold: int | None = None,
        breeze_confidence_threshold: float | None = None,
        cross_object_threshold: int | None = None,
        bot_velocity_threshold: int | None = None,
        high_touch_contact_threshold: int | None = None,
        bulk_record_threshold: int | None = None,
        sensitive_properties: Iterable[str] | None = None,
        contact_info_properties: Iterable[str] | None = None,
        closed_won_labels: Iterable[str] | None = None,
        super_admin_labels: Iterable[str] | None = None,
        webhook_host_allowlist: Iterable[str] | None = None,
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

        self.large_deal_threshold = _resolve_int(
            large_deal_threshold,
            "large_deal_threshold",
            _DEFAULT_LARGE_DEAL_THRESHOLD,
        )
        self.bulk_export_threshold = _resolve_int(
            bulk_export_threshold,
            "bulk_export_threshold",
            _DEFAULT_BULK_EXPORT_THRESHOLD,
        )
        self.cross_object_threshold = _resolve_int(
            cross_object_threshold,
            "cross_object_threshold",
            _DEFAULT_CROSS_OBJECT_THRESHOLD,
        )
        self.bot_velocity_threshold = _resolve_int(
            bot_velocity_threshold,
            "bot_velocity_threshold",
            _DEFAULT_BOT_VELOCITY_THRESHOLD,
        )
        self.high_touch_contact_threshold = _resolve_int(
            high_touch_contact_threshold,
            "high_touch_contact_threshold",
            _DEFAULT_HIGH_TOUCH_CONTACT_THRESHOLD,
        )
        self.bulk_record_threshold = _resolve_int(
            bulk_record_threshold,
            "bulk_record_threshold",
            _DEFAULT_BULK_RECORD_THRESHOLD,
        )
        self.breeze_confidence_threshold = _resolve_float(
            breeze_confidence_threshold,
            "breeze_confidence_threshold",
            _DEFAULT_BREEZE_CONFIDENCE_THRESHOLD,
        )

        if sensitive_properties is not None:
            self.sensitive_properties = frozenset(
                str(p).lower() for p in sensitive_properties
            )
        else:
            meta_sens = meta.get("sensitive_property_patterns")
            if isinstance(meta_sens, list) and meta_sens:
                self.sensitive_properties = frozenset(
                    str(p).lower() for p in meta_sens
                )
            else:
                self.sensitive_properties = _DEFAULT_SENSITIVE_PROPERTIES

        if contact_info_properties is not None:
            self.contact_info_properties = frozenset(
                str(p).lower() for p in contact_info_properties
            )
        else:
            meta_ci = meta.get("contact_info_property_patterns")
            if isinstance(meta_ci, list) and meta_ci:
                self.contact_info_properties = frozenset(
                    str(p).lower() for p in meta_ci
                )
            else:
                self.contact_info_properties = _DEFAULT_CONTACT_INFO_PROPERTIES

        if closed_won_labels is not None:
            self.closed_won_labels = frozenset(
                str(label).strip().lower() for label in closed_won_labels
            )
        else:
            meta_cw = meta.get("closed_won_stage_labels")
            if isinstance(meta_cw, list) and meta_cw:
                self.closed_won_labels = frozenset(
                    str(label).strip().lower() for label in meta_cw
                )
            else:
                self.closed_won_labels = _DEFAULT_CLOSED_WON_LABELS

        if super_admin_labels is not None:
            self.super_admin_labels = frozenset(
                str(label).strip().lower() for label in super_admin_labels
            )
        else:
            meta_sa = meta.get("super_admin_role_labels")
            if isinstance(meta_sa, list) and meta_sa:
                self.super_admin_labels = frozenset(
                    str(label).strip().lower() for label in meta_sa
                )
            else:
                self.super_admin_labels = _DEFAULT_SUPER_ADMIN_LABELS

        if webhook_host_allowlist is not None:
            self.webhook_host_allowlist = frozenset(
                str(h).strip().lower() for h in webhook_host_allowlist
            )
        else:
            self.webhook_host_allowlist = frozenset()

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a HubSpot audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse HubSpot audit-log content from a JSON or JSONL string."""
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

    def _actor_key(self, event: dict[str, Any]) -> str | None:
        """Stable per-actor key used for synthetic aggregations."""
        actor = event.get("actor")
        if not isinstance(actor, dict):
            return None
        user_id = actor.get("user_id")
        if isinstance(user_id, str) and user_id.strip():
            return user_id.strip()
        email = actor.get("email")
        if isinstance(email, str) and email.strip():
            return email.strip().lower()
        return None

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass: aggregate cross-object / bot-velocity / high-touch patterns
        # bucketed by actor + hour.
        cross_object_bucket: dict[tuple[str, str], set[str]] = defaultdict(set)
        bot_velocity_bucket: dict[tuple[str, str], int] = defaultdict(int)
        high_touch_bucket: dict[tuple[str, str], int] = defaultdict(int)

        for ev in events:
            actor_key = self._actor_key(ev)
            actor = ev.get("actor") or {}
            is_breeze = bool(actor.get("is_breeze_agent")) if isinstance(actor, dict) else False
            hour = _coerce_ts_to_hour(ev.get("timestamp"))
            target = ev.get("target") or {}
            if isinstance(target, dict):
                obj_type = target.get("object_type")
                obj_id = target.get("object_id")
            else:
                obj_type = None
                obj_id = None

            if actor_key and is_breeze:
                if isinstance(obj_type, str) and obj_type.strip():
                    cross_object_bucket[(actor_key, hour)].add(obj_type.strip())
                bot_velocity_bucket[(actor_key, hour)] += 1

            event_type = str(ev.get("event_type") or "")
            if (
                isinstance(obj_id, str)
                and obj_id.strip()
                and isinstance(obj_type, str)
                and obj_type.strip().lower() == "contact"
                and event_type.startswith("contact.")
            ):
                high_touch_bucket[(obj_id.strip(), hour)] += 1

        cross_object_hits: dict[tuple[str, str], list[str]] = {
            key: sorted(types)
            for key, types in cross_object_bucket.items()
            if len(types) > self.cross_object_threshold
        }
        bot_velocity_hits: dict[tuple[str, str], int] = {
            key: count
            for key, count in bot_velocity_bucket.items()
            if count > self.bot_velocity_threshold
        }
        high_touch_hits: dict[tuple[str, str], int] = {
            key: count
            for key, count in high_touch_bucket.items()
            if count > self.high_touch_contact_threshold
        }

        results = [
            self._parse_event(ev, file_sha256=file_sha256)
            for ev in events
        ]

        # Synthetic findings.
        for (actor_key, hour), object_types in sorted(cross_object_hits.items()):
            results.append(
                self._synthetic_cross_object_result(
                    actor_key=actor_key,
                    hour=hour,
                    object_types=object_types,
                    file_sha256=file_sha256,
                )
            )
        for (actor_key, hour), count in sorted(bot_velocity_hits.items()):
            results.append(
                self._synthetic_bot_velocity_result(
                    actor_key=actor_key,
                    hour=hour,
                    count=count,
                    file_sha256=file_sha256,
                )
            )
        for (object_id, hour), count in sorted(high_touch_hits.items()):
            results.append(
                self._synthetic_high_touch_contact_result(
                    object_id=object_id,
                    hour=hour,
                    count=count,
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
            "source_format": "hubspot_audit_log",
            "source_tool_name": "hubspot_audit_log",
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
    ) -> EvaluationResult:
        event_id = str(event.get("id") or uuid.uuid4())
        event_type = str(event.get("event_type") or "Unknown")
        timestamp_raw = event.get("timestamp")
        if isinstance(timestamp_raw, (int, float)):
            try:
                timestamp = datetime.fromtimestamp(
                    timestamp_raw / 1000.0, tz=timezone.utc
                ).isoformat()
            except (OverflowError, OSError, ValueError):
                timestamp = datetime.now(timezone.utc).isoformat()
        elif isinstance(timestamp_raw, str) and timestamp_raw.strip():
            timestamp = timestamp_raw.strip()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        # -- Actor ----------------------------------------------------------
        actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
        actor_user_id_last8 = _last_8(actor.get("user_id"))
        actor_email_domain = _email_domain(actor.get("email"))
        is_breeze_agent = bool(actor.get("is_breeze_agent"))
        agent_action_raw = actor.get("agent_action")
        agent_action = (
            str(agent_action_raw).strip().lower()
            if isinstance(agent_action_raw, str) and agent_action_raw.strip()
            else None
        )

        # -- Target ---------------------------------------------------------
        target = event.get("target") if isinstance(event.get("target"), dict) else {}
        object_type = (
            str(target.get("object_type"))
            if isinstance(target.get("object_type"), str)
            else None
        )
        object_id_last8 = _last_8(target.get("object_id"))
        try:
            record_count = int(target.get("record_count") or 0)
        except (TypeError, ValueError):
            record_count = 0
        is_marketing_contact = bool(target.get("is_marketing_contact"))

        # -- Properties / change shape -------------------------------------
        properties_changed_raw = event.get("properties_changed") or []
        properties_changed: list[str] = (
            [str(p) for p in properties_changed_raw]
            if isinstance(properties_changed_raw, list)
            else []
        )
        properties_changed_lower = {p.lower() for p in properties_changed}

        # -- Volumes / shape ------------------------------------------------
        is_bulk = bool(event.get("is_bulk"))
        is_breeze_generated = bool(event.get("is_breeze_generated"))
        breeze_confidence_score_raw = event.get("breeze_confidence_score")
        try:
            breeze_confidence_score: float | None = (
                float(breeze_confidence_score_raw)
                if breeze_confidence_score_raw is not None
                else None
            )
        except (TypeError, ValueError):
            breeze_confidence_score = None
        try:
            export_size_bytes = int(event.get("export_size_bytes") or 0)
        except (TypeError, ValueError):
            export_size_bytes = 0
        try:
            amount_value = float(event.get("amount") or 0.0)
        except (TypeError, ValueError):
            amount_value = 0.0
        new_stage_raw = event.get("new_stage")
        new_stage_normalized = (
            str(new_stage_raw).strip().lower()
            if isinstance(new_stage_raw, str) and new_stage_raw.strip()
            else None
        )
        new_role_raw = event.get("new_role")
        new_role_normalized = (
            str(new_role_raw).strip().lower()
            if isinstance(new_role_raw, str) and new_role_raw.strip()
            else None
        )

        workflow_id = (
            str(event.get("workflow_id"))
            if isinstance(event.get("workflow_id"), str)
            else None
        )
        app_id = (
            str(event.get("app_id"))
            if isinstance(event.get("app_id"), str)
            else None
        )
        webhook_host = _webhook_host(event.get("webhook_url_host") or event.get("webhook_url"))
        client_ip_redacted = _classify_source_ip(event.get("client_ip"))
        tenant_id = (
            str(event.get("tenant_id"))
            if isinstance(event.get("tenant_id"), str)
            else None
        )
        subscription_tier = (
            str(event.get("subscription_tier"))
            if isinstance(event.get("subscription_tier"), str)
            else None
        )

        common_evidence: dict[str, Any] = {
            "hubspot_event_id": event_id,
            "event_type": event_type,
            "event_time": timestamp,
            "actor_user_id_last8": actor_user_id_last8,
            "actor_email_domain": actor_email_domain,
            "actor_is_breeze_agent": is_breeze_agent,
            "actor_agent_action": agent_action,
            "target_object_type": object_type,
            "target_object_id_last8": object_id_last8,
            "target_record_count": record_count,
            "target_is_marketing_contact": is_marketing_contact,
            "properties_changed": properties_changed,
            "properties_changed_count": len(properties_changed),
            "is_bulk": is_bulk,
            "is_breeze_generated": is_breeze_generated,
            "breeze_confidence_score": breeze_confidence_score,
            "export_size_bytes": export_size_bytes,
            "workflow_id": workflow_id,
            "app_id": app_id,
            "webhook_url_host": webhook_host,
            "client_ip_redacted": client_ip_redacted,
            "tenant_id": tenant_id,
            "subscription_tier": subscription_tier,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "hubspot_audit_log",
        }

        control_results: list[ControlResult] = []
        primary_emitted = False

        # ------------------------------------------------------------------
        # 1. Breeze contact creation / deletion.
        # ------------------------------------------------------------------
        if event_type == "contact.creation" and is_breeze_agent:
            signal = "breeze_contact_creation"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"HubSpot event {event_id} contact.creation by Breeze agent "
                        f"(actor_email_domain={actor_email_domain!r}) — agent-created "
                        f"contact, review for provenance"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True
        elif event_type == "contact.deletion" and is_breeze_agent:
            signal = "breeze_contact_deletion"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"HubSpot event {event_id} contact.deletion by Breeze agent — "
                        f"autonomous data destruction is out-of-scope for an AI agent"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 2. contact.propertyChange — sensitive PII / contact-info changes.
        # ------------------------------------------------------------------
        elif event_type == "contact.propertyChange":
            sensitive_hits = sorted(
                p for p in properties_changed if p.lower() in self.sensitive_properties
            )
            if sensitive_hits:
                signal = "sensitive_property_change"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"HubSpot event {event_id} contact.propertyChange touched "
                            f"sensitive properties {sensitive_hits} — "
                            f"sensitive PII modification by agent="
                            f"{is_breeze_agent} (BLOCK)"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "sensitive_properties_changed": sensitive_hits,
                        },
                    )
                )
                primary_emitted = True
            elif is_breeze_generated and any(
                p.lower() in self.contact_info_properties
                for p in properties_changed
            ):
                contact_info_hits = sorted(
                    p for p in properties_changed
                    if p.lower() in self.contact_info_properties
                )
                signal = "breeze_property_change_contact_info"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} contact.propertyChange by Breeze "
                            f"on contact-info properties {contact_info_hits} "
                            f"— review for accuracy"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "contact_info_properties_changed": contact_info_hits,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 3. deal.creation — Breeze low-confidence.
        # ------------------------------------------------------------------
        elif event_type == "deal.creation":
            if (
                is_breeze_agent
                and breeze_confidence_score is not None
                and breeze_confidence_score < self.breeze_confidence_threshold
            ):
                signal = "breeze_low_confidence_deal"
                control_id = _control_for(signal, self._mappings, "PR-03")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} deal.creation by Breeze "
                            f"with breeze_confidence_score={breeze_confidence_score} "
                            f"below threshold {self.breeze_confidence_threshold} "
                            f"— low-confidence AI deal creation"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "breeze_confidence_threshold": self.breeze_confidence_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 4. deal.creation.amountChange — large autonomous mutation.
        # ------------------------------------------------------------------
        elif event_type == "deal.creation.amountChange":
            if is_breeze_agent and amount_value > self.large_deal_threshold:
                signal = "large_deal_amount_change"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"HubSpot event {event_id} deal.creation.amountChange "
                            f"amount={amount_value} by Breeze exceeds threshold "
                            f"{self.large_deal_threshold} — autonomous large-deal "
                            f"modification (BLOCK)"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "amount": amount_value,
                            "large_deal_threshold": self.large_deal_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 5. deal.creation.stageChange — autonomous Closed Won.
        # ------------------------------------------------------------------
        elif event_type == "deal.creation.stageChange":
            if (
                is_breeze_agent
                and new_stage_normalized is not None
                and new_stage_normalized in self.closed_won_labels
            ):
                signal = "autonomous_deal_closure"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"HubSpot event {event_id} deal.creation.stageChange to "
                            f"{new_stage_raw!r} by Breeze — autonomous deal closure has "
                            f"direct revenue impact and must be human-approved (BLOCK)"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "new_stage": new_stage_raw,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 6. engagement.email — Breeze-sent.
        # ------------------------------------------------------------------
        elif event_type == "engagement.email":
            if is_breeze_generated:
                signal = "breeze_email_sent"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} engagement.email is_breeze_generated "
                            f"— agent-sent outbound communication"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 7. engagement.note — Breeze-generated note on a contact.
        # ------------------------------------------------------------------
        elif event_type == "engagement.note":
            if (
                is_breeze_generated
                and isinstance(object_type, str)
                and object_type.lower() == "contact"
                and any("internal_note" in p.lower() for p in properties_changed)
            ):
                signal = "breeze_internal_note"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} engagement.note by Breeze on contact "
                            f"with internal-note property — captured for audit"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 8. workflow.trigger — automation, expected audit-trail.
        # ------------------------------------------------------------------
        elif event_type == "workflow.trigger":
            if workflow_id:
                signal = "workflow_trigger"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"HubSpot event {event_id} workflow.trigger workflow_id="
                            f"{workflow_id} — automation audit-trail"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 9. breeze_copilot.message — capture as audit signal.
        # ------------------------------------------------------------------
        elif event_type == "breeze_copilot.message":
            signal = "breeze_copilot_message"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"HubSpot event {event_id} breeze_copilot.message — Breeze "
                        f"AI conversation captured for audit"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 10. breeze_agent.action — draft_email / qualify_lead.
        # ------------------------------------------------------------------
        elif event_type == "breeze_agent.action":
            if agent_action == "draft_email":
                signal = "breeze_draft_email"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} breeze_agent.action draft_email "
                            f"— agent drafting outbound communication"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True
            elif agent_action == "qualify_lead":
                signal = "breeze_qualify_lead"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"HubSpot event {event_id} breeze_agent.action qualify_lead "
                            f"— captured (read-mostly Breeze action)"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 11. export.contacts — bulk-export of contacts.
        # ------------------------------------------------------------------
        elif event_type == "export.contacts":
            if export_size_bytes > self.bulk_export_threshold:
                signal = "bulk_contact_export"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"HubSpot event {event_id} export.contacts "
                            f"export_size_bytes={export_size_bytes} exceeds threshold "
                            f"{self.bulk_export_threshold} (bulk-export of contacts)"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "bulk_export_threshold": self.bulk_export_threshold,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 12. webhook.created — new external surface.
        # ------------------------------------------------------------------
        elif event_type == "webhook.created":
            if (
                webhook_host is not None
                and webhook_host.lower() not in self.webhook_host_allowlist
            ):
                signal = "webhook_external"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} webhook.created host="
                            f"{webhook_host!r} not in allowlist — new external surface"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "webhook_host_allowlist": sorted(self.webhook_host_allowlist),
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 13. app.install — new automation surface.
        # ------------------------------------------------------------------
        elif event_type == "app.install":
            signal = "app_install"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"HubSpot event {event_id} app.install app_id={app_id!r} "
                        f"— new automation surface added to portal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # 14. user.role.update — Super Admin promotion.
        # ------------------------------------------------------------------
        elif event_type == "user.role.update":
            if (
                new_role_normalized is not None
                and new_role_normalized in self.super_admin_labels
            ):
                signal = "super_admin_promotion"
                control_id = _control_for(signal, self._mappings, "PR-02")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"HubSpot event {event_id} user.role.update new_role="
                            f"{new_role_raw!r} — Super Admin promotion is a "
                            f"high-impact governance event"
                        ),
                        evidence_data={
                            **common_evidence,
                            "signal": signal,
                            "new_role": new_role_raw,
                        },
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 15. property_change.list_membership — marketing-list audit.
        # ------------------------------------------------------------------
        elif event_type == "property_change.list_membership":
            if is_marketing_contact:
                signal = "list_membership_marketing"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"HubSpot event {event_id} property_change.list_membership "
                            f"on marketing contact — list-membership audit"
                        ),
                        evidence_data={**common_evidence, "signal": signal},
                    )
                )
                primary_emitted = True

        # ------------------------------------------------------------------
        # 16. company.merger / contact.merger.
        # ------------------------------------------------------------------
        elif event_type in ("company.merger", "contact.merger"):
            signal = "merge_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"HubSpot event {event_id} {event_type} — data merge "
                        f"requires audit-trail completeness review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Additive: bulk + record_count over threshold.
        # ------------------------------------------------------------------
        if is_bulk and record_count > self.bulk_record_threshold:
            signal = "bulk_operation"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"HubSpot event {event_id} {event_type} bulk operation with "
                        f"record_count={record_count} exceeds threshold "
                        f"{self.bulk_record_threshold} — mass operation"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "bulk_record_threshold": self.bulk_record_threshold,
                    },
                )
            )
            primary_emitted = True

        # ------------------------------------------------------------------
        # Fallback: unmatched event — surface as PR-05 FLAG.
        # ------------------------------------------------------------------
        if not primary_emitted:
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"HubSpot event {event_id} event_type={event_type!r} "
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
            f"Imported from HubSpot Audit Log: event_type={event_type} "
            f"actor_email_domain={actor_email_domain or 'unknown'} "
            f"is_breeze_agent={is_breeze_agent} "
            f"target_object_type={object_type or 'none'} "
            f"is_breeze_generated={is_breeze_generated}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"hubspot-{event_id[:32]}",
            timestamp=timestamp,
            agent_id=self.agent_id,
            source_type="hubspot_audit_log_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=tenant_id,
        )

    # ------------------------------------------------------------------
    # Synthetic findings
    # ------------------------------------------------------------------

    def _synthetic_cross_object_result(
        self,
        *,
        actor_key: str,
        hour: str,
        object_types: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_object_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        actor_last8 = _last_8(actor_key) or actor_key
        synthetic_id = f"hubspot-cross-object-{actor_last8}-{hour}"
        evidence: dict[str, Any] = {
            "hubspot_event_id": synthetic_id,
            "actor_user_id_last8": actor_last8,
            "hour_bucket": hour,
            "cross_object_object_types": object_types,
            "cross_object_object_count": len(object_types),
            "cross_object_threshold": self.cross_object_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "hubspot_audit_log",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"HubSpot synthetic finding: Breeze actor {actor_last8} touched "
                f"{len(object_types)} object types ({', '.join(object_types)}) "
                f"in hour {hour} — exceeds cross-object threshold "
                f"{self.cross_object_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="hubspot_audit_log_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from HubSpot Audit Log: synthetic cross-object pattern "
                f"actor={actor_last8} hour={hour} "
                f"object_types={len(object_types)}>threshold={self.cross_object_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_bot_velocity_result(
        self,
        *,
        actor_key: str,
        hour: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "bot_velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        actor_last8 = _last_8(actor_key) or actor_key
        synthetic_id = f"hubspot-bot-velocity-{actor_last8}-{hour}"
        evidence: dict[str, Any] = {
            "hubspot_event_id": synthetic_id,
            "actor_user_id_last8": actor_last8,
            "hour_bucket": hour,
            "action_count": count,
            "bot_velocity_threshold": self.bot_velocity_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "hubspot_audit_log",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"HubSpot synthetic finding: Breeze actor {actor_last8} performed "
                f"{count} actions in hour {hour} — exceeds bot-velocity threshold "
                f"{self.bot_velocity_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="hubspot_audit_log_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from HubSpot Audit Log: synthetic bot-velocity pattern "
                f"actor={actor_last8} hour={hour} "
                f"actions={count}>threshold={self.bot_velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_high_touch_contact_result(
        self,
        *,
        object_id: str,
        hour: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_touch_contact_pattern"
        control_id = _control_for(signal, self._mappings, "PR-05")
        object_id_last8 = _last_8(object_id) or object_id
        synthetic_id = f"hubspot-high-touch-{object_id_last8}-{hour}"
        evidence: dict[str, Any] = {
            "hubspot_event_id": synthetic_id,
            "target_object_id_last8": object_id_last8,
            "hour_bucket": hour,
            "modification_count": count,
            "high_touch_contact_threshold": self.high_touch_contact_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synthetic_id
            ),
            "source_tool": "hubspot_audit_log",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"HubSpot synthetic finding: contact id-suffix {object_id_last8} "
                f"modified {count} times in hour {hour} — exceeds high-touch "
                f"threshold {self.high_touch_contact_threshold} (audit anomaly)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="hubspot_audit_log_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from HubSpot Audit Log: synthetic high-touch contact "
                f"object_id_last8={object_id_last8} hour={hour} "
                f"modifications={count}>threshold={self.high_touch_contact_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
