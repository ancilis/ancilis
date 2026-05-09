"""Mailchimp marketing-email audit-log importer — maps Mailchimp audit / activity
records to AKSI controls.

Mailchimp (https://mailchimp.com) is the dominant *marketing* email platform.
Where SendGrid is the transactional + marketing rail, Mailchimp is
marketing-first: campaigns, audiences (lists), automations, double-opt-in
flows, and the sender-reputation hygiene that goes with bulk marketing send.
Agents that orchestrate marketing campaigns, manage audiences, schedule
automations, push list updates, or rotate Mailchimp API keys surface in the
Mailchimp Audit Log + activity feeds. Every campaign send carries CAN-SPAM
exposure (US — required physical-postal-address line, working unsubscribe
link, recorded consent for the recipient), GDPR exposure for EU subscribers
(consent must be explicit opt-in), sender-reputation exposure (deliverability
score, complaint rate, bounce rate, SPF / DKIM / DMARC / BIMI authentication),
and audience-PII exposure (importing / exporting / deleting member lists with
PII columns).

This importer ingests Mailchimp exports in the following on-disk shapes:

  * ``{"events": [...]}`` — Mailchimp Audit Log envelope
  * ``{"data": [...]}``   — generic data envelope
  * JSONL                  — one record per line
  * Single record envelope — one bare object

Signal mapping (see shared/mappings/mailchimp-aksi-controls.json):

  * ``event_type=campaign_sent`` & ``is_marketing=true`` & ``consent_basis``
    null                                                                  → DE-01 FAIL (CAN-SPAM)
  * ``event_type=campaign_sent`` & ``is_marketing=true`` &
    ``consent_basis=legitimate_interest``                                 → PR-04 FLAG (GDPR review)
  * ``event_type=campaign_sent`` & ``contains_eu_subscribers=true`` &
    ``consent_basis != opt_in``                                           → PR-04 FAIL (GDPR EU consent)
  * ``event_type=campaign_sent`` & ``unsubscribe_link_present=false``     → PR-05 FAIL (CAN-SPAM)
  * ``event_type=campaign_sent`` & ``physical_address_present=false``     → PR-05 FAIL (CAN-SPAM)
  * ``event_type=campaign_sent`` & ``compliance_check_passed=false``      → PR-04 FAIL (Mailchimp pre-send)
  * ``event_type=campaign_sent`` & SPF / DKIM / DMARC any false           → PR-04 FAIL (sender auth)
  * ``event_type=campaign_sent`` & ``deliverability_score < floor``       → PR-04 FLAG (low reputation)
  * ``event_type=campaign_sent`` & ``complaint_rate > max``               → PR-04 FAIL (ESP danger zone)
  * ``event_type=campaign_sent`` & ``bounce_rate > max``                  → PR-04 FAIL (list hygiene)
  * ``event_type=list_imported`` & ``contains_pii_columns=true``          → PR-04 FLAG (importing PII)
  * ``event_type=list_imported`` & ``is_double_optin=false``              → PR-04 FAIL (single-opt-in)
  * ``event_type=list_exported``                                          → PR-04 FLAG (PII off-platform)
  * ``event_type=list_deleted``                                           → PR-02 FAIL (audience destruction)
  * ``event_type=list_member_added`` & double-opt-in disabled & no
    ``consent_basis``                                                     → PR-04 FAIL
  * ``event_type=list_member_unsubscribed``                               → PR-05 PASS
  * ``event_type=automation_started`` & ``actor.is_api_user=true``        → PR-05 PASS (capture)
  * ``event_type=connected_site_added``                                   → PR-01 FLAG (new tracking surface)
  * ``event_type=webhook_added`` & host not in allowlist                  → PR-04 FLAG (external destination)
  * ``event_type=api_key_created``                                        → PR-01 FLAG
  * ``event_type=team_member_role_changed`` & ``new_role=admin``          → PR-02 FAIL (admin promotion)
  * ``event_type=compliance_settings_changed`` (weakening)                → PR-02 FAIL
  * ``event_type=gdpr_data_request``                                      → PR-05 PASS (compliance trail)
  * ``event_type=gdpr_data_deletion``                                     → PR-05 PASS
  * ``event_type=unsubscribe_required_link_removed``                      → PR-05 FAIL
  * ``event_type=send_to_unverified_domain``                              → PR-04 FAIL
  * ``action_metadata.is_bulk=true`` & ``target_count > threshold``       → PR-04 FLAG (very-large send)

Synthetic patterns
  * Cross-list: actor touching > N audience_ids in 1h (default 5)         → PR-04 FLAG
  * High-volume marketing: same actor sending > N campaigns to total
    > X recipients in 24h (default 5 / 250000)                            → PR-04 FLAG

Sanitization (privacy-critical):

  * ``actor.email`` raw addresses are NEVER stored. Only the ``@domain``
    portion survives: ``alice@corp.example.com`` → ``"@corp.example.com"``.
  * Campaign subject text is DROPPED entirely (``subject_length`` only).
  * ``campaign.audience_id`` and ``audience.id`` are reduced to the last 8
    characters only — enough to correlate within an export, not enough to
    re-identify an audience cross-tenant.
  * ``audience.name`` is dropped (``audience_name_length`` only).
  * ``webhook_url`` is reduced to host only.
  * ``action_metadata.ip_address`` is masked to /16.
  * ``sender_email_domain`` is already a domain — stored as-is.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``mailchimp-marketing`` package; exports are
parsed with the standard library only.
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

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/mailchimp-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/mailchimp.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "mailchimp-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_CROSS_LIST_THRESHOLD = 5
_DEFAULT_CROSS_LIST_WINDOW_MINUTES = 60
_DEFAULT_HIGH_VOLUME_CAMPAIGNS_24H = 5
_DEFAULT_HIGH_VOLUME_RECIPIENTS_24H = 250000
_DEFAULT_BULK_TARGET_THRESHOLD = 100000
_DEFAULT_DELIVERABILITY_FLOOR = 80
_DEFAULT_COMPLAINT_RATE_MAX = 0.005
_DEFAULT_BOUNCE_RATE_MAX = 0.05


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the mailchimp-aksi-controls.json mapping; tolerate missing file."""
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


def _email_to_domain(email: str | None) -> str | None:
    """Reduce a full email address to its ``@domain`` portion only."""
    if not email or not isinstance(email, str):
        return None
    s = email.strip()
    if "@" not in s:
        return None
    domain = s.rsplit("@", 1)[-1].strip().lower()
    if not domain:
        return None
    return f"@{domain}"


def _last8(value: str | None) -> str | None:
    """Reduce an opaque id (audience_id, campaign.audience_id) to last 8 chars."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if len(s) <= 8:
        return s
    return s[-8:]


def _mask_ip(ip: str | None) -> str | None:
    """Mask an IPv4/IPv6 address to a /16 (v4) or /32 (v6) prefix."""
    if not ip or not isinstance(ip, str):
        return None
    s = ip.strip()
    if not s:
        return None
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{s}/16", strict=False)
        return str(net)
    net = ipaddress.ip_network(f"{s}/32", strict=False)
    return str(net)


def _url_host(url: str | None) -> str | None:
    """Reduce a webhook URL to its host only (no path / query / fragment)."""
    if not url or not isinstance(url, str):
        return None
    s = url.strip()
    if not s:
        return None
    # Strip scheme://
    if "://" in s:
        s = s.split("://", 1)[1]
    # Strip path / query / fragment
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    s = s.strip().lower()
    return s or None


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
    return None


def _str_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Best-effort ISO 8601 → naive UTC datetime; tolerate trailing 'Z'."""
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class MailchimpImporter:
    """Parse a Mailchimp audit-log / activity export into ``EvaluationResult``
    records.

    A single import file may carry events from any combination of campaign
    send, audience management, automation, and admin actions. The enclosing
    envelope (``{"events": [...]}``, ``{"data": [...]}``, JSONL, or single
    object) is auto-detected.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        cross_list_threshold: int | None = None,
        cross_list_window_minutes: int | None = None,
        high_volume_campaigns_24h: int | None = None,
        high_volume_recipients_24h: int | None = None,
        bulk_target_threshold: int | None = None,
        deliverability_score_floor: int | None = None,
        complaint_rate_max: float | None = None,
        bounce_rate_max: float | None = None,
        marketing_consent_required: bool | None = None,
        webhook_host_allowlist: list[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        if cross_list_threshold is not None:
            self.cross_list_threshold = int(cross_list_threshold)
        else:
            self.cross_list_threshold = int(
                meta.get("cross_list_threshold", _DEFAULT_CROSS_LIST_THRESHOLD)
            )
        if cross_list_window_minutes is not None:
            self.cross_list_window_minutes = int(cross_list_window_minutes)
        else:
            self.cross_list_window_minutes = int(
                meta.get(
                    "cross_list_window_minutes",
                    _DEFAULT_CROSS_LIST_WINDOW_MINUTES,
                )
            )
        if high_volume_campaigns_24h is not None:
            self.high_volume_campaigns_24h = int(high_volume_campaigns_24h)
        else:
            self.high_volume_campaigns_24h = int(
                meta.get(
                    "high_volume_campaigns_24h",
                    _DEFAULT_HIGH_VOLUME_CAMPAIGNS_24H,
                )
            )
        if high_volume_recipients_24h is not None:
            self.high_volume_recipients_24h = int(high_volume_recipients_24h)
        else:
            self.high_volume_recipients_24h = int(
                meta.get(
                    "high_volume_recipients_24h",
                    _DEFAULT_HIGH_VOLUME_RECIPIENTS_24H,
                )
            )
        if bulk_target_threshold is not None:
            self.bulk_target_threshold = int(bulk_target_threshold)
        else:
            self.bulk_target_threshold = int(
                meta.get(
                    "bulk_target_threshold",
                    _DEFAULT_BULK_TARGET_THRESHOLD,
                )
            )
        if deliverability_score_floor is not None:
            self.deliverability_score_floor = int(deliverability_score_floor)
        else:
            self.deliverability_score_floor = int(
                meta.get(
                    "deliverability_score_floor",
                    _DEFAULT_DELIVERABILITY_FLOOR,
                )
            )
        if complaint_rate_max is not None:
            self.complaint_rate_max = float(complaint_rate_max)
        else:
            self.complaint_rate_max = float(
                meta.get("complaint_rate_max", _DEFAULT_COMPLAINT_RATE_MAX)
            )
        if bounce_rate_max is not None:
            self.bounce_rate_max = float(bounce_rate_max)
        else:
            self.bounce_rate_max = float(
                meta.get("bounce_rate_max", _DEFAULT_BOUNCE_RATE_MAX)
            )
        if marketing_consent_required is not None:
            self.marketing_consent_required = bool(marketing_consent_required)
        else:
            self.marketing_consent_required = bool(
                meta.get("marketing_consent_required", True)
            )
        if webhook_host_allowlist is not None:
            self.webhook_host_allowlist = [
                str(h).strip().lower()
                for h in webhook_host_allowlist
                if isinstance(h, str) and h.strip()
            ]
        else:
            raw_allowlist = meta.get("webhook_host_allowlist", []) or []
            self.webhook_host_allowlist = [
                str(h).strip().lower()
                for h in raw_allowlist
                if isinstance(h, str) and h.strip()
            ]

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Mailchimp audit-log export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Mailchimp audit-log content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect Mailchimp-shaped envelopes / JSONL / single record."""
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
                for key in ("events", "data"):
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
        """Per-record dispatch + synthetic cross-list + high-volume findings."""
        # Per-actor: list of (timestamp, audience_id) for cross-list pattern.
        actor_audience_touches: dict[str, list[tuple[datetime, str]]] = defaultdict(
            list
        )
        # Per-actor: list of (timestamp, recipient_count) for high-volume.
        actor_campaign_sends: dict[str, list[tuple[datetime, int]]] = defaultdict(
            list
        )

        for rec in records:
            actor_key = self._actor_key(rec)
            ts = _parse_iso_timestamp(rec.get("timestamp"))
            event_type = _str_or_none(rec.get("event_type"))
            # Cross-list: any audience-touching event by an actor.
            if actor_key and ts and event_type:
                aud_id = self._extract_audience_id(rec)
                if aud_id and event_type in {
                    "list_member_added",
                    "list_member_removed",
                    "list_member_updated",
                    "list_member_unsubscribed",
                    "list_imported",
                    "list_exported",
                    "list_deleted",
                    "list_merged",
                    "campaign_sent",
                    "campaign_created",
                }:
                    actor_audience_touches[actor_key].append((ts, aud_id))
            # High-volume: campaign_sent events.
            if (
                actor_key
                and ts
                and event_type == "campaign_sent"
            ):
                campaign = rec.get("campaign") if isinstance(
                    rec.get("campaign"), dict
                ) else {}
                rc = _coerce_int(campaign.get("recipient_count")) or 0
                actor_campaign_sends[actor_key].append((ts, rc))

        cross_list_actors = self._compute_cross_list_actors(
            actor_audience_touches
        )
        high_volume_actors = self._compute_high_volume_actors(
            actor_campaign_sends
        )

        results: list[EvaluationResult] = []
        for rec in records:
            results.append(
                self._parse_event(
                    rec,
                    file_sha256=file_sha256,
                    cross_list_actors=cross_list_actors,
                    high_volume_actors=high_volume_actors,
                )
            )

        # Synthetic cross-list findings — one per actor.
        for actor_key, info in sorted(cross_list_actors.items()):
            results.append(
                self._synthetic_cross_list_result(
                    actor_key=actor_key,
                    audience_ids=info["audience_ids"],
                    file_sha256=file_sha256,
                )
            )
        # Synthetic high-volume findings — one per actor.
        for actor_key, info in sorted(high_volume_actors.items()):
            results.append(
                self._synthetic_high_volume_result(
                    actor_key=actor_key,
                    campaign_count=info["campaigns"],
                    total_recipients=info["recipients"],
                    file_sha256=file_sha256,
                )
            )
        return results

    def _actor_key(self, record: dict[str, Any]) -> str | None:
        actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
        user_id = _str_or_none(actor.get("user_id"))
        if user_id:
            return f"user:{user_id}"
        domain = _email_to_domain(actor.get("email"))
        if domain:
            return f"emaildomain:{domain}"
        return None

    def _extract_audience_id(self, record: dict[str, Any]) -> str | None:
        audience = record.get("audience") if isinstance(
            record.get("audience"), dict
        ) else {}
        aud_id = _str_or_none(audience.get("id"))
        if aud_id:
            return aud_id
        campaign = record.get("campaign") if isinstance(
            record.get("campaign"), dict
        ) else {}
        cid = _str_or_none(campaign.get("audience_id"))
        return cid

    def _compute_cross_list_actors(
        self,
        touches: dict[str, list[tuple[datetime, str]]],
    ) -> dict[str, dict[str, Any]]:
        """For each actor, find the largest sliding-window-1h distinct
        audience_id set; flag if > threshold."""
        window = self.cross_list_window_minutes * 60
        out: dict[str, dict[str, Any]] = {}
        for actor_key, items in touches.items():
            items_sorted = sorted(items, key=lambda x: x[0])
            n = len(items_sorted)
            best: set[str] = set()
            for i in range(n):
                window_set: set[str] = set()
                start_ts = items_sorted[i][0]
                for j in range(i, n):
                    delta = (items_sorted[j][0] - start_ts).total_seconds()
                    if delta > window:
                        break
                    window_set.add(items_sorted[j][1])
                if len(window_set) > len(best):
                    best = window_set
            if len(best) > self.cross_list_threshold:
                out[actor_key] = {"audience_ids": sorted(best)}
        return out

    def _compute_high_volume_actors(
        self,
        sends: dict[str, list[tuple[datetime, int]]],
    ) -> dict[str, dict[str, Any]]:
        """For each actor, sliding 24h window: > N campaigns AND > X recipients."""
        window = 24 * 60 * 60
        out: dict[str, dict[str, Any]] = {}
        for actor_key, items in sends.items():
            items_sorted = sorted(items, key=lambda x: x[0])
            n = len(items_sorted)
            best_campaigns = 0
            best_recipients = 0
            for i in range(n):
                count = 0
                total = 0
                start_ts = items_sorted[i][0]
                for j in range(i, n):
                    delta = (items_sorted[j][0] - start_ts).total_seconds()
                    if delta > window:
                        break
                    count += 1
                    total += items_sorted[j][1]
                if (
                    count > self.high_volume_campaigns_24h
                    and total > self.high_volume_recipients_24h
                    and (count > best_campaigns or total > best_recipients)
                ):
                    best_campaigns = count
                    best_recipients = total
            if best_campaigns and best_recipients:
                out[actor_key] = {
                    "campaigns": best_campaigns,
                    "recipients": best_recipients,
                }
        return out

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "mailchimp",
            "source_tool_name": "mailchimp",
            "source_tool_version": "",
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-record parser
    # ------------------------------------------------------------------

    def _common_evidence(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        """Build the shared evidence dict (sanitized)."""
        event_id_raw = _str_or_none(record.get("id"))
        record_id = event_id_raw or str(uuid.uuid4())
        event_type = _str_or_none(record.get("event_type"))
        timestamp = _str_or_none(record.get("timestamp"))

        actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
        actor_user_id = _str_or_none(actor.get("user_id"))
        actor_email_domain = _email_to_domain(actor.get("email"))
        actor_is_api_user = _coerce_bool(actor.get("is_api_user"))
        actor_is_workspace_admin = _coerce_bool(actor.get("is_workspace_admin"))

        campaign = record.get("campaign") if isinstance(
            record.get("campaign"), dict
        ) else {}
        campaign_id = _str_or_none(campaign.get("id"))
        campaign_subject_length = _coerce_int(campaign.get("subject_length"))
        campaign_audience_id_last8 = _last8(_str_or_none(campaign.get("audience_id")))
        campaign_contains_personalization = _coerce_bool(
            campaign.get("contains_personalization")
        )
        campaign_recipient_count = _coerce_int(campaign.get("recipient_count"))
        campaign_is_marketing = _coerce_bool(campaign.get("is_marketing"))
        campaign_consent_basis = _str_or_none(campaign.get("consent_basis"))
        if campaign_consent_basis:
            campaign_consent_basis = campaign_consent_basis.lower()
        campaign_compliance_check_passed = _coerce_bool(
            campaign.get("compliance_check_passed")
        )
        campaign_dma_disclosures = _coerce_bool(
            campaign.get("contains_dma_required_disclosures")
        )
        campaign_audience_size = _coerce_int(campaign.get("audience_size"))
        campaign_unsubscribe_link_present = _coerce_bool(
            campaign.get("unsubscribe_link_present")
        )
        campaign_physical_address_present = _coerce_bool(
            campaign.get("physical_address_present")
        )
        sender_auth_raw = campaign.get("sender_authentication")
        sender_auth = (
            sender_auth_raw if isinstance(sender_auth_raw, dict) else {}
        )
        sender_authentication = {
            "spf": _coerce_bool(sender_auth.get("spf")),
            "dkim": _coerce_bool(sender_auth.get("dkim")),
            "dmarc": _coerce_bool(sender_auth.get("dmarc")),
            "bimi": _coerce_bool(sender_auth.get("bimi")),
        }
        deliverability_score = _coerce_int(campaign.get("deliverability_score"))
        complaint_rate = _coerce_float(campaign.get("complaint_rate"))
        bounce_rate = _coerce_float(campaign.get("bounce_rate"))

        audience = record.get("audience") if isinstance(
            record.get("audience"), dict
        ) else {}
        audience_id_last8 = _last8(_str_or_none(audience.get("id")))
        audience_name_length = _coerce_int(audience.get("name_length"))
        audience_contains_pii_columns = _coerce_bool(
            audience.get("contains_pii_columns")
        )
        audience_member_count = _coerce_int(audience.get("member_count"))
        audience_is_double_optin = _coerce_bool(audience.get("is_double_optin"))
        audience_contains_eu = _coerce_bool(
            audience.get("contains_eu_subscribers")
        )

        action_metadata_raw = record.get("action_metadata")
        action_metadata = (
            action_metadata_raw if isinstance(action_metadata_raw, dict) else {}
        )
        am_target_count = _coerce_int(action_metadata.get("target_count"))
        am_is_bulk = _coerce_bool(action_metadata.get("is_bulk"))
        am_webhook_host = _url_host(action_metadata.get("webhook_url_host"))
        am_new_role = _str_or_none(action_metadata.get("new_role"))
        am_old_role = _str_or_none(action_metadata.get("old_role"))
        am_ip_masked = _mask_ip(action_metadata.get("ip_address"))
        am_sender_email_domain = _str_or_none(
            action_metadata.get("sender_email_domain")
        )
        am_unsubscribe_method_changed = _str_or_none(
            action_metadata.get("unsubscribe_method_changed")
        )

        evidence: dict[str, Any] = {
            "event_id": event_id_raw,
            "event_type": event_type,
            "timestamp": timestamp,
            "actor": {
                "user_id": actor_user_id,
                "email_domain": actor_email_domain,
                "is_api_user": actor_is_api_user,
                "is_workspace_admin": actor_is_workspace_admin,
            },
            "campaign": {
                "id": campaign_id,
                "subject_length": campaign_subject_length,
                "audience_id_last8": campaign_audience_id_last8,
                "contains_personalization": campaign_contains_personalization,
                "recipient_count": campaign_recipient_count,
                "is_marketing": campaign_is_marketing,
                "consent_basis": campaign_consent_basis,
                "compliance_check_passed": campaign_compliance_check_passed,
                "contains_dma_required_disclosures": campaign_dma_disclosures,
                "audience_size": campaign_audience_size,
                "unsubscribe_link_present": campaign_unsubscribe_link_present,
                "physical_address_present": campaign_physical_address_present,
                "sender_authentication": sender_authentication,
                "deliverability_score": deliverability_score,
                "complaint_rate": complaint_rate,
                "bounce_rate": bounce_rate,
            },
            "audience": {
                "id_last8": audience_id_last8,
                "name_length": audience_name_length,
                "contains_pii_columns": audience_contains_pii_columns,
                "member_count": audience_member_count,
                "is_double_optin": audience_is_double_optin,
                "contains_eu_subscribers": audience_contains_eu,
            },
            "action_metadata": {
                "target_count": am_target_count,
                "is_bulk": am_is_bulk,
                "webhook_url_host": am_webhook_host,
                "new_role": am_new_role,
                "old_role": am_old_role,
                "ip_masked": am_ip_masked,
                "sender_email_domain": am_sender_email_domain,
                "unsubscribe_method_changed": am_unsubscribe_method_changed,
            },
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=record_id,
            ),
            "source_tool": "mailchimp",
        }
        return evidence

    def _parse_event(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_list_actors: dict[str, dict[str, Any]],
        high_volume_actors: dict[str, dict[str, Any]],
    ) -> EvaluationResult:
        evidence = self._common_evidence(record, file_sha256=file_sha256)
        event_id = evidence["event_id"] or str(uuid.uuid4())
        event_type = evidence["event_type"] or "unknown"
        actor = evidence["actor"]
        campaign = evidence["campaign"]
        audience = evidence["audience"]
        action_metadata = evidence["action_metadata"]

        control_results: list[ControlResult] = []

        # Dispatch primary signal by event_type.
        if event_type == "campaign_sent":
            self._eval_campaign_sent(
                evidence, campaign, audience, control_results, event_id
            )
        elif event_type == "list_imported":
            self._eval_list_imported(
                evidence, audience, control_results, event_id
            )
        elif event_type == "list_exported":
            self._add(
                control_results,
                signal="list_exported",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp list_exported event {event_id} — audience "
                    f"export is potential PII off-platform"
                ),
                evidence=evidence,
            )
        elif event_type == "list_deleted":
            self._add(
                control_results,
                signal="list_deleted",
                default="PR-02",
                result="FAIL",
                detail=(
                    f"Mailchimp list_deleted event {event_id} — audience "
                    f"destruction"
                ),
                evidence=evidence,
            )
        elif event_type == "list_member_added":
            if (
                audience.get("is_double_optin") is False
                and not campaign.get("consent_basis")
            ):
                self._add(
                    control_results,
                    signal="member_added_no_consent",
                    default="PR-04",
                    result="FAIL",
                    detail=(
                        f"Mailchimp list_member_added event {event_id} on a "
                        f"single-opt-in audience without recorded consent_basis"
                    ),
                    evidence=evidence,
                )
            else:
                self._add(
                    control_results,
                    signal="campaign_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Mailchimp list_member_added event {event_id} — "
                        f"audit trail recorded"
                    ),
                    evidence=evidence,
                )
        elif event_type == "list_member_unsubscribed":
            self._add(
                control_results,
                signal="list_member_unsubscribed",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp list_member_unsubscribed event {event_id} — "
                    f"opt-out audit trail recorded"
                ),
                evidence=evidence,
            )
        elif event_type == "automation_started":
            if actor.get("is_api_user"):
                self._add(
                    control_results,
                    signal="automation_started_api",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Mailchimp automation_started event {event_id} by "
                        f"API user — programmatic automation captured"
                    ),
                    evidence=evidence,
                )
            else:
                self._add(
                    control_results,
                    signal="campaign_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Mailchimp automation_started event {event_id} — "
                        f"audit trail recorded"
                    ),
                    evidence=evidence,
                )
        elif event_type == "connected_site_added":
            self._add(
                control_results,
                signal="connected_site_added",
                default="PR-01",
                result="FLAG",
                detail=(
                    f"Mailchimp connected_site_added event {event_id} — new "
                    f"tracking surface attached"
                ),
                evidence=evidence,
            )
        elif event_type == "webhook_added":
            host = action_metadata.get("webhook_url_host")
            if host and host not in self.webhook_host_allowlist:
                self._add(
                    control_results,
                    signal="webhook_external",
                    default="PR-04",
                    result="FLAG",
                    detail=(
                        f"Mailchimp webhook_added event {event_id} pointing "
                        f"to host={host} not in allowlist — external "
                        f"destination"
                    ),
                    evidence=evidence,
                )
            else:
                self._add(
                    control_results,
                    signal="campaign_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Mailchimp webhook_added event {event_id} — host "
                        f"in allowlist"
                    ),
                    evidence=evidence,
                )
        elif event_type == "api_key_created":
            self._add(
                control_results,
                signal="api_key_created",
                default="PR-01",
                result="FLAG",
                detail=(
                    f"Mailchimp api_key_created event {event_id} — new API "
                    f"credential issued"
                ),
                evidence=evidence,
            )
        elif event_type == "team_member_role_changed":
            new_role = (action_metadata.get("new_role") or "").lower()
            if new_role == "admin":
                self._add(
                    control_results,
                    signal="role_promoted_admin",
                    default="PR-02",
                    result="FAIL",
                    detail=(
                        f"Mailchimp team_member_role_changed event {event_id}"
                        f" — admin promotion (new_role=admin)"
                    ),
                    evidence=evidence,
                )
            else:
                self._add(
                    control_results,
                    signal="campaign_audit",
                    default="PR-05",
                    result="PASS",
                    detail=(
                        f"Mailchimp team_member_role_changed event {event_id}"
                        f" — new_role={new_role or 'unknown'}"
                    ),
                    evidence=evidence,
                )
        elif event_type == "compliance_settings_changed":
            # Treat any change to compliance settings as PR-02 FAIL (weakening
            # heuristic — Mailchimp does not expose a strict before/after
            # boolean; any agent-driven change to compliance posture is
            # surfaced as a FAIL by default).
            self._add(
                control_results,
                signal="compliance_settings_weakened",
                default="PR-02",
                result="FAIL",
                detail=(
                    f"Mailchimp compliance_settings_changed event {event_id}"
                    f" — compliance posture changed; review required"
                ),
                evidence=evidence,
            )
        elif event_type == "gdpr_data_request":
            self._add(
                control_results,
                signal="gdpr_data_request",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp gdpr_data_request event {event_id} — "
                    f"compliance audit trail recorded"
                ),
                evidence=evidence,
            )
        elif event_type == "gdpr_data_deletion":
            self._add(
                control_results,
                signal="gdpr_data_deletion",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp gdpr_data_deletion event {event_id} — "
                    f"compliance audit trail recorded"
                ),
                evidence=evidence,
            )
        elif event_type == "audit_log_exported":
            self._add(
                control_results,
                signal="audit_log_exported",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp audit_log_exported event {event_id} — "
                    f"audit log export recorded"
                ),
                evidence=evidence,
            )
        elif event_type == "unsubscribe_required_link_removed":
            self._add(
                control_results,
                signal="unsubscribe_required_link_removed",
                default="PR-05",
                result="FAIL",
                detail=(
                    f"Mailchimp unsubscribe_required_link_removed event "
                    f"{event_id} — required CAN-SPAM unsubscribe link "
                    f"removed"
                ),
                evidence=evidence,
            )
        elif event_type == "send_to_unverified_domain":
            self._add(
                control_results,
                signal="send_to_unverified_domain",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp send_to_unverified_domain event {event_id} "
                    f"— sender domain not verified"
                ),
                evidence=evidence,
            )
        else:
            # Unknown / non-terminal event_type — record as audit-trail PASS.
            self._add(
                control_results,
                signal="campaign_audit",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp {event_type} event {event_id} — audit "
                    f"trail recorded"
                ),
                evidence=evidence,
            )

        # Bulk-action threshold (event-agnostic — applies to any event with
        # action_metadata.is_bulk=true and target_count > threshold).
        target_count = action_metadata.get("target_count")
        if (
            action_metadata.get("is_bulk") is True
            and isinstance(target_count, int)
            and target_count > self.bulk_target_threshold
        ):
            self._add(
                control_results,
                signal="bulk_send_large",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp bulk action {event_id} target_count="
                    f"{target_count} exceeds bulk threshold "
                    f"{self.bulk_target_threshold}"
                ),
                evidence=evidence,
            )

        # Cross-list / high-volume pattern markers (informational; the
        # synthetic finding lives in a separate EvaluationResult).
        actor_key = self._actor_key(record)
        if actor_key and actor_key in cross_list_actors:
            self._add(
                control_results,
                signal="cross_list_pattern",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp event {event_id} contributes to cross-list "
                    f"pattern — actor touched "
                    f"{len(cross_list_actors[actor_key]['audience_ids'])} "
                    f"distinct audiences in {self.cross_list_window_minutes}m"
                ),
                evidence=evidence,
                extra={
                    "cross_list_audience_ids_last8": [
                        _last8(a) for a in
                        cross_list_actors[actor_key]["audience_ids"]
                    ],
                    "cross_list_threshold": self.cross_list_threshold,
                },
            )
        if actor_key and actor_key in high_volume_actors:
            info = high_volume_actors[actor_key]
            self._add(
                control_results,
                signal="high_volume_marketing_pattern",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp event {event_id} contributes to high-volume "
                    f"marketing pattern — {info['campaigns']} campaigns / "
                    f"{info['recipients']} recipients in 24h"
                ),
                evidence=evidence,
                extra={
                    "high_volume_campaigns": info["campaigns"],
                    "high_volume_recipients": info["recipients"],
                    "high_volume_campaigns_threshold": (
                        self.high_volume_campaigns_24h
                    ),
                    "high_volume_recipients_threshold": (
                        self.high_volume_recipients_24h
                    ),
                },
            )

        decision = self._decide(control_results)
        decision_reason = (
            f"Imported from Mailchimp: event_id={event_id} "
            f"event_type={event_type} "
            f"actor_user_id={actor.get('user_id') or 'none'} "
            f"is_marketing="
            f"{campaign.get('is_marketing') if campaign.get('is_marketing') is not None else 'unknown'} "
            f"consent_basis={campaign.get('consent_basis') or 'none'} "
            f"recipient_count="
            f"{campaign.get('recipient_count') if campaign.get('recipient_count') is not None else 'none'}"
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"mailchimp-{event_id}",
            timestamp=evidence.get("timestamp")
            or datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mailchimp_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=actor.get("user_id") or None,
        )

    # ------------------------------------------------------------------
    # campaign_sent / list_imported helpers
    # ------------------------------------------------------------------

    def _eval_campaign_sent(
        self,
        evidence: dict[str, Any],
        campaign: dict[str, Any],
        audience: dict[str, Any],
        control_results: list[ControlResult],
        event_id: str,
    ) -> None:
        is_marketing = campaign.get("is_marketing") is True
        consent_basis = campaign.get("consent_basis")
        contains_eu = audience.get("contains_eu_subscribers") is True

        # 1. CAN-SPAM consent missing for marketing.
        if (
            self.marketing_consent_required
            and is_marketing
            and consent_basis is None
        ):
            self._add(
                control_results,
                signal="marketing_no_consent_canspam",
                default="DE-01",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} marketing campaign "
                    f"without recorded consent_basis — direct CAN-SPAM "
                    f"violation indicator"
                ),
                evidence=evidence,
            )
        # 2. Legitimate-interest GDPR review surface (only when consent
        # actually present and = legitimate_interest).
        if is_marketing and consent_basis == "legitimate_interest":
            self._add(
                control_results,
                signal="marketing_legitimate_interest",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp campaign_sent {event_id} marketing under "
                    f"legitimate-interest basis — GDPR review surface"
                ),
                evidence=evidence,
            )
        # 3. EU subscribers — must be explicit opt-in.
        if (
            is_marketing
            and contains_eu
            and consent_basis != "opt_in"
        ):
            self._add(
                control_results,
                signal="marketing_eu_no_optin",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} marketing to EU "
                    f"subscribers under consent_basis="
                    f"{consent_basis or 'none'} (not explicit opt-in) — "
                    f"GDPR consent missing for EU"
                ),
                evidence=evidence,
            )
        # 4. CAN-SPAM unsubscribe link present.
        if campaign.get("unsubscribe_link_present") is False:
            self._add(
                control_results,
                signal="missing_unsubscribe_link",
                default="PR-05",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} missing unsubscribe "
                    f"link — CAN-SPAM unsubscribe requirement missing"
                ),
                evidence=evidence,
            )
        # 5. CAN-SPAM physical-address line present.
        if campaign.get("physical_address_present") is False:
            self._add(
                control_results,
                signal="missing_physical_address",
                default="PR-05",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} missing physical "
                    f"address — CAN-SPAM physical-address requirement missing"
                ),
                evidence=evidence,
            )
        # 6. Mailchimp pre-send compliance check.
        if campaign.get("compliance_check_passed") is False:
            self._add(
                control_results,
                signal="compliance_check_failed",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} pre-send compliance "
                    f"check did not pass"
                ),
                evidence=evidence,
            )
        # 7. Sender authentication missing (any of SPF / DKIM / DMARC false).
        sender_auth = campaign.get("sender_authentication") or {}
        spf = sender_auth.get("spf")
        dkim = sender_auth.get("dkim")
        dmarc = sender_auth.get("dmarc")
        missing = [
            name for name, val in
            (("spf", spf), ("dkim", dkim), ("dmarc", dmarc))
            if val is False
        ]
        if missing:
            self._add(
                control_results,
                signal="sender_auth_missing",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} sender authentication"
                    f" missing: {', '.join(missing)} — bad reputation guarantee"
                ),
                evidence=evidence,
            )
        # 8. Deliverability score floor.
        ds = campaign.get("deliverability_score")
        if isinstance(ds, int) and ds < self.deliverability_score_floor:
            self._add(
                control_results,
                signal="deliverability_low",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp campaign_sent {event_id} deliverability_score"
                    f"={ds} below floor {self.deliverability_score_floor} "
                    f"— low reputation"
                ),
                evidence=evidence,
            )
        # 9. Complaint-rate ceiling.
        cr = campaign.get("complaint_rate")
        if isinstance(cr, (int, float)) and cr > self.complaint_rate_max:
            self._add(
                control_results,
                signal="complaint_rate_high",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} complaint_rate={cr} "
                    f"exceeds ESP danger-zone threshold "
                    f"{self.complaint_rate_max}"
                ),
                evidence=evidence,
            )
        # 10. Bounce-rate ceiling.
        br = campaign.get("bounce_rate")
        if isinstance(br, (int, float)) and br > self.bounce_rate_max:
            self._add(
                control_results,
                signal="bounce_rate_high",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp campaign_sent {event_id} bounce_rate={br} "
                    f"exceeds threshold {self.bounce_rate_max} — list-hygiene "
                    f"sender-reputation risk"
                ),
                evidence=evidence,
            )
        # If no FAIL/FLAG signals fired so far, surface a PASS audit signal so
        # the record always carries at least one ControlResult.
        if not control_results:
            self._add(
                control_results,
                signal="campaign_audit",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp campaign_sent {event_id} — audit trail "
                    f"recorded"
                ),
                evidence=evidence,
            )

    def _eval_list_imported(
        self,
        evidence: dict[str, Any],
        audience: dict[str, Any],
        control_results: list[ControlResult],
        event_id: str,
    ) -> None:
        if audience.get("is_double_optin") is False:
            self._add(
                control_results,
                signal="list_imported_single_optin",
                default="PR-04",
                result="FAIL",
                detail=(
                    f"Mailchimp list_imported event {event_id} on a "
                    f"single-opt-in audience — compliance risk"
                ),
                evidence=evidence,
            )
        if audience.get("contains_pii_columns") is True:
            self._add(
                control_results,
                signal="list_imported_pii",
                default="PR-04",
                result="FLAG",
                detail=(
                    f"Mailchimp list_imported event {event_id} importing "
                    f"audience with PII columns"
                ),
                evidence=evidence,
            )
        if not control_results:
            self._add(
                control_results,
                signal="campaign_audit",
                default="PR-05",
                result="PASS",
                detail=(
                    f"Mailchimp list_imported event {event_id} — audit "
                    f"trail recorded"
                ),
                evidence=evidence,
            )

    # ------------------------------------------------------------------
    # ControlResult builder
    # ------------------------------------------------------------------

    def _add(
        self,
        control_results: list[ControlResult],
        *,
        signal: str,
        default: str,
        result: str,
        detail: str,
        evidence: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> None:
        control_id = _control_for(signal, self._mappings, default)
        evidence_data: dict[str, Any] = {**evidence, "signal": signal}
        if extra:
            evidence_data.update(extra)
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result=result,
                detail=detail,
                evidence_data=evidence_data,
            )
        )

    # ------------------------------------------------------------------
    # Synthetic finding builders
    # ------------------------------------------------------------------

    def _synthetic_cross_list_result(
        self,
        *,
        actor_key: str,
        audience_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_list_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = (
            f"mailchimp-cross-list-{abs(hash(actor_key)) & 0xFFFFFFFF:08x}"
        )
        ids_last8 = [_last8(a) or "????????" for a in audience_ids]
        evidence: dict[str, Any] = {
            "mailchimp_record_kind": "synthetic_cross_list",
            "actor_key": actor_key,
            "cross_list_audience_ids_last8": ids_last8,
            "cross_list_count": len(audience_ids),
            "cross_list_threshold": self.cross_list_threshold,
            "cross_list_window_minutes": self.cross_list_window_minutes,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id,
            ),
            "source_tool": "mailchimp",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Mailchimp synthetic finding: actor {actor_key} touched "
                f"{len(audience_ids)} distinct audiences in "
                f"{self.cross_list_window_minutes}m — exceeds cross-list "
                f"threshold {self.cross_list_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mailchimp_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Mailchimp: synthetic cross-list pattern "
                f"actor={actor_key} audiences={len(audience_ids)}>"
                f"threshold={self.cross_list_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_high_volume_result(
        self,
        *,
        actor_key: str,
        campaign_count: int,
        total_recipients: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_volume_marketing_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = (
            f"mailchimp-high-volume-{abs(hash(actor_key)) & 0xFFFFFFFF:08x}"
        )
        evidence: dict[str, Any] = {
            "mailchimp_record_kind": "synthetic_high_volume",
            "actor_key": actor_key,
            "high_volume_campaigns": campaign_count,
            "high_volume_recipients": total_recipients,
            "high_volume_campaigns_threshold": self.high_volume_campaigns_24h,
            "high_volume_recipients_threshold": (
                self.high_volume_recipients_24h
            ),
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id,
            ),
            "source_tool": "mailchimp",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Mailchimp synthetic finding: actor {actor_key} sent "
                f"{campaign_count} campaigns to {total_recipients} recipients"
                f" in 24h — exceeds high-volume thresholds "
                f"({self.high_volume_campaigns_24h} campaigns / "
                f"{self.high_volume_recipients_24h} recipients)"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="mailchimp_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Mailchimp: synthetic high-volume marketing "
                f"actor={actor_key} campaigns={campaign_count} "
                f"recipients={total_recipients}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    @staticmethod
    def _decide(control_results: list[ControlResult]) -> str:
        """Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW."""
        if any(cr.result == "FAIL" for cr in control_results):
            return "BLOCK"
        if any(cr.result == "FLAG" for cr in control_results):
            return "FLAG"
        return "ALLOW"
