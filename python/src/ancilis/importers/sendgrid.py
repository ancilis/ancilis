# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""SendGrid email-activity importer — maps transactional/marketing email records to AKSI controls.

SendGrid (https://sendgrid.com) is the leading transactional and marketing
email platform. Agents that emit emails — notification bots, daily-summary
agents, support-reply agents, marketing-campaign orchestrators — flow through
SendGrid's ``/v3/mail/send`` endpoint and surface in the
``/v3/messages`` Email Activity API and the event webhook export. From a
runtime-control perspective, an email crossed by an agent is qualitatively
different from an internal LLM completion: it crosses into a regulated
communications channel addressed at a recipient with PII (their address) and
governed by CAN-SPAM (US — physical-address requirement, opt-out, and recorded
consent for marketing), sender-reputation hygiene (spam reports + reputation
bounces directly degrade IP / domain reputation), and GDPR consent territory
(legitimate-interest is a flagged basis; cross-border marketing without
explicit opt-in is high-risk).

This importer ingests SendGrid exports in the following on-disk shapes:

  * ``{"messages": [...]}`` — the documented Email Activity API envelope
  * ``{"data": [...]}``     — generic data envelope
  * ``{"events": [...]}``   — event-webhook bundle envelope
  * JSONL                    — one record per line
  * Single record envelope   — one bare object

Signal mapping (see shared/mappings/sendgrid-aksi-controls.json):

  * ``status=delivered`` & ``categories`` contains "transactional"        → PR-05 PASS (audit trail)
  * ``status=delivered`` & ``categories`` contains "marketing"
    & ``consent_basis=marketing_opt_in``                                  → PR-04 PASS
  * ``status=delivered`` & ``is_marketing=true``
    & ``consent_basis`` is null                                           → DE-01 FAIL (CAN-SPAM violation)
  * ``status=delivered`` & ``is_marketing=true``
    & ``consent_basis=marketing_legitimate_interest``                     → PR-04 FLAG (GDPR review surface)
  * ``status=bounce`` & ``bounce_classification=Hard Bounce``             → PR-03 FLAG (invalid-address persisting)
  * ``status=bounce`` & ``bounce_classification=Reputation``              → PR-04 FAIL (sender-domain reputation issue)
  * ``status=block``                                                      → PR-04 FAIL (recipient ESP rejection)
  * ``status=spam_report``                                                → DE-01 FAIL (top-priority reputation event)
  * ``status=dropped``                                                    → PR-02 FLAG (pre-flight drop — invalid template / suppressed recipient)
  * ``status=unsubscribe``                                                → PR-05 PASS (opt-out audit trail)
  * ``status=clicked`` & ``categories`` contains "marketing"              → PR-04 PASS (engagement-confirmed)
  * ``to_country_resolved`` ≠ ``from_country`` & ``consent_basis`` null
    & ``is_marketing=true``                                               → PR-04 FLAG (cross-border marketing without explicit opt-in)
  * ``is_marketing=true`` & ``asm_group_id`` is null/missing              → PR-05 FAIL (no unsubscribe group = CAN-SPAM violation)

Synthetic patterns
  * Volume velocity: > N emails to same ``to_email`` in 24h (default 10)  → PR-04 FLAG
  * Cross-country fan-out: one ``api_key_id`` sending to > N distinct
    ``to_country_resolved`` codes (default 20)                            → PR-04 FLAG
  * High bounce-rate: per-``api_key_id`` bounces / messages
    (counted per 100) > threshold (default 0.05 i.e. 5%)                  → PR-04 FLAG

Sanitization (privacy-critical):

  * ``from_email`` and ``to_email`` raw addresses are NEVER stored. Only the
    ``@domain`` portion survives: ``alice@corp.example.com`` →
    ``"@corp.example.com"``. Domains alone are still useful for grouping
    sender / recipient by organization but materially less identifying than
    the full local-part.
  * Subject text is DROPPED entirely. Agents have a tendency to put
    structured data — order numbers, OTPs, snippets of conversation — into
    subjects; ``subject_length`` is the only thing captured.
  * Event-list ``ip`` fields (the recipient ESP's connecting IP per event)
    are masked to a /16 prefix. Full IPs can correlate with corporate
    egress mappings.
  * Raw event payloads (``events: [...]``) are reduced to a count + sorted
    distinct event-type list — never stored verbatim.
  * ``api_key_id`` is preserved as the last 4 characters only.
  * ``msg_id`` is preserved verbatim — non-secret per SendGrid docs.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``sendgrid`` package; exports are parsed with
the standard library only.
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


# Mapping table lives at <repo>/shared/mappings/sendgrid-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/sendgrid.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "sendgrid-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_VOLUME_VELOCITY = 10
_DEFAULT_CROSS_COUNTRY_THRESHOLD = 20
_DEFAULT_BOUNCE_RATE_THRESHOLD = 0.05


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the sendgrid-aksi-controls.json mapping; tolerate missing file."""
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
    """Reduce a full email address to its ``@domain`` portion only.

    Email local-parts identify the natural person ("alice") and are PII; the
    domain alone is materially less identifying and still useful for grouping
    by organization. ``alice@corp.example.com`` → ``"@corp.example.com"``.
    Inputs without ``@`` return None.
    """
    if not email or not isinstance(email, str):
        return None
    s = email.strip()
    if "@" not in s:
        return None
    domain = s.rsplit("@", 1)[-1].strip().lower()
    if not domain:
        return None
    return f"@{domain}"


def _abbreviate_api_key_id(api_key_id: str | None) -> str | None:
    """Reduce a SendGrid API key id to its last 4 characters."""
    if not api_key_id or not isinstance(api_key_id, str):
        return None
    s = api_key_id.strip()
    if not s:
        return None
    if len(s) <= 4:
        return s
    return s[-4:]


def _mask_ip(ip: str | None) -> str | None:
    """Mask an IPv4/IPv6 address to a /16 (v4) or /32 (v6) prefix.

    Full per-event IPs can correlate with corporate egress mappings; a /16
    keeps geographic-AS-level signal without preserving the host identity.
    """
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
    # IPv6 — coarser mask /32 is still strongly de-identifying.
    net = ipaddress.ip_network(f"{s}/32", strict=False)
    return str(net)


def _coerce_int(value: Any) -> int | None:
    """Coerce a SendGrid-style stringified int to int; None on failure."""
    if value is None:
        return None
    if isinstance(value, bool):
        # Avoid bool→int coercion; SendGrid event counts are ints.
        return int(value) if isinstance(value, int) and not isinstance(value, bool) else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool | None:
    """Coerce a SendGrid-style bool/string-bool to a Python bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
    return None


def _normalize_categories(value: Any) -> list[str]:
    """Categories may be a list[str] or a comma-separated string; normalize."""
    if isinstance(value, list):
        return [str(c).strip().lower() for c in value if isinstance(c, str) and c.strip()]
    if isinstance(value, str):
        return [
            c.strip().lower()
            for c in value.split(",")
            if c.strip()
        ]
    return []


def _summarize_events(value: Any) -> dict[str, Any]:
    """Reduce a raw events list to {count, types, masked_ips} only."""
    if not isinstance(value, list):
        return {"count": 0, "types": [], "masked_ips": []}
    types: set[str] = set()
    masked_ips: set[str] = set()
    for ev in value:
        if not isinstance(ev, dict):
            continue
        ev_type = ev.get("event")
        if isinstance(ev_type, str) and ev_type.strip():
            types.add(ev_type.strip().lower())
        ev_ip = ev.get("ip")
        if isinstance(ev_ip, str) and ev_ip.strip():
            masked = _mask_ip(ev_ip)
            if masked:
                masked_ips.add(masked)
    return {
        "count": len(value),
        "types": sorted(types),
        "masked_ips": sorted(masked_ips),
    }


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class SendGridImporter:
    """Parse a SendGrid email-activity export into ``EvaluationResult`` records.

    A single import file may carry messages from any combination of
    transactional and marketing categories. The enclosing envelope
    (``{"messages": [...]}``, ``{"data": [...]}``, ``{"events": [...]}``,
    JSONL, or single object) is auto-detected.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        volume_velocity: int | None = None,
        cross_country_threshold: int | None = None,
        bounce_rate_threshold: float | None = None,
        marketing_consent_required: bool | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Volume-velocity threshold (records to same recipient in export).
        if volume_velocity is not None:
            self.volume_velocity = int(volume_velocity)
        else:
            self.volume_velocity = int(
                meta.get("volume_velocity", _DEFAULT_VOLUME_VELOCITY)
            )
        # Cross-country fan-out threshold (per api_key_id).
        if cross_country_threshold is not None:
            self.cross_country_threshold = int(cross_country_threshold)
        else:
            self.cross_country_threshold = int(
                meta.get("cross_country_threshold", _DEFAULT_CROSS_COUNTRY_THRESHOLD)
            )
        # Bounce-rate threshold (fraction; e.g. 0.05 = 5%).
        if bounce_rate_threshold is not None:
            self.bounce_rate_threshold = float(bounce_rate_threshold)
        else:
            self.bounce_rate_threshold = float(
                meta.get("bounce_rate_threshold", _DEFAULT_BOUNCE_RATE_THRESHOLD)
            )
        # Marketing-consent requirement.
        if marketing_consent_required is not None:
            self.marketing_consent_required = bool(marketing_consent_required)
        else:
            self.marketing_consent_required = bool(
                meta.get("marketing_consent_required", True)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a SendGrid export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse SendGrid export content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect SendGrid-shaped envelopes / JSONL / single record."""
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
                for key in ("messages", "data", "events"):
                    if key in doc and isinstance(doc[key], list):
                        return [r for r in doc[key] if isinstance(r, dict)]
                # Single record envelope.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        records: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Per-record dispatch + synthetic velocity/cross-country/bounce-rate findings."""
        # Aggregations for synthetic patterns.
        # to_email -> count (for volume velocity)
        recipient_counts: dict[str, int] = defaultdict(int)
        # api_key_id -> set of to_country_resolved (cross-country fan-out)
        api_key_countries: dict[str, set[str]] = defaultdict(set)
        # api_key_id -> {messages: int, bounces: int}
        api_key_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"messages": 0, "bounces": 0}
        )

        for rec in records:
            to_raw = rec.get("to_email")
            if isinstance(to_raw, str) and to_raw.strip():
                recipient_counts[to_raw.strip().lower()] += 1
            api_key_raw = rec.get("api_key_id")
            api_key = (
                str(api_key_raw).strip()
                if isinstance(api_key_raw, str) and api_key_raw.strip()
                else None
            )
            if api_key:
                api_key_stats[api_key]["messages"] += 1
                status = str(rec.get("status") or "").strip().lower()
                if status == "bounce":
                    api_key_stats[api_key]["bounces"] += 1
                cc_to = rec.get("to_country_resolved")
                if isinstance(cc_to, str) and cc_to.strip():
                    api_key_countries[api_key].add(cc_to.strip().upper())

        velocity_recipients = {
            recipient: count
            for recipient, count in recipient_counts.items()
            if count > self.volume_velocity
        }
        cross_country_keys = {
            api_key: sorted(ccs)
            for api_key, ccs in api_key_countries.items()
            if len(ccs) > self.cross_country_threshold
        }
        # High-bounce-rate computed per api_key — only meaningful for keys with
        # at least 1 message; threshold is bounces / messages, not per-100.
        high_bounce_keys: dict[str, dict[str, Any]] = {}
        for api_key, stats in api_key_stats.items():
            msgs = stats["messages"]
            bounces = stats["bounces"]
            if msgs <= 0:
                continue
            rate = bounces / msgs
            if rate > self.bounce_rate_threshold:
                high_bounce_keys[api_key] = {
                    "messages": msgs,
                    "bounces": bounces,
                    "rate": rate,
                }

        results: list[EvaluationResult] = []
        for rec in records:
            results.append(
                self._parse_message(
                    rec,
                    file_sha256=file_sha256,
                    velocity_recipients=velocity_recipients,
                    cross_country_keys=cross_country_keys,
                )
            )

        # Synthetic volume-velocity findings — one per recipient.
        for recipient, count in sorted(velocity_recipients.items()):
            results.append(
                self._synthetic_volume_velocity_result(
                    recipient=recipient,
                    count=count,
                    file_sha256=file_sha256,
                )
            )

        # Synthetic cross-country findings — one per api_key_id.
        for api_key, ccs in sorted(cross_country_keys.items()):
            results.append(
                self._synthetic_cross_country_result(
                    api_key_id=api_key,
                    country_codes=ccs,
                    file_sha256=file_sha256,
                )
            )

        # Synthetic high-bounce-rate findings — one per api_key_id.
        for api_key, stats in sorted(high_bounce_keys.items()):
            results.append(
                self._synthetic_high_bounce_rate_result(
                    api_key_id=api_key,
                    bounces=stats["bounces"],
                    messages=stats["messages"],
                    rate=stats["rate"],
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "sendgrid",
            "source_tool_name": "sendgrid",
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
        """Build the shared evidence dict (sanitized — no full email, no subject text)."""
        msg_id_raw = record.get("msg_id")
        msg_id = (
            str(msg_id_raw).strip()
            if isinstance(msg_id_raw, str) and msg_id_raw.strip()
            else None
        )
        record_id = msg_id or str(uuid.uuid4())
        from_domain = _email_to_domain(record.get("from_email"))
        to_domain = _email_to_domain(record.get("to_email"))
        subject_length = _coerce_int(record.get("subject_length"))
        status = str(record.get("status") or "").strip().lower()
        categories = _normalize_categories(record.get("categories"))
        is_marketing = _coerce_bool(record.get("is_marketing"))
        consent_basis_raw = record.get("consent_basis")
        consent_basis = (
            str(consent_basis_raw).strip().lower()
            if isinstance(consent_basis_raw, str) and consent_basis_raw.strip()
            else None
        )
        asm_group_id = _coerce_int(record.get("asm_group_id"))
        from_country_raw = record.get("from_country")
        to_country_raw = record.get("to_country_resolved")
        from_country = (
            str(from_country_raw).strip().upper()
            if isinstance(from_country_raw, str) and from_country_raw.strip()
            else None
        )
        to_country = (
            str(to_country_raw).strip().upper()
            if isinstance(to_country_raw, str) and to_country_raw.strip()
            else None
        )
        bounce_classification_raw = record.get("bounce_classification")
        bounce_classification = (
            str(bounce_classification_raw).strip()
            if isinstance(bounce_classification_raw, str)
            and bounce_classification_raw.strip()
            else None
        )
        api_key_id_full = record.get("api_key_id")
        api_key_id_full_str = (
            str(api_key_id_full).strip()
            if isinstance(api_key_id_full, str) and api_key_id_full.strip()
            else None
        )
        api_key_last4 = _abbreviate_api_key_id(api_key_id_full_str)
        events_summary = _summarize_events(record.get("events"))
        last_event_time = (
            str(record.get("last_event_time"))
            if isinstance(record.get("last_event_time"), str)
            else None
        )
        # Note: subject TEXT is intentionally never captured — only length.
        evidence: dict[str, Any] = {
            "msg_id": msg_id,
            "from_domain": from_domain,
            "to_domain": to_domain,
            "subject_length": subject_length,
            "status": status,
            "categories": categories,
            "is_marketing": is_marketing,
            "consent_basis": consent_basis,
            "asm_group_id": asm_group_id,
            "from_country": from_country,
            "to_country_resolved": to_country,
            "opens_count": _coerce_int(record.get("opens_count")),
            "clicks_count": _coerce_int(record.get("clicks_count")),
            "bounce_classification": bounce_classification,
            "api_key_id_last4": api_key_last4,
            "last_event_time": last_event_time,
            "events_summary": events_summary,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=record_id,
            ),
            "source_tool": "sendgrid",
        }
        return evidence

    def _parse_message(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        velocity_recipients: dict[str, int],
        cross_country_keys: dict[str, list[str]],
    ) -> EvaluationResult:
        evidence = self._common_evidence(record, file_sha256=file_sha256)
        msg_id = evidence["msg_id"] or str(uuid.uuid4())
        status = evidence["status"]
        categories: list[str] = evidence["categories"]
        is_marketing = evidence["is_marketing"]
        consent_basis = evidence["consent_basis"]
        asm_group_id = evidence["asm_group_id"]
        from_country = evidence["from_country"]
        to_country = evidence["to_country_resolved"]
        bounce_classification = evidence["bounce_classification"]

        is_marketing_effective = bool(
            is_marketing is True or "marketing" in categories
        )

        control_results: list[ControlResult] = []

        # 1. Primary status mapping. Order is meaningful: spam_report and
        # reputation/block FAILs must surface before generic delivered PASSes.
        if status == "spam_report":
            signal = "spam_report"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"SendGrid message {msg_id} marked as spam by recipient "
                        f"— top-priority sender-reputation event"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "block":
            signal = "blocked"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"SendGrid message {msg_id} blocked by recipient ESP "
                        f"— likely sender-reputation or content rejection"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "bounce" and bounce_classification == "Reputation":
            signal = "reputation_bounce"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"SendGrid message {msg_id} bounced with classification="
                        f"Reputation — sender-domain reputation problem"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "bounce" and bounce_classification == "Hard Bounce":
            signal = "hard_bounce"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} hard-bounced "
                        f"— invalid recipient persisting in list, list-hygiene gap"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "bounce":
            # Soft / Mailbox Unavailable / unspecified bounce — surface as
            # PR-03 FLAG by default (less severe than hard or reputation).
            signal = "hard_bounce"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} bounced "
                        f"(classification={bounce_classification or 'unspecified'})"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "dropped":
            signal = "dropped"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} dropped pre-flight "
                        f"— invalid template or suppressed recipient"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "unsubscribe":
            signal = "unsubscribe_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"SendGrid message {msg_id} unsubscribe event — opt-out "
                        f"audit trail recorded"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif status == "delivered":
            # Delivered fans out by category + consent.
            if (
                self.marketing_consent_required
                and is_marketing_effective
                and consent_basis is None
            ):
                signal = "marketing_no_consent_canspam"
                control_id = _control_for(signal, self._mappings, "DE-01")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FAIL",
                        detail=(
                            f"SendGrid message {msg_id} delivered marketing email "
                            f"to country={to_country or 'unknown'} without "
                            f"recorded consent_basis — direct CAN-SPAM "
                            f"violation indicator"
                        ),
                        evidence_data={**evidence, "signal": signal},
                    )
                )
            elif (
                is_marketing_effective
                and consent_basis == "marketing_legitimate_interest"
            ):
                signal = "marketing_legitimate_interest"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="FLAG",
                        detail=(
                            f"SendGrid message {msg_id} delivered marketing email "
                            f"under legitimate-interest basis — GDPR review surface"
                        ),
                        evidence_data={**evidence, "signal": signal},
                    )
                )
            elif (
                is_marketing_effective
                and consent_basis == "marketing_opt_in"
            ):
                signal = "marketing_with_consent"
                control_id = _control_for(signal, self._mappings, "PR-04")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"SendGrid message {msg_id} delivered marketing email "
                            f"with verified opt-in consent"
                        ),
                        evidence_data={**evidence, "signal": signal},
                    )
                )
            elif "transactional" in categories:
                signal = "transactional_delivered"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"SendGrid message {msg_id} transactional email "
                            f"delivered — audit trail recorded"
                        ),
                        evidence_data={**evidence, "signal": signal},
                    )
                )
            else:
                # Delivered, no clear category — record as transactional-style
                # PR-05 PASS (audit trail) but note ambiguity.
                signal = "transactional_delivered"
                control_id = _control_for(signal, self._mappings, "PR-05")
                control_results.append(
                    ControlResult(
                        control_id=control_id,
                        control_name=_CONTROL_NAMES.get(control_id, control_id),
                        result="PASS",
                        detail=(
                            f"SendGrid message {msg_id} delivered "
                            f"(category=unspecified) — audit trail recorded"
                        ),
                        evidence_data={**evidence, "signal": signal},
                    )
                )
        elif status == "clicked" and "marketing" in categories:
            signal = "marketing_engagement_clicked"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"SendGrid message {msg_id} marketing engagement confirmed "
                        f"via click event"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        else:
            # processed / deferred / opened / clicked-non-marketing / unknown.
            signal = "transactional_delivered"
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} status={status or 'unknown'} "
                        f"— non-terminal or unrecognized"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 2. Marketing email without an attached unsubscribe group — additive
        # CAN-SPAM violation finding (independent of delivery status, but
        # only meaningful when the email actually went out / will go out).
        if (
            is_marketing_effective
            and asm_group_id is None
            and status not in {"dropped"}
        ):
            signal = "marketing_no_unsubscribe_group"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"SendGrid message {msg_id} marketing email has no "
                        f"asm_group_id (unsubscribe group) — CAN-SPAM requires "
                        f"a working opt-out mechanism"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 3. Cross-border marketing without explicit opt-in — GDPR-territory FLAG.
        if (
            is_marketing_effective
            and consent_basis is None
            and from_country
            and to_country
            and from_country != to_country
        ):
            signal = "cross_border_marketing_no_consent"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} cross-border marketing "
                        f"{from_country}->{to_country} without explicit opt-in "
                        f"— GDPR concern"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 4. Velocity / cross-country pattern markers (informational; the
        # synthetic finding lives in a separate EvaluationResult).
        to_raw = (
            record.get("to_email").strip().lower()
            if isinstance(record.get("to_email"), str)
            and record.get("to_email").strip()
            else None
        )
        if to_raw and to_raw in velocity_recipients:
            signal = "volume_velocity"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} contributes to volume-velocity "
                        f"pattern ({velocity_recipients[to_raw]} > "
                        f"threshold {self.volume_velocity})"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "velocity_count": velocity_recipients[to_raw],
                        "velocity_threshold": self.volume_velocity,
                    },
                )
            )
        api_key_full = (
            record.get("api_key_id").strip()
            if isinstance(record.get("api_key_id"), str)
            and record.get("api_key_id").strip()
            else None
        )
        if api_key_full and api_key_full in cross_country_keys:
            signal = "cross_country_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"SendGrid message {msg_id} api_key fan-out "
                        f"({len(cross_country_keys[api_key_full])} countries > "
                        f"threshold {self.cross_country_threshold})"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "cross_country_codes": cross_country_keys[api_key_full],
                        "cross_country_threshold": self.cross_country_threshold,
                    },
                )
            )

        decision = self._decide(control_results)
        decision_reason = (
            f"Imported from SendGrid: msg_id={msg_id} "
            f"status={status or 'unknown'} "
            f"categories={','.join(categories) or 'none'} "
            f"is_marketing={is_marketing if is_marketing is not None else 'unknown'} "
            f"consent_basis={consent_basis or 'none'} "
            f"asm_group_id={asm_group_id if asm_group_id is not None else 'none'} "
            f"bounce_classification={bounce_classification or 'none'}"
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"sendgrid-{msg_id}",
            timestamp=evidence.get("last_event_time")
            or datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sendgrid_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=evidence.get("api_key_id_last4") or None,
        )

    def _synthetic_volume_velocity_result(
        self,
        *,
        recipient: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-recipient volume-velocity finding."""
        signal = "volume_velocity"
        control_id = _control_for(signal, self._mappings, "PR-04")
        domain = _email_to_domain(recipient) or "@unknown"
        synthetic_id = f"sendgrid-velocity-{abs(hash(recipient)) & 0xFFFFFFFF:08x}"
        evidence: dict[str, Any] = {
            "sendgrid_record_kind": "synthetic_volume_velocity",
            "to_domain": domain,
            "velocity_count": count,
            "velocity_threshold": self.volume_velocity,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "sendgrid",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"SendGrid synthetic finding: recipient {domain} received {count} "
                f"emails in this export — exceeds volume-velocity threshold "
                f"{self.volume_velocity}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sendgrid_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from SendGrid: synthetic volume-velocity pattern "
                f"recipient={domain} count={count}>threshold={self.volume_velocity}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_country_result(
        self,
        *,
        api_key_id: str,
        country_codes: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-api-key cross-country fan-out finding."""
        signal = "cross_country_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        api_key_last4 = _abbreviate_api_key_id(api_key_id) or "????"
        synthetic_id = f"sendgrid-cross-country-{api_key_last4}"
        evidence: dict[str, Any] = {
            "sendgrid_record_kind": "synthetic_cross_country",
            "api_key_id_last4": api_key_last4,
            "cross_country_codes": country_codes,
            "cross_country_count": len(country_codes),
            "cross_country_threshold": self.cross_country_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "sendgrid",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"SendGrid synthetic finding: api_key ...{api_key_last4} sent to "
                f"{len(country_codes)} distinct countries in this export "
                f"({', '.join(country_codes)}) — exceeds cross-country threshold "
                f"{self.cross_country_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sendgrid_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from SendGrid: synthetic cross-country pattern "
                f"api_key=...{api_key_last4} countries={len(country_codes)}>"
                f"threshold={self.cross_country_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=api_key_last4,
        )

    def _synthetic_high_bounce_rate_result(
        self,
        *,
        api_key_id: str,
        bounces: int,
        messages: int,
        rate: float,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-api-key high-bounce-rate finding."""
        signal = "high_bounce_rate"
        control_id = _control_for(signal, self._mappings, "PR-04")
        api_key_last4 = _abbreviate_api_key_id(api_key_id) or "????"
        synthetic_id = f"sendgrid-bounce-rate-{api_key_last4}"
        evidence: dict[str, Any] = {
            "sendgrid_record_kind": "synthetic_high_bounce_rate",
            "api_key_id_last4": api_key_last4,
            "bounces": bounces,
            "messages": messages,
            "bounce_rate": rate,
            "bounce_rate_threshold": self.bounce_rate_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "sendgrid",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"SendGrid synthetic finding: api_key ...{api_key_last4} bounce "
                f"rate {rate:.4f} ({bounces}/{messages}) exceeds threshold "
                f"{self.bounce_rate_threshold:.4f} — list-hygiene / sender-reputation risk"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="sendgrid_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from SendGrid: synthetic high-bounce-rate "
                f"api_key=...{api_key_last4} rate={rate:.4f}>"
                f"threshold={self.bounce_rate_threshold:.4f} "
                f"({bounces}/{messages})"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=api_key_last4,
        )

    @staticmethod
    def _decide(control_results: list[ControlResult]) -> str:
        """Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW."""
        if any(cr.result == "FAIL" for cr in control_results):
            return "BLOCK"
        if any(cr.result == "FLAG" for cr in control_results):
            return "FLAG"
        return "ALLOW"
