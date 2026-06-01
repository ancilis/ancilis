"""Stripe event importer — maps agent-driven payment activity to AKSI controls.

Stripe (https://stripe.com) is the dominant payments rail for autonomous-agent
commerce: charges, refunds, subscriptions, payouts, transfers, invoices, and
Radar reviews are recorded as ``event`` objects via ``GET /v1/events``. Every
Stripe API call performed by an agent is a regulated financial action with
KYC/AML/SOX implications, so this importer treats payment surfaces as the
highest-stakes class of agent activity.

Key design decisions:

* **Money in vs money out.** ``charge.succeeded`` (money IN) is graded by
  Radar risk_level; ``payout.paid`` and ``transfer.created`` (money OUT) are
  always FLAG because the consequence of an agent moving money OUT
  unauthorized is materially worse than authorizing an inbound charge.
* **Amount-threshold approval gates.** ``payment_intent.succeeded`` above the
  default $10,000 (1,000,000 cents) ``fail_threshold`` is a PR-04 FAIL —
  large autonomous transactions need an explicit human approval gate.
  Between ``flag_threshold`` ($1,000) and ``fail_threshold`` it is a FLAG.
* **livemode=false downgrade.** Test-mode events are captured as evidence but
  every decision is downgraded so that test-mode events can never BLOCK
  production traffic if exports are accidentally mixed.
* **Card-country / billing-country mismatch.** Cards issued in one country
  with a billing address in another are a textbook fraud signal — surfaced
  as PR-04 FLAG (additive to the primary signal).
* **Cross-customer pattern.** A single ``metadata.agent_id`` acting on more
  than ``cross_customer_threshold`` (default 50) customers in an export
  produces a synthetic PR-02 FLAG.

Sanitization (security-critical — Stripe events carry PII and card data):

* ``card.last4`` / ``card.exp_*`` / ``card.cvc`` / raw PAN are NEVER stored.
  Only ``card.country``, ``card.funding``, and ``card.brand`` are surfaced —
  these are non-sensitive classifiers used for fraud signals.
* ``billing_details.email`` is reduced to its domain (``user@host`` →
  ``host``); the local part is dropped.
* ``billing_details.name`` is replaced by ``{length, sha256}``.
* ``billing_details.address`` and ``shipping.address`` are reduced to
  ``country`` only — street/city/postal are dropped.
* ``description`` is replaced by ``{length, sha256}``.
* Custom ``metadata`` is filtered to ``agent_id``/``tenant_id``/``order_id``
  only — other keys could carry PII and are dropped (presence count + key
  list captured for analyst orientation).
* The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``stripe`` package; Stripe ``events.list``
exports are parsed with the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/stripe.py
# so five .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "stripe-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# Fall-back tables when the mapping JSON is missing or malformed.
_DEFAULT_EVENT_PATTERNS: tuple[dict[str, Any], ...] = (
    {"event_type": "charge.succeeded", "signal": "charge_succeeded",
     "result": "PASS", "control": "PR-02"},
    {"event_type": "charge.failed", "signal": "charge_failed",
     "result": "PASS", "control": "DE-01"},
    {"event_type": "charge.refunded", "signal": "charge_refunded",
     "result": "PASS", "control": "PR-05"},
    {"event_type": "charge.dispute.created", "signal": "charge_dispute",
     "result": "FAIL", "control": "PR-02"},
    {"event_type": "payment_intent.succeeded", "signal": "payment_intent_succeeded",
     "result": "PASS", "control": "PR-04"},
    {"event_type": "payment_intent.payment_failed", "signal": "payment_intent_failed",
     "result": "FLAG", "control": "PR-02"},
    {"event_type": "payment_intent.requires_action", "signal": "payment_intent_3ds",
     "result": "FLAG", "control": "PR-01"},
    {"event_type": "payout.paid", "signal": "payout_paid",
     "result": "FLAG", "control": "PR-04"},
    {"event_type": "payout.failed", "signal": "payout_failed",
     "result": "FAIL", "control": "DE-01"},
    {"event_type": "transfer.created", "signal": "transfer_created",
     "result": "FLAG", "control": "PR-04"},
    {"event_type": "refund.created", "signal": "refund_created",
     "result": "PASS", "control": "PR-05"},
    {"event_type": "review.opened", "signal": "review_opened",
     "result": "PASS", "control": "PR-02"},
    {"event_type": "review.closed", "signal": "review_closed",
     "result": "PASS", "control": "PR-02"},
    {"event_type": "customer.created", "signal": "customer_created",
     "result": "PASS", "control": "PR-05"},
    {"event_type": "customer.subscription.created", "signal": "subscription_created",
     "result": "PASS", "control": "PR-05"},
    {"event_type": "customer.subscription.deleted", "signal": "subscription_deleted",
     "result": "PASS", "control": "PR-05"},
    {"event_type": "invoice.payment_succeeded", "signal": "invoice_payment_succeeded",
     "result": "PASS", "control": "PR-02"},
    {"event_type": "invoice.payment_failed", "signal": "invoice_payment_failed",
     "result": "FLAG", "control": "PR-02"},
    {"event_type": "account.updated", "signal": "account_updated",
     "result": "FLAG", "control": "PR-05"},
)

_DEFAULT_RISK_LEVEL_OVERRIDES: dict[str, dict[str, dict[str, str]]] = {
    "charge.succeeded": {
        "normal": {"signal": "charge_succeeded", "result": "PASS", "control": "PR-02"},
        "elevated": {"signal": "charge_succeeded_elevated_risk",
                     "result": "FLAG", "control": "PR-02"},
        "highest": {"signal": "charge_succeeded_highest_risk",
                    "result": "FAIL", "control": "PR-02"},
    },
}

_DEFAULT_OUTCOME_TYPE_OVERRIDES: dict[str, dict[str, str]] = {
    "blocked": {"signal": "outcome_blocked", "result": "PASS", "control": "PR-02"},
    "manual_review": {"signal": "outcome_manual_review", "result": "FLAG", "control": "PR-02"},
}

_DEFAULT_REVIEW_CLOSED_OUTCOMES: dict[str, dict[str, str]] = {
    "approved": {"signal": "review_closed_approved", "result": "PASS", "control": "PR-02"},
    "refunded": {"signal": "review_closed_refunded", "result": "FAIL", "control": "PR-02"},
    "refunded_as_fraud": {"signal": "review_closed_refunded", "result": "FAIL", "control": "PR-02"},
    "disputed": {"signal": "review_closed_refunded", "result": "FAIL", "control": "PR-02"},
}

_DEFAULT_AMOUNT_FLAG_CENTS = 100_000     # $1,000
_DEFAULT_AMOUNT_FAIL_CENTS = 1_000_000   # $10,000
_DEFAULT_CROSS_CUSTOMER_THRESHOLD = 50

# Result-severity ordering for the livemode=false downgrade rule.
_DECISION_SEVERITY: dict[str, int] = {"PASS": 0, "FLAG": 1, "FAIL": 2}

# Allow-list of metadata keys we will store; anything else may carry PII.
_METADATA_KEY_ALLOWLIST: frozenset[str] = frozenset({"agent_id", "tenant_id", "order_id"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the stripe-aksi-controls.json mapping; tolerate missing file."""
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


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _email_domain(email: str | None) -> str | None:
    """Reduce ``user@host`` to ``host``; drop the local part."""
    if not email or not isinstance(email, str):
        return None
    s = email.strip()
    if "@" not in s:
        return None
    domain = s.rsplit("@", 1)[1].strip().lower()
    return domain or None


def _redact_string(value: Any) -> dict[str, Any] | None:
    """Replace a free-form string with ``{length, sha256}``; non-strings → None."""
    if not isinstance(value, str) or not value:
        return None
    return {"length": len(value), "sha256": _sha256_hex(value)}


def _filter_metadata(metadata: Any) -> dict[str, Any]:
    """Filter metadata to the allow-listed keys + a key-list summary.

    Stripe ``metadata`` is a free-form key/value dict that may carry PII
    (customer email, internal IDs, etc.). We surface only the keys an
    operator typically uses for joins (``agent_id``, ``tenant_id``,
    ``order_id``) and a sorted list of *other* keys so the analyst can
    see what was attached without exposing values.
    """
    if not isinstance(metadata, dict):
        return {"metadata_filtered": {}, "metadata_other_keys": [],
                "metadata_other_count": 0}
    filtered: dict[str, Any] = {}
    other_keys: list[str] = []
    for k, v in metadata.items():
        ks = str(k)
        if ks in _METADATA_KEY_ALLOWLIST:
            filtered[ks] = str(v) if v is not None else None
        else:
            other_keys.append(ks)
    return {
        "metadata_filtered": filtered,
        "metadata_other_keys": sorted(other_keys),
        "metadata_other_count": len(other_keys),
    }


def _safe_address_country(address: Any) -> str | None:
    if not isinstance(address, dict):
        return None
    country = address.get("country")
    return str(country) if isinstance(country, str) and country else None


def _safe_card(card: Any) -> dict[str, Any]:
    """Capture only non-sensitive card classifiers — never PAN/last4/exp/cvc."""
    if not isinstance(card, dict):
        return {"country": None, "funding": None, "brand": None}
    return {
        "country": (
            str(card["country"])
            if isinstance(card.get("country"), str) and card.get("country")
            else None
        ),
        "funding": (
            str(card["funding"])
            if isinstance(card.get("funding"), str) and card.get("funding")
            else None
        ),
        "brand": (
            str(card["brand"])
            if isinstance(card.get("brand"), str) and card.get("brand")
            else None
        ),
    }


def _downgrade_to_flag(result: str) -> str:
    """Cap a control result at FLAG (used for livemode=false events)."""
    if _DECISION_SEVERITY.get(result, 0) >= _DECISION_SEVERITY["FAIL"]:
        return "FLAG"
    return result


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class StripeImporter:
    """Parse a Stripe ``events.list`` export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        amount_flag_cents: int | None = None,
        amount_fail_cents: int | None = None,
        cross_customer_threshold: int | None = None,
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

        # Risk-level overrides keyed by event_type.
        meta_risk = meta.get("risk_level_overrides")
        if isinstance(meta_risk, dict) and meta_risk:
            self._risk_overrides: dict[str, dict[str, dict[str, str]]] = {
                str(k): {
                    str(rk): {str(kk): str(vv) for kk, vv in (rv or {}).items()}
                    for rk, rv in (v or {}).items()
                    if isinstance(rv, dict)
                }
                for k, v in meta_risk.items()
                if isinstance(v, dict)
            }
        else:
            self._risk_overrides = {
                k: {rk: dict(rv) for rk, rv in v.items()}
                for k, v in _DEFAULT_RISK_LEVEL_OVERRIDES.items()
            }

        # Outcome-type overrides (Stripe Radar outcome.type).
        meta_outcome = meta.get("outcome_type_overrides")
        if isinstance(meta_outcome, dict) and meta_outcome:
            self._outcome_type_overrides: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_outcome.items()
                if isinstance(v, dict)
            }
        else:
            self._outcome_type_overrides = dict(_DEFAULT_OUTCOME_TYPE_OVERRIDES)

        # Review.closed outcome overrides.
        meta_review = meta.get("review_closed_outcomes")
        if isinstance(meta_review, dict) and meta_review:
            self._review_closed_outcomes: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_review.items()
                if isinstance(v, dict)
            }
        else:
            self._review_closed_outcomes = dict(_DEFAULT_REVIEW_CLOSED_OUTCOMES)

        # Amount thresholds precedence: explicit arg > mapping metadata > default.
        meta_amounts = meta.get("amount_thresholds") or {}
        if amount_flag_cents is not None:
            self.amount_flag_cents = int(amount_flag_cents)
        else:
            self.amount_flag_cents = int(
                meta_amounts.get("flag_cents", _DEFAULT_AMOUNT_FLAG_CENTS)
            )
        if amount_fail_cents is not None:
            self.amount_fail_cents = int(amount_fail_cents)
        else:
            self.amount_fail_cents = int(
                meta_amounts.get("fail_cents", _DEFAULT_AMOUNT_FAIL_CENTS)
            )

        # Cross-customer threshold precedence: explicit arg > mapping metadata > default.
        if cross_customer_threshold is not None:
            self.cross_customer_threshold = int(cross_customer_threshold)
        else:
            self.cross_customer_threshold = int(
                meta.get("cross_customer_threshold", _DEFAULT_CROSS_CUSTOMER_THRESHOLD)
            )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Stripe events export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Stripe events export content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"data": [...]}`` / ``{"data": obj}`` / single event / JSONL."""
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
                if "data" in doc and isinstance(doc["data"], list):
                    return [e for e in doc["data"] if isinstance(e, dict)]
                # Bare event detection: a top-level object with both ``id`` and
                # ``type`` is itself a Stripe event — return it directly so the
                # event's own ``id`` is preserved (do NOT unwrap ``data``).
                if (
                    isinstance(doc.get("id"), str)
                    and isinstance(doc.get("type"), str)
                ):
                    return [doc]
                if "data" in doc and isinstance(doc["data"], dict):
                    # ``{"data": single_obj}`` — single event variant.
                    return [doc["data"]]
                # Last-resort single-object: treat as a single event.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Build per-event EvaluationResults plus cross-customer synthetic findings."""
        # First pass: aggregate customer_ids per agent_id for cross-customer detection.
        agent_customers: dict[str, set[str]] = {}
        for ev in events:
            obj = self._object_from_event(ev)
            agent_id = self._extract_metadata_agent_id(obj)
            customer_id = obj.get("customer") if isinstance(obj, dict) else None
            if (
                isinstance(agent_id, str) and agent_id
                and isinstance(customer_id, str) and customer_id
            ):
                agent_customers.setdefault(agent_id, set()).add(customer_id)

        cross_customer_agents = {
            agent_id: sorted(custs)
            for agent_id, custs in agent_customers.items()
            if len(custs) > self.cross_customer_threshold
        }

        results = [
            self._parse_event(
                ev,
                file_sha256=file_sha256,
                cross_customer_agents=cross_customer_agents,
            )
            for ev in events
        ]

        for agent_id, customers in sorted(cross_customer_agents.items()):
            results.append(
                self._synthetic_cross_customer_result(
                    agent_id=agent_id,
                    customer_ids=customers,
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
            "source_format": "stripe",
            "source_tool_name": "stripe",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    @staticmethod
    def _object_from_event(event: dict[str, Any]) -> dict[str, Any]:
        """Return the inner ``data.object`` (or ``{}`` when malformed)."""
        data = event.get("data")
        if isinstance(data, dict):
            obj = data.get("object")
            if isinstance(obj, dict):
                return obj
        return {}

    @staticmethod
    def _extract_metadata_agent_id(obj: dict[str, Any]) -> str | None:
        """Pull ``metadata.agent_id`` from an inner data object."""
        if not isinstance(obj, dict):
            return None
        md = obj.get("metadata")
        if not isinstance(md, dict):
            return None
        agent_id = md.get("agent_id")
        return str(agent_id) if isinstance(agent_id, str) and agent_id else None

    def _classify_event_type(self, event_type: str) -> dict[str, Any] | None:
        """Find the first event-pattern whose ``event_type`` glob matches."""
        for pattern in self._event_patterns:
            pat = str(pattern.get("event_type", ""))
            if pat and fnmatch.fnmatchcase(event_type, pat):
                return pattern
        return None

    def _classify_charge_succeeded(
        self, event_type: str, risk_level: str | None
    ) -> dict[str, Any] | None:
        """Apply ``charge.succeeded`` risk-level grading."""
        overrides = self._risk_overrides.get(event_type)
        if not overrides or not risk_level:
            return None
        return overrides.get(risk_level)

    def _classify_review_closed(self, review_outcome: str | None) -> dict[str, str] | None:
        if not review_outcome:
            return None
        return self._review_closed_outcomes.get(review_outcome)

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
        cross_customer_agents: dict[str, list[str]],
    ) -> EvaluationResult:
        event_id = str(event.get("id") or uuid.uuid4())
        event_type = str(event.get("type") or "").strip()
        api_version = str(event.get("api_version") or "")
        livemode_raw = event.get("livemode")
        livemode: bool | None = (
            bool(livemode_raw) if isinstance(livemode_raw, bool) else None
        )
        created_raw = event.get("created")
        if isinstance(created_raw, (int, float)):
            try:
                event_time = datetime.fromtimestamp(
                    float(created_raw), tz=timezone.utc
                ).isoformat()
            except (OverflowError, OSError, ValueError):
                event_time = datetime.now(timezone.utc).isoformat()
        else:
            event_time = datetime.now(timezone.utc).isoformat()

        request = event.get("request") or {}
        if not isinstance(request, dict):
            request = {}
        idempotency_key_present = bool(request.get("idempotency_key"))
        request_id = request.get("id") if isinstance(request.get("id"), str) else None

        obj = self._object_from_event(event)

        # ---- amount / currency ----
        amount_raw = obj.get("amount")
        try:
            amount_cents: int | None = (
                int(amount_raw) if amount_raw is not None else None
            )
        except (TypeError, ValueError):
            amount_cents = None
        currency = obj.get("currency") if isinstance(obj.get("currency"), str) else None

        # ---- outcome (charges) ----
        outcome = obj.get("outcome") or {}
        if not isinstance(outcome, dict):
            outcome = {}
        risk_level = (
            str(outcome["risk_level"]).strip().lower()
            if isinstance(outcome.get("risk_level"), str) and outcome.get("risk_level")
            else None
        )
        try:
            risk_score = (
                int(outcome["risk_score"]) if outcome.get("risk_score") is not None else None
            )
        except (TypeError, ValueError):
            risk_score = None
        outcome_type = (
            str(outcome["type"]).strip().lower()
            if isinstance(outcome.get("type"), str) and outcome.get("type")
            else None
        )
        network_status = (
            str(outcome["network_status"])
            if isinstance(outcome.get("network_status"), str) and outcome.get("network_status")
            else None
        )
        outcome_reason = (
            str(outcome["reason"])
            if isinstance(outcome.get("reason"), str) and outcome.get("reason")
            else None
        )

        # ---- card / billing / shipping (sanitized) ----
        card = _safe_card(obj.get("card"))
        billing_details = obj.get("billing_details") or {}
        if not isinstance(billing_details, dict):
            billing_details = {}
        billing_country = _safe_address_country(billing_details.get("address"))
        billing_email_domain = _email_domain(billing_details.get("email"))
        billing_name_redacted = _redact_string(billing_details.get("name"))

        shipping = obj.get("shipping") or {}
        if not isinstance(shipping, dict):
            shipping = {}
        shipping_country = _safe_address_country(shipping.get("address"))

        description_redacted = _redact_string(obj.get("description"))

        # ---- metadata (filtered) ----
        metadata_summary = _filter_metadata(obj.get("metadata"))
        agent_id_observed = metadata_summary["metadata_filtered"].get("agent_id")
        tenant_id_observed = metadata_summary["metadata_filtered"].get("tenant_id")
        order_id_observed = metadata_summary["metadata_filtered"].get("order_id")

        customer_id = (
            str(obj["customer"])
            if isinstance(obj.get("customer"), str) and obj.get("customer")
            else None
        )

        common_evidence: dict[str, Any] = {
            "stripe_event_id": event_id,
            "event_type": event_type,
            "api_version": api_version,
            "livemode": livemode,
            "event_time": event_time,
            "request_id": request_id,
            "idempotency_key_present": idempotency_key_present,
            "object_id": (
                str(obj["id"])
                if isinstance(obj.get("id"), str) and obj.get("id")
                else None
            ),
            "amount_cents": amount_cents,
            "currency": currency,
            "status": (
                str(obj["status"])
                if isinstance(obj.get("status"), str) and obj.get("status")
                else None
            ),
            "captured": obj.get("captured") if isinstance(obj.get("captured"), bool) else None,
            "paid": obj.get("paid") if isinstance(obj.get("paid"), bool) else None,
            "refunded": obj.get("refunded") if isinstance(obj.get("refunded"), bool) else None,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "outcome_type": outcome_type,
            "outcome_network_status": network_status,
            "outcome_reason": outcome_reason,
            "customer_id": customer_id,
            "agent_id_observed": agent_id_observed,
            "tenant_id_observed": tenant_id_observed,
            "order_id_observed": order_id_observed,
            "metadata_other_keys": metadata_summary["metadata_other_keys"],
            "metadata_other_count": metadata_summary["metadata_other_count"],
            "card_country": card["country"],
            "card_funding": card["funding"],
            "card_brand": card["brand"],
            "billing_country": billing_country,
            "billing_email_domain": billing_email_domain,
            "billing_name_redacted": billing_name_redacted,
            "shipping_country": shipping_country,
            "description_redacted": description_redacted,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "stripe",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Primary classification — event_type, with risk_level / outcome
        #    grading for charges and review-outcome handling for reviews.
        # ----------------------------------------------------------------
        risk_meta = self._classify_charge_succeeded(event_type, risk_level)
        review_outcome_meta: dict[str, str] | None = None
        if event_type == "review.closed":
            review_outcome_field = obj.get("reason")  # Stripe stores the close reason here.
            if not isinstance(review_outcome_field, str) or not review_outcome_field:
                # Older API shapes use ``closed_reason``; tests use both.
                review_outcome_field = obj.get("closed_reason")
            if isinstance(review_outcome_field, str) and review_outcome_field:
                review_outcome_meta = self._classify_review_closed(
                    review_outcome_field.strip().lower()
                )

        primary_meta: dict[str, Any] | None
        if risk_meta is not None:
            primary_meta = dict(risk_meta)
        elif review_outcome_meta is not None:
            primary_meta = dict(review_outcome_meta)
        else:
            primary_meta = self._classify_event_type(event_type)

        if primary_meta is None:
            # Unknown event type — surface as PR-05 FLAG so it doesn't silently pass.
            signal = "unknown_event"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Stripe event {event_id} type={event_type!r} "
                        f"has no matching pattern — surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )
        else:
            signal = str(primary_meta.get("signal", "unknown_event"))
            control_id = _control_for(
                signal, self._mappings, str(primary_meta.get("control", "PR-05"))
            )
            primary_result = str(primary_meta.get("result", "PASS"))

            # payment_intent.succeeded amount-threshold approval gate.
            if (
                event_type == "payment_intent.succeeded"
                and amount_cents is not None
            ):
                if amount_cents > self.amount_fail_cents:
                    signal = "payment_intent_succeeded_large"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    primary_result = "FAIL"
                elif amount_cents > self.amount_flag_cents:
                    signal = "payment_intent_succeeded_medium"
                    control_id = _control_for(signal, self._mappings, "PR-04")
                    primary_result = "FLAG"

            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result=primary_result,
                    detail=(
                        f"Stripe event {event_id} type={event_type} "
                        f"classified as {signal} ({primary_result}) "
                        f"amount={amount_cents} {currency or ''} "
                        f"risk_level={risk_level or 'n/a'}"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Outcome.type override (additive) — manual_review FLAG, blocked PASS.
        # ----------------------------------------------------------------
        if outcome_type and outcome_type in self._outcome_type_overrides:
            ot_meta = self._outcome_type_overrides[outcome_type]
            ot_signal = ot_meta.get("signal", f"outcome_{outcome_type}")
            ot_control = _control_for(
                ot_signal, self._mappings, ot_meta.get("control", "PR-02")
            )
            ot_result = ot_meta.get("result", "FLAG")
            control_results.append(
                ControlResult(
                    control_id=ot_control,
                    control_name=_CONTROL_NAMES.get(ot_control, ot_control),
                    result=ot_result,
                    detail=(
                        f"Stripe event {event_id} outcome.type={outcome_type!r} — "
                        f"surfaced as {ot_signal} ({ot_result})"
                    ),
                    evidence_data={**common_evidence, "signal": ot_signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. Card-country / billing-country mismatch — additive PR-04 FLAG.
        # Cards issued in one country with a billing address in a different
        # country are a textbook fraud signal. Both must be present and
        # both must be strings before we compare.
        # ----------------------------------------------------------------
        if (
            card["country"]
            and billing_country
            and str(card["country"]).strip().upper()
               != str(billing_country).strip().upper()
        ):
            signal = "card_country_mismatch"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Stripe event {event_id} card.country={card['country']!r} "
                        f"differs from billing country {billing_country!r} — "
                        f"mismatched-geography fraud signal"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 4. Cross-customer pattern — informational per-event marker. The
        # synthetic per-agent finding is added separately in the second pass.
        # ----------------------------------------------------------------
        if (
            isinstance(agent_id_observed, str)
            and agent_id_observed in cross_customer_agents
        ):
            signal = "cross_customer_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Stripe event {event_id} agent {agent_id_observed} "
                        f"is part of a cross-customer pattern "
                        f"({len(cross_customer_agents[agent_id_observed])} "
                        f"customers > threshold {self.cross_customer_threshold})"
                    ),
                    evidence_data={
                        **common_evidence,
                        "signal": signal,
                        "cross_customer_customer_ids":
                            cross_customer_agents[agent_id_observed],
                        "cross_customer_threshold": self.cross_customer_threshold,
                    },
                )
            )

        # ----------------------------------------------------------------
        # 5. livemode=false downgrade — cap every control result at FLAG so
        # test-mode events captured as evidence cannot BLOCK.
        # ----------------------------------------------------------------
        if livemode is False:
            for cr in control_results:
                if cr.result == "FAIL":
                    cr.result = _downgrade_to_flag(cr.result)
                    cr.evidence_data["livemode_downgraded"] = True

        # Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW.
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from Stripe: type={event_type} "
            f"livemode={livemode} amount_cents={amount_cents} "
            f"currency={currency or 'n/a'} "
            f"risk_level={risk_level or 'n/a'} "
            f"outcome_type={outcome_type or 'n/a'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"stripe-{event_id[:32]}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="stripe_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=request_id,
        )

    def _synthetic_cross_customer_result(
        self,
        *,
        agent_id: str,
        customer_ids: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-agent cross-customer pattern finding."""
        signal = "cross_customer_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        synthetic_id = f"stripe-cross-customer-{agent_id}"
        evidence: dict[str, Any] = {
            "stripe_event_id": synthetic_id,
            "agent_id_observed": agent_id,
            "cross_customer_customer_ids": customer_ids,
            "cross_customer_customer_count": len(customer_ids),
            "cross_customer_threshold": self.cross_customer_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                event_id=synthetic_id,
            ),
            "source_tool": "stripe",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Stripe synthetic finding: agent {agent_id} acted on "
                f"{len(customer_ids)} customers in this export — exceeds "
                f"cross-customer threshold {self.cross_customer_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="stripe_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Stripe: synthetic cross-customer pattern for "
                f"agent={agent_id} customers={len(customer_ids)}>threshold="
                f"{self.cross_customer_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )
