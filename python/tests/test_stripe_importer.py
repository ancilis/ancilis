"""Tests for the Stripe events importer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ancilis.importers.stripe import StripeImporter


# ---------------------------------------------------------------------------
# Fixture helpers — inline Stripe event objects (no `stripe` package required)
# ---------------------------------------------------------------------------


def _event(
    *,
    event_id: str = "evt_001",
    event_type: str = "charge.succeeded",
    livemode: bool = True,
    created: int = 1730000000,
    api_version: str = "2024-12-18.acacia",
    request_id: str = "req_abc",
    idempotency_key: str | None = "ik-1",
    obj: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if obj is None:
        obj = {}
    request: dict[str, Any] = {"id": request_id}
    if idempotency_key is not None:
        request["idempotency_key"] = idempotency_key
    return {
        "id": event_id,
        "object": "event",
        "type": event_type,
        "api_version": api_version,
        "created": created,
        "livemode": livemode,
        "request": request,
        "data": {"object": obj},
    }


def _charge_obj(
    *,
    object_id: str = "ch_001",
    amount: int = 5000,
    currency: str = "usd",
    risk_level: str = "normal",
    risk_score: int = 23,
    outcome_type: str = "authorized",
    network_status: str = "approved_by_network",
    customer: str = "cus_001",
    captured: bool = True,
    paid: bool = True,
    refunded: bool = False,
    status: str = "succeeded",
    card_country: str = "US",
    card_funding: str = "credit",
    card_brand: str = "visa",
    billing_country: str = "US",
    billing_email: str = "buyer@example.com",
    billing_name: str = "Kevin Bauer",
    shipping_country: str = "US",
    description: str = "Order #4242 — premium subscription",
    metadata: dict[str, str] | None = None,
    extra_card: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if metadata is None:
        metadata = {"agent_id": "agent-x", "tenant_id": "tnt-1", "order_id": "ord-1"}
    card: dict[str, Any] = {
        "country": card_country,
        "funding": card_funding,
        "brand": card_brand,
    }
    if extra_card:
        card.update(extra_card)
    return {
        "id": object_id,
        "amount": amount,
        "currency": currency,
        "metadata": metadata,
        "status": status,
        "captured": captured,
        "paid": paid,
        "refunded": refunded,
        "outcome": {
            "network_status": network_status,
            "reason": None,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "type": outcome_type,
        },
        "customer": customer,
        "description": description,
        "card": card,
        "billing_details": {
            "address": {"country": billing_country},
            "email": billing_email,
            "name": billing_name,
        },
        "shipping": {"address": {"country": shipping_country}},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_charge_succeeded_normal() -> None:
    """charge.succeeded with risk_level=normal → PR-02 PASS, ALLOW."""
    doc = json.dumps({"data": [_event(obj=_charge_obj(risk_level="normal"))]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "ALLOW"
    assert result.source_type == "stripe_import"
    assert result.action_id == "stripe-evt_001"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "PASS"
    assert cr.evidence_data["signal"] == "charge_succeeded"
    assert cr.evidence_data["livemode"] is True
    assert cr.evidence_data["amount_cents"] == 5000
    assert cr.evidence_data["currency"] == "usd"
    assert cr.evidence_data["idempotency_key_present"] is True


def test_charge_succeeded_elevated_risk_flags() -> None:
    """charge.succeeded with risk_level=elevated → PR-02 FLAG."""
    doc = json.dumps({"data": [_event(obj=_charge_obj(risk_level="elevated"))]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "FLAG"
    crs = [c for c in result.control_results if c.control_id == "PR-02"]
    assert any(c.result == "FLAG" and c.evidence_data["signal"] ==
               "charge_succeeded_elevated_risk" for c in crs)


def test_charge_succeeded_highest_risk_fails() -> None:
    """charge.succeeded with risk_level=highest → PR-02 FAIL, BLOCK."""
    doc = json.dumps({"data": [_event(obj=_charge_obj(risk_level="highest"))]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    crs = [c for c in result.control_results if c.control_id == "PR-02"]
    assert any(c.result == "FAIL" and c.evidence_data["signal"] ==
               "charge_succeeded_highest_risk" for c in crs)


def test_charge_dispute_fails() -> None:
    """charge.dispute.created → PR-02 FAIL (chargeback). High-priority operator review."""
    obj = {
        "id": "dp_001",
        "amount": 9900,
        "currency": "usd",
        "customer": "cus_001",
        "metadata": {"agent_id": "agent-x"},
    }
    doc = json.dumps({"data": [_event(
        event_id="evt_dispute",
        event_type="charge.dispute.created",
        obj=obj,
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "charge_dispute"


def test_payment_intent_large_fails_approval_gate() -> None:
    """payment_intent.succeeded > $10,000 default → PR-04 FAIL approval gate."""
    obj = {
        "id": "pi_001",
        "amount": 1_500_000,  # $15,000 > 1,000,000-cent default fail threshold
        "currency": "usd",
        "status": "succeeded",
        "customer": "cus_001",
        "metadata": {"agent_id": "agent-x"},
    }
    doc = json.dumps({"data": [_event(
        event_id="evt_pi_large",
        event_type="payment_intent.succeeded",
        obj=obj,
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "payment_intent_succeeded_large"
    assert cr.evidence_data["amount_cents"] == 1_500_000


def test_payment_intent_medium_flags() -> None:
    """payment_intent.succeeded between $1k and $10k default → PR-04 FLAG."""
    obj = {
        "id": "pi_002",
        "amount": 250_000,  # $2,500 — between flag (100k) and fail (1m) thresholds
        "currency": "usd",
        "status": "succeeded",
        "customer": "cus_002",
        "metadata": {"agent_id": "agent-x"},
    }
    doc = json.dumps({"data": [_event(
        event_id="evt_pi_med",
        event_type="payment_intent.succeeded",
        obj=obj,
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "payment_intent_succeeded_medium"


def test_payout_paid_flags_money_out() -> None:
    """payout.paid → PR-04 FLAG. Money LEAVING is more critical than money in."""
    obj = {
        "id": "po_001",
        "amount": 50_000,
        "currency": "usd",
        "status": "paid",
        "metadata": {"agent_id": "agent-x"},
    }
    doc = json.dumps({"data": [_event(
        event_id="evt_payout",
        event_type="payout.paid",
        obj=obj,
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "payout_paid"


def test_transfer_flags() -> None:
    """transfer.created → PR-04 FLAG. Money moving between accounts."""
    obj = {
        "id": "tr_001",
        "amount": 12_000,
        "currency": "usd",
        "metadata": {"agent_id": "agent-x"},
    }
    doc = json.dumps({"data": [_event(
        event_id="evt_transfer",
        event_type="transfer.created",
        obj=obj,
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "FLAG"
    [cr] = result.control_results
    assert cr.control_id == "PR-04"
    assert cr.result == "FLAG"
    assert cr.evidence_data["signal"] == "transfer_created"


def test_review_closed_refunded_fails_fraud() -> None:
    """review.closed with reason=refunded → PR-02 FAIL (Stripe Radar fraud)."""
    obj = {
        "id": "prv_001",
        "reason": "refunded",
        "metadata": {"agent_id": "agent-x"},
    }
    doc = json.dumps({"data": [_event(
        event_id="evt_review",
        event_type="review.closed",
        obj=obj,
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "BLOCK"
    [cr] = result.control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FAIL"
    assert cr.evidence_data["signal"] == "review_closed_refunded"


def test_livemode_false_downgrades_max_to_flag() -> None:
    """livemode=false downgrades any FAIL to FLAG so test events never BLOCK."""
    # A highest-risk charge would normally be FAIL/BLOCK. With livemode=false
    # the decision must drop to FLAG (never BLOCK).
    doc = json.dumps({"data": [_event(
        event_id="evt_test",
        livemode=False,
        obj=_charge_obj(risk_level="highest"),
    )]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "FLAG"
    assert all(cr.result != "FAIL" for cr in result.control_results)
    # Confirm the downgrade marker is on the originally-FAIL control.
    assert any(cr.evidence_data.get("livemode_downgraded") is True
               for cr in result.control_results)


def test_card_country_mismatch_flags() -> None:
    """card.country differs from billing_details.address.country → PR-04 FLAG."""
    obj = _charge_obj(card_country="GB", billing_country="US")
    doc = json.dumps({"data": [_event(event_id="evt_geo", obj=obj)]})
    [result] = StripeImporter().parse_string(doc)
    assert result.decision == "FLAG"
    mismatch = [cr for cr in result.control_results
                if cr.evidence_data.get("signal") == "card_country_mismatch"]
    assert len(mismatch) == 1
    assert mismatch[0].control_id == "PR-04"
    assert mismatch[0].result == "FLAG"


def test_card_pan_never_stored() -> None:
    """Even when last4/exp/cvc/PAN are present in input, evidence keeps only country/funding/brand."""
    obj = _charge_obj(
        extra_card={
            "last4": "4242",
            "exp_month": 12,
            "exp_year": 2030,
            "cvc": "123",
            "number": "4242424242424242",
            "fingerprint": "abc123",
        },
    )
    doc = json.dumps({"data": [_event(event_id="evt_pan", obj=obj)]})
    [result] = StripeImporter().parse_string(doc)
    [cr] = result.control_results
    ev = cr.evidence_data
    # Allowed.
    assert ev["card_country"] == "US"
    assert ev["card_funding"] == "credit"
    assert ev["card_brand"] == "visa"
    # Banned — must not be present anywhere in evidence_data.
    serialized = json.dumps(ev, default=str)
    for forbidden in ("4242", "exp_month", "exp_year", "cvc", "fingerprint",
                      "4242424242424242"):
        assert forbidden not in serialized, f"{forbidden!r} leaked into evidence"


def test_cross_customer_pattern_synthetic() -> None:
    """Same agent_id touching > threshold customers → synthetic PR-02 FLAG."""
    events = []
    # 3 customers with a threshold of 2 → cross-customer pattern fires.
    for i, cus in enumerate(("cus_a", "cus_b", "cus_c")):
        obj = _charge_obj(customer=cus)
        events.append(_event(event_id=f"evt_{i}", obj=obj))
    doc = json.dumps({"data": events})
    results = StripeImporter(cross_customer_threshold=2).parse_string(doc)
    # 3 per-event results + 1 synthetic = 4.
    assert len(results) == 4
    synthetic = [r for r in results
                 if r.action_id == "stripe-cross-customer-agent-x"]
    assert len(synthetic) == 1
    [cr] = synthetic[0].control_results
    assert cr.control_id == "PR-02"
    assert cr.result == "FLAG"
    assert cr.evidence_data["synthetic"] is True
    assert cr.evidence_data["cross_customer_customer_count"] == 3
    # Per-event results should also carry the cross_customer_pattern marker.
    per_event_with_marker = [
        r for r in results
        if r.action_id != "stripe-cross-customer-agent-x"
        and any(c.evidence_data.get("signal") == "cross_customer_pattern"
                for c in r.control_results)
    ]
    assert len(per_event_with_marker) == 3


def test_billing_email_only_domain_stored() -> None:
    """billing_details.email is stored as domain only — local part dropped."""
    obj = _charge_obj(billing_email="kevin.private@example.com")
    doc = json.dumps({"data": [_event(event_id="evt_email", obj=obj)]})
    [result] = StripeImporter().parse_string(doc)
    [cr] = result.control_results
    ev = cr.evidence_data
    assert ev["billing_email_domain"] == "example.com"
    # Local part must NOT be present anywhere in the evidence blob.
    serialized = json.dumps(ev, default=str)
    assert "kevin.private" not in serialized
    # billing_details.name is stored as length+sha256 only — never the raw name.
    assert ev["billing_name_redacted"] == {
        "length": len("Kevin Bauer"),
        "sha256": hashlib.sha256("Kevin Bauer".encode("utf-8")).hexdigest(),
    }
    assert "Kevin Bauer" not in serialized


def test_metadata_values_filtered() -> None:
    """Only agent_id/tenant_id/order_id metadata values are kept; others dropped."""
    obj = _charge_obj(metadata={
        "agent_id": "agent-x",
        "tenant_id": "tnt-1",
        "order_id": "ord-7",
        "customer_email": "private@example.com",  # could carry PII — drop
        "internal_note": "ssn=123-45-6789",         # could carry PII — drop
    })
    doc = json.dumps({"data": [_event(event_id="evt_md", obj=obj)]})
    [result] = StripeImporter().parse_string(doc)
    [cr] = result.control_results
    ev = cr.evidence_data
    assert ev["agent_id_observed"] == "agent-x"
    assert ev["tenant_id_observed"] == "tnt-1"
    assert ev["order_id_observed"] == "ord-7"
    assert sorted(ev["metadata_other_keys"]) == ["customer_email", "internal_note"]
    assert ev["metadata_other_count"] == 2
    serialized = json.dumps(ev, default=str)
    assert "private@example.com" not in serialized
    assert "ssn=123-45-6789" not in serialized
    assert "123-45-6789" not in serialized


# ---------------------------------------------------------------------------
# Additional behavior / format coverage
# ---------------------------------------------------------------------------


def test_parse_jsonl_and_single_event_shapes(tmp_path: Path) -> None:
    """JSONL and ``{"data": single_obj}`` and bare-event shapes all work."""
    # JSONL — two events on two lines.
    jsonl = "\n".join(
        json.dumps(_event(event_id=f"evt_{i}", obj=_charge_obj()))
        for i in range(2)
    )
    results_jsonl = StripeImporter().parse_string(jsonl)
    assert len(results_jsonl) == 2

    # {"data": single_obj} envelope.
    single_env = json.dumps({"data": _event(event_id="evt_se", obj=_charge_obj())})
    [r1] = StripeImporter().parse_string(single_env)
    assert r1.action_id == "stripe-evt_se"

    # Bare event.
    bare = json.dumps(_event(event_id="evt_bare", obj=_charge_obj()))
    [r2] = StripeImporter().parse_string(bare)
    assert r2.action_id == "stripe-evt_bare"

    # parse(path) wraps parse_string + adds file_sha256 provenance.
    p = tmp_path / "events.json"
    p.write_text(json.dumps({"data": [_event(event_id="evt_disk", obj=_charge_obj())]}))
    [rd] = StripeImporter().parse(p)
    expected_sha = hashlib.sha256(p.read_bytes()).hexdigest()
    [cr] = rd.control_results
    assert cr.evidence_data["source_provenance"]["original_file_sha256"] == expected_sha
