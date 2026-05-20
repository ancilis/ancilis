"""Tests for deterministic Cover gap target normalization."""

from __future__ import annotations

from ancilis.mcp_server.cover.models import GapTarget, NormalizationSignal
from ancilis.mcp_server.cover.normalization import normalize_gap_target


def test_gap_target_defaults_are_empty_lists() -> None:
    target = GapTarget()

    assert target.my_agent_handles == []
    assert target.active_overlays == []
    assert target.certification_targets == []


def test_normalization_signal_serializes() -> None:
    signal = NormalizationSignal(
        source="business_context",
        phrase="patient records",
        mapped_to="health_records",
        target_type="my_agent_handles",
        confidence="high",
    )

    assert signal.model_dump(mode="json")["mapped_to"] == "health_records"


def test_normalize_patient_records_and_hipaa() -> None:
    result = normalize_gap_target(
        business_context="We handle patient records and need HIPAA."
    )

    assert result.target.my_agent_handles == ["health_records"]
    assert result.target.active_overlays == ["hipaa"]
    assert result.review_items == []
    assert result.confidence == "high"
    assert {signal.mapped_to for signal in result.signals} == {"health_records", "hipaa"}


def test_normalize_checkout_and_pci() -> None:
    result = normalize_gap_target(
        business_context="Checkout agent accepts cards and needs PCI."
    )

    assert result.target.my_agent_handles == ["credit_cards"]
    assert result.target.active_overlays == ["pci-dss-v4"]


def test_explicit_targets_merge_with_business_context() -> None:
    result = normalize_gap_target(
        business_context="Customer support bot stores emails.",
        target_data_types=["health_records"],
        target_overlays=["hipaa"],
        target_certifications=["aiuc-1"],
    )

    assert result.target.my_agent_handles == ["health_records", "personal_info"]
    assert result.target.active_overlays == ["gdpr", "hipaa"]
    assert result.target.certification_targets == ["aiuc-1"]
    assert any(signal.source == "explicit_input" for signal in result.signals)


def test_unknown_compliance_phrase_becomes_review_item() -> None:
    result = normalize_gap_target(
        business_context="We need banana compliance for this assistant."
    )

    assert result.target.my_agent_handles == []
    assert result.target.active_overlays == []
    assert result.review_items[0].value == "banana compliance"
    assert result.confidence == "low"
