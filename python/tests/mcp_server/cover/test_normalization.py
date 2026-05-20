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


def test_review_items_lower_confidence_even_with_high_signals() -> None:
    result = normalize_gap_target(
        business_context="We need HIPAA and banana compliance for this assistant."
    )

    assert result.target.active_overlays == ["hipaa"]
    assert result.review_items[0].value == "banana compliance"
    assert result.confidence == "low"


def test_mrn_maps_to_health_records() -> None:
    result = normalize_gap_target(
        business_context="Clinical workflow stores MRN values."
    )

    assert result.target.my_agent_handles == ["health_records"]


def test_trust_services_maps_to_soc2() -> None:
    result = normalize_gap_target(
        business_context="The platform needs trust services coverage."
    )

    assert result.target.active_overlays == ["soc2"]


def test_short_multi_token_unknown_compliance_phrase_becomes_review_item() -> None:
    result = normalize_gap_target(business_context="We need ISO 27001 compliance.")

    assert result.review_items[0].value == "iso 27001 compliance"
    assert result.review_items[0].reason == "unmapped_compliance_phrase"
    assert result.confidence == "low"


def test_unknown_framework_before_mapped_compliance_is_reviewed() -> None:
    result = normalize_gap_target(
        business_context="We need ISO 27001 and SOC 2 compliance."
    )

    assert result.target.active_overlays == ["soc2"]
    assert any(item.value == "iso 27001 compliance" for item in result.review_items)
    assert result.confidence == "low"


def test_generic_compliance_phrases_are_not_review_items() -> None:
    need_result = normalize_gap_target(business_context="We need compliance.")
    require_result = normalize_gap_target(business_context="We require compliance.")

    assert {item.value for item in need_result.review_items} == set()
    assert {item.value for item in require_result.review_items} == set()
