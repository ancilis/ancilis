"""Tests for deterministic Cover classification and setup recommendations."""

from __future__ import annotations

from ancilis.mcp_server.cover.classification import classify_project
from ancilis.mcp_server.cover.models import CoverSignal
from ancilis.mcp_server.cover.recommendations import recommend_setup


def test_classify_project_maps_payment_signals_to_credit_card_overlays() -> None:
    result = classify_project(
        description="Stripe checkout accepts card payments for subscriptions.",
        signals=[
            CoverSignal(
                source="dependency",
                value="stripe",
                rule_id="dependency.detected",
                confidence="medium",
            )
        ],
    )

    assert "credit_cards" in result.my_agent_handles
    assert "pci-dss-v4" in result.active_overlays
    assert result.confidence == "high"
    assert any(signal.rule_id == "data.credit_cards.stripe" for signal in result.signals)


def test_classify_project_maps_health_signals_to_health_overlays() -> None:
    result = classify_project(
        description="Therapist patient portal with clinic messages and MRN lookup."
    )

    assert "health_records" in result.my_agent_handles
    assert {"hipaa", "gdpr", "soc2"}.issubset(set(result.active_overlays))
    assert result.confidence == "high"


def test_classify_project_keeps_weak_personal_info_signal_as_review_item() -> None:
    result = classify_project(description="User dashboard")

    assert "personal_info" not in result.my_agent_handles
    assert result.review_items
    assert result.review_items[0].recommendation == "personal_info"
    assert result.confidence == "low"


def test_recommend_setup_generates_config_and_python_snippet() -> None:
    classification = classify_project(
        description="Patient portal with medical records and therapist notes."
    )

    result = recommend_setup(
        classification=classification,
        project_name="therapy-agent",
        language="python",
    )

    assert "pip install ancilis" in result.install_commands
    assert "my_agent_handles:" in result.config_yaml
    assert "health_records" in result.config_yaml
    assert "hipaa" in result.config_yaml
    assert "ToolActionProducer" in result.integration_snippets["python"]
    assert "ancilis doctor" in result.validation_commands
    assert result.next_steps[0].startswith("Create ancilis.yaml")
