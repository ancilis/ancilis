"""Tests for deterministic Cover gap target normalization."""

from __future__ import annotations

from ancilis.mcp_server.cover.models import GapTarget, NormalizationSignal


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
