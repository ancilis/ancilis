"""Integration tests for multi-overlay activation flows."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest

from ancilis.activation.resolver import ActivationResolver
from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.tool import ToolActionProducer


def _raw_config(
    handles: Sequence[str],
    certifications: Sequence[str] | None = None,
    *,
    allowed_tools: Sequence[str] | None = None,
) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "agent": {"name": "overlay-integration-agent"},
        "my_agent_handles": list(handles),
    }
    if certifications is not None:
        raw["certification_targets"] = list(certifications)
    if allowed_tools is not None:
        raw["security"] = {
            "mode": "audit",
            "tools": {"allowed": list(allowed_tools)},
        }
    return raw


def _load_resolved(
    handles: Sequence[str],
    certifications: Sequence[str] | None = None,
    *,
    allowed_tools: Sequence[str] | None = None,
) -> ResolvedConfig:
    return load_config(raw=_raw_config(handles, certifications, allowed_tools=allowed_tools))


def _dummy_tool(payload: str) -> str:
    return payload.upper()


def _run_tool_flow(
    handles: Sequence[str],
    certifications: Sequence[str] | None = None,
) -> tuple[list[EvidenceRecord], dict[str, Any], tuple[bool, list[str]]]:
    config = _load_resolved(handles, certifications, allowed_tools=["overlay-tool"])
    store = EvidenceStore(config, in_memory=True)
    try:
        producer = ToolActionProducer(config=config, engine=Engine(config), evidence_store=store)
        producer.execute(_dummy_tool, agent_name=config.agent_name, tool_name="overlay-tool", args=("first",))
        producer.execute(_dummy_tool, agent_name=config.agent_name, tool_name="overlay-tool", args=("second",))
        records = store.get_records(limit=10)
        summary = store.get_summary()
        chain_status = store.verify_chain()
        return records, summary, chain_status
    finally:
        store.close()


@pytest.mark.parametrize(
    ("handles", "expected_overlays", "expected_classifications"),
    [
        (
            ["financial_data", "government_cui"],
            {"nist-csf", "glba", "soc2", "cmmc-l2"},
            {"DC-FIN", "DC-GOV", "DC-CUI"},
        ),
        (
            ["financial_data", "mnpi"],
            {"nist-csf", "glba", "soc2", "securities-mnpi"},
            {"DC-FIN", "DC-MNPI"},
        ),
        (
            ["biometric_data", "government_cui"],
            {"nist-csf", "eu-ai-act", "cmmc-l2"},
            {"DC-BIO", "DC-GOV", "DC-CUI"},
        ),
    ],
)
def test_resolver_activates_expected_multi_overlay_sets(
    handles: list[str],
    expected_overlays: set[str],
    expected_classifications: set[str],
) -> None:
    spec = ActivationResolver().resolve(my_agent_handles=handles)

    assert set(spec.active_overlays) == expected_overlays
    assert set(spec.data_classifications) == expected_classifications


@pytest.mark.parametrize(
    ("handles", "control_id", "expected_threshold"),
    [
        (["financial_data"], "PR-01", "strict"),
        (["personal_info", "financial_data"], "DE-01", "strict"),
        (["personal_info", "financial_data"], "PR-03", "standard"),
    ],
)
def test_resolver_applies_strictest_thresholds_across_overlay_combinations(
    handles: list[str],
    control_id: str,
    expected_threshold: str,
) -> None:
    spec = ActivationResolver().resolve(my_agent_handles=handles)

    assert spec.control_thresholds[control_id] == expected_threshold


@pytest.mark.parametrize(
    ("handles", "expected_retention", "expected_human_oversight", "expected_thresholds"),
    [
        (
            ["financial_data", "government_cui"],
            2555,
            False,
            {"PR-05": "strict"},
        ),
        (
            ["biometric_data", "government_cui"],
            3650,
            True,
            {"GOV-04": "strict", "PR-05": "strict"},
        ),
    ],
)
def test_resolver_composes_overlay_and_aiuc1_requirements_without_weakening_overlays(
    handles: list[str],
    expected_retention: int,
    expected_human_oversight: bool,
    expected_thresholds: dict[str, str],
) -> None:
    spec = ActivationResolver().resolve(
        my_agent_handles=handles,
        certification_targets=["aiuc-1"],
    )

    assert spec.active_certifications == ["aiuc-1"]
    assert spec.activation_source["PR-05"] == "certification_targets:aiuc-1"
    assert spec.activation_source["PR-05_threshold"].startswith("overlay:")
    assert spec.evidence_retention_days == expected_retention
    assert spec.human_oversight_required is expected_human_oversight
    for control_id, threshold in expected_thresholds.items():
        assert spec.control_thresholds[control_id] == threshold


@pytest.mark.parametrize(
    (
        "handles",
        "certifications",
        "expected_overlays",
        "expected_retention",
        "expected_human_oversight",
        "expected_thresholds",
    ),
    [
        (
            ["financial_data", "government_cui"],
            None,
            {"cmmc-l2", "glba", "soc2"},
            2555,
            False,
            {"PR-01": "strict", "PR-03": "strict"},
        ),
        (
            ["biometric_data", "government_cui"],
            None,
            {"cmmc-l2", "eu-ai-act"},
            3650,
            True,
            {"GOV-04": "strict", "PR-03": "strict"},
        ),
        (
            ["personal_info", "financial_data"],
            None,
            {"gdpr", "ccpa", "glba", "soc2"},
            2555,
            False,
            {"PR-01": "strict", "PR-03": "standard"},
        ),
        (
            ["financial_data", "mnpi"],
            ["aiuc-1"],
            {"glba", "securities-mnpi", "soc2"},
            2555,
            False,
            {"PR-05": "strict", "DE-01": "strict"},
        ),
    ],
)
def test_load_config_tracks_combined_overlay_state(
    handles: list[str],
    certifications: list[str] | None,
    expected_overlays: set[str],
    expected_retention: int,
    expected_human_oversight: bool,
    expected_thresholds: dict[str, str],
) -> None:
    config = _load_resolved(handles, certifications)

    assert set(config.active_overlays) == expected_overlays
    assert config.active_certifications == list(certifications or [])
    assert config.evidence_retention_days == expected_retention
    assert config.human_oversight_required is expected_human_oversight
    for control_id, threshold in expected_thresholds.items():
        assert config.controls[control_id].threshold == threshold


@pytest.mark.parametrize(
    ("handles", "control_id", "expected_overlay_ids"),
    [
        (["financial_data", "government_cui"], "PR-01", {"cmmc-l2", "glba", "soc2"}),
        (["financial_data", "mnpi"], "PR-05", {"glba", "securities-mnpi", "soc2"}),
        (["biometric_data", "government_cui"], "PR-01", {"cmmc-l2", "eu-ai-act"}),
    ],
)
def test_load_config_merges_per_control_overlay_requirements(
    handles: list[str],
    control_id: str,
    expected_overlay_ids: set[str],
) -> None:
    config = _load_resolved(handles)

    requirements = config.overlay_requirements[control_id]

    assert set(requirements) == expected_overlay_ids
    for overlay_id in expected_overlay_ids:
        assert requirements[overlay_id]["framework_reference"]


@pytest.mark.parametrize(
    ("handles", "expected_overlays"),
    [
        (["financial_data", "government_cui"], {"cmmc-l2", "glba", "soc2"}),
        (["financial_data", "mnpi"], {"glba", "securities-mnpi", "soc2"}),
        (["biometric_data", "government_cui"], {"cmmc-l2", "eu-ai-act"}),
    ],
)
def test_tool_producer_keeps_hash_chain_valid_for_multi_overlay_runs(
    handles: list[str],
    expected_overlays: set[str],
) -> None:
    records, summary, (chain_valid, chain_errors) = _run_tool_flow(handles, ["aiuc-1"])

    assert len(records) == 2
    assert set(records[0].active_overlays) == expected_overlays
    assert set(records[1].active_overlays) == expected_overlays
    assert records[0].active_certifications == ["aiuc-1"]
    assert records[1].active_certifications == ["aiuc-1"]
    assert records[1].previous_hash == records[0].record_hash
    assert next(cr for cr in records[0].control_results if cr["control_id"] == "PR-05")["result"] == "PASS"
    assert summary["decisions"] == {"ALLOW": 2}
    assert summary["chain_valid"] is True
    assert chain_valid is True
    assert chain_errors == []
