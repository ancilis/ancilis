"""V1 release contract for AKSI v0.6 full control support."""

from __future__ import annotations

from ancilis.config import load_config, load_control_definitions
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.evaluators.attestation import (
    ATTESTATION_CONTROL_SPECS,
    make_attestation_evaluators,
)
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.evidence.query import certification_coverage
from ancilis.evidence.store import EvidenceStore


def _action() -> Action:
    return Action(
        action_id="v1-full-support-action",
        timestamp="2026-05-20T12:00:00+00:00",
        agent_id="v1-agent",
        agent_owner="security-team",
        action_type="tool_call",
        tool=ToolInfo(name="read_file", description_hash="v1-support"),
        parameters=ActionParameters(raw={}, parameter_hash="v1-support"),
        context=ActionContext(session_id="v1-support-session"),
    )


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolEntry(
            name="read_file",
            status=ToolStatus.APPROVED,
            description_hash="v1-support",
            approved_by="v1-release-test",
        )
    )
    return registry


def test_shared_catalog_marks_controls_as_direct_runtime_or_attestation_backed() -> None:
    controls = load_control_definitions()
    direct_runtime_controls = {
        "DE-01",
        "DE-02",
        "DE-03",
        "DE-04",
        "GOV-01",
        "GOV-02",
        "GOV-03",
        "ID-01",
        "PR-01",
        "PR-02",
        "PR-03",
        "PR-04",
        "PR-05",
        "PR-06",
        "PR-07",
        "PR-08",
        "PR-09",
        "RS-02",
    }

    assert len(controls) == 41
    assert {
        control_id
        for control_id, control in controls.items()
        if control.get("support_level") == "runtime_evaluator"
    } == direct_runtime_controls
    assert {
        control_id: control.get("support_level")
        for control_id, control in controls.items()
        if control.get("support_level") not in {"runtime_evaluator", "attestation"}
    } == {}


def test_python_engine_has_evaluation_path_for_every_active_v06_control() -> None:
    config = load_config(
        raw={
            "agent": {
                "name": "v1-agent",
                "owner": "security-team",
            }
        }
    )

    evaluation = Engine(config, registry=_registry()).evaluate(_action())

    active_control_ids = {
        control_id for control_id, status in config.controls.items() if status.enabled
    }
    configured_control_ids = set(config.controls)
    result_by_id = {result.control_id: result for result in evaluation.control_results}

    assert len(active_control_ids) == 39
    assert len(configured_control_ids) == 41
    assert set(result_by_id) == configured_control_ids
    assert not [
        result.control_id
        for result in evaluation.control_results
        if "No evaluator implemented" in result.detail
        or "Evaluator is not registered" in result.detail
        or result.detail.startswith("DEFERRED:")
    ]


def test_python_engine_does_not_describe_attestation_skips_as_all_passed() -> None:
    config = load_config(
        raw={
            "agent": {
                "name": "v1-agent",
                "owner": "security-team",
            }
        }
    )

    evaluation = Engine(config, registry=_registry()).evaluate(_action())

    assert any(result.result == "SKIP" for result in evaluation.control_results)
    assert evaluation.decision == "ALLOW"
    assert evaluation.decision_reason != "All controls passed."
    assert "Skipped controls" in evaluation.decision_reason


def test_certify_no_longer_routes_v1_controls_to_roadmap(tmp_path) -> None:
    config = load_config(raw={"agent": {"name": "v1-agent", "owner": "security-team"}})
    store = EvidenceStore(config, db_path=tmp_path / "evidence.duckdb")
    try:
        _, rows = certification_coverage(store, target="soc2", config=config)
    finally:
        store.close()

    assert rows
    assert not [
        row.control_id
        for row in rows
        if row.action_required == "v0.2 roadmap"
        or row.coverage_status.startswith("deferred_")
    ]


def test_python_attestation_backed_controls_require_manual_evidence() -> None:
    config = load_config(raw={"agent": {"name": "v1-agent", "owner": "security-team"}})
    action = _action()

    evaluators = make_attestation_evaluators(evidence_store=None)

    assert set(evaluators) == set(ATTESTATION_CONTROL_SPECS)
    for control_id, evaluator in sorted(evaluators.items()):
        result = evaluator.evaluate(action, config)
        assert result.result == "SKIP", control_id
        assert result.detail == "MANUAL: attestation required", control_id
        assert result.evidence_data["command"] == f"ancilis attest {control_id}"
