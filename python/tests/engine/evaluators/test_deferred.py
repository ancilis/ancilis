from __future__ import annotations

from datetime import datetime, timezone
import uuid

from ancilis.config import load_config, load_control_definitions
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.evaluators.deferred import (
    DEFERRED_CONTROL_SPECS,
    LEGACY_DEFERRED_CONTROL_SPECS,
    DeferredEvaluator,
)
from ancilis.evidence.store import EvidenceStore


def _action() -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id="deferred-agent",
        action_type="tool_call",
        tool=ToolInfo(name="probe-tool"),
        parameters=ActionParameters(raw={"operation": "read"}),
        context=ActionContext(session_id="deferred-tests"),
    )


def test_deferred_evaluator_returns_honest_skip_payload() -> None:
    evaluator = DeferredEvaluator("ID-03", "cross_action", "track data-flow graph")

    result = evaluator.evaluate(_action(), load_config(raw={"agent": {"name": "deferred-agent"}}))

    assert result.result == "SKIP"
    assert result.detail == "Legacy architecture blocker: cross_action"
    assert result.evidence_data["blocking_capability"] == "cross_action"
    assert result.evidence_data["todo"] == "track data-flow graph"


def test_deferred_specs_are_legacy_only() -> None:
    controls = load_control_definitions()

    assert DEFERRED_CONTROL_SPECS == {}
    assert set(LEGACY_DEFERRED_CONTROL_SPECS).issubset(controls)
    assert "ID-03" in LEGACY_DEFERRED_CONTROL_SPECS


def test_engine_no_longer_registers_legacy_deferred_evaluators() -> None:
    config = load_config(
        raw={
            "agent": {"name": "deferred-agent", "agent_id": "deferred-agent"},
            "security": {
                "tools": {"allowed": ["probe-tool"]},
                "sandbox_policy": {"approved_execution_classes": ["firecracker"]},
            },
            "my_agent_handles": ["agent_payments"],
        }
    )
    store = EvidenceStore(config, in_memory=True)
    try:
        result = Engine(config, evidence_store=store).evaluate(_action())
    finally:
        store.close()
    by_id = {control.control_id: control for control in result.control_results}

    assert by_id["ID-03"].detail == "MANUAL: attestation required"
    assert all(
        not control.detail.startswith("Legacy architecture blocker")
        for control in result.control_results
    )
    assert all(
        control.detail != "Evaluator is not registered for this control."
        for control in result.control_results
    )
