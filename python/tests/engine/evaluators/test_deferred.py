from __future__ import annotations

from datetime import datetime, timezone
import uuid

from ancilis.config import load_config, load_control_definitions
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.evaluators.deferred import DEFERRED_CONTROL_SPECS, DeferredEvaluator
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
    assert result.detail == "DEFERRED: cross_action"
    assert result.evidence_data["blocking_capability"] == "cross_action"
    assert result.evidence_data["todo"] == "track data-flow graph"


def test_deferred_specs_match_current_control_catalog() -> None:
    controls = load_control_definitions()

    assert set(DEFERRED_CONTROL_SPECS).issubset(controls)
    assert "DE-03" not in DEFERRED_CONTROL_SPECS


def test_engine_returns_deferred_not_no_evaluator_for_phase4_gaps() -> None:
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
    result = Engine(config, evidence_store=store).evaluate(_action())
    by_id = {control.control_id: control for control in result.control_results}

    for control_id, spec in DEFERRED_CONTROL_SPECS.items():
        assert by_id[control_id].result == "SKIP"
        assert by_id[control_id].detail == f"DEFERRED: {spec.reason}"
        assert by_id[control_id].evidence_data["todo"] == spec.todo_block

    assert all(
        control.detail != "No evaluator implemented for this control."
        for control in result.control_results
    )
