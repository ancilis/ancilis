from __future__ import annotations

from datetime import datetime, timezone
import uuid

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.evaluators.rs02_containment import RS02ContainmentEvaluator
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import ControlResult


def _config(**overrides):
    raw = {
        "agent": {"name": "containment-agent"},
        "security": {
            "mode": "audit",
            "tools": {"allowed": ["read_file"]},
        },
    }
    raw.update(overrides)
    return load_config(raw=raw)


def _action(
    *,
    tool_name: str = "read_file",
    params: dict | None = None,
    metadata: dict | None = None,
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id="containment-agent",
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw=params or {}, parameter_hash="params"),
        context=ActionContext(session_id="containment-tests"),
        metadata=metadata or {},
    )


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ToolEntry(name="read_file", status=ToolStatus.APPROVED))
    return registry


def test_rs02_passes_when_no_prior_failures() -> None:
    result = RS02ContainmentEvaluator().evaluate(
        _action(),
        _config(),
        prior_results=[ControlResult("PR-01", "Action Authorization", "PASS", "ok")],
    )

    assert result.result == "PASS"
    assert result.evidence_data["triggering_failures"] == []


def test_rs02_fails_when_prior_failure_has_no_containment_intent() -> None:
    result = RS02ContainmentEvaluator().evaluate(
        _action(),
        _config(),
        prior_results=[ControlResult("PR-04", "Data Exposure", "FAIL", "blocked")],
    )

    assert result.result == "FAIL"
    assert "containment" in result.detail.lower()


def test_rs02_passes_when_containment_intent_present() -> None:
    result = RS02ContainmentEvaluator().evaluate(
        _action(metadata={"containment_intent": "quarantine"}),
        _config(),
        prior_results=[ControlResult("PR-04", "Data Exposure", "FAIL", "blocked")],
    )

    assert result.result == "PASS"
    assert result.evidence_data["containment_intent"] == "quarantine"


def test_rs02_accepts_kill_switch_boolean() -> None:
    result = RS02ContainmentEvaluator().evaluate(
        _action(metadata={"kill_switch": True}),
        _config(),
        prior_results=[ControlResult("PR-04", "Data Exposure", "FAIL", "blocked")],
    )

    assert result.result == "PASS"
    assert result.evidence_data["containment_intent"] == "kill_switch"


def test_engine_runs_rs02_after_other_controls() -> None:
    config = _config(
        security={
            "mode": "audit",
            "tools": {"allowed": ["read_file"]},
            "scope": {"blocked_destinations": ["blocked.example"]},
        }
    )
    engine = Engine(config, registry=_registry())
    evaluation = engine.evaluate(
        _action(params={"destination": "blocked.example"})
    )

    pr02 = next(result for result in evaluation.control_results if result.control_id == "PR-02")
    rs02 = next(result for result in evaluation.control_results if result.control_id == "RS-02")
    assert pr02.result == "FAIL"
    assert rs02.result == "FAIL"
    assert "PR-02" in rs02.evidence_data["triggering_failures"]
