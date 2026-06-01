from __future__ import annotations

from datetime import datetime, timezone
import uuid

from ancilis.config import load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.evaluators.pr09_sandbox import PR09SandboxEvaluator


def _config(*, approved: list[str] | None = None):
    raw = {"agent": {"name": "sandbox-agent"}}
    if approved is not None:
        raw["security"] = {
            "sandbox_policy": {
                "approved_execution_classes": approved,
            }
        }
    return load_config(raw=raw)


def _action(
    *,
    action_type: str = "code_execution",
    params: dict | None = None,
    metadata: dict | None = None,
    tool_name: str = "python.exec",
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id="sandbox-agent",
        action_type=action_type,
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw=params or {}, parameter_hash="params"),
        context=ActionContext(session_id="sandbox-tests"),
        metadata=metadata or {},
    )


def test_pr09_passes_approved_sandbox_from_metadata() -> None:
    result = PR09SandboxEvaluator().evaluate(
        _action(metadata={"sandbox_class": "firecracker"}),
        _config(approved=["firecracker"]),
    )

    assert result.result == "PASS"
    assert result.control_id == "PR-09"
    assert result.evidence_data["sandbox_class"] == "firecracker"


def test_pr09_fails_code_execution_without_sandbox() -> None:
    result = PR09SandboxEvaluator().evaluate(
        _action(),
        _config(approved=["firecracker"]),
    )

    assert result.result == "FAIL"
    assert "no sandbox" in result.detail.lower()


def test_pr09_fails_unapproved_sandbox() -> None:
    result = PR09SandboxEvaluator().evaluate(
        _action(metadata={"sandbox_class": "local"}),
        _config(approved=["firecracker"]),
    )

    assert result.result == "FAIL"
    assert result.evidence_data["approved_execution_classes"] == ["firecracker"]


def test_pr09_skips_non_code_action() -> None:
    result = PR09SandboxEvaluator().evaluate(
        _action(action_type="tool_call", tool_name="read_file"),
        _config(approved=["firecracker"]),
    )

    assert result.result == "SKIP"
    assert result.detail == "not a code execution action"


def test_pr09_fails_when_policy_missing_for_code_action() -> None:
    result = PR09SandboxEvaluator().evaluate(
        _action(metadata={"sandbox_class": "firecracker"}),
        _config(),
    )

    assert result.result == "FAIL"
    assert "no approved sandbox execution classes configured" in result.detail.lower()
