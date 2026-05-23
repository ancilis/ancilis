"""PR-09: Controlled Code Execution and Sandbox Enforcement evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


CODE_ACTION_TYPES = {
    "code_execution",
    "shell_command",
    "container_exec",
    "dynamic_eval",
    "code_interpreter",
}
CODE_TOOL_MARKERS = ("shell", "exec", "eval", "python", "node", "bash", "container")
SANDBOX_KEYS = ("sandbox_class", "execution_class", "sandbox")


class PR09SandboxEvaluator:
    control_id = "PR-09"
    control_name = "Controlled Code Execution and Sandbox Enforcement"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        is_code_action = _is_code_execution_action(action)
        sandbox_class = _sandbox_class(action)
        approved = list(getattr(config, "sandbox_approved_execution_classes", []) or [])
        evidence: dict[str, Any] = {
            "is_code_execution_action": is_code_action,
            "action_type": action.action_type,
            "tool_name": action.tool.name if action.tool else None,
            "sandbox_class": sandbox_class,
            "approved_execution_classes": approved,
        }

        if not is_code_action:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail="not a code execution action",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if not approved:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="No approved sandbox execution classes configured for code execution actions.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if not sandbox_class:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="Code execution action has no sandbox execution class declared.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if sandbox_class not in approved:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Sandbox execution class '{sandbox_class}' is not approved.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail=f"Code execution action uses approved sandbox class '{sandbox_class}'.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def _is_code_execution_action(action: Action) -> bool:
    if action.action_type in CODE_ACTION_TYPES:
        return True
    tool_name = (action.tool.name if action.tool else "").lower()
    if any(marker in tool_name for marker in CODE_TOOL_MARKERS):
        return True
    return any(key in action.parameters.raw for key in ("code", "script"))


def _sandbox_class(action: Action) -> str | None:
    for source in (action.metadata, action.parameters.raw):
        for key in SANDBOX_KEYS:
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None
