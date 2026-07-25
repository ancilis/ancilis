"""PR-02: Permission Scope Enforcement evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.engine.patterns import extract_destinations
from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class RateTracker:
    """Interface for rate tracking. Middleware provides the implementation."""

    def get_action_count(self, agent_id: str) -> int:
        return 0


class PR02ScopeEvaluator:
    control_id = "PR-02"
    control_name = "Permission Scope Enforcement"

    def __init__(self, rate_tracker: RateTracker | None = None) -> None:
        self.rate_tracker = rate_tracker or RateTracker()

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        tool_name = action.tool.name

        evidence: dict[str, Any] = {
            "tool_name": tool_name,
            "allowed_tools": config.tools_allowed,
            "blocked_tools": config.tools_blocked,
        }

        # Check blocked list first (takes precedence)
        if config.tools_blocked and self._matches_tool_list(tool_name, config.tools_blocked):
            evidence["scope_check"] = "out_of_scope"
            evidence["failure_reason"] = "tool is explicitly blocked"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Tool '{tool_name}' is explicitly blocked.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Check allowed list
        if config.tools_allowed and not self._matches_tool_list(tool_name, config.tools_allowed):
            evidence["scope_check"] = "out_of_scope"
            evidence["failure_reason"] = "tool not in allowlist"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Tool '{tool_name}' is not in the allowlist.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Check blocked destinations — any candidate anywhere in the
        # parameters counts; enforcing only the first found lets a second
        # destination-like key smuggle a blocked value through.
        if config.scope_blocked_destinations:
            destinations = extract_destinations(action.parameters.raw)
            blocked = [d for d in destinations if d in config.scope_blocked_destinations]
            destination = blocked[0] if blocked else None
            if destination:
                evidence["scope_check"] = "out_of_scope"
                evidence["failure_reason"] = "destination is blocked"
                evidence["destination"] = destination
                evidence["destinations"] = destinations
                return ControlResult(
                    control_id=self.control_id,
                    control_name=self.control_name,
                    result="FAIL",
                    detail=f"Destination '{destination}' is blocked.",
                    evidence_data=evidence,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        # Check rate limit
        if config.scope_max_actions_per_minute is not None:
            count = self.rate_tracker.get_action_count(action.agent_id)
            if count >= config.scope_max_actions_per_minute:
                evidence["scope_check"] = "out_of_scope"
                evidence["failure_reason"] = "rate limit exceeded"
                return ControlResult(
                    control_id=self.control_id,
                    control_name=self.control_name,
                    result="FAIL",
                    detail="Rate limit exceeded.",
                    evidence_data=evidence,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        evidence["scope_check"] = "within_scope"
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Action within declared permission scope.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    @staticmethod
    def _matches_tool_list(tool_name: str, tool_list: list[str]) -> bool:
        """Check if tool matches a list, accounting for producer prefixes.

        Handles: bare 'echo' in config matching 'cli:echo' action,
        and 'cli:echo' in config matching 'cli:echo' action.
        """
        if tool_name in tool_list:
            return True
        # Strip prefix and check bare name (cli:echo -> echo)
        if ":" in tool_name:
            bare_name = tool_name.split(":", 1)[1]
            if bare_name in tool_list:
                return True
        return False


