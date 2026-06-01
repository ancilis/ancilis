"""GOV-01: Agent Identity and Authentication evaluator."""

from __future__ import annotations

import time

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class GOV01IdentityAuthEvaluator:
    control_id = "GOV-01"
    control_name = "Agent Identity and Authentication"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        if not action.agent_id:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="Agent identity missing.",
                evidence_data={
                    "agent_id": None,
                    "agent_owner": action.agent_owner,
                    "verification_result": "failed",
                    "failure_reason": "agent_id is empty or missing",
                },
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        expected_agent_id = config.agent_id or config.agent_name
        allowed_agent_ids = {config.agent_name}
        if config.agent_id:
            allowed_agent_ids.add(config.agent_id)
        if action.agent_id not in allowed_agent_ids:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=(
                    f"Agent identity mismatch: '{action.agent_id}' is not one of "
                    f"configured identities {sorted(allowed_agent_ids)}."
                ),
                evidence_data={
                    "agent_id": action.agent_id,
                    "expected_agent_id": expected_agent_id,
                    "allowed_agent_ids": sorted(allowed_agent_ids),
                    "agent_owner": action.agent_owner,
                    "verification_result": "failed",
                    "failure_reason": "agent_id does not match configured agent identity",
                },
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if config.agent_owner and action.agent_owner is not None and action.agent_owner != config.agent_owner:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Agent owner mismatch: '{action.agent_owner}' does not match configured '{config.agent_owner}'.",
                evidence_data={
                    "agent_id": action.agent_id,
                    "agent_owner": action.agent_owner,
                    "verification_result": "failed",
                    "failure_reason": "agent_owner does not match configured owner",
                },
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Agent identity verified.",
            evidence_data={
                "agent_id": action.agent_id,
                "expected_agent_id": expected_agent_id,
                "allowed_agent_ids": sorted(allowed_agent_ids),
                "agent_owner": action.agent_owner,
                "verification_result": "verified",
            },
            duration_ms=(time.perf_counter() - start) * 1000,
        )
