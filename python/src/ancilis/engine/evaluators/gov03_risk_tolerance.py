"""GOV-03: Risk Tolerance Definition evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class GOV03RiskToleranceEvaluator:
    """Validates that risk tolerance parameters are defined in machine-readable format.

    Checks ResolvedConfig for the presence of risk-relevant configuration:
    - security.mode must be explicitly set
    - data_classifications must be non-empty (data assets known)
    - scope constraints must be defined (tools_allowed or tools_blocked, or
      scope limits configured)

    A complete risk tolerance posture requires all three. Partial configuration
    produces a FLAG; absent configuration produces a FAIL.
    """

    control_id = "GOV-03"
    control_name = "Risk Tolerance Definition"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        criteria_met: list[str] = []
        criteria_missing: list[str] = []

        # 1. security.mode must be explicitly set (non-empty)
        if config.mode and config.mode.strip():
            criteria_met.append("security_mode")
        else:
            criteria_missing.append("security_mode")

        # 2. data_classifications must be non-empty
        if config.data_classifications:
            criteria_met.append("data_classifications")
        else:
            criteria_missing.append("data_classifications")

        # 3. scope constraints defined: tools_allowed, tools_blocked, or rate limit
        has_scope = bool(
            config.tools_allowed
            or config.tools_blocked
            or config.scope_max_actions_per_minute is not None
            or config.scope_allowed_destinations
            or config.scope_blocked_destinations
        )
        if has_scope:
            criteria_met.append("scope_constraints")
        else:
            criteria_missing.append("scope_constraints")

        total = len(criteria_met) + len(criteria_missing)
        met_count = len(criteria_met)

        evidence: dict[str, Any] = {
            "criteria_met": criteria_met,
            "criteria_missing": criteria_missing,
            "security_mode": config.mode or None,
            "has_data_classifications": bool(config.data_classifications),
            "has_scope_constraints": has_scope,
        }

        if met_count == total:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=(
                    f"Risk tolerance fully defined: mode='{config.mode}', "
                    f"data classifications configured, scope constraints present."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if met_count >= 1:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=(
                    f"Risk tolerance partially defined — missing: {', '.join(criteria_missing)}. "
                    "Configure the missing fields in ancilis.yaml to fully express risk appetite."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FAIL",
            detail=(
                "Risk tolerance not defined. "
                "Configure security.mode, my_agent_handles, and scope constraints in ancilis.yaml."
            ),
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
