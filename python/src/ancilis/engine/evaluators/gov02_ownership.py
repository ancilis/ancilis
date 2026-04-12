"""GOV-02: Agent Ownership & Accountability evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult

# Values that indicate an unset or placeholder owner
_PLACEHOLDER_VALUES = {"todo", "unknown", "changeme", "tbd", "n/a", "none", "placeholder", "example"}


class GOV02OwnershipEvaluator:
    """Validates that the agent has a designated human owner.

    Checks config.agent_owner. Flags placeholder values that indicate the
    field was not properly configured.
    """

    control_id = "GOV-02"
    control_name = "Agent Ownership & Accountability"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        owner_value = getattr(config, "agent_owner", None) or ""
        owner_value = owner_value.strip()

        evidence: dict[str, Any] = {
            "owner_declared": False,
            "owner_value": owner_value or None,
            "source_field": "agent.owner",
        }

        if not owner_value:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="No agent owner configured. Add agent.owner in ancilis.yaml.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence["owner_declared"] = True

        if owner_value.lower() in _PLACEHOLDER_VALUES:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=(
                    f"Agent owner appears to be a placeholder value: '{owner_value}'. "
                    "Replace with a contactable individual."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail=f"Agent owner declared: '{owner_value}'.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
