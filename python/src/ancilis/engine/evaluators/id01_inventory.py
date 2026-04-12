"""ID-01: Agent Inventory & Registry evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class ID01InventoryEvaluator:
    """Validates that the agent is registered in the organizational inventory.

    Checks config.agent_name and config.agent_id. Both set → registered (PASS).
    Name set but no ID → partial documentation (FLAG).
    Neither set → unregistered (FAIL).
    """

    control_id = "ID-01"
    control_name = "Agent Inventory & Registry"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        agent_name = (getattr(config, "agent_name", None) or "").strip()
        agent_id = (getattr(config, "agent_id", None) or "").strip() if getattr(config, "agent_id", None) else ""

        has_name = bool(agent_name)
        has_id = bool(agent_id)

        evidence: dict[str, Any] = {
            "inventory_status": "unregistered",
            "fields": {
                "name": agent_name or None,
                "id": agent_id or None,
            },
        }

        if has_name and has_id:
            evidence["inventory_status"] = "registered"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=f"Agent registered in inventory: name='{agent_name}', id='{agent_id}'.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if has_name and not has_id:
            evidence["inventory_status"] = "partial"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=(
                    f"Agent '{agent_name}' has a name but no agent_id. "
                    "Add agent.agent_id in ancilis.yaml for complete inventory registration."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FAIL",
            detail="Agent is not registered. Set agent.name and agent.agent_id in ancilis.yaml.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
