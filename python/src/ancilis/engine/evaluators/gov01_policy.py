"""GOV-01: Governance Policy evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class GOV01PolicyEvaluator:
    control_id = "GOV-01"
    control_name = "Governance Policy"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        fields_present: list[str] = []
        fields_missing: list[str] = []

        # 1. agent_name must be set (non-empty)
        if config.agent_name and config.agent_name.strip():
            fields_present.append("agent_name")
        else:
            fields_missing.append("agent_name")

        # 2. mode must be explicitly set
        if config.mode and config.mode.strip():
            fields_present.append("mode")
        else:
            fields_missing.append("mode")

        # 3. data_classifications must have at least one entry
        if config.data_classifications:
            fields_present.append("data_classifications")
        else:
            fields_missing.append("data_classifications")

        # 4. scope constraints — tools_allowed or tools_blocked must be set
        has_scope = bool(config.tools_allowed or config.tools_blocked)
        if has_scope:
            fields_present.append("scope_constraints")
        else:
            fields_missing.append("scope_constraints")

        total = len(fields_present) + len(fields_missing)
        present_count = len(fields_present)

        if present_count == total:
            completeness = "complete"
        elif present_count >= 2:
            completeness = "partial"
        else:
            completeness = "insufficient"

        evidence: dict[str, Any] = {
            "policy_completeness": completeness,
            "fields_present": fields_present,
            "fields_missing": fields_missing,
        }

        duration_ms = (time.perf_counter() - start) * 1000

        if completeness == "complete":
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail="Complete governance policy: all required fields are configured.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        if completeness == "partial":
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=f"Partial governance policy: missing {', '.join(fields_missing)}.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FAIL",
            detail=f"Insufficient governance policy: {len(fields_missing)} of {total} required fields are missing.",
            evidence_data=evidence,
            duration_ms=duration_ms,
        )
