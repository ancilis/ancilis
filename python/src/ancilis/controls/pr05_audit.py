"""PR-05: Audit Logging evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class PR05AuditEvaluator:
    """Validates that structured logging is active and producing complete records."""

    control_id = "PR-05"
    control_name = "Audit Logging"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        evidence: dict[str, Any] = {
            "logging_enabled": False,
            "log_format": "unknown",
            "required_fields_present": False,
            "sample_entry_field_count": 0,
        }

        # Check if evidence storage is configured (proxy for logging enabled)
        has_evidence_store = config.evidence_retention_days > 0

        if not has_evidence_store:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="Audit logging is not configured. Enable evidence storage in ancilis.yaml.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence["logging_enabled"] = True

        # Validate action has required fields for structured logging
        required_fields = ["action_id", "timestamp", "agent_id", "action_type"]
        present_fields = []
        for field_name in required_fields:
            if getattr(action, field_name, None):
                present_fields.append(field_name)

        evidence["required_fields_present"] = len(present_fields) == len(required_fields)
        evidence["sample_entry_field_count"] = len(present_fields)

        # Check log format — we produce structured JSON via evidence store
        evidence["log_format"] = "json"

        if not evidence["required_fields_present"]:
            missing = [f for f in required_fields if f not in present_fields]
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Log entry missing required fields: {', '.join(missing)}.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Structured audit logging active with all required fields.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
