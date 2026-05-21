"""PR-06: Audit Trail Completeness evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class PR06AuditTrailEvaluator:
    """Validates that action evidence can reconstruct the evaluation chain."""

    control_id = "PR-06"
    control_name = "Audit Trail Completeness"

    def evaluate(
        self,
        action: Action,
        config: ResolvedConfig,
        *,
        prior_results: list[ControlResult] | None = None,
        evidence_store: object | None = None,
    ) -> ControlResult:
        start = time.perf_counter()

        required_fields = ["action_id", "timestamp", "agent_id", "action_type"]
        present_fields = [field_name for field_name in required_fields if getattr(action, field_name, None)]
        missing_fields = [field_name for field_name in required_fields if field_name not in present_fields]
        evaluation_chain = [
            (result.control_id, result.result, bool(result.detail))
            for result in (prior_results or [])
            if result.control_id != self.control_id
        ]
        incomplete_chain = [
            control_id
            for control_id, result, detail_present in evaluation_chain
            if not control_id or not result or not detail_present
        ]
        evidence_store_configured = evidence_store is not None

        evidence: dict[str, Any] = {
            "logging_enabled": config.evidence_retention_days > 0,
            "log_format": "json",
            "required_fields_present": not missing_fields,
            "required_fields": required_fields,
            "missing_fields": missing_fields,
            "sample_entry_field_count": len(present_fields),
            "control_results_present": bool(evaluation_chain),
            "evaluation_chain_control_ids": [
                control_id for control_id, _result, _detail_present in evaluation_chain
            ],
            "incomplete_chain_control_ids": incomplete_chain,
            "evidence_store_configured": evidence_store_configured,
            "evidence_write_before_completion": evidence_store_configured,
        }

        if not evidence["logging_enabled"]:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="Audit logging is not configured. Enable evidence storage in ancilis.yaml.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if missing_fields:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Audit trail missing action fields: {', '.join(missing_fields)}.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if not evidence["control_results_present"]:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail="Audit trail missing control evaluation results.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if incomplete_chain:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Audit trail has incomplete control results: {', '.join(incomplete_chain)}.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if not evidence_store_configured:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=(
                    "Audit trail has structured evaluation data, but no evidence store "
                    "was attached to verify pre-completion persistence."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Audit trail complete: action identity, control results, and evidence store path are present.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
