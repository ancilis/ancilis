"""RS-02: Containment, Quarantine and Kill Switch evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


CONTAINMENT_KEYS = (
    "containment_intent",
    "kill_switch",
    "quarantine",
    "degrade",
    "block",
    "revoke_credentials",
)


class RS02ContainmentEvaluator:
    control_id = "RS-02"
    control_name = "Containment, Quarantine and Kill Switch"

    def evaluate(
        self,
        action: Action,
        config: ResolvedConfig,
        *,
        prior_results: list[ControlResult] | None = None,
        evidence_store: object | None = None,
    ) -> ControlResult:
        start = time.perf_counter()
        required_statuses = set(
            getattr(config, "response_containment_required_for_results", None)
            or ["FAIL", "ERROR"]
        )
        triggering = [
            result
            for result in (prior_results or [])
            if result.result.upper() in required_statuses
        ]
        containment_intent = _containment_intent(action)
        evidence: dict[str, Any] = {
            "required_result_threshold": sorted(required_statuses),
            "triggering_failures": [result.control_id for result in triggering],
            "containment_intent": containment_intent,
            "evidence_store_configured": evidence_store is not None,
        }

        if triggering and not containment_intent:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=(
                    "Containment required because prior controls failed, but no "
                    "containment, quarantine, kill-switch, degrade, block, or "
                    "credential revocation intent was declared."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if triggering:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=f"Containment intent '{containment_intent}' declared for failing controls.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="No prior control failures require containment.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def _containment_intent(action: Action) -> str | None:
    for key in CONTAINMENT_KEYS:
        value = action.metadata.get(key)
        if key == "containment_intent" and isinstance(value, str) and value.strip():
            return value.strip()
        if key != "containment_intent" and value is True:
            return key
    containment = action.parameters.raw.get("containment_intent")
    if isinstance(containment, str) and containment.strip():
        return containment.strip()
    return None
