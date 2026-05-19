"""PR-05: Context and Tenant Isolation evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


CONTEXT_KEYS = ("tenant_id", "user_id", "session_id", "jurisdiction")


class PR05IsolationEvaluator:
    control_id = "PR-05"
    control_name = "Context and Tenant Isolation"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        context_values = {
            key: getattr(action.context, key, None)
            for key in CONTEXT_KEYS
            if getattr(action.context, key, None) is not None
        }
        references = _extract_reference_values(action.parameters.raw)
        leaks: dict[str, dict[str, str]] = {}
        for key, expected in context_values.items():
            observed = references.get(key)
            if observed is not None and str(observed) != str(expected):
                leaks[key] = {"context": str(expected), "referenced": str(observed)}

        evidence: dict[str, Any] = {
            "context_values": context_values,
            "referenced_context_values": references,
            "cross_context_references": leaks,
            "missing_context_fields": [
                key for key in CONTEXT_KEYS if getattr(action.context, key, None) is None
            ],
        }

        if leaks:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=(
                    "Context isolation violation: action references a different "
                    f"{', '.join(sorted(leaks))}."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if not context_values:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail="Context isolation cannot verify tenant/user/session boundaries; context fields are missing.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Context is isolated; no cross-context references detected.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def _extract_reference_values(params: dict[str, Any]) -> dict[str, str]:
    references: dict[str, str] = {}
    for key in CONTEXT_KEYS:
        value = params.get(key)
        if isinstance(value, str):
            references[key] = value
    return references
