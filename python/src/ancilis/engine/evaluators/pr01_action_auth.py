"""PR-01: Action Authorization evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.patterns import extract_destinations, scan_parameters
from ancilis.engine.result import ControlResult


SENSITIVE_ACTION_TYPES = {
    "api_request",
    "data_access",
    "payment",
    "write",
    "delete",
    "code_execution",
    "shell_command",
}


class PR01ActionAuthorizationEvaluator:
    control_id = "PR-01"
    control_name = "Action Authorization"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        sensitive_reasons = _sensitivity_reasons(action, config)
        destinations = _extract_destinations(action)
        destination = destinations[0] if destinations else None
        expected_identity = config.agent_id or config.agent_name
        allowed_identities = {config.agent_name}
        if config.agent_id:
            allowed_identities.add(config.agent_id)

        evidence: dict[str, Any] = {
            "sensitive": bool(sensitive_reasons),
            "sensitive_reasons": sensitive_reasons,
            "agent_id": action.agent_id,
            "expected_agent_id": expected_identity,
            "allowed_agent_ids": sorted(allowed_identities),
            "identity_authorized": action.agent_id in allowed_identities,
            "action_type": action.action_type,
            "destination": destination,
            "target_authorized": True,
            "policy_gate_satisfied": bool(config.mode),
        }

        if not action.agent_id:
            evidence["identity_authorized"] = False
            return _result(
                self,
                "FAIL",
                "Action authorization failed: agent identity is missing.",
                evidence,
                start,
            )

        if not evidence["identity_authorized"]:
            return _result(
                self,
                "FAIL",
                (
                    "Action authorization failed: agent identity "
                    f"'{action.agent_id}' is not in configured identities "
                    f"{sorted(allowed_identities)}."
                ),
                evidence,
                start,
            )

        blocked_hits = [
            d for d in destinations
            if config.scope_blocked_destinations and d in config.scope_blocked_destinations
        ]
        if blocked_hits:
            destination = blocked_hits[0]
            evidence["destination"] = destination
            evidence["target_authorized"] = False
            return _result(
                self,
                "FAIL",
                f"Action authorization failed: destination '{destination}' is blocked.",
                evidence,
                start,
            )

        unlisted = [
            d for d in destinations
            if config.scope_allowed_destinations and d not in config.scope_allowed_destinations
        ]
        if unlisted:
            destination = unlisted[0]
            evidence["destination"] = destination
            evidence["target_authorized"] = False
            return _result(
                self,
                "FAIL",
                f"Action authorization failed: destination '{destination}' is not allowed.",
                evidence,
                start,
            )

        if sensitive_reasons and not evidence["policy_gate_satisfied"]:
            return _result(
                self,
                "FAIL",
                "Action authorization failed: sensitive action has no policy mode configured.",
                evidence,
                start,
            )

        return _result(
            self,
            "PASS",
            "Action authorized for identity, context, and target.",
            evidence,
            start,
        )


def _result(
    evaluator: PR01ActionAuthorizationEvaluator,
    status: str,
    detail: str,
    evidence: dict[str, Any],
    start: float,
) -> ControlResult:
    return ControlResult(
        control_id=evaluator.control_id,
        control_name=evaluator.control_name,
        result=status,
        detail=detail,
        evidence_data=evidence,
        duration_ms=(time.perf_counter() - start) * 1000,
    )


def _sensitivity_reasons(action: Action, config: ResolvedConfig) -> list[str]:
    reasons: list[str] = []
    if action.action_type in SENSITIVE_ACTION_TYPES:
        reasons.append(f"action_type:{action.action_type}")
    if getattr(action.context, "active_overlays", None) or config.active_overlays:
        reasons.append("overlay_active")
    if getattr(action, "detected_data_types", None) or getattr(action.context, "data_classifications", None):
        reasons.append("classification_context")
    if scan_parameters(action.parameters.raw):
        reasons.append("sensitive_parameter_pattern")
    return sorted(set(reasons))


def _extract_destinations(action: Action) -> list[str]:
    found = extract_destinations(action.parameters.raw)
    if found:
        return found
    fallback = getattr(action, "destination", None)
    return [fallback] if isinstance(fallback, str) else []
