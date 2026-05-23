"""PR-01: Action Authorization evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.patterns import scan_parameters
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
        destination = _extract_destination(action)
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

        if destination and config.scope_blocked_destinations and destination in config.scope_blocked_destinations:
            evidence["target_authorized"] = False
            return _result(
                self,
                "FAIL",
                f"Action authorization failed: destination '{destination}' is blocked.",
                evidence,
                start,
            )

        if (
            destination
            and config.scope_allowed_destinations
            and destination not in config.scope_allowed_destinations
        ):
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


def _extract_destination(action: Action) -> str | None:
    for key in ("destination", "url", "endpoint", "host", "server"):
        value = action.parameters.raw.get(key)
        if isinstance(value, str):
            return value
    return getattr(action, "destination", None)
