"""DE-02: Classification Drift and Boundary Validation evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.patterns import scan_parameters
from ancilis.engine.result import ControlResult

PATTERN_TO_DC: dict[str, str] = {
    "ssn": "DC-PII",
    "email": "DC-PII",
    "phone": "DC-PII",
    "credit_card": "DC-CHD",
    "mrn": "DC-PHI",
    "api_key": "DC-IP",
}

COMPATIBLE_DECLARATIONS: dict[str, set[str]] = {
    "DC-PII": {"DC-PHI"},
}


class DE02ClassificationDriftEvaluator:
    control_id = "DE-02"
    control_name = "Classification Drift and Boundary Validation"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        declared = _declared_data_classes(config)
        observed = _observed_data_classes(action)
        undeclared = sorted(observed - declared)
        compatible = sorted(
            code
            for code in undeclared
            if COMPATIBLE_DECLARATIONS.get(code, set()).intersection(declared)
        )
        incompatible = [code for code in undeclared if code not in compatible]
        destination = _extract_destination(action)
        boundary_violation = _boundary_violation(destination, config)

        evidence: dict[str, Any] = {
            "declared_data_classes": sorted(declared),
            "observed_data_classes": sorted(observed),
            "undeclared_data_classes": incompatible,
            "compatible_data_classes": compatible,
            "destination": destination,
            "boundary_violation": boundary_violation,
        }

        duration_ms = (time.perf_counter() - start) * 1000

        if boundary_violation:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Observed processing boundary violation: {boundary_violation}.",
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        if incompatible:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=(
                    "Classification drift detected: observed undeclared data classes "
                    f"{', '.join(incompatible)}."
                ),
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        if compatible:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=(
                    "Compatible classification expansion observed: "
                    f"{', '.join(compatible)} is implied by declared classes."
                ),
                evidence_data=evidence,
                duration_ms=duration_ms,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Observed classifications are within declared processing boundaries.",
            evidence_data=evidence,
            duration_ms=duration_ms,
        )


def _declared_data_classes(config: ResolvedConfig) -> set[str]:
    declared: set[str] = set()
    for codes in config.data_classifications.values():
        declared.update(codes)
    return declared


def _observed_data_classes(action: Action) -> set[str]:
    observed: set[str] = set()
    for code in getattr(action, "detected_data_types", []) or []:
        observed.add(str(code))
    for code in getattr(action.context, "data_classifications", []) or []:
        observed.add(str(code))
    for match in scan_parameters(action.parameters.raw):
        dc_code = PATTERN_TO_DC.get(match.pattern_type)
        if dc_code:
            observed.add(dc_code)
    return observed


def _extract_destination(action: Action) -> str | None:
    for key in ("destination", "url", "endpoint", "host", "server"):
        value = action.parameters.raw.get(key)
        if isinstance(value, str):
            return value
    return getattr(action, "destination", None)


def _boundary_violation(destination: str | None, config: ResolvedConfig) -> str | None:
    if not destination:
        return None
    if destination in config.scope_blocked_destinations:
        return f"destination '{destination}' is blocked"
    if config.scope_allowed_destinations and destination not in config.scope_allowed_destinations:
        return f"destination '{destination}' is outside allowed destinations"
    return None
