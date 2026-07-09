"""PR-04: Data Exposure Prevention evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.patterns import extract_destination, scan_parameters
from ancilis.engine.result import ControlResult


class PR04ExposureEvaluator:
    control_id = "PR-04"
    control_name = "Data Exposure Prevention"

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        evidence: dict[str, Any] = {
            "scan_result": "clean",
            "patterns_detected": [],
            "destination": None,
            "destination_authorized": True,
        }

        # Scan parameters for sensitive patterns
        matches = scan_parameters(action.parameters.raw)

        if not matches:
            evidence["scan_result"] = "clean"
            detail = "No sensitive data detected in outbound parameters."
            if not config.data_classifications:
                detail += " No data classifications declared."
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=detail,
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Patterns found
        evidence["scan_result"] = "patterns_found"
        evidence["patterns_detected"] = [
            {"type": m.pattern_type, "count": m.count, "redacted_sample": m.redacted_sample}
            for m in matches
        ]

        # Check destination
        destination = self._extract_destination(action)
        evidence["destination"] = destination

        if destination and config.scope_blocked_destinations and destination in config.scope_blocked_destinations:
            evidence["destination_authorized"] = False
            evidence["scan_result"] = "blocked"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Sensitive data detected going to blocked destination '{destination}'.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if destination and config.scope_allowed_destinations and destination not in config.scope_allowed_destinations:
            evidence["destination_authorized"] = False
            evidence["scan_result"] = "blocked"
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FAIL",
                detail=f"Sensitive data detected going to unauthorized destination '{destination}'.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Patterns found and no FAIL above. Sensitive data only PASSES PR-04 when
        # it is going to a destination that a configured policy actually
        # authorized. Every other case (no policy, or no determinable
        # destination) is a FLAG — never a silent PASS that green-lights
        # potential exfiltration. (FLAG does not BLOCK — blocking requires a
        # configured policy and a matched destination — but it can never report
        # as "all passing".)
        pattern_types = ", ".join(m.pattern_type for m in matches)
        has_destination_policy = bool(
            config.scope_allowed_destinations or config.scope_blocked_destinations
        )
        if destination is not None and has_destination_policy:
            # Destination was present and cleared the blocked/allowed checks above.
            evidence["destination_authorized"] = True
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=(
                    f"Sensitive data patterns detected ({pattern_types}); "
                    f"destination '{destination}' authorized by configured scope policy."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence["destination_authorized"] = False
        if not has_destination_policy:
            detail = (
                f"Sensitive data patterns detected ({pattern_types}) but no destination "
                "restrictions are configured. Add scope.allowed_destinations or "
                "scope.blocked_destinations so outbound destinations can be authorized."
            )
        else:
            detail = (
                f"Sensitive data patterns detected ({pattern_types}) but no outbound "
                "destination could be determined to verify against the configured scope policy."
            )
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="FLAG",
            detail=detail,
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    def _extract_destination(self, action: Action) -> str | None:
        return extract_destination(action.parameters.raw)
