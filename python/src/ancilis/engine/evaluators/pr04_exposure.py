"""PR-04: Data Exposure Prevention evaluator."""

from __future__ import annotations

import time
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.patterns import scan_parameters
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

        if destination and config.scope_blocked_destinations:
            if destination in config.scope_blocked_destinations:
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

        if destination and config.scope_allowed_destinations:
            if destination not in config.scope_allowed_destinations:
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

        # Patterns found but no destination restrictions — PASS with evidence
        pattern_types = ", ".join(m.pattern_type for m in matches)
        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail=f"Sensitive data patterns detected ({pattern_types}) but no destination restrictions configured.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    def _extract_destination(self, action: Action) -> str | None:
        raw = action.parameters.raw
        for key in ("url", "destination", "endpoint", "host", "server"):
            if key in raw:
                val = raw[key]
                if isinstance(val, str):
                    return val
        return None
