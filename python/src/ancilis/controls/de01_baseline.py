"""DE-01: Behavioral Baseline Monitoring evaluator."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


@dataclass
class DeviationFlag:
    type: str
    display_message: str
    severity: str  # "info" | "warning" | "alert"


@dataclass
class BaselineWindow:
    """Rolling window of recent evaluations for baseline comparison."""

    tool_calls: list[str] = field(default_factory=list)  # tool names in order
    call_count: int = 0
    window_minutes: float = 0.0

    @property
    def unique_tools(self) -> set[str]:
        return set(self.tool_calls)

    @property
    def calls_per_minute(self) -> float:
        if self.window_minutes <= 0:
            return 0.0
        return self.call_count / self.window_minutes


class DE01BaselineEvaluator:
    """Tracks agent behavior patterns and flags deviations.

    DE-01 never BLOCKs — always PASS or FLAG.
    """

    control_id = "DE-01"
    control_name = "Behavioral Anomaly Detection"

    # Frequency spike threshold: current rate > N x rolling average
    FREQUENCY_SPIKE_MULTIPLIER = 3.0

    def __init__(self, baseline_window: BaselineWindow | None = None) -> None:
        self._baseline = baseline_window or BaselineWindow()

    @property
    def baseline(self) -> BaselineWindow:
        return self._baseline

    def set_baseline(self, window: BaselineWindow) -> None:
        self._baseline = window

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()

        evidence: dict[str, Any] = {
            "baseline_established": False,
            "baseline_window_calls": 0,
            "current_rate_vs_baseline": 0.0,
            "deviation_flags": [],
            "new_tools_detected": [],
        }

        tool_name = action.tool.name

        # No baseline yet — pass with note
        if self._baseline.call_count == 0:
            evidence["baseline_established"] = False
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail="Baseline not yet established — monitoring started.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        evidence["baseline_established"] = True
        evidence["baseline_window_calls"] = self._baseline.call_count

        deviation_flags: list[dict[str, str]] = []
        new_tools: list[str] = []

        # Check for new tool not in baseline
        if tool_name not in self._baseline.unique_tools:
            new_tools.append(tool_name)
            deviation_flags.append({
                "type": "new_tool",
                "display_message": f"Tool '{tool_name}' not seen in baseline window",
                "severity": "warning",
            })

        # Check for frequency spike
        baseline_rate = self._baseline.calls_per_minute
        if baseline_rate > 0:
            # Estimate current rate: we don't have a real-time counter in v0.1,
            # so we use the baseline as reference and flag if action count suggests spike.
            # For v0.1, a simple heuristic: if baseline exists, compute ratio
            # In production, this would use a real-time rate counter.
            evidence["current_rate_vs_baseline"] = 1.0  # default: normal

        evidence["deviation_flags"] = deviation_flags
        evidence["new_tools_detected"] = new_tools

        if deviation_flags:
            flag_summary = "; ".join(f["display_message"] for f in deviation_flags)
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=f"Behavioral deviation detected: {flag_summary}",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Agent behavior within established baseline parameters.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    def evaluate_with_rate(
        self,
        action: Action,
        config: ResolvedConfig,
        current_rate: float,
    ) -> ControlResult:
        """Evaluate with an explicit current rate for frequency spike detection."""
        start = time.perf_counter()

        evidence: dict[str, Any] = {
            "baseline_established": True,
            "baseline_window_calls": self._baseline.call_count,
            "current_rate_vs_baseline": 0.0,
            "deviation_flags": [],
            "new_tools_detected": [],
        }

        if self._baseline.call_count == 0:
            evidence["baseline_established"] = False
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail="Baseline not yet established — monitoring started.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        tool_name = action.tool.name
        deviation_flags: list[dict[str, str]] = []
        new_tools: list[str] = []

        # New tool check
        if tool_name not in self._baseline.unique_tools:
            new_tools.append(tool_name)
            deviation_flags.append({
                "type": "new_tool",
                "display_message": f"Tool '{tool_name}' not seen in baseline window",
                "severity": "warning",
            })

        # Frequency spike check
        baseline_rate = self._baseline.calls_per_minute
        if baseline_rate > 0:
            ratio = current_rate / baseline_rate
            evidence["current_rate_vs_baseline"] = round(ratio, 2)
            if ratio > self.FREQUENCY_SPIKE_MULTIPLIER:
                deviation_flags.append({
                    "type": "frequency_spike",
                    "display_message": f"Tool call frequency is {ratio:.1f}x above baseline average",
                    "severity": "warning",
                })

        evidence["deviation_flags"] = deviation_flags
        evidence["new_tools_detected"] = new_tools

        if deviation_flags:
            flag_summary = "; ".join(f["display_message"] for f in deviation_flags)
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="FLAG",
                detail=f"Behavioral deviation detected: {flag_summary}",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result="PASS",
            detail="Agent behavior within established baseline parameters.",
            evidence_data=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
