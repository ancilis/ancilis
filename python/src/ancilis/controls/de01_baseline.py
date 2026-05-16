"""DE-01: Behavioral Baseline Monitoring evaluator."""

from __future__ import annotations

import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ancilis.config import ResolvedConfig

if TYPE_CHECKING:
    from ancilis.engine.action import Action
    from ancilis.engine.result import ControlResult


BASELINE_MIN_EVENTS = 25
MAX_WINDOW_OBSERVATIONS = 1000


@dataclass
class DeviationFlag:
    type: str
    display_message: str
    severity: str  # "info" | "warning" | "alert"


@dataclass
class BehaviorObservation:
    tool_name: str
    parameter_hash: str
    timestamp: str


@dataclass
class BaselineWindow:
    """Rolling window of recent evaluations for baseline comparison."""

    tool_calls: list[str] = field(default_factory=list)  # tool names in order
    call_count: int = 0
    window_minutes: float = 0.0
    observations: list[BehaviorObservation] = field(default_factory=list)
    max_observations: int = MAX_WINDOW_OBSERVATIONS

    @property
    def event_count(self) -> int:
        return max(self.call_count, len(self.tool_calls), len(self.observations))

    @property
    def unique_tools(self) -> set[str]:
        if self.tool_calls:
            return set(self.tool_calls)
        return {observation.tool_name for observation in self.observations}

    @property
    def ordered_unique_tools(self) -> list[str]:
        return sorted(self.unique_tools)

    @property
    def calls_per_minute(self) -> float:
        if self.window_minutes <= 0:
            return 0.0
        return self.event_count / self.window_minutes

    def append(self, tool_name: str, parameter_hash: str, timestamp: str) -> None:
        self.observations.append(
            BehaviorObservation(
                tool_name=tool_name,
                parameter_hash=parameter_hash,
                timestamp=timestamp,
            )
        )
        self.tool_calls.append(tool_name)

        if len(self.observations) > self.max_observations:
            overflow = len(self.observations) - self.max_observations
            del self.observations[:overflow]
        if len(self.tool_calls) > self.max_observations:
            overflow = len(self.tool_calls) - self.max_observations
            del self.tool_calls[:overflow]

        self.call_count = min(
            max(self.call_count + 1, len(self.tool_calls), len(self.observations)),
            self.max_observations,
        )
        self.window_minutes = self._compute_window_minutes()

    def _compute_window_minutes(self) -> float:
        timestamps = [
            self._parse_timestamp(observation.timestamp)
            for observation in self.observations
            if observation.timestamp
        ]
        if len(timestamps) < 2:
            return self.window_minutes

        start = min(timestamps)
        end = max(timestamps)
        elapsed_seconds = max((end - start).total_seconds(), 0.0)
        if elapsed_seconds == 0:
            return self.window_minutes
        return elapsed_seconds / 60.0

    @staticmethod
    def _parse_timestamp(timestamp: str) -> datetime:
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        return datetime.fromisoformat(timestamp)


class DE01BaselineEvaluator:
    """Tracks agent behavior patterns and flags deviations.

    DE-01 never BLOCKs — always PASS or FLAG.
    """

    control_id = "DE-01"
    control_name = "Behavioral Anomaly Detection"
    behavior_schema_version = 1

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
        from ancilis.engine.result import ControlResult

        tool_name = action.tool.name
        parameter_hash = action.parameters.parameter_hash or ""
        prior_count = self._baseline.event_count
        baseline_established = prior_count >= BASELINE_MIN_EVENTS

        evidence = self._base_evidence(
            tool_name=tool_name,
            parameter_hash=parameter_hash,
            prior_count=prior_count,
            prior_unique_tools=self._baseline.unique_tools,
            baseline_established=baseline_established,
            observation_type=action.action_type,
        )

        if action.action_type != "tool_call" or not tool_name:
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail="Behavioral baseline monitoring currently applies to tool-call actions only.",
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        result = "PASS"
        if not baseline_established:
            warmed_count = min(prior_count + 1, BASELINE_MIN_EVENTS)
            detail = (
                "Baseline not yet established — warming behavioral window "
                f"({warmed_count}/{BASELINE_MIN_EVENTS})."
            )
        else:
            new_tools = self._new_tools_detected(tool_name, self._baseline.unique_tools)
            evidence["new_tools_detected"] = new_tools
            if new_tools:
                evidence["deviation_flags"] = [self._new_tool_flag(new_tools[0])]
                result = "FLAG"
                detail = (
                    "Behavioral deviation detected: "
                    f"{evidence['deviation_flags'][0]['display_message']}"
                )
            else:
                detail = "Agent behavior within established baseline parameters."

        self._baseline.append(tool_name, parameter_hash, action.timestamp)

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result=result,
            detail=detail,
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
        from ancilis.engine.result import ControlResult

        prior_count = self._baseline.event_count
        baseline_established = prior_count >= BASELINE_MIN_EVENTS
        evidence = self._base_evidence(
            tool_name=action.tool.name,
            parameter_hash=action.parameters.parameter_hash or "",
            prior_count=prior_count,
            prior_unique_tools=self._baseline.unique_tools,
            baseline_established=baseline_established,
            observation_type=action.action_type,
        )
        evidence["current_rate_vs_baseline"] = 0.0

        if not baseline_established:
            warmed_count = min(prior_count + 1, BASELINE_MIN_EVENTS)
            return ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="PASS",
                detail=(
                    "Baseline not yet established — warming behavioral window "
                    f"({warmed_count}/{BASELINE_MIN_EVENTS})."
                ),
                evidence_data=evidence,
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        tool_name = action.tool.name
        deviation_flags: list[dict[str, str]] = []
        new_tools = self._new_tools_detected(tool_name, self._baseline.unique_tools)

        if new_tools:
            deviation_flags.append(self._new_tool_flag(new_tools[0]))

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

        evidence["new_tools_detected"] = new_tools
        evidence["deviation_flags"] = deviation_flags

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

    def _base_evidence(
        self,
        *,
        tool_name: str,
        parameter_hash: str,
        prior_count: int,
        prior_unique_tools: set[str],
        baseline_established: bool,
        observation_type: str,
    ) -> dict[str, Any]:
        return {
            "behavior_schema_version": self.behavior_schema_version,
            "observation_type": observation_type,
            "observed_tool_name": tool_name,
            "observed_parameter_hash": parameter_hash,
            "baseline_established": baseline_established,
            "baseline_min_events": BASELINE_MIN_EVENTS,
            "window_event_count": prior_count,
            "window_unique_tools": sorted(prior_unique_tools),
            "baseline_window_calls": prior_count,
            "deviation_flags": [],
            "new_tools_detected": [],
        }

    @staticmethod
    def _new_tools_detected(tool_name: str, prior_unique_tools: set[str]) -> list[str]:
        if tool_name and tool_name not in prior_unique_tools:
            return [tool_name]
        return []

    @staticmethod
    def _new_tool_flag(tool_name: str) -> dict[str, str]:
        return {
            "type": "new_tool",
            "display_message": f"Tool '{tool_name}' not seen in warmed baseline window",
            "severity": "warning",
        }
