from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ControlSnapshot:
    """Point-in-time snapshot of a single control's posture."""

    control_id: str
    result: str  # "PASS" | "FAIL" | "FLAG" | "SKIP" | "ERROR"
    pass_rate: float  # 0.0–1.0
    total_evaluations: int
    evidence_window_start: str  # ISO timestamp
    evidence_window_end: str  # ISO timestamp


@dataclass
class Baseline:
    """Captured posture snapshot for an agent/overlay."""

    baseline_id: str
    created_at: str  # ISO timestamp
    agent_id: str
    label: str
    control_snapshots: list[ControlSnapshot]
    overlay_id: str | None = None
    metadata: dict[str, Any] | None = None
    is_active: bool = True


@dataclass
class ControlDrift:
    """Detected drift for a single control."""

    control_id: str
    control_name: str
    baseline_result: str
    baseline_pass_rate: float
    current_result: str
    current_pass_rate: float
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    first_failure_at: str | None
    failure_count: int
    evidence_delta: int  # current_evals - baseline_evals


@dataclass
class DriftReport:
    """Full drift analysis result."""

    drift_report_id: str
    baseline_id: str
    baseline_label: str
    checked_at: str  # ISO timestamp
    agent_id: str
    overall_status: str  # "STABLE" | "DRIFTED"
    summary: str
    control_drifts: list[ControlDrift] = field(default_factory=list)
    overlay_id: str | None = None
