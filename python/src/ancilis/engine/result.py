"""Evaluation result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ControlResult:
    control_id: str
    control_name: str
    result: str  # "PASS" | "FAIL" | "SKIP" | "ERROR" | "FLAG"
    detail: str
    evidence_data: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    display_name: str = ""
    display_detail: str = ""
    remediation_hint: str = ""


@dataclass
class EvaluationResult:
    evaluation_id: str
    action_id: str
    timestamp: str
    agent_id: str
    source_type: str = "agent"
    mode: str = "audit"  # "audit" | "enforce"
    control_results: list[ControlResult] = field(default_factory=list)
    decision: str = "ALLOW"  # "ALLOW" | "BLOCK" | "FLAG"
    decision_reason: str = ""
    active_overlays: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)
    detected_data_types: list[str] = field(default_factory=list)
    total_duration_ms: float = 0.0
    session_id: str | None = None
