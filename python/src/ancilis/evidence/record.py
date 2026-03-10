"""Evidence record model — immutable record of a control evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceRecord:
    record_id: str
    evaluation_id: str
    timestamp: str
    agent_id: str
    tool_name: str
    decision: str  # "ALLOW" | "BLOCK" | "FLAG"
    mode: str  # "audit" | "enforce"
    control_results: list[dict[str, Any]]
    active_overlays: list[str]
    data_classifications: list[str]
    active_certifications: list[str]
    record_hash: str
    previous_hash: str
    total_duration_ms: float = 0.0
