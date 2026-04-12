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
    source_type: str
    tool_name: str
    decision: str  # "ALLOW" | "BLOCK" | "FLAG"
    mode: str  # "audit" | "enforce"
    control_results: list[dict[str, Any]]
    active_overlays: list[str]
    data_classifications: list[str]
    active_certifications: list[str]
    record_hash: str
    previous_hash: str
    detected_data_types: list[str] = field(default_factory=list)
    total_duration_ms: float = 0.0
    output_summary: str | None = None
    session_id: str | None = None
    tenant_id: str | None = None
    sdk_version: str | None = None
    classification_context: dict[str, Any] = field(default_factory=dict)
