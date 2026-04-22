"""Shared scenario models for the demo evidence generator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Outcome = Literal["ALLOW", "BLOCK", "FLAG"]


@dataclass(frozen=True)
class DemoCall:
    tool_name: str
    arguments: dict[str, Any]
    response: str
    outcome: Outcome = "ALLOW"
    detected_data_types: tuple[str, ...] = ()
    reason: str = "All controls passed."
    description: str = ""


@dataclass(frozen=True)
class DemoScenario:
    agent_id: str
    display_name: str
    architecture: str
    agent_owner: str
    llm_provider: str
    handles: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    blocked_tools: tuple[str, ...]
    calls: tuple[DemoCall, ...]
    certification_targets: tuple[str, ...] = ("aiuc-1",)
    metadata: dict[str, str] = field(default_factory=dict)
