"""Action object — the standardized representation of an agent action for evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ancilis.aksi.version import AKSI_FRAMEWORK_VERSION


@dataclass
class ToolInfo:
    name: str
    version: str | None = None
    server: str | None = None
    description_hash: str | None = None


@dataclass
class ActionParameters:
    raw: dict[str, Any] = field(default_factory=dict)
    parameter_hash: str = ""


@dataclass
class ActionContext:
    session_id: str | None = None
    parent_action_id: str | None = None
    tenant_id: str | None = None
    user_id: str | None = None
    jurisdiction: str | None = None
    data_classifications: list[str] = field(default_factory=list)
    active_overlays: list[str] = field(default_factory=list)


@dataclass
class Action:
    action_id: str
    timestamp: str
    agent_id: str
    action_type: str  # "tool_call" | "api_request" | "data_access"
    tool: ToolInfo
    parameters: ActionParameters
    agent_owner: str | None = None
    context: ActionContext = field(default_factory=ActionContext)
    source_type: str = "agent"
    framework_version: str = AKSI_FRAMEWORK_VERSION
    producer_type: str = "mcp"  # default preserves backward compat
    producer_version: str = "0.1.0"
    destination: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
