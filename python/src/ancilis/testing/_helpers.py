"""Internal helpers shared across the ancilis.testing module."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig, load_config
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


def make_test_config(
    agent_name: str = "test-agent",
    mode: str = "audit",
    overlay: str | None = None,
    **extra: Any,
) -> ResolvedConfig:
    """Create a minimal ResolvedConfig for testing without a yaml file."""
    raw: dict[str, Any] = {
        "agent": {"name": agent_name},
        "security": {"mode": mode},
    }
    if overlay:
        raw["compliance"] = {"overlays": [overlay]}
    raw.update(extra)
    return load_config(raw=raw)


def make_action(
    tool_name: str = "test_tool",
    agent_id: str = "test-agent",
    agent_owner: str | None = None,
    parameters: dict[str, Any] | None = None,
    session_id: str | None = None,
    data_classifications: list[str] | None = None,
    source_type: str = "agent",
) -> Action:
    """Create a test Action with sensible defaults."""
    return Action(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        action_type="tool_call",
        tool=ToolInfo(name=tool_name),
        parameters=ActionParameters(raw=parameters or {}),
        agent_owner=agent_owner,
        context=ActionContext(
            session_id=session_id,
            data_classifications=data_classifications or [],
        ),
        source_type=source_type,
    )
