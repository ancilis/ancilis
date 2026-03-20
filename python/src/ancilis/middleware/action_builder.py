"""Translates MCP tool calls into framework-agnostic Action objects."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.registry import ToolRegistry


def build_action(
    tool_name: str,
    arguments: dict[str, Any] | None,
    config: ResolvedConfig,
    registry: ToolRegistry,
) -> Action:
    """Build an Action object from an MCP tool call."""
    args = arguments or {}
    param_hash = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()

    # Look up tool metadata from registry
    entry = registry.lookup(tool_name)
    tool_version = entry.version if entry else None
    description_hash = entry.description_hash if entry else None

    # Collect DC codes from config
    dc_codes: list[str] = []
    for codes in config.data_classifications.values():
        for code in codes:
            if code not in dc_codes:
                dc_codes.append(code)

    overlay_ids = list(config.active_overlays.keys())

    return Action(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=config.agent_name,
        source_type="mcp",
        agent_owner=config.agent_owner or None,
        action_type="tool_call",
        tool=ToolInfo(
            name=tool_name,
            version=tool_version,
            description_hash=description_hash,
        ),
        parameters=ActionParameters(raw=args, parameter_hash=param_hash),
        context=ActionContext(
            data_classifications=dc_codes,
            active_overlays=overlay_ids,
        ),
        producer_type="mcp",
    )
