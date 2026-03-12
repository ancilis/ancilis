"""Auto-discovery: registers tools from MCP list_tools into the ToolRegistry."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus

logger = logging.getLogger("ancilis.discovery")


@dataclass
class DriftEvent:
    tool_name: str
    old_hash: str | None
    new_hash: str


def register_tools_from_list(
    tools: list[Any],
    registry: ToolRegistry,
    pre_approved: list[str] | None = None,
) -> list[DriftEvent]:
    """Register tools from MCP list_tools response. Returns drift events.

    Tools are registered as OBSERVED by default. Tools listed in
    pre_approved (from security.tools.allowed) are registered as APPROVED.
    """
    drift_events: list[DriftEvent] = []
    approved_set = set(pre_approved) if pre_approved else set()

    for tool in tools:
        name: str = tool.name
        description: str = tool.description or ""
        desc_hash = hashlib.sha256(description.encode()).hexdigest()

        existing = registry.lookup(name)
        if existing and existing.description_hash and existing.description_hash != desc_hash:
            drift_events.append(DriftEvent(
                tool_name=name,
                old_hash=existing.description_hash,
                new_hash=desc_hash,
            ))
            logger.warning(
                "Tool description drift detected for '%s': hash changed from %s to %s",
                name, existing.description_hash[:12], desc_hash[:12],
            )

        # Pre-approved tools (from config allowlist) get APPROVED status;
        # all others start as OBSERVED until explicitly approved.
        status = ToolStatus.APPROVED if name in approved_set else ToolStatus.OBSERVED

        registry.register(ToolEntry(
            name=name,
            description_hash=desc_hash,
            status=status,
        ))

    return drift_events
