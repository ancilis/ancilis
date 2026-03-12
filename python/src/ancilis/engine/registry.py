"""Tool registry for provenance verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ToolStatus(str, Enum):
    """Trust status of a registered tool."""

    OBSERVED = "observed"    # Discovered at runtime, not yet approved
    APPROVED = "approved"    # Explicitly approved by operator
    BLOCKED = "blocked"      # Explicitly blocked


@dataclass
class ToolEntry:
    name: str
    version: str | None = None
    description_hash: str | None = None
    status: ToolStatus = ToolStatus.OBSERVED
    approved_by: str | None = None
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status_changed: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def approved(self) -> bool:
        """Backwards-compatible: True only when explicitly approved."""
        return self.status == ToolStatus.APPROVED


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {}

    def register(self, entry: ToolEntry) -> None:
        self._tools[entry.name] = entry

    def lookup(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._tools

    def approve(self, name: str, approved_by: str = "operator") -> bool:
        """Mark a tool as approved. Returns False if tool is not registered."""
        entry = self._tools.get(name)
        if entry is None:
            return False
        entry.status = ToolStatus.APPROVED
        entry.approved_by = approved_by
        entry.status_changed = datetime.now(timezone.utc).isoformat()
        return True

    def get_all(self) -> list[ToolEntry]:
        """Return all registered tools."""
        return list(self._tools.values())
