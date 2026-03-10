"""Tool registry for provenance verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ToolEntry:
    name: str
    version: str | None = None
    description_hash: str | None = None
    approved: bool = True
    approved_date: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {}

    def register(self, entry: ToolEntry) -> None:
        self._tools[entry.name] = entry

    def lookup(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._tools
