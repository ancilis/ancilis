"""ADR-005: Action Object Producer Protocol.

Any source of agent actions implements ActionProducer.
The control engine evaluates Action objects regardless of source.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable

from ancilis.engine.action import Action
from ancilis.engine.registry import ToolRegistry


class ProducerType(str, Enum):
    """Identifies the source protocol for an action."""

    MCP = "mcp"
    CLI = "cli"
    HTTP = "http"
    A2A = "a2a"
    FRAMEWORK = "framework"
    MANUAL = "manual"


@runtime_checkable
class ActionProducer(Protocol):
    """Protocol that any action source must implement.

    MCP middleware, CLI interceptors, HTTP proxies, A2A adapters,
    and framework callbacks all implement this interface.
    The engine does not know or care which producer created an Action.
    """

    @property
    def producer_type(self) -> ProducerType:
        """Identifies what kind of producer this is."""
        ...

    @property
    def producer_version(self) -> str:
        """Version string for this producer implementation."""
        ...

    def translate(self, raw_invocation: Any) -> Action:
        """Convert a raw tool invocation into a standardized Action object."""
        ...

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        """Compute a provenance hash for the tool.

        PR-03 requires a stable hash to detect tool drift.
        Each protocol hashes different content (descriptions, version strings, specs).
        """
        ...

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        """Discover and register tools available through this producer.

        All tools enter as OBSERVED status. Approval is a separate step.
        Returns list of tool names registered.
        """
        ...
