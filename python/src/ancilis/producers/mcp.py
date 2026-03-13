"""MCPActionProducer — wraps existing MCP action building and discovery logic."""

from __future__ import annotations

import hashlib
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.middleware.action_builder import build_action
from ancilis.middleware.discovery import DriftEvent, register_tools_from_list
from ancilis.producers.protocol import ProducerType


class MCPActionProducer:
    """Produces Action objects from MCP tool calls.

    Delegates to existing action_builder and discovery modules.
    This class satisfies the ActionProducer protocol.
    """

    def __init__(self, config: ResolvedConfig, registry: ToolRegistry) -> None:
        self._config = config
        self._registry = registry

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.MCP

    @property
    def producer_version(self) -> str:
        return "0.1.0"

    def translate(self, raw_invocation: Any) -> Action:
        """Translate an MCP tool call into an Action.

        raw_invocation: dict with 'name' and optional 'arguments' keys,
        matching the MCP callTool params shape.
        """
        name: str = raw_invocation["name"]
        arguments: dict[str, Any] | None = raw_invocation.get("arguments")

        action = build_action(name, arguments, self._config, self._registry)
        action.producer_type = self.producer_type.value
        action.producer_version = self.producer_version
        return action

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        """Compute hash of an MCP tool description string."""
        description = str(tool_identifier) if tool_identifier else ""
        return hashlib.sha256(description.encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        """Register tools from an MCP tools list.

        Note: In practice, AncilisMiddleware calls register_tools_from_list
        directly with the MCP response. This method exists to satisfy the
        ActionProducer protocol for protocol-level compliance checks.
        """
        return [entry.name for entry in registry.get_all()]

    def register_tools_from_response(
        self,
        tools: list[Any],
        registry: ToolRegistry,
        pre_approved: list[str] | None = None,
    ) -> list[DriftEvent]:
        """Delegate to the existing MCP discovery logic."""
        return register_tools_from_list(tools, registry, pre_approved)
