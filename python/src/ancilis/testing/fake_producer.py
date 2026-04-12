"""FakeProducer — inject synthetic evidence without running real agent code."""

from __future__ import annotations

import hashlib
from typing import Any

from ancilis.engine.action import Action
from ancilis.engine.registry import ToolEntry, ToolRegistry
from ancilis.producers.protocol import ProducerType
from ancilis.testing._helpers import make_action


class FakeProducer:
    """Injects synthetic evidence without running real agent code.

    Implements the ActionProducer protocol. Use in tests to produce Action
    objects with controlled data, without any real tool connectivity.

    Usage::

        from ancilis.testing import FakeProducer

        producer = FakeProducer("identity")
        producer.emit("user.id", "alice")
        producer.emit("session.start", {"timestamp": "2026-04-11T10:00:00Z"})

        action = producer.make_action()
        result = engine.evaluate(action)
    """

    def __init__(
        self,
        producer_name: str = "fake",
        agent_id: str = "test-agent",
        agent_owner: str | None = None,
    ) -> None:
        self._producer_name = producer_name
        self._agent_id = agent_id
        self._agent_owner = agent_owner
        self._emitted: dict[str, Any] = {}

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.MANUAL

    @property
    def producer_version(self) -> str:
        return "0.1.0-test"

    def emit(self, key: str, value: Any) -> None:
        """Record a synthetic evidence item.

        Emitted items are available via ``emitted_data`` and are included
        as parameters in any Action created with ``make_action()``.
        """
        self._emitted[key] = value

    @property
    def emitted_data(self) -> dict[str, Any]:
        """All emitted evidence items (read-only copy)."""
        return dict(self._emitted)

    def clear(self) -> None:
        """Reset all emitted items."""
        self._emitted.clear()

    def make_action(
        self,
        tool_name: str | None = None,
        parameters: dict[str, Any] | None = None,
        session_id: str | None = None,
        data_classifications: list[str] | None = None,
        source_type: str = "agent",
    ) -> Action:
        """Create an Action for engine evaluation.

        Parameters are merged from emitted items (base) plus any explicit
        overrides supplied here.
        """
        merged_params = dict(self._emitted)
        if parameters:
            merged_params.update(parameters)

        return make_action(
            tool_name=tool_name or self._producer_name,
            agent_id=self._agent_id,
            agent_owner=self._agent_owner,
            parameters=merged_params,
            session_id=session_id,
            data_classifications=data_classifications,
            source_type=source_type,
        )

    # --- ActionProducer protocol ---

    def translate(self, raw_invocation: Any) -> Action:
        """Translate a raw dict invocation into an Action."""
        if isinstance(raw_invocation, dict):
            return self.make_action(
                tool_name=raw_invocation.get("tool", self._producer_name),
                parameters=raw_invocation.get("parameters"),
            )
        return self.make_action()

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        tool_name = self._producer_name
        registry.register(ToolEntry(name=tool_name))
        return [tool_name]
