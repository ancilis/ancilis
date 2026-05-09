"""Shared test fixtures for ancilis-pydantic-ai tests.

The producer is duck-typed and never imports pydantic_ai. To keep the test suite
fast and dep-free, we provide a minimal mock Agent that mimics the surface of
``pydantic_ai.Agent`` we care about (run, run_sync, iter), plus mock RunResult /
event objects with the attributes the wrapper extracts.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Make the package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class MockUsage:
    """Pydantic-AI Usage-like object."""

    def __init__(
        self,
        *,
        input_tokens: int = 10,
        output_tokens: int = 5,
        total_tokens: int = 15,
        requests: int = 1,
    ) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.total_tokens = total_tokens
        self.requests = requests


class MockRunResult:
    """Duck-typed Pydantic-AI RunResult."""

    def __init__(
        self,
        *,
        data: Any = "result text",
        model: str = "openai:gpt-4o",
        usage: MockUsage | None = None,
    ) -> None:
        self.data = data
        self.output = data  # newer pydantic-ai uses .output
        self.model = model
        self._usage = usage or MockUsage()

    def usage(self) -> MockUsage:
        return self._usage


class MockAgent:
    """Duck-typed Pydantic-AI Agent."""

    def __init__(
        self,
        *,
        result: MockRunResult | None = None,
        run_exc: BaseException | None = None,
        sync_exc: BaseException | None = None,
        iter_events: list[Any] | None = None,
        existing_attr: str = "agent-attr-value",
    ) -> None:
        self._result = result or MockRunResult()
        self._run_exc = run_exc
        self._sync_exc = sync_exc
        self._iter_events = iter_events or []
        self.existing_attr = existing_attr
        self.run_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.run_sync_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    async def run(self, *args: Any, **kwargs: Any) -> MockRunResult:
        self.run_calls.append((args, kwargs))
        if self._run_exc is not None:
            raise self._run_exc
        return self._result

    def run_sync(self, *args: Any, **kwargs: Any) -> MockRunResult:
        self.run_sync_calls.append((args, kwargs))
        if self._sync_exc is not None:
            raise self._sync_exc
        return self._result

    def iter(self, *args: Any, **kwargs: Any) -> "MockStream":
        return MockStream(self._iter_events)


class MockStream:
    """Async iterator that yields the configured events."""

    def __init__(self, events: list[Any]) -> None:
        self._events = list(events)

    def __aiter__(self) -> "MockStream":
        return self

    async def __anext__(self) -> Any:
        if not self._events:
            raise StopAsyncIteration
        return self._events.pop(0)


class MockStreamEvent:
    """Mimics a Pydantic-AI stream event (ModelResponseStreamEvent etc)."""

    def __init__(
        self,
        *,
        kind: str,
        event_id: str = "evt-1",
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        model: str | None = None,
        output: Any = None,
        usage: MockUsage | None = None,
        error: Any = None,
        parent_event_id: str | None = None,
    ) -> None:
        self.kind = kind
        self.event_id = event_id
        if tool_name is not None:
            self.tool_name = tool_name
        if tool_args is not None:
            self.tool_args = tool_args
        if model is not None:
            self.model = model
        if output is not None:
            self.output = output
        if usage is not None:
            self.usage = usage
        if error is not None:
            self.error = error
        if parent_event_id is not None:
            self.parent_event_id = parent_event_id


@pytest.fixture
def mock_agent() -> MockAgent:
    return MockAgent()


@pytest.fixture
def mock_usage() -> MockUsage:
    return MockUsage(input_tokens=42, output_tokens=18, total_tokens=60, requests=1)


@pytest.fixture
def mock_run_result(mock_usage: MockUsage) -> MockRunResult:
    return MockRunResult(data="hello world", model="openai:gpt-4o", usage=mock_usage)
