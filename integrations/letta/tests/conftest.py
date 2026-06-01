"""Shared test fixtures for ancilis-letta tests.

The producer is duck-typed and never imports letta_client. To keep the test
suite fast and dep-free, we provide minimal mock client / response / message
objects that mimic the surface of the letta-client REST API we record from.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Make the package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# Message subtype mocks — mirror letta-client's pydantic message classes.
# ---------------------------------------------------------------------------


class MockSystemMessage:
    message_type = "system_message"

    def __init__(self, *, id: str = "m-sys", content: str = "system text") -> None:
        self.id = id
        self.role = "system"
        self.content = content


class MockUserMessage:
    message_type = "user_message"

    def __init__(self, *, id: str = "m-usr", content: str = "user text") -> None:
        self.id = id
        self.role = "user"
        self.content = content


class MockAssistantMessage:
    message_type = "assistant_message"

    def __init__(self, *, id: str = "m-ast", content: str = "assistant text") -> None:
        self.id = id
        self.role = "assistant"
        self.content = content


class MockReasoningMessage:
    message_type = "reasoning_message"

    def __init__(self, *, id: str = "m-rsn", reasoning: str = "thinking...") -> None:
        self.id = id
        self.role = "assistant"
        self.reasoning = reasoning
        self.content = reasoning


class MockToolCall:
    def __init__(
        self,
        *,
        name: str = "send_message",
        arguments: str = '{"message": "hi"}',
        tool_call_id: str = "tc-1",
    ) -> None:
        self.name = name
        self.arguments = arguments
        self.tool_call_id = tool_call_id


class MockToolCallMessage:
    message_type = "tool_call_message"

    def __init__(
        self,
        *,
        id: str = "m-tc",
        tool_call: MockToolCall | None = None,
        tool_call_id: str = "tc-1",
    ) -> None:
        self.id = id
        self.tool_call = tool_call or MockToolCall()
        self.tool_call_id = tool_call_id


class MockToolReturnMessage:
    message_type = "tool_return_message"

    def __init__(
        self,
        *,
        id: str = "m-tr",
        tool_call_id: str = "tc-1",
        tool_return: str = "ok",
        status: str = "success",
        stderr: Any = None,
    ) -> None:
        self.id = id
        self.tool_call_id = tool_call_id
        self.tool_return = tool_return
        self.status = status
        self.stderr = stderr


class MockUsageStatistics:
    def __init__(
        self,
        *,
        completion_tokens: int = 12,
        prompt_tokens: int = 80,
        total_tokens: int = 92,
        step_count: int = 1,
    ) -> None:
        self.completion_tokens = completion_tokens
        self.prompt_tokens = prompt_tokens
        self.total_tokens = total_tokens
        self.step_count = step_count


class MockLettaResponse:
    def __init__(
        self,
        *,
        messages: list[Any] | None = None,
        usage: MockUsageStatistics | None = None,
    ) -> None:
        self.messages = messages or []
        self.usage = usage


# ---------------------------------------------------------------------------
# Memory passages (archival) and core blocks
# ---------------------------------------------------------------------------


class MockPassage:
    def __init__(self, *, id: str = "p-1", text: str = "memory text") -> None:
        self.id = id
        self.text = text


# ---------------------------------------------------------------------------
# Letta client mocks — top-level Letta(), agents.messages, agents.archival_memory,
# agents.core_memory.
# ---------------------------------------------------------------------------


class MockMessages:
    def __init__(
        self,
        *,
        response: MockLettaResponse | None = None,
        create_exc: BaseException | None = None,
        stream_events: list[Any] | None = None,
    ) -> None:
        self._response = response or MockLettaResponse()
        self._create_exc = create_exc
        self._stream_events = stream_events or []
        self.create_calls: list[dict[str, Any]] = []
        self.list_calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> MockLettaResponse:
        self.create_calls.append(kwargs)
        if self._create_exc is not None:
            raise self._create_exc
        return self._response

    def create_stream(self, **kwargs: Any) -> Any:
        return iter(list(self._stream_events))

    def list(self, **kwargs: Any) -> list[Any]:
        self.list_calls.append(kwargs)
        return list(self._response.messages)


class MockArchivalMemory:
    def __init__(
        self,
        *,
        passages: list[MockPassage] | None = None,
        create_exc: BaseException | None = None,
        search_results: list[MockPassage] | None = None,
    ) -> None:
        self._passages = passages or []
        self._create_exc = create_exc
        self._search_results = search_results or []
        self.create_calls: list[dict[str, Any]] = []
        self.update_calls: list[dict[str, Any]] = []
        self.search_calls: list[dict[str, Any]] = []
        self.delete_calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> MockPassage:
        self.create_calls.append(kwargs)
        if self._create_exc is not None:
            raise self._create_exc
        return MockPassage(id="p-new", text=kwargs.get("text", ""))

    def update(self, **kwargs: Any) -> MockPassage:
        self.update_calls.append(kwargs)
        return MockPassage(id=kwargs.get("memory_id", "p-x"), text=kwargs.get("text", ""))

    def search(self, **kwargs: Any) -> list[MockPassage]:
        self.search_calls.append(kwargs)
        return list(self._search_results)

    def list(self, **kwargs: Any) -> list[MockPassage]:
        return list(self._passages)

    def delete(self, **kwargs: Any) -> dict[str, Any]:
        self.delete_calls.append(kwargs)
        return {"deleted": True}


class MockCoreMemory:
    def __init__(self) -> None:
        self.update_calls: list[dict[str, Any]] = []

    def update(self, **kwargs: Any) -> dict[str, Any]:
        self.update_calls.append(kwargs)
        return {"block_label": kwargs.get("block_label"), "value": kwargs.get("new_value")}


class MockAgents:
    def __init__(
        self,
        *,
        messages: MockMessages | None = None,
        archival_memory: MockArchivalMemory | None = None,
        core_memory: MockCoreMemory | None = None,
    ) -> None:
        self.messages = messages or MockMessages()
        self.archival_memory = archival_memory or MockArchivalMemory()
        self.core_memory = core_memory or MockCoreMemory()


class MockLettaClient:
    def __init__(self, agents: MockAgents | None = None) -> None:
        self.agents = agents or MockAgents()
        self.api_version = "v1"

    def health(self) -> dict[str, Any]:
        return {"ok": True}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_client() -> MockLettaClient:
    return MockLettaClient()


@pytest.fixture
def mock_response_full() -> MockLettaResponse:
    """A full LettaResponse with every message subtype + usage tail."""
    return MockLettaResponse(
        messages=[
            MockSystemMessage(content="you are a helpful agent"),
            MockUserMessage(content="hello"),
            MockReasoningMessage(reasoning="planning the response"),
            MockToolCallMessage(
                tool_call=MockToolCall(
                    name="send_message",
                    arguments='{"message": "hi there", "user_id": 7}',
                ),
                tool_call_id="tc-1",
            ),
            MockToolReturnMessage(tool_call_id="tc-1", tool_return="ok"),
            MockAssistantMessage(content="hi there"),
        ],
        usage=MockUsageStatistics(),
    )
