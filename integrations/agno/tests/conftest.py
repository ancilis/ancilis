"""Shared test fixtures for ancilis-agno tests.

The producer is duck-typed and never imports ``agno``. To keep the test
suite fast and dep-free, we provide minimal mock Agent / Team / RunResponse /
ToolCall / Memory / Knowledge objects that mimic the surface of the agno
public API we record from.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Make the package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# RunResponse / ToolCall mocks — mirror agno's response classes.
# ---------------------------------------------------------------------------


class MockMetrics:
    def __init__(
        self,
        *,
        time_to_first_token: float = 0.42,
        total_tokens: int = 128,
        tokens_per_second: float = 60.0,
        input_tokens: int = 80,
        output_tokens: int = 48,
    ) -> None:
        self.time_to_first_token = time_to_first_token
        self.total_tokens = total_tokens
        self.tokens_per_second = tokens_per_second
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class MockToolCall:
    def __init__(
        self,
        *,
        tool_name: str = "search_web",
        tool_args: dict[str, Any] | None = None,
        tool_call_id: str = "tc-1",
        result: Any = "ok",
    ) -> None:
        self.tool_name = tool_name
        self.tool_args = tool_args or {"query": "weather"}
        self.tool_call_id = tool_call_id
        self.result = result


class MockRunResponse:
    def __init__(
        self,
        *,
        id: str = "run-1",
        run_id: str | None = None,
        agent_id: str | None = None,
        content: str = "the answer is 42",
        model: str = "claude-sonnet-4",
        metrics: MockMetrics | None = None,
        tools: list[MockToolCall] | None = None,
        event: str | None = None,
        member_name: str | None = None,
    ) -> None:
        self.id = id
        self.run_id = run_id or id
        self.agent_id = agent_id
        self.content = content
        self.model = model
        self.metrics = metrics or MockMetrics()
        self.tools = tools or []
        self.event = event
        if member_name is not None:
            self.member_name = member_name
        # carry messages list to mirror real RunResponse
        self.messages: list[Any] = []


class MockStreamEvent:
    """A lightweight streaming event — Agno emits these with an ``event`` field."""

    def __init__(
        self,
        *,
        event: str,
        id: str = "evt-1",
        content: str | None = None,
        tool_call: MockToolCall | None = None,
        metrics: MockMetrics | None = None,
        model: str | None = None,
        member_name: str | None = None,
    ) -> None:
        self.event = event
        self.id = id
        self.content = content
        self.tool_call = tool_call
        self.metrics = metrics
        self.model = model
        self.member_name = member_name


# ---------------------------------------------------------------------------
# Agent / Team mocks — top-level Agent.run/arun/run_stream + memory + knowledge.
# ---------------------------------------------------------------------------


class MockMemory:
    def __init__(self) -> None:
        self.add_calls: list[dict[str, Any]] = []
        self.summary_calls: list[dict[str, Any]] = []
        self.search_calls: list[dict[str, Any]] = []
        self.get_summary_calls: list[dict[str, Any]] = []
        self._search_results: list[Any] = []

    def add_user_memory(self, memory: str, **kwargs: Any) -> dict[str, Any]:
        self.add_calls.append({"memory": memory, **kwargs})
        return {"memory_id": f"mem-{len(self.add_calls)}"}

    def update_session_summary(self, summary: str, **kwargs: Any) -> dict[str, Any]:
        self.summary_calls.append({"summary": summary, **kwargs})
        return {"updated": True}

    def search_user_memories(self, query: str, **kwargs: Any) -> list[Any]:
        self.search_calls.append({"query": query, **kwargs})
        return list(self._search_results)

    def get_session_summary(self, **kwargs: Any) -> dict[str, Any]:
        self.get_summary_calls.append(kwargs)
        return {"summary": "session summary text"}


class MockKnowledge:
    def __init__(self) -> None:
        self.search_calls: list[dict[str, Any]] = []
        self.add_calls: list[dict[str, Any]] = []
        self.update_calls: list[dict[str, Any]] = []
        self._search_results: list[Any] = [{"id": "doc-1"}, {"id": "doc-2"}]

    def search(
        self,
        query: str,
        limit: int | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[Any]:
        self.search_calls.append(
            {"query": query, "limit": limit, "filters": filters}
        )
        return list(self._search_results)

    def add(self, documents: list[Any], **kwargs: Any) -> dict[str, Any]:
        self.add_calls.append({"documents": documents, **kwargs})
        return {"added": len(documents)}

    def update(self, documents: list[Any], **kwargs: Any) -> dict[str, Any]:
        self.update_calls.append({"documents": documents, **kwargs})
        return {"updated": len(documents)}


class MockAgent:
    def __init__(
        self,
        *,
        response: MockRunResponse | None = None,
        run_exc: BaseException | None = None,
        stream_events: list[Any] | None = None,
        memory: MockMemory | None = None,
        knowledge: MockKnowledge | None = None,
    ) -> None:
        self._response = response or MockRunResponse()
        self._run_exc = run_exc
        self._stream_events = stream_events or []
        self.memory = memory
        self.knowledge = knowledge
        self.run_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.arun_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def run(self, *args: Any, **kwargs: Any) -> MockRunResponse:
        self.run_calls.append((args, kwargs))
        if self._run_exc is not None:
            raise self._run_exc
        return self._response

    async def arun(self, *args: Any, **kwargs: Any) -> MockRunResponse:
        self.arun_calls.append((args, kwargs))
        if self._run_exc is not None:
            raise self._run_exc
        return self._response

    def run_stream(self, *args: Any, **kwargs: Any) -> Any:
        return iter(list(self._stream_events))


class MockTeamResponse:
    """Aggregated team response with per-member RunResponse list."""

    def __init__(
        self,
        *,
        id: str = "team-run-1",
        content: str = "team-aggregated answer",
        member_responses: list[MockRunResponse] | None = None,
        metrics: MockMetrics | None = None,
    ) -> None:
        self.id = id
        self.run_id = id
        self.content = content
        self.member_responses = member_responses or []
        self.metrics = metrics or MockMetrics(total_tokens=256)
        self.model = "team-coordinator"


class MockTeam:
    def __init__(
        self,
        *,
        response: MockTeamResponse | None = None,
        run_exc: BaseException | None = None,
        members: list[MockAgent] | None = None,
    ) -> None:
        self._response = response or MockTeamResponse()
        self._run_exc = run_exc
        self.members = members or []
        self.run_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.arun_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def run(self, *args: Any, **kwargs: Any) -> MockTeamResponse:
        self.run_calls.append((args, kwargs))
        if self._run_exc is not None:
            raise self._run_exc
        return self._response

    async def arun(self, *args: Any, **kwargs: Any) -> MockTeamResponse:
        self.arun_calls.append((args, kwargs))
        if self._run_exc is not None:
            raise self._run_exc
        return self._response


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_agent() -> MockAgent:
    return MockAgent(memory=MockMemory(), knowledge=MockKnowledge())


@pytest.fixture
def mock_team() -> MockTeam:
    members = [
        MockRunResponse(
            id="m1-run", agent_id="researcher", content="research notes"
        ),
        MockRunResponse(
            id="m2-run", agent_id="writer", content="draft text"
        ),
    ]
    members[0].member_name = "researcher"
    members[1].member_name = "writer"
    return MockTeam(response=MockTeamResponse(member_responses=members))
