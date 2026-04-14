"""Shared fixtures for ancilis-crewai tests."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Make package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
# Make 'from tests.conftest import ...' work when pytest runs from outside the package
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Minimal CrewAI stubs
# ---------------------------------------------------------------------------

class _FakeTask:
    def __init__(self, description: str = "Do something", expected_output: str = "A result") -> None:
        self.description = description
        self.expected_output = expected_output


class _FakeAgent:
    def __init__(self, role: str = "researcher") -> None:
        self.role = role
        self._execute_results: list[str] = ["task output"]

    def execute_task(self, task: Any, *args: Any, **kwargs: Any) -> str:
        if self._execute_results:
            return self._execute_results.pop(0)
        return "default output"


class _FakeCrew:
    def __init__(self, agents: list[Any] | None = None, tasks: list[Any] | None = None) -> None:
        self.agents = agents or []
        self.tasks = tasks or []

    def kickoff(self) -> str:
        # Simulate executing each task via each agent
        results = []
        for task in self.tasks:
            for agent in self.agents:
                if hasattr(agent, "execute_task"):
                    r = agent.execute_task(task)
                    results.append(r)
        return " ".join(results) if results else "crew done"

    async def kickoff_async(self) -> str:
        return self.kickoff()


@pytest.fixture
def fake_task() -> _FakeTask:
    return _FakeTask()


@pytest.fixture
def fake_agent() -> _FakeAgent:
    return _FakeAgent(role="researcher")


@pytest.fixture
def fake_crew(fake_agent, fake_task) -> _FakeCrew:
    return _FakeCrew(agents=[fake_agent], tasks=[fake_task])


@pytest.fixture
def crew_start_raw() -> dict[str, Any]:
    return {
        "event": "crew_start",
        "crew_name": "ResearchCrew",
        "execution_id": "abc123",
        "agent_count": 2,
        "task_count": 3,
    }


@pytest.fixture
def crew_end_raw() -> dict[str, Any]:
    return {
        "event": "crew_end",
        "crew_name": "ResearchCrew",
        "execution_id": "abc123",
        "output": "Final report with 500 words.",
        "agent_count": 2,
        "task_count": 3,
    }


@pytest.fixture
def task_start_raw() -> dict[str, Any]:
    return {
        "event": "task_start",
        "crew_name": "ResearchCrew",
        "agent_role": "researcher",
        "execution_id": "abc123",
        "task_description": "Research the topic",
        "expected_output": "A detailed report",
    }


@pytest.fixture
def task_end_raw() -> dict[str, Any]:
    return {
        "event": "task_end",
        "crew_name": "ResearchCrew",
        "agent_role": "researcher",
        "execution_id": "abc123",
        "task_description": "Research the topic",
        "output": "Completed research with 300 words.",
    }


@pytest.fixture
def tool_use_raw() -> dict[str, Any]:
    return {
        "event": "tool_use",
        "crew_name": "ResearchCrew",
        "agent_role": "researcher",
        "execution_id": "abc123",
        "tool_name": "web_search",
        "tool_input": "latest AI news",
    }


@pytest.fixture
def delegation_raw() -> dict[str, Any]:
    return {
        "event": "delegation",
        "crew_name": "ResearchCrew",
        "execution_id": "abc123",
        "from_agent": "researcher",
        "to_agent": "writer",
        "task_description": "Write the report",
    }
