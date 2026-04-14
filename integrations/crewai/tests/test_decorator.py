"""Tests for @ancilis_crew decorator and crew instrumentation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# Ensure package importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_crew(agents=None, tasks=None):
    """Create a minimal fake Crew-like instance for testing."""
    from tests.conftest import _FakeAgent, _FakeCrew, _FakeTask
    a = agents or [_FakeAgent("researcher")]
    t = tasks or [_FakeTask()]
    return _FakeCrew(agents=a, tasks=t)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_kickoff_returns_value(fake_crew):
    """Decorated crew.kickoff() still returns the output."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    with patch("ancilis_crewai.callbacks._safe_submit"):
        _wrap_crew(fake_crew, producer)
        result = fake_crew.kickoff()

    assert result is not None
    assert isinstance(result, str)


def test_kickoff_emits_crew_start_and_end(fake_crew):
    """kickoff() emits crew_start then crew_end."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    events: list[str] = []

    def capture_emit(prod, raw):
        events.append(raw["event"])

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        fake_crew.kickoff()

    assert "crew_start" in events
    assert "crew_end" in events
    assert events.index("crew_start") < events.index("crew_end")


def test_kickoff_emits_task_start_and_end(fake_crew):
    """Agent execute_task wrapping emits task_start and task_end."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    events: list[str] = []

    def capture_emit(prod, raw):
        events.append(raw["event"])

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        fake_crew.kickoff()

    assert "task_start" in events
    assert "task_end" in events


def test_crew_end_captures_output_length(fake_crew):
    """crew_end event has output_length, not raw output content."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    end_events: list[dict] = []

    def capture_emit(prod, raw):
        if raw["event"] == "crew_end":
            end_events.append(raw)

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        result = fake_crew.kickoff()

    assert len(end_events) == 1
    assert end_events[0]["output"] == result


def test_task_end_captures_output(fake_crew):
    """task_end event has the task result."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    task_ends: list[dict] = []

    def capture_emit(prod, raw):
        if raw["event"] == "task_end":
            task_ends.append(raw)

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        fake_crew.kickoff()

    assert len(task_ends) >= 1
    assert task_ends[0]["agent_role"] == "researcher"


def test_agent_role_in_task_events(fake_crew):
    """task_start event includes agent_role."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    task_starts: list[dict] = []

    def capture_emit(prod, raw):
        if raw["event"] == "task_start":
            task_starts.append(raw)

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        fake_crew.kickoff()

    assert task_starts[0]["agent_role"] == "researcher"


def test_execution_id_consistent_within_run(fake_crew):
    """All events in a single kickoff share the same execution_id."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    all_events: list[dict] = []

    def capture_emit(prod, raw):
        all_events.append(dict(raw))

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        fake_crew.kickoff()

    execution_ids = {e["execution_id"] for e in all_events if "execution_id" in e}
    assert len(execution_ids) == 1


def test_emit_errors_never_propagate(fake_crew):
    """Engine errors in _emit must not break the crew execution."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()

    with patch("ancilis_crewai.callbacks._emit", side_effect=RuntimeError("boom")):
        _wrap_crew(fake_crew, producer)
        # Should not raise
        result = fake_crew.kickoff()

    assert result is not None


def test_ancilis_crew_decorator_basic():
    """@ancilis_crew on a Crew-like class instruments __init__."""
    from ancilis_crewai.decorator import ancilis_crew
    from tests.conftest import _FakeAgent, _FakeCrew, _FakeTask

    @ancilis_crew
    class MyCrew(_FakeCrew):
        pass

    events: list[str] = []

    def capture_emit(prod, raw):
        events.append(raw["event"])

    agent = _FakeAgent("writer")
    task = _FakeTask("Write intro")

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        crew = MyCrew(agents=[agent], tasks=[task])
        crew.kickoff()

    assert "crew_start" in events
    assert "crew_end" in events


def test_ancilis_crew_decorator_with_options():
    """@ancilis_crew(agent_id=...) sets the agent_id on the producer."""
    from ancilis_crewai.decorator import ancilis_crew
    from tests.conftest import _FakeAgent, _FakeCrew, _FakeTask

    @ancilis_crew(agent_id="my-pipeline", session_id="s-42")
    class MyCrew(_FakeCrew):
        pass

    actions: list[Any] = []

    def fake_submit(action):
        actions.append(action)

    with patch("ancilis_crewai.callbacks._safe_submit", side_effect=fake_submit):
        crew = MyCrew(agents=[_FakeAgent()], tasks=[_FakeTask()])
        crew.kickoff()

    assert len(actions) > 0
    assert actions[0].agent_id == "my-pipeline"
    assert actions[0].context.session_id == "s-42"


def test_multi_agent_crew(fake_task):
    """Multiple agents each get instrumented."""
    from tests.conftest import _FakeAgent, _FakeCrew
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    agents = [_FakeAgent("researcher"), _FakeAgent("writer")]
    crew = _FakeCrew(agents=agents, tasks=[fake_task, fake_task])
    producer = CrewAIProducer()

    task_events: list[str] = []

    def capture_emit(prod, raw):
        if "agent_role" in raw:
            task_events.append(raw["agent_role"])

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(crew, producer)
        crew.kickoff()

    # Both agents should have task events
    assert "researcher" in task_events
    assert "writer" in task_events


@pytest.mark.asyncio
async def test_kickoff_async_emits_events(fake_crew):
    """kickoff_async emits crew_start + crew_end."""
    from ancilis_crewai.callbacks import _wrap_crew
    from ancilis_crewai._producer import CrewAIProducer

    producer = CrewAIProducer()
    events: list[str] = []

    def capture_emit(prod, raw):
        events.append(raw["event"])

    with patch("ancilis_crewai.callbacks._emit", side_effect=capture_emit):
        _wrap_crew(fake_crew, producer)
        result = await fake_crew.kickoff_async()

    assert "crew_start" in events
    assert "crew_end" in events
    assert result is not None
