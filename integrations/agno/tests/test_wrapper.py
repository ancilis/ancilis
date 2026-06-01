"""Tests for ancilis_agno.wrapper.wrap_agent / wrap_team."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from conftest import (
    MockAgent,
    MockKnowledge,
    MockMemory,
    MockMetrics,
    MockRunResponse,
    MockStreamEvent,
    MockTeam,
    MockTeamResponse,
    MockToolCall,
)


def test_wrap_agent_proxies_unknown_attributes() -> None:
    from ancilis_agno import wrap_agent

    agent = MockAgent()
    agent.role = "researcher"
    wrapped = wrap_agent(agent, agent_id="ag-1")
    assert wrapped.role == "researcher"


def test_agent_run_records_run_response_and_tool_calls() -> None:
    from ancilis_agno import wrap_agent

    response = MockRunResponse(
        id="r-1",
        content="hi",
        tools=[
            MockToolCall(
                tool_name="lookup",
                tool_args={"q": "leak-secret-A"},
                tool_call_id="tc-1",
            )
        ],
    )
    agent = MockAgent(response=response)
    engine = MagicMock()
    store = MagicMock()
    wrapped = wrap_agent(
        agent, agent_id="ag-1", engine=engine, evidence_store=store
    )
    out = wrapped.run("what's the weather?")
    assert out is response

    actions = wrapped.captured_actions
    # 1 RunResponse-level + 1 synthetic ToolCallCompleted = 2 actions.
    assert len(actions) == 2
    full = repr([a.parameters.raw for a in actions])
    assert "leak-secret-A" not in full
    assert engine.evaluate.call_count == 2
    assert store.append.call_count == 2


async def test_agent_arun_async_records() -> None:
    from ancilis_agno import wrap_agent

    response = MockRunResponse(id="r-async", content="async-hi")
    agent = MockAgent(response=response)
    wrapped = wrap_agent(agent, agent_id="ag-1")

    out = await wrapped.arun("question")
    assert out is response
    actions = wrapped.captured_actions
    assert len(actions) >= 1
    assert any(a.action_id == "r-async" for a in actions)


def test_agent_run_stream_emits_per_event_actions() -> None:
    from ancilis_agno import wrap_agent

    events = [
        MockStreamEvent(event="RunStarted", id="e1"),
        MockStreamEvent(
            event="ToolCallStarted",
            id="e2",
            tool_call=MockToolCall(
                tool_name="search",
                tool_args={"q": "stream-secret-XYZ"},
            ),
        ),
        MockStreamEvent(event="ToolCallCompleted", id="e3"),
        MockStreamEvent(
            event="RunResponse", id="e4", content="streamed answer", metrics=MockMetrics()
        ),
        MockStreamEvent(event="RunCompleted", id="e5"),
    ]
    agent = MockAgent(stream_events=events)
    wrapped = wrap_agent(agent, agent_id="ag-1")

    yielded = list(wrapped.run_stream("go"))
    assert len(yielded) == 5

    actions = wrapped.captured_actions
    assert len(actions) == 5
    kinds = [a.parameters.raw["kind"] for a in actions]
    assert kinds == [
        "RunStarted",
        "ToolCallStarted",
        "ToolCallCompleted",
        "RunResponse",
        "RunCompleted",
    ]
    assert "stream-secret-XYZ" not in repr([a.parameters.raw for a in actions])


def test_agent_run_exception_path_records_error_and_reraises() -> None:
    from ancilis_agno import wrap_agent

    err = RuntimeError("agno blew up")
    agent = MockAgent(run_exc=err)
    wrapped = wrap_agent(agent, agent_id="ag-1")
    with pytest.raises(RuntimeError, match="agno blew up"):
        wrapped.run("x")
    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["error_type"] == "RuntimeError"


def test_observe_only_mode_no_engine_no_store_still_captures() -> None:
    from ancilis_agno import wrap_agent

    agent = MockAgent(response=MockRunResponse(content="quiet"))
    wrapped = wrap_agent(agent, agent_id="ag-1")  # no engine, no store
    wrapped.run("hi")
    assert len(wrapped.captured_actions) >= 1


def test_memory_add_user_memory_sanitized_in_wrapper() -> None:
    from ancilis_agno import wrap_agent

    memory = MockMemory()
    agent = MockAgent(memory=memory)
    wrapped = wrap_agent(agent, agent_id="ag-1")

    pii = "User credit card 4111111111111111 stored persistently"
    wrapped.memory.add_user_memory(pii)

    # Underlying memory was actually called.
    assert memory.add_calls == [{"memory": pii}]
    # Evidence does NOT contain the raw PII.
    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].action_type == "data_access"
    assert actions[0].parameters.raw["content_length"] == len(pii)
    assert "4111111111111111" not in repr(actions[0].parameters.raw)


def test_knowledge_search_query_sanitized_in_wrapper() -> None:
    from ancilis_agno import wrap_agent

    knowledge = MockKnowledge()
    agent = MockAgent(knowledge=knowledge)
    wrapped = wrap_agent(agent, agent_id="ag-1")

    secret_query = "show me docs about ssn 999-00-9999 and email kevin@example.com"
    out = wrapped.knowledge.search(query=secret_query, limit=3, filters={"team": "ops"})
    assert len(out) == 2

    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].action_type == "data_access"
    rendered = repr(actions[0].parameters.raw)
    assert "999-00-9999" not in rendered
    assert "kevin@example.com" not in rendered
    # Filter VALUES never leak — only filter KEYS recorded.
    assert "ops" not in rendered
    assert "team" in rendered  # the key is fine to record


def test_team_run_records_team_plus_per_member_actions() -> None:
    from ancilis_agno import wrap_team

    members = [
        MockRunResponse(id="m1-run", agent_id="researcher", content="research"),
        MockRunResponse(id="m2-run", agent_id="writer", content="draft"),
    ]
    members[0].member_name = "researcher"
    members[1].member_name = "writer"
    team = MockTeam(response=MockTeamResponse(member_responses=members))
    wrapped = wrap_team(team, agent_id="team-1")

    wrapped.run("write a memo")
    actions = wrapped.captured_actions
    # 1 team-level + 2 member-level = 3 actions.
    assert len(actions) == 3

    team_action = actions[0]
    assert team_action.action_type == "tool_call"

    member_actions = actions[1:]
    member_names = [a.parameters.raw.get("member_name") for a in member_actions]
    assert sorted(member_names) == ["researcher", "writer"]
    # Each member action carries member_name in evidence_data.
    for a in member_actions:
        assert a.tool.name.startswith("agno:member:")
        assert a.parameters.raw["kind"] == "MemberRunCompleted"


async def test_team_arun_records_per_member() -> None:
    from ancilis_agno import wrap_team

    members = [MockRunResponse(id="m1-run", agent_id="researcher")]
    members[0].member_name = "researcher"
    team = MockTeam(response=MockTeamResponse(member_responses=members))
    wrapped = wrap_team(team, agent_id="team-1")

    await wrapped.arun("delegate this")
    actions = wrapped.captured_actions
    assert any(
        a.parameters.raw.get("member_name") == "researcher" for a in actions
    )


def test_pii_never_appears_in_repr_for_memory_and_knowledge() -> None:
    """Cross-surface PII smoke test: SSN + email never leak through wrapper."""
    from ancilis_agno import wrap_agent

    memory = MockMemory()
    knowledge = MockKnowledge()
    agent = MockAgent(memory=memory, knowledge=knowledge)
    wrapped = wrap_agent(agent, agent_id="ag-1")

    ssn = "123-45-6789"
    email = "ceo@example.com"

    wrapped.memory.add_user_memory(f"User SSN is {ssn}")
    wrapped.memory.update_session_summary(f"Sent invoice to {email}")
    wrapped.knowledge.search(query=f"docs mentioning {ssn} or {email}")
    wrapped.knowledge.add(documents=[{"text": f"private: {ssn}"}])

    rendered = repr([a.parameters.raw for a in wrapped.captured_actions])
    assert ssn not in rendered
    assert email not in rendered
