"""Tests for ancilis_pydantic_ai.wrapper.wrap_agent()."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from conftest import MockAgent, MockRunResult, MockStreamEvent, MockUsage


def test_wrap_agent_proxies_attribute_access() -> None:
    from ancilis_pydantic_ai import wrap_agent

    agent = MockAgent(existing_attr="hello-from-inner")
    wrapped = wrap_agent(agent)

    # Attribute proxying via __getattr__
    assert wrapped.existing_attr == "hello-from-inner"

    # Attribute set proxies through to the underlying agent
    wrapped.new_attr = "set-on-wrapped"
    assert agent.new_attr == "set-on-wrapped"


async def test_run_records_evidence_with_engine_and_store() -> None:
    from ancilis_pydantic_ai import wrap_agent

    engine = MagicMock()
    store = MagicMock()
    agent = MockAgent(result=MockRunResult(data="abc", model="openai:gpt-4o"))
    wrapped = wrap_agent(agent, agent_id="ag", engine=engine, evidence_store=store)

    result = await wrapped.run("hello?")

    assert result.data == "abc"
    assert agent.run_calls == [(("hello?",), {})]

    # Exactly one Action was recorded for the run.
    actions = wrapped.captured_actions
    assert len(actions) == 1
    action = actions[0]
    assert action.action_type == "tool_call"
    assert action.parameters.raw["kind"] == "run_result"
    assert action.parameters.raw["model"] == "openai:gpt-4o"
    assert action.parameters.raw["usage"]["total_tokens"] == 15

    engine.evaluate.assert_called_once()
    store.append.assert_called_once()


def test_run_sync_records_evidence() -> None:
    from ancilis_pydantic_ai import wrap_agent

    store = MagicMock()
    agent = MockAgent(result=MockRunResult(data="sync result", model="m1"))
    wrapped = wrap_agent(agent, evidence_store=store)

    result = wrapped.run_sync("prompt")

    assert result.data == "sync result"
    assert len(wrapped.captured_actions) == 1
    action = wrapped.captured_actions[0]
    assert action.parameters.raw["model"] == "m1"
    assert action.parameters.raw["output_length"] == len("sync result")
    store.append.assert_called_once()


async def test_run_exception_records_error_then_reraises() -> None:
    from ancilis_pydantic_ai import wrap_agent

    engine = MagicMock()
    agent = MockAgent(run_exc=RuntimeError("agent boom"))
    wrapped = wrap_agent(agent, engine=engine)

    with pytest.raises(RuntimeError, match="agent boom"):
        await wrapped.run("trigger")

    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["kind"] == "run_result"
    assert actions[0].parameters.raw["error_type"] == "RuntimeError"
    engine.evaluate.assert_called_once()


def test_run_sync_exception_records_error_then_reraises() -> None:
    from ancilis_pydantic_ai import wrap_agent

    agent = MockAgent(sync_exc=ValueError("sync boom"))
    wrapped = wrap_agent(agent)

    with pytest.raises(ValueError, match="sync boom"):
        wrapped.run_sync("trigger")

    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["error_type"] == "ValueError"


def test_observe_only_when_engine_and_store_are_none() -> None:
    """With no engine and no store, run still records the Action locally."""
    from ancilis_pydantic_ai import wrap_agent

    agent = MockAgent()
    wrapped = wrap_agent(agent)  # engine=None, evidence_store=None

    result = wrapped.run_sync("hi")

    assert result is not None
    actions = wrapped.captured_actions
    assert len(actions) == 1
    # Nothing else to assert — we just verified that observe-only works without crash.


def test_engine_failure_does_not_break_run() -> None:
    from ancilis_pydantic_ai import wrap_agent

    engine = MagicMock()
    engine.evaluate.side_effect = RuntimeError("engine exploded")
    agent = MockAgent()
    wrapped = wrap_agent(agent, engine=engine)

    # Should NOT raise
    result = wrapped.run_sync("hi")
    assert result is not None
    assert len(wrapped.captured_actions) == 1


async def test_iter_records_each_stream_event() -> None:
    from ancilis_pydantic_ai import wrap_agent

    events = [
        MockStreamEvent(kind="model_response", event_id="e1", model="openai:gpt-4o"),
        MockStreamEvent(
            kind="function_tool_call",
            event_id="e2",
            tool_name="lookup",
            tool_args={"q": "secret-query-value"},
        ),
        MockStreamEvent(
            kind="function_tool_result",
            event_id="e3",
            tool_name="lookup",
            output="result-bytes",
        ),
        MockStreamEvent(
            kind="final_result",
            event_id="e4",
            model="openai:gpt-4o",
            output="final",
        ),
    ]
    agent = MockAgent(iter_events=events)
    wrapped = wrap_agent(agent)

    seen = []
    async for ev in wrapped.iter("user prompt"):
        seen.append(ev)

    assert len(seen) == 4
    actions = wrapped.captured_actions
    assert len(actions) == 4

    # Tool-call event must NOT leak the raw value.
    tool_call_action = actions[1]
    params = tool_call_action.parameters.raw
    assert params["kind"] == "function_tool_call"
    assert params["tool_arg_keys"] == ["q"]
    assert "secret-query-value" not in repr(params)


def test_wrap_agent_session_id_default_is_unique() -> None:
    from ancilis_pydantic_ai import wrap_agent

    a = wrap_agent(MockAgent())
    b = wrap_agent(MockAgent())
    assert a._producer.session_id != b._producer.session_id


def test_wrap_agent_session_id_passthrough() -> None:
    from ancilis_pydantic_ai import wrap_agent

    wrapped = wrap_agent(MockAgent(), session_id="fixed-sess")
    assert wrapped._producer.session_id == "fixed-sess"

    result = wrapped.run_sync("p")  # noqa: F841
    action = wrapped.captured_actions[0]
    assert action.context.session_id == "fixed-sess"


def test_exports_from_package_root() -> None:
    """wrap_agent, PydanticAIProducer, __version__ are all exported."""
    import ancilis_pydantic_ai

    assert hasattr(ancilis_pydantic_ai, "wrap_agent")
    assert hasattr(ancilis_pydantic_ai, "PydanticAIProducer")
    assert ancilis_pydantic_ai.__version__ == "0.1.0"
