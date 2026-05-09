"""Tests for ancilis_letta.wrapper.wrap_client()."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from conftest import (
    MockAgents,
    MockArchivalMemory,
    MockAssistantMessage,
    MockCoreMemory,
    MockLettaClient,
    MockLettaResponse,
    MockMessages,
    MockPassage,
    MockToolCall,
    MockToolCallMessage,
    MockToolReturnMessage,
    MockUsageStatistics,
    MockUserMessage,
)


def test_wrap_client_proxies_unknown_attributes() -> None:
    from ancilis_letta import wrap_client

    client = MockLettaClient()
    wrapped = wrap_client(client, agent_id="ag-1")

    assert wrapped.api_version == "v1"
    assert wrapped.health() == {"ok": True}


def test_messages_create_records_each_message_and_usage() -> None:
    from ancilis_letta import wrap_client

    response = MockLettaResponse(
        messages=[
            MockUserMessage(content="hello"),
            MockToolCallMessage(
                tool_call=MockToolCall(
                    name="send_message",
                    arguments='{"message": "hi", "private": "secret-leaked-payload"}',
                )
            ),
            MockToolReturnMessage(tool_return="done"),
            MockAssistantMessage(content="world"),
        ],
        usage=MockUsageStatistics(),
    )
    client = MockLettaClient(MockAgents(messages=MockMessages(response=response)))
    engine = MagicMock()
    store = MagicMock()
    wrapped = wrap_client(client, agent_id="ag-1", engine=engine, evidence_store=store)

    out = wrapped.agents.messages.create(
        agent_id="ag-1", messages=[{"role": "user", "content": "hello"}]
    )
    assert out is response

    actions = wrapped.captured_actions
    # 4 messages + 1 usage_statistics tail
    assert len(actions) == 5
    # No raw secret should appear in any captured action.
    full = repr([a.parameters.raw for a in actions])
    assert "secret-leaked-payload" not in full
    assert engine.evaluate.call_count == 5
    assert store.append.call_count == 5


def test_archival_memory_create_records_data_access() -> None:
    from ancilis_letta import wrap_client

    archival = MockArchivalMemory()
    client = MockLettaClient(MockAgents(archival_memory=archival))
    wrapped = wrap_client(client, agent_id="ag-1")

    pii_text = "User SSN is 999-00-0000"
    result = wrapped.agents.archival_memory.create(agent_id="ag-1", text=pii_text)
    assert isinstance(result, MockPassage)
    assert archival.create_calls == [{"agent_id": "ag-1", "text": pii_text}]

    actions = wrapped.captured_actions
    assert len(actions) == 1
    action = actions[0]
    assert action.action_type == "data_access"
    # Tool name uses the new memory_id when available (more informative than
    # the bare "archival" label).
    assert action.tool.name.startswith("letta:archival_memory:")
    assert "999-00-0000" not in repr(action.parameters.raw)
    assert action.parameters.raw["content_length"] == len(pii_text)


def test_archival_memory_search_records_query_and_count() -> None:
    from ancilis_letta import wrap_client

    archival = MockArchivalMemory(
        search_results=[MockPassage(id="p1"), MockPassage(id="p2")]
    )
    client = MockLettaClient(MockAgents(archival_memory=archival))
    wrapped = wrap_client(client, agent_id="ag-1")

    results = wrapped.agents.archival_memory.search(agent_id="ag-1", query="my email")
    assert len(results) == 2

    actions = wrapped.captured_actions
    assert len(actions) == 1
    params = actions[0].parameters.raw
    assert params["kind"] == "archival_memory_search"
    assert params["result_count"] == 2
    assert params["query_length"] == len("my email")
    assert "email" not in params["query_sha256"]


def test_archival_memory_update_records_data_access() -> None:
    from ancilis_letta import wrap_client

    archival = MockArchivalMemory()
    client = MockLettaClient(MockAgents(archival_memory=archival))
    wrapped = wrap_client(client, agent_id="ag-1")

    wrapped.agents.archival_memory.update(
        agent_id="ag-1", memory_id="p-77", text="updated content"
    )

    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["kind"] == "archival_memory_update"
    assert actions[0].action_type == "data_access"


def test_core_memory_update_records_data_access_with_block_label() -> None:
    from ancilis_letta import wrap_client

    core = MockCoreMemory()
    client = MockLettaClient(MockAgents(core_memory=core))
    wrapped = wrap_client(client, agent_id="ag-1")

    pii = "User name is Kevin Bauer"
    wrapped.agents.core_memory.update(
        agent_id="ag-1", block_label="human", new_value=pii
    )

    actions = wrapped.captured_actions
    assert len(actions) == 1
    params = actions[0].parameters.raw
    assert params["kind"] == "core_memory_update"
    assert params["block_label"] == "human"
    assert params["content_length"] == len(pii)
    assert "Kevin Bauer" not in repr(params)


def test_observe_only_when_no_engine_or_store() -> None:
    """Without engine/store, the wrapper still translates and captures actions."""
    from ancilis_letta import wrap_client

    response = MockLettaResponse(messages=[MockAssistantMessage(content="hi")])
    client = MockLettaClient(MockAgents(messages=MockMessages(response=response)))
    wrapped = wrap_client(client, agent_id="ag-1")  # no engine, no store

    wrapped.agents.messages.create(agent_id="ag-1", messages=[])

    assert len(wrapped.captured_actions) == 1


def test_messages_create_exception_records_error_then_reraises() -> None:
    from ancilis_letta import wrap_client

    client = MockLettaClient(
        MockAgents(messages=MockMessages(create_exc=RuntimeError("boom")))
    )
    wrapped = wrap_client(client, agent_id="ag-1")

    with pytest.raises(RuntimeError, match="boom"):
        wrapped.agents.messages.create(agent_id="ag-1", messages=[])

    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["error_type"] == "RuntimeError"


def test_engine_failure_does_not_break_call() -> None:
    """If engine.evaluate explodes, the wrapped call still succeeds."""
    from ancilis_letta import wrap_client

    engine = MagicMock()
    engine.evaluate.side_effect = RuntimeError("engine exploded")
    response = MockLettaResponse(messages=[MockAssistantMessage(content="hi")])
    client = MockLettaClient(MockAgents(messages=MockMessages(response=response)))
    wrapped = wrap_client(client, agent_id="ag-1", engine=engine)

    # Should NOT raise
    wrapped.agents.messages.create(agent_id="ag-1", messages=[])
    assert len(wrapped.captured_actions) == 1


def test_session_id_default_is_unique_and_passthrough() -> None:
    from ancilis_letta import wrap_client

    a = wrap_client(MockLettaClient(), agent_id="ag-a")
    b = wrap_client(MockLettaClient(), agent_id="ag-b")
    assert a._producer.session_id != b._producer.session_id

    fixed = wrap_client(MockLettaClient(), agent_id="ag-c", session_id="fixed")
    assert fixed._producer.session_id == "fixed"


def test_streaming_records_each_event() -> None:
    """create_stream yields events that each become an Action."""
    from ancilis_letta import wrap_client

    events = [
        MockUserMessage(content="hi"),
        MockToolCallMessage(),
        MockToolReturnMessage(),
        MockAssistantMessage(content="bye"),
    ]
    client = MockLettaClient(
        MockAgents(messages=MockMessages(stream_events=events))
    )
    wrapped = wrap_client(client, agent_id="ag-1")

    seen = list(wrapped.agents.messages.create_stream(agent_id="ag-1"))
    assert len(seen) == 4
    assert len(wrapped.captured_actions) == 4
