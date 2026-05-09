"""Tests for ancilis_letta.recorder.record_response()."""

from __future__ import annotations

from unittest.mock import MagicMock

from conftest import (
    MockAssistantMessage,
    MockLettaResponse,
    MockToolCall,
    MockToolCallMessage,
    MockToolReturnMessage,
    MockUsageStatistics,
    MockUserMessage,
)


def test_record_response_with_object_records_each_message() -> None:
    """Pass a duck-typed LettaResponse object (the SDK's actual return type)."""
    from ancilis_letta import record_response

    response = MockLettaResponse(
        messages=[
            MockUserMessage(content="hello"),
            MockAssistantMessage(content="world"),
        ]
    )
    engine = MagicMock()
    store = MagicMock()
    actions = record_response(
        response, agent_id="ag-1", engine=engine, evidence_store=store
    )

    assert len(actions) == 2
    assert actions[0].agent_id == "ag-1"
    assert actions[0].parameters.raw["role"] == "user"
    assert actions[1].parameters.raw["role"] == "assistant"
    assert engine.evaluate.call_count == 2
    assert store.append.call_count == 2


def test_record_response_with_dict_works() -> None:
    """A plain dict shape (e.g. JSON-deserialised fixture) is supported."""
    from ancilis_letta import record_response

    response = {
        "messages": [
            {
                "kind": "tool_call_message",
                "id": "m-1",
                "tool_call": {
                    "name": "lookup",
                    "arguments": '{"q": "leaked-secret-do-not-store"}',
                },
            },
            {
                "kind": "tool_return_message",
                "id": "m-2",
                "tool_call": {"name": "lookup"},
                "tool_return": "result data",
            },
        ]
    }
    actions = record_response(response, agent_id="ag-1")

    assert len(actions) == 2
    assert actions[0].tool.name == "letta:tool:lookup"
    # No raw secret leaked.
    assert "leaked-secret-do-not-store" not in repr(
        [a.parameters.raw for a in actions]
    )


def test_record_response_multi_message_with_usage_tail() -> None:
    """A response with messages + usage produces an extra usage_statistics action."""
    from ancilis_letta import record_response

    response = MockLettaResponse(
        messages=[
            MockUserMessage(content="hi"),
            MockToolCallMessage(tool_call=MockToolCall()),
            MockToolReturnMessage(),
            MockAssistantMessage(content="done"),
        ],
        usage=MockUsageStatistics(
            completion_tokens=5, prompt_tokens=20, total_tokens=25, step_count=1
        ),
    )
    actions = record_response(response, agent_id="ag-1")

    # 4 messages + 1 usage tail
    assert len(actions) == 5
    last = actions[-1]
    assert last.tool.name == "letta:usage:usage_statistics"
    assert last.parameters.raw["usage"]["total_tokens"] == 25


def test_record_response_no_engine_no_store_is_noop_for_submission() -> None:
    """Without engine/store, record_response still returns translated actions."""
    from ancilis_letta import record_response

    response = MockLettaResponse(messages=[MockAssistantMessage(content="x")])
    actions = record_response(response, agent_id="ag-1")

    assert len(actions) == 1
    # No engine / store — and no exception. We just verified it works observe-only.


def test_record_response_session_id_threaded_through() -> None:
    from ancilis_letta import record_response

    response = MockLettaResponse(messages=[MockAssistantMessage(content="x")])
    actions = record_response(response, agent_id="ag-1", session_id="sess-fixed")

    assert actions[0].context.session_id == "sess-fixed"


def test_record_response_handles_empty_response() -> None:
    from ancilis_letta import record_response

    actions = record_response(MockLettaResponse(messages=[]), agent_id="ag-1")
    assert actions == []
