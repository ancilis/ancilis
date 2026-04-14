"""Tests for AutoGenProducer.translate()."""

from __future__ import annotations

import pytest


def test_translate_message_event():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer(agent_id="test-agent")
    raw = {
        "event": "message",
        "conversation_id": "conv-1",
        "sender_name": "assistant",
        "recipient_name": "user_proxy",
        "role": "assistant",
        "content": "Hello, how can I help you?",
        "message_index": 0,
    }
    action = producer.translate(raw)

    assert action.tool.name == "agent:assistant"
    assert action.tool.server == "autogen"
    assert action.agent_id == "test-agent"
    assert action.parameters.raw["event"] == "message"
    assert action.parameters.raw["sender_name"] == "assistant"
    assert action.parameters.raw["content_length"] == len("Hello, how can I help you?")
    assert "Hello, how can I help you?" not in str(action.parameters.raw)


def test_translate_function_call_event():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {
        "event": "function_call",
        "conversation_id": "conv-1",
        "function_name": "get_weather",
        "function_args": '{"city": "NYC"}',
    }
    action = producer.translate(raw)

    assert action.tool.name == "get_weather"
    assert action.parameters.raw["event"] == "function_call"
    assert action.parameters.raw["function_name"] == "get_weather"
    assert action.parameters.raw["function_args_preview"] == '{"city": "NYC"}'
    assert action.parameters.raw["function_args_length"] == len('{"city": "NYC"}')


def test_translate_function_call_truncates_long_args():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {
        "event": "function_call",
        "function_name": "big_func",
        "function_args": "x" * 1000,
        "conversation_id": "conv-1",
    }
    action = producer.translate(raw)
    assert len(action.parameters.raw["function_args_preview"]) == 512
    assert action.parameters.raw["function_args_length"] == 1000


def test_translate_function_result_event():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {
        "event": "function_result",
        "conversation_id": "conv-1",
        "function_name": "get_weather",
        "function_result": "Sunny, 72°F",
    }
    action = producer.translate(raw)

    assert action.tool.name == "get_weather"
    assert action.parameters.raw["event"] == "function_result"
    assert action.parameters.raw["result_length"] == len("Sunny, 72°F")
    assert "Sunny" not in str(action.parameters.raw)


def test_translate_conversation_end_event():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {
        "event": "conversation_end",
        "conversation_id": "conv-1",
        "turn_count": 8,
        "termination_reason": "max_turns_reached",
    }
    action = producer.translate(raw)

    assert action.tool.name == "conversation"
    assert action.parameters.raw["event"] == "conversation_end"
    assert action.parameters.raw["turn_count"] == 8
    assert action.parameters.raw["termination_reason"] == "max_turns_reached"


def test_session_id_in_context():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer(session_id="sess-xyz")
    raw = {"event": "message", "conversation_id": "c1", "sender_name": "a", "content": "hi"}
    action = producer.translate(raw)
    assert action.context.session_id == "sess-xyz"


def test_parameter_hash_set():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {"event": "message", "conversation_id": "c1", "sender_name": "a", "content": "x"}
    action = producer.translate(raw)
    assert action.parameters.parameter_hash != ""


def test_action_id_is_conversation_id():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {"event": "message", "conversation_id": "myconv", "sender_name": "a", "content": "x"}
    action = producer.translate(raw)
    assert action.action_id == "myconv"


def test_content_not_stored_in_params():
    """Message content never stored in params — only content_length."""
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {
        "event": "message",
        "conversation_id": "c1",
        "sender_name": "assistant",
        "content": "This is secret output",
        "role": "assistant",
    }
    action = producer.translate(raw)
    assert "content_length" in action.parameters.raw
    assert "This is secret output" not in str(action.parameters.raw)


def test_message_index_captured():
    from ancilis_autogen._producer import AutoGenProducer

    producer = AutoGenProducer()
    raw = {
        "event": "message",
        "conversation_id": "c1",
        "sender_name": "assistant",
        "content": "hi",
        "message_index": 5,
    }
    action = producer.translate(raw)
    assert action.parameters.raw["message_index"] == 5
