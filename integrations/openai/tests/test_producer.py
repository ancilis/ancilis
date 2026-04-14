"""Tests for OpenAIProducer.translate()."""

from __future__ import annotations

from typing import Any

import pytest


def test_translate_basic_response(response_dict):
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer(agent_id="test-agent")
    raw = {
        "event": "response",
        "model": "gpt-4o",
        "request": {"messages": [{"role": "user", "content": "hi"}], "temperature": 0.7},
        "response": response_dict,
    }
    action = producer.translate(raw)

    assert action.tool.name == "gpt-4o"
    assert action.tool.server == "openai"
    assert action.agent_id == "test-agent"
    assert action.parameters.raw["gen_ai.system"] == "openai"
    assert action.parameters.raw["gen_ai.request.model"] == "gpt-4o"
    assert action.parameters.raw["prompt_tokens"] == 30
    assert action.parameters.raw["completion_tokens"] == 15
    assert action.parameters.raw["total_tokens"] == 45
    assert action.parameters.raw["message_count"] == 1
    assert action.parameters.raw["finish_reason"] == "stop"
    assert action.parameters.raw["output_length"] == len("Hello from GPT-4o")


def test_translate_tool_call_response(tool_call_response_dict):
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {
        "event": "response",
        "model": "gpt-4o",
        "request": {"messages": [{"role": "user", "content": "weather?"}], "tools": [{}]},
        "response": tool_call_response_dict,
    }
    action = producer.translate(raw)

    assert action.parameters.raw["tool_call_count"] == 2
    assert action.parameters.raw["tool_names_called"] == ["get_weather", "search"]
    assert action.parameters.raw["has_tools"] is True
    assert action.parameters.raw["finish_reason"] == "tool_calls"


def test_translate_request_event():
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {
        "event": "request",
        "model": "gpt-4o-mini",
        "request": {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 100},
        "response": {},
    }
    action = producer.translate(raw)

    assert action.parameters.raw["event"] == "request"
    assert action.parameters.raw["max_tokens"] == 100
    # No usage keys in request events
    assert "prompt_tokens" not in action.parameters.raw


def test_translate_stream_complete():
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {
        "event": "stream_complete",
        "model": "gpt-4o",
        "request": {"messages": [], "stream": True},
        "response": {
            "model": "gpt-4o",
            "choices": [{"finish_reason": "stop", "message": {"content": "streamed!", "tool_calls": []}}],
            "usage": {},
        },
    }
    action = producer.translate(raw)

    assert action.parameters.raw["event"] == "stream_complete"
    assert action.parameters.raw["stream"] is True
    assert action.parameters.raw["finish_reason"] == "stop"


def test_translate_error_event():
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {
        "event": "error",
        "model": "gpt-4o",
        "request": {"messages": []},
        "response": {},
        "error": "Rate limit exceeded",
    }
    action = producer.translate(raw)

    assert action.parameters.raw["event"] == "error"
    assert action.parameters.raw["error"] == "Rate limit exceeded"


def test_translate_no_tool_calls_in_regular_response(response_dict):
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {"event": "response", "model": "gpt-4o", "request": {"messages": []}, "response": response_dict}
    action = producer.translate(raw)

    assert action.parameters.raw["tool_call_count"] == 0
    assert "tool_names_called" not in action.parameters.raw


def test_translate_has_tools_false_when_no_tools():
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {
        "event": "request",
        "model": "gpt-4o",
        "request": {"messages": [{"role": "user", "content": "hi"}]},
        "response": {},
    }
    action = producer.translate(raw)
    assert action.parameters.raw["has_tools"] is False


def test_parameter_hash_set(response_dict):
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {"event": "response", "model": "gpt-4o", "request": {"messages": []}, "response": response_dict}
    action = producer.translate(raw)
    assert action.parameters.parameter_hash != ""


def test_session_id_in_context():
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer(session_id="sess-123")
    raw = {"event": "request", "model": "gpt-4o", "request": {"messages": []}, "response": {}}
    action = producer.translate(raw)
    assert action.context.session_id == "sess-123"


def test_temperature_captured():
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {
        "event": "request",
        "model": "gpt-4o",
        "request": {"messages": [], "temperature": 0.3},
        "response": {},
    }
    action = producer.translate(raw)
    assert action.parameters.raw["temperature"] == 0.3


def test_content_length_not_content_itself(response_dict):
    """We capture output_length but not the actual content (privacy)."""
    from ancilis_openai._producer import OpenAIProducer

    producer = OpenAIProducer()
    raw = {"event": "response", "model": "gpt-4o", "request": {"messages": []}, "response": response_dict}
    action = producer.translate(raw)

    assert "output_length" in action.parameters.raw
    assert "Hello from GPT-4o" not in str(action.parameters.raw)
