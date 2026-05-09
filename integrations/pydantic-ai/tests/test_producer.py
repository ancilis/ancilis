"""Tests for PydanticAIProducer.translate()."""

from __future__ import annotations

import hashlib
from typing import Any


def test_translate_model_response_captures_model_and_usage() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer(agent_id="test-agent")
    raw = {
        "kind": "model_response",
        "event_id": "evt-1",
        "model": "openai:gpt-4o",
        "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16},
    }
    action = producer.translate(raw)

    assert action.action_type == "tool_call"
    assert action.tool.name == "pydantic_ai:model_response:openai:gpt-4o"
    assert action.tool.server == "pydantic-ai"
    assert action.agent_id == "test-agent"
    assert action.parameters.raw["model"] == "openai:gpt-4o"
    assert action.parameters.raw["usage"]["total_tokens"] == 16


def test_translate_function_tool_call_sanitizes_arg_values() -> None:
    """Tool arg values must NEVER be stored raw; only key names + sha256 hashes."""
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    secret = "S3CRET-API-KEY-do-not-leak"
    raw = {
        "kind": "function_tool_call",
        "event_id": "evt-2",
        "tool_name": "fetch_data",
        "tool_args": {"api_key": secret, "user_id": 12345},
    }
    action = producer.translate(raw)

    params = action.parameters.raw
    assert params["kind"] == "function_tool_call"
    assert params["tool_name"] == "fetch_data"
    assert sorted(params["tool_arg_keys"]) == ["api_key", "user_id"]

    # Raw values must NOT appear anywhere in the params payload.
    serialized = repr(params)
    assert secret not in serialized
    assert "12345" not in params["tool_arg_value_hashes"]["user_id"]

    # Hash should be sha256 of repr(value).
    expected = hashlib.sha256(repr(secret).encode("utf-8", "replace")).hexdigest()
    assert params["tool_arg_value_hashes"]["api_key"] == expected
    # And it should be a 64-char hex digest.
    assert len(params["tool_arg_value_hashes"]["user_id"]) == 64


def test_translate_function_tool_call_with_complex_pydantic_payload_sanitized() -> None:
    """A typical Pydantic-AI tool may receive a Pydantic model in tool_args."""
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    class _FakeModel:
        def __repr__(self) -> str:  # noqa: D401
            return "FakeModel(ssn='000-00-0000', balance=99.5)"

    producer = PydanticAIProducer()
    raw = {
        "kind": "function_tool_call",
        "event_id": "evt-3",
        "tool_name": "process_account",
        "tool_args": {"account": _FakeModel()},
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["tool_arg_keys"] == ["account"]
    # The repr() string contains '000-00-0000' but the digest must obfuscate it.
    assert "000-00-0000" not in repr(params)
    assert "ssn" not in repr(params["tool_arg_value_hashes"])
    assert len(params["tool_arg_value_hashes"]["account"]) == 64


def test_translate_function_tool_result_captures_output_length_and_error() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    raw = {
        "kind": "function_tool_result",
        "event_id": "evt-4",
        "tool_name": "fetch_data",
        "output": "the result body x" * 4,
        "error": ValueError("boom"),
    }
    action = producer.translate(raw)

    params = action.parameters.raw
    assert params["tool_name"] == "fetch_data"
    assert params["output_length"] == len("the result body x" * 4)
    assert params["error_type"] == "ValueError"


def test_translate_final_result() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    raw = {
        "kind": "final_result",
        "event_id": "evt-5",
        "model": "openai:gpt-4o",
        "tool_name": "final_tool",
        "output": "final answer text",
    }
    action = producer.translate(raw)

    assert action.action_type == "tool_call"
    assert action.tool.name.endswith(":openai:gpt-4o")
    assert action.parameters.raw["output_length"] == len("final answer text")
    assert action.parameters.raw["tool_name"] == "final_tool"


def test_translate_run_result_with_usage_object() -> None:
    """Usage may arrive as an object with attributes, not a dict."""
    from ancilis_pydantic_ai._producer import PydanticAIProducer
    from conftest import MockUsage

    producer = PydanticAIProducer()
    raw = {
        "kind": "run_result",
        "event_id": "evt-6",
        "model": "openai:gpt-4o-mini",
        "usage": MockUsage(input_tokens=11, output_tokens=22, total_tokens=33),
        "output": "hello",
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["model"] == "openai:gpt-4o-mini"
    assert params["usage"]["input_tokens"] == 11
    assert params["usage"]["output_tokens"] == 22
    assert params["usage"]["total_tokens"] == 33
    assert params["output_length"] == len("hello")


def test_translate_run_result_with_error_dict() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    raw = {
        "kind": "run_result",
        "event_id": "evt-7",
        "model": "openai:gpt-4o",
        "error": {"type": "RateLimitError", "message": "leaked-message-do-not-store"},
    }
    action = producer.translate(raw)

    assert action.parameters.raw["error_type"] == "RateLimitError"
    # Make sure the message body is NOT echoed into params.
    assert "leaked-message-do-not-store" not in repr(action.parameters.raw)


def test_translate_unknown_kind_falls_back() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    raw = {"kind": "weird_event", "event_id": "evt-8", "tool_name": "x"}
    action = producer.translate(raw)

    assert action.action_type == "tool_call"
    assert action.tool.name == "pydantic_ai:weird_event:x"
    assert action.parameters.raw["kind"] == "weird_event"


def test_session_id_and_parent_event_id_preserved() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer(session_id="sess-123")
    raw = {
        "kind": "function_tool_call",
        "event_id": "evt-child",
        "parent_event_id": "evt-parent",
        "tool_name": "do_thing",
        "tool_args": {"k": "v"},
    }
    action = producer.translate(raw)

    assert action.context.session_id == "sess-123"
    assert action.context.parent_action_id == "evt-parent"
    assert action.parameters.raw["parent_event_id"] == "evt-parent"


def test_parameter_hash_is_set_and_stable() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    raw: dict[str, Any] = {
        "kind": "model_response",
        "event_id": "evt-9",
        "model": "openai:gpt-4o",
    }
    action_a = producer.translate(raw)
    action_b = producer.translate(raw)

    assert action_a.parameters.parameter_hash != ""
    # Same input → same hash (event_id is deterministic here)
    assert action_a.parameters.parameter_hash == action_b.parameters.parameter_hash


def test_function_tool_call_with_no_args() -> None:
    """Missing tool_args should produce empty keys/value_hashes, not crash."""
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    raw = {
        "kind": "function_tool_call",
        "event_id": "evt-10",
        "tool_name": "no_args_tool",
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["tool_arg_keys"] == []
    assert params["tool_arg_value_hashes"] == {}


def test_producer_metadata_is_framework() -> None:
    from ancilis_pydantic_ai._producer import PydanticAIProducer

    producer = PydanticAIProducer()
    assert PydanticAIProducer.producer_type == "framework"
    assert PydanticAIProducer.producer_version == "0.1.0"

    raw = {"kind": "run_result", "event_id": "x", "model": "m"}
    action = producer.translate(raw)
    assert action.producer_type == "framework"
    assert action.producer_version == "0.1.0"
    assert action.source_type == "agent"
