"""Tests for LettaProducer.translate()."""

from __future__ import annotations

import hashlib

from conftest import MockUsageStatistics


def test_translate_assistant_message_sanitizes_content() -> None:
    """Message content must NEVER be stored raw — only role + length + sha256."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer(agent_id="ag-1", session_id="sess-1")
    secret = "user-revealed-something-sensitive-here"
    raw = {
        "kind": "assistant_message",
        "id": "m-1",
        "role": "assistant",
        "content": secret,
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.action_type == "tool_call"
    assert action.tool.server == "letta"
    assert action.tool.name == "letta:message:assistant"
    assert params["role"] == "assistant"
    assert params["content_length"] == len(secret)
    assert params["content_sha256"] == hashlib.sha256(secret.encode()).hexdigest()
    # Raw content must NOT appear anywhere.
    assert secret not in repr(params)


def test_translate_tool_call_message_sanitizes_arg_values() -> None:
    """Tool arg values arrive as a JSON string from Letta — never store raw."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    secret_value = "S3CRET-API-KEY"
    raw = {
        "kind": "tool_call_message",
        "id": "m-2",
        "tool_call": {
            "name": "fetch_data",
            "arguments": f'{{"api_key": "{secret_value}", "user_id": 1234}}',
            "tool_call_id": "tc-9",
        },
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.tool.name == "letta:tool:fetch_data"
    assert params["tool_name"] == "fetch_data"
    assert sorted(params["tool_arg_keys"]) == ["api_key", "user_id"]
    assert secret_value not in repr(params)
    assert "1234" not in params["tool_arg_value_hashes"]["user_id"]
    assert len(params["tool_arg_value_hashes"]["api_key"]) == 64


def test_translate_tool_return_message_captures_length_status_error() -> None:
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {
        "kind": "tool_return_message",
        "id": "m-3",
        "tool_call_id": "tc-9",
        "tool_call": {"name": "fetch_data"},
        "tool_return": "x" * 42,
        "status": "error",
        "stderr": ValueError("downstream failed"),
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["tool_name"] == "fetch_data"
    assert params["return_length"] == 42
    assert len(params["return_sha256"]) == 64
    assert params["status"] == "error"
    assert params["error_type"] == "ValueError"


def test_translate_reasoning_message_uses_reasoning_field() -> None:
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {
        "kind": "reasoning_message",
        "id": "m-4",
        "reasoning": "step one then step two",
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.tool.name == "letta:message:reasoning"
    assert params["role"] == "reasoning"
    assert params["content_length"] == len("step one then step two")
    assert "step one" not in repr(params)


def test_translate_archival_memory_create_sanitizes_content() -> None:
    """Archival memory writes must hash the text — never store user PII raw."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer(agent_id="ag-mem")
    pii = "User SSN is 123-45-6789 and email is leaks@example.com"
    raw = {
        "kind": "archival_memory_create",
        "id": "p-1",
        "agent_id": "ag-mem",
        "text": pii,
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.action_type == "data_access"
    assert action.tool.name == "letta:archival_memory:archival"
    assert params["content_length"] == len(pii)
    assert params["content_sha256"] == hashlib.sha256(pii.encode()).hexdigest()
    # The raw PII must NEVER appear in evidence.
    assert "123-45-6789" not in repr(params)
    assert "leaks@example.com" not in repr(params)


def test_translate_archival_memory_search_records_query_and_count() -> None:
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {
        "kind": "archival_memory_search",
        "id": "s-1",
        "query": "what is my SSN",
        "results": [{"id": "p-1"}, {"id": "p-2"}, {"id": "p-3"}],
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.action_type == "data_access"
    assert params["query_length"] == len("what is my SSN")
    assert "SSN" not in params["query_sha256"]  # hashed, not raw
    assert params["result_count"] == 3


def test_translate_core_memory_update_sanitizes_block_value() -> None:
    """Core memory updates must hash new_value — block content is highest-PII."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {
        "kind": "core_memory_update",
        "id": "cm-1",
        "block_label": "human",
        "new_value": "User name is Kevin Bauer, lives in Austin",
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.action_type == "data_access"
    assert action.tool.name == "letta:core_memory:human"
    assert params["block_label"] == "human"
    assert params["content_length"] == len("User name is Kevin Bauer, lives in Austin")
    assert "Kevin Bauer" not in repr(params)


def test_translate_usage_statistics_captured() -> None:
    """Token usage attached to a usage_statistics or message-level event."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {
        "kind": "usage_statistics",
        "usage_statistics": MockUsageStatistics(
            completion_tokens=44, prompt_tokens=100, total_tokens=144, step_count=2
        ),
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["usage"]["completion_tokens"] == 44
    assert params["usage"]["prompt_tokens"] == 100
    assert params["usage"]["total_tokens"] == 144


def test_translate_captures_correlators_agent_message_tool_call() -> None:
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer(session_id="sess-x")
    raw = {
        "kind": "tool_call_message",
        "id": "msg-1",
        "message_id": "msg-1",
        "tool_call_id": "tc-7",
        "agent_id": "ag-overridden",
        "model": "openai/gpt-4o",
        "parent_id": "msg-parent",
        "tool_call": {"name": "doit", "arguments": "{}"},
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert action.agent_id == "ag-overridden"
    assert action.context.session_id == "sess-x"
    assert action.context.parent_action_id == "msg-parent"
    assert params["tool_call_id"] == "tc-7"
    assert params["model"] == "openai/gpt-4o"
    assert params["parent_id"] == "msg-parent"


def test_translate_error_capture_for_non_tool_event() -> None:
    """Errors on non-tool-return events are still captured as error_type."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {
        "kind": "archival_memory_create",
        "id": "p-x",
        "text": "irrelevant",
        "error": RuntimeError("write failed - leak text"),
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["error_type"] == "RuntimeError"
    # Make sure the message body of the error is NOT echoed.
    assert "leak text" not in repr(params)


def test_translate_unknown_kind_falls_back_safely() -> None:
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    raw = {"kind": "weird_event", "id": "x", "name": "wat"}
    action = producer.translate(raw)

    assert action.action_type == "tool_call"
    assert action.tool.name == "letta:unknown:wat"
    assert action.parameters.raw["kind"] == "weird_event"


def test_translate_non_json_tool_arguments_fallback() -> None:
    """If tool_call.arguments is non-JSON, it's hashed under a __raw__ key."""
    from ancilis_letta._producer import LettaProducer

    producer = LettaProducer()
    secret = "this is not json - secret-token-abc"
    raw = {
        "kind": "tool_call_message",
        "id": "m-x",
        "tool_call": {"name": "thing", "arguments": secret},
    }
    action = producer.translate(raw)
    params = action.parameters.raw

    assert params["tool_arg_keys"] == ["__raw__"]
    assert secret not in repr(params)
    assert len(params["tool_arg_value_hashes"]["__raw__"]) == 64


def test_producer_metadata_is_framework() -> None:
    from ancilis_letta._producer import LettaProducer

    assert LettaProducer.producer_type == "framework"
    assert LettaProducer.producer_version == "0.1.0"

    action = LettaProducer().translate({"kind": "assistant_message", "content": "hi"})
    assert action.producer_type == "framework"
    assert action.producer_version == "0.1.0"
    assert action.source_type == "agent"
