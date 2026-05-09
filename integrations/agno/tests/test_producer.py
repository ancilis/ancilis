"""Tests for ancilis_agno._producer.AgnoProducer.translate()."""

from __future__ import annotations

import hashlib

from ancilis_agno import AgnoProducer


def _producer() -> AgnoProducer:
    return AgnoProducer(agent_id="ag-1", session_id="sess-1")


def test_run_response_event_maps_to_tool_call() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "RunResponse",
            "id": "run-7",
            "content": "hello world",
            "model": "claude-sonnet-4",
        }
    )
    assert action.action_type == "tool_call"
    assert action.tool.name.startswith("agno:run:")
    assert action.tool.server == "agno"
    assert action.action_id == "run-7"
    assert action.parameters.raw["semantic_kind"] == "run"
    # Content sanitized: length + sha256 only, no raw text.
    assert action.parameters.raw["content_length"] == len("hello world")
    assert (
        action.parameters.raw["content_sha256"]
        == hashlib.sha256(b"hello world").hexdigest()
    )
    assert "hello world" not in repr(action.parameters.raw)


def test_run_started_and_completed_events_map_to_tool_call() -> None:
    p = _producer()
    started = p.translate({"kind": "RunStarted", "id": "r1"})
    completed = p.translate({"kind": "RunCompleted", "id": "r1"})
    assert started.action_type == "tool_call"
    assert completed.action_type == "tool_call"
    assert started.parameters.raw["kind"] == "RunStarted"
    assert completed.parameters.raw["kind"] == "RunCompleted"


def test_tool_call_started_sanitizes_args() -> None:
    p = _producer()
    secret = "ssn=999-00-0000 user@example.com"
    action = p.translate(
        {
            "kind": "ToolCallStarted",
            "id": "tc-evt",
            "tool_call_id": "tc-99",
            "tool_call": {
                "tool_name": "send_email",
                "tool_args": {"to": "user@example.com", "body": secret},
            },
        }
    )
    assert action.action_type == "tool_call"
    assert action.tool.name == "agno:tool:send_email"
    assert action.parameters.raw["tool_arg_keys"] == ["body", "to"]
    # Raw values must NOT appear anywhere in evidence.
    rendered = repr(action.parameters.raw)
    assert "999-00-0000" not in rendered
    assert "user@example.com" not in rendered
    # Hash of the secret value is recorded.
    expected_body_hash = hashlib.sha256(repr(secret).encode()).hexdigest()
    assert action.parameters.raw["tool_arg_value_hashes"]["body"] == expected_body_hash


def test_tool_call_completed_records_result_hash_and_error_type() -> None:
    p = _producer()
    err = ValueError("boom")
    action = p.translate(
        {
            "kind": "ToolCallCompleted",
            "tool_call": {"tool_name": "math", "tool_args": {"x": 1}, "result": "42"},
            "error": err,
        }
    )
    assert action.parameters.raw["result_length"] == 2
    assert (
        action.parameters.raw["result_sha256"]
        == hashlib.sha256(b"42").hexdigest()
    )
    assert action.parameters.raw["error_type"] == "ValueError"


def test_member_run_started_completed_team_delegation() -> None:
    p = _producer()
    started = p.translate(
        {
            "kind": "MemberRunStarted",
            "id": "mrs-1",
            "member_name": "researcher",
            "member_agent_id": "agent-research",
        }
    )
    completed = p.translate(
        {
            "kind": "MemberRunCompleted",
            "id": "mrc-1",
            "member_name": "writer",
            "content": "draft",
        }
    )
    assert started.tool.name == "agno:member:researcher"
    assert started.parameters.raw["member_name"] == "researcher"
    assert started.parameters.raw["member_agent_id"] == "agent-research"
    assert completed.tool.name == "agno:member:writer"
    assert completed.parameters.raw["content_length"] == len("draft")


def test_memory_add_user_memory_sanitizes_text() -> None:
    p = _producer()
    pii = "User's SSN is 999-00-1234"
    action = p.translate(
        {"kind": "add_user_memory", "memory_text": pii, "id": "mem-evt-1"}
    )
    assert action.action_type == "data_access"
    assert action.tool.name == "agno:memory:add-user-memory"
    assert action.parameters.raw["content_length"] == len(pii)
    assert (
        action.parameters.raw["content_sha256"]
        == hashlib.sha256(pii.encode()).hexdigest()
    )
    # No raw PII anywhere in the params dict's repr.
    assert "999-00-1234" not in repr(action.parameters.raw)


def test_memory_update_session_summary_data_access() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "update_session_summary",
            "memory_text": "the user is a fan of jazz",
            "session_id": "s-99",
        }
    )
    assert action.action_type == "data_access"
    assert action.parameters.raw["session_id"] == "s-99"
    assert "jazz" not in repr(action.parameters.raw)


def test_memory_search_user_memories_query_sanitized() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "search_user_memories",
            "query": "what did the user say about credit card 4111111111111111",
            "results": [{"id": "m1"}, {"id": "m2"}],
        }
    )
    assert action.action_type == "data_access"
    assert action.parameters.raw["query_length"] > 0
    assert action.parameters.raw["result_count"] == 2
    # PII-like substring in the query must NOT survive into evidence.
    assert "4111111111111111" not in repr(action.parameters.raw)


def test_knowledge_search_with_filters_records_filter_keys_only() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "knowledge_search",
            "query": "Q3 revenue",
            "limit": 5,
            "filters": {"department": "finance", "year": 2026},
            "results": [{"id": "d1"}],
        }
    )
    assert action.action_type == "data_access"
    assert action.tool.name == "agno:knowledge:search"
    assert action.parameters.raw["limit"] == 5
    assert action.parameters.raw["filter_keys"] == ["department", "year"]
    assert action.parameters.raw["result_count"] == 1
    # The filter VALUES (e.g. department="finance") must NOT leak.
    assert "finance" not in repr(action.parameters.raw)


def test_knowledge_add_records_document_count_only() -> None:
    p = _producer()
    docs = [{"text": "secret-doc-1"}, {"text": "secret-doc-2"}, {"text": "secret-doc-3"}]
    action = p.translate({"kind": "knowledge_add", "documents": docs})
    assert action.action_type == "data_access"
    assert action.parameters.raw["document_count"] == 3
    # Document content never appears in evidence.
    assert "secret-doc" not in repr(action.parameters.raw)


def test_knowledge_update_records_document_count_only() -> None:
    p = _producer()
    docs = [{"text": "x"}, {"text": "y"}]
    action = p.translate({"kind": "knowledge_update", "documents": docs})
    assert action.action_type == "data_access"
    assert action.tool.name == "agno:knowledge:update"
    assert action.parameters.raw["document_count"] == 2


def test_token_metrics_capture_from_run_response() -> None:
    p = _producer()
    action = p.translate(
        {
            "kind": "RunCompleted",
            "metrics": {
                "time_to_first_token": 0.42,
                "total_tokens": 1024,
                "tokens_per_second": 60.0,
                "input_tokens": 800,
                "output_tokens": 224,
            },
            "model": "claude-sonnet-4",
        }
    )
    assert action.parameters.raw["metrics"]["time_to_first_token"] == 0.42
    assert action.parameters.raw["metrics"]["total_tokens"] == 1024
    assert action.parameters.raw["metrics"]["tokens_per_second"] == 60.0
    assert action.parameters.raw["metrics"]["input_tokens"] == 800


def test_unknown_event_falls_back_to_tool_call() -> None:
    p = _producer()
    action = p.translate({"kind": "WeirdNewEvent", "id": "x-1"})
    assert action.action_type == "tool_call"
    assert action.parameters.raw["semantic_kind"] == "unknown"
    assert action.tool.server == "agno"


def test_producer_metadata_fields() -> None:
    assert AgnoProducer.producer_type == "framework"
    assert AgnoProducer.producer_version == "0.1.0"
    p = _producer()
    action = p.translate({"kind": "RunResponse", "id": "x"})
    assert action.producer_type == "framework"
    assert action.producer_version == "0.1.0"
    assert action.context.session_id == "sess-1"


def test_tool_args_as_json_string_is_sanitized() -> None:
    """Tool args may arrive as a JSON string — must still be parsed and hashed."""
    p = _producer()
    action = p.translate(
        {
            "kind": "ToolCallStarted",
            "tool_call": {
                "tool_name": "exfil",
                "tool_args": '{"secret": "supersecret-token-xyz"}',
            },
        }
    )
    assert action.parameters.raw["tool_arg_keys"] == ["secret"]
    assert "supersecret-token-xyz" not in repr(action.parameters.raw)
