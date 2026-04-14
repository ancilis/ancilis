"""Tests for AncilisCallbackHandler."""

from __future__ import annotations

import threading
import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _make_handler(**kwargs) -> Any:
    from ancilis_langchain.handler import AncilisCallbackHandler
    return AncilisCallbackHandler(**kwargs)


def test_handler_instantiation():
    h = _make_handler(agent_id="test-agent")
    assert h._producer.agent_id == "test-agent"
    assert h._session_id is not None


def test_handler_session_id_passthrough():
    h = _make_handler(session_id="fixed-session")
    assert h._session_id == "fixed-session"
    assert h._producer.session_id == "fixed-session"


def test_on_llm_start_captures_action(run_id, serialized_llm):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_llm_start(serialized_llm, ["prompt text"], run_id=run_id)

    actions = h.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["event_type"] == "llm_start"
    assert actions[0].parameters.raw["prompt_count"] == 1


def test_on_llm_end_captures_token_usage(run_id, llm_result_dict):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_llm_end(llm_result_dict, run_id=run_id)

    actions = h.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["token_usage"]["total_tokens"] == 60


def test_on_tool_start_captures(run_id, serialized_tool):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_tool_start(serialized_tool, "my query", run_id=run_id)

    assert len(h.captured_actions) == 1
    assert h.captured_actions[0].tool.name == "duckduckgo_search"


def test_on_tool_end_captures(run_id):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_tool_end("result text", run_id=run_id)

    assert h.captured_actions[0].parameters.raw["output_length"] == len("result text")


def test_on_chain_start_captures_input_keys(run_id):
    h = _make_handler()
    serialized = {"id": ["langchain_core", "runnables", "RunnableSequence"], "name": "RunnableSequence"}
    with patch.object(h, "_submit"):
        h.on_chain_start(serialized, {"question": "q", "context": "c"}, run_id=run_id)

    assert h.captured_actions[0].parameters.raw["input_keys"] == ["question", "context"]


def test_on_chain_end_captures_output_keys(run_id):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_chain_end({"answer": "42"}, run_id=run_id)

    assert h.captured_actions[0].parameters.raw["output_keys"] == ["answer"]


def test_on_retriever_start_captures_query(run_id, serialized_retriever):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_retriever_start(serialized_retriever, "compliance docs", run_id=run_id)

    assert h.captured_actions[0].parameters.raw["query"] == "compliance docs"
    assert h.captured_actions[0].action_type == "data_access"


def test_on_retriever_end_captures_doc_count_not_content(run_id, mock_doc):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_retriever_end([mock_doc, mock_doc], run_id=run_id)

    params = h.captured_actions[0].parameters.raw
    assert params["document_count"] == 2
    # No raw content in captured evidence
    assert "Secret content" not in str(params)


def test_on_llm_error_captures(run_id):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_llm_error(ValueError("rate limit"), run_id=run_id)

    assert h.captured_actions[0].parameters.raw["event_type"] == "llm_error"


def test_on_tool_error_captures(run_id):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_tool_error(RuntimeError("tool failed"), run_id=run_id)

    assert "tool_error" == h.captured_actions[0].parameters.raw["event_type"]


def test_on_chain_error_captures(run_id):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_chain_error(RuntimeError("chain failed"), run_id=run_id)

    assert "chain_error" == h.captured_actions[0].parameters.raw["event_type"]


def test_on_retriever_error_captures(run_id, serialized_retriever):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_retriever_error(RuntimeError("index error"), run_id=run_id)

    assert "retriever_error" == h.captured_actions[0].parameters.raw["event_type"]


def test_submit_error_does_not_propagate(run_id, serialized_llm):
    """Engine errors must never break the application."""
    h = _make_handler()
    h._engine = MagicMock()
    h._engine.evaluate.side_effect = RuntimeError("engine exploded")

    # Should not raise
    h.on_llm_start(serialized_llm, ["prompt"], run_id=run_id)
    assert len(h.captured_actions) == 1


def test_thread_safety(run_id, serialized_tool):
    """Concurrent callbacks must not corrupt captured_actions."""
    h = _make_handler()
    errors: list[Exception] = []

    def fire_callback():
        try:
            with patch.object(h, "_submit"):
                h.on_tool_start(serialized_tool, "query", run_id=uuid.uuid4())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=fire_callback) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(h.captured_actions) == 20


def test_parent_run_id_propagates(run_id, parent_run_id, serialized_llm):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_llm_start(serialized_llm, ["hi"], run_id=run_id, parent_run_id=parent_run_id)

    action = h.captured_actions[0]
    assert action.context.parent_action_id == str(parent_run_id)


def test_captured_actions_returns_copy(run_id, serialized_tool):
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_tool_start(serialized_tool, "q", run_id=run_id)

    a = h.captured_actions
    b = h.captured_actions
    assert a is not b  # different list objects
    assert a == b


def test_llm_result_dict_passthrough(run_id, llm_result_dict):
    """When response is already a dict, it should not fail."""
    h = _make_handler()
    with patch.object(h, "_submit"):
        h.on_llm_end(llm_result_dict, run_id=run_id)

    assert len(h.captured_actions) == 1


def test_handler_without_engine_config(run_id, serialized_llm):
    """Handler works fine even if Ancilis config is not present."""
    h = _make_handler()
    # _get_engine returns None when config unavailable — should not crash
    with patch("ancilis_langchain.handler.AncilisCallbackHandler._get_engine", return_value=None):
        h.on_llm_start(serialized_llm, ["hi"], run_id=run_id)

    assert len(h.captured_actions) == 1
