"""Tests for LangChainProducer.translate()."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest


def test_translate_llm_start(serialized_llm, run_id, parent_run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer(agent_id="test-agent")
    raw = {
        "event_type": "llm_start",
        "serialized": serialized_llm,
        "prompts": ["Hello, world!", "Second prompt"],
        "run_id": run_id,
        "parent_run_id": parent_run_id,
    }
    action = producer.translate(raw)

    assert action.tool.name == "gpt-4o"
    assert action.tool.server == "langchain"
    assert action.agent_id == "test-agent"
    assert action.action_type == "tool_call"
    assert action.parameters.raw["event_type"] == "llm_start"
    assert action.parameters.raw["prompt_count"] == 2
    assert action.parameters.raw["run_id"] == str(run_id)
    assert action.parameters.raw["parent_run_id"] == str(parent_run_id)
    assert action.context.parent_action_id == str(parent_run_id)


def test_translate_llm_end(serialized_llm, run_id, llm_result_dict):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "llm_end",
        "response": llm_result_dict,
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    assert action.action_type == "tool_call"
    assert action.parameters.raw["event_type"] == "llm_end"
    token_usage = action.parameters.raw["token_usage"]
    assert token_usage["prompt_tokens"] == 42
    assert token_usage["completion_tokens"] == 18
    assert action.parameters.raw["model_name"] == "gpt-4o"
    assert action.context.parent_action_id is None


def test_translate_tool_start(serialized_tool, run_id, parent_run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "tool_start",
        "serialized": serialized_tool,
        "input_str": "search query",
        "run_id": run_id,
        "parent_run_id": parent_run_id,
    }
    action = producer.translate(raw)

    assert action.tool.name == "duckduckgo_search"
    assert action.action_type == "tool_call"
    assert action.parameters.raw["input_str"] == "search query"


def test_translate_tool_end(run_id, parent_run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "tool_end",
        "output": "search results here",
        "run_id": run_id,
        "parent_run_id": parent_run_id,
    }
    action = producer.translate(raw)

    assert action.parameters.raw["event_type"] == "tool_end"
    assert action.parameters.raw["output_length"] == len("search results here")


def test_translate_chain_start(serialized_llm, run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    chain_serialized = {
        "id": ["langchain_core", "runnables", "RunnableSequence"],
        "name": "RunnableSequence",
    }
    raw = {
        "event_type": "chain_start",
        "serialized": chain_serialized,
        "inputs": {"question": "What is 2+2?", "context": "math"},
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    assert action.tool.name == "RunnableSequence"
    assert action.parameters.raw["input_keys"] == ["question", "context"]


def test_translate_chain_end(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "chain_end",
        "outputs": {"answer": "4", "reasoning": "arithmetic"},
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    assert action.parameters.raw["output_keys"] == ["answer", "reasoning"]


def test_translate_retriever_start(serialized_retriever, run_id, parent_run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "retriever_start",
        "serialized": serialized_retriever,
        "query": "What are the compliance requirements?",
        "run_id": run_id,
        "parent_run_id": parent_run_id,
    }
    action = producer.translate(raw)

    assert action.action_type == "data_access"
    assert action.tool.name == "FAISSRetriever"
    assert action.parameters.raw["query"] == "What are the compliance requirements?"


def test_translate_retriever_end_metadata_only(run_id, mock_doc):
    """Verify retriever_end captures doc metadata but NOT page_content (privacy)."""
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "retriever_end",
        "documents": [mock_doc, mock_doc],
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    params = action.parameters.raw
    assert params["document_count"] == 2
    # Only metadata fields allowed
    for doc_meta in params["document_sources"]:
        assert "page_content" not in doc_meta
        assert "Secret content" not in str(doc_meta)
    assert params["document_sources"][0]["source"] == "doc.pdf"
    assert params["document_sources"][0]["page"] == 3


def test_translate_llm_error(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "llm_error",
        "error": "Rate limit exceeded",
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    assert action.action_type == "tool_call"
    assert action.parameters.raw["event_type"] == "llm_error"


def test_translate_unknown_event(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {"event_type": "custom_event", "run_id": run_id, "parent_run_id": None}
    action = producer.translate(raw)

    assert action.tool.name == "custom_event"
    assert action.action_type == "tool_call"


def test_input_str_truncated_at_512(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    long_input = "x" * 1000
    raw = {
        "event_type": "tool_start",
        "serialized": {"name": "mytool"},
        "input_str": long_input,
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    assert len(action.parameters.raw["input_str"]) == 512


def test_session_id_in_context(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer(session_id="my-session-123")
    raw = {
        "event_type": "chain_start",
        "serialized": {},
        "inputs": {},
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)

    assert action.context.session_id == "my-session-123"


def test_no_parent_run_id(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "llm_start",
        "serialized": {"kwargs": {"model_name": "gpt-4"}},
        "prompts": ["hi"],
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)
    assert action.context.parent_action_id is None
    assert "parent_run_id" not in action.parameters.raw


def test_parameter_hash_is_set(run_id):
    from ancilis_langchain._producer import LangChainProducer

    producer = LangChainProducer()
    raw = {
        "event_type": "chain_end",
        "outputs": {"out": "val"},
        "run_id": run_id,
        "parent_run_id": None,
    }
    action = producer.translate(raw)
    assert action.parameters.parameter_hash != ""
