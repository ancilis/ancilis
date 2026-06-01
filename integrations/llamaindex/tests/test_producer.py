"""Tests for LlamaIndexProducer.translate()."""

from __future__ import annotations


def test_translate_llm_chat_start(llm_chat_start_event, event_id, parent_id):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer(agent_id="test-agent")
    action = producer.translate(llm_chat_start_event)

    assert action.action_type == "tool_call"
    assert action.tool.name == "llama_index:llm:gpt-4o"
    assert action.tool.server == "llama_index"
    assert action.agent_id == "test-agent"
    assert action.action_id == event_id
    assert action.context.parent_action_id == parent_id
    assert action.parameters.raw["class_name"] == "LLMChatStartEvent"
    assert action.parameters.raw["event_kind"] == "llm"
    assert action.parameters.raw["lifecycle"] == "start"
    assert action.parameters.raw["model"] == "gpt-4o"
    assert action.parameters.raw["message_count"] == 2


def test_translate_llm_chat_end_captures_token_usage(llm_chat_end_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(llm_chat_end_event)

    usage = action.parameters.raw["token_usage"]
    assert usage["prompt_tokens"] == 42
    assert usage["completion_tokens"] == 18
    assert usage["total_tokens"] == 60
    assert action.parameters.raw["model"] == "gpt-4o"
    assert action.action_type == "tool_call"


def test_translate_llm_completion_aliases_to_llm():
    """LLMCompletionStartEvent should also map to event_kind=llm."""
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(
        {
            "class_name": "LLMCompletionStartEvent",
            "id_": "x",
            "model": "claude-3-5-sonnet",
            "prompt": "Hello!",
        }
    )
    assert action.tool.name == "llama_index:llm:claude-3-5-sonnet"
    assert action.parameters.raw["event_kind"] == "llm"
    assert action.parameters.raw["prompt_chars"] == len("Hello!")


def test_translate_embedding_start(embedding_start_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(embedding_start_event)

    assert action.action_type == "data_access"
    assert action.tool.name == "llama_index:embedding:text-embedding-3-small"
    assert action.parameters.raw["chunk_count"] == 3
    assert action.parameters.raw["event_kind"] == "embedding"


def test_translate_retrieval_start(retrieval_start_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(retrieval_start_event)

    assert action.action_type == "data_access"
    assert action.tool.name == "llama_index:retrieval:VectorStoreRetriever"
    assert action.parameters.raw["query"] == "What are the compliance requirements?"


def test_translate_retrieval_end_metadata_only(retrieval_end_event):
    """Retrieved nodes capture metadata but never raw text content."""
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(retrieval_end_event)

    params = action.parameters.raw
    assert params["node_count"] == 2
    assert "Secret content" not in str(params)
    sources = params["node_sources"]
    assert sources[0]["source"] == "doc.pdf"
    assert sources[0]["page"] == 3
    assert sources[0]["score"] == 0.91
    assert sources[0]["node_id"] == "node-abc"


def test_translate_agent_tool_call(agent_tool_call_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(agent_tool_call_event)

    assert action.action_type == "tool_call"
    assert action.tool.name == "llama_index:tool:duckduckgo_search"
    assert action.parameters.raw["tool_name"] == "duckduckgo_search"
    assert "ancilis" in action.parameters.raw["arguments_preview"]


def test_translate_agent_tool_call_truncates_arguments():
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    long_payload = "x" * 1000
    action = producer.translate(
        {
            "class_name": "AgentToolCallEvent",
            "id_": "x",
            "tool_name": "noisy_tool",
            "arguments": long_payload,
        }
    )
    assert len(action.parameters.raw["arguments_preview"]) == 512
    assert action.parameters.raw["arguments_length"] == 1000


def test_translate_query_start(query_start_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(query_start_event)

    assert action.action_type == "tool_call"
    assert action.tool.name == "llama_index:query:RouterQueryEngine"
    assert action.parameters.raw["query"] == "Summarise the policy doc"


def test_translate_query_end_captures_response_length():
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(
        {
            "class_name": "QueryEndEvent",
            "id_": "x",
            "query_engine_name": "RouterQueryEngine",
            "response": "This is the synthesised answer.",
        }
    )
    assert action.parameters.raw["response_length"] == len(
        "This is the synthesised answer."
    )


def test_translate_error_event_captures_error_type():
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(
        {
            "class_name": "LLMChatEndEvent",
            "id_": "x",
            "error": ValueError("rate limit"),
        }
    )
    assert action.parameters.raw["error"] == "rate limit"
    assert action.parameters.raw["error_type"] == "ValueError"


def test_translate_unknown_event_falls_back_to_tool_call():
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate({"class_name": "MysteryEvent", "id_": "x"})
    assert action.action_type == "tool_call"
    assert action.tool.name.startswith("llama_index:unknown:")
    assert action.parameters.raw["event_kind"] == "unknown"


def test_translate_session_id_propagates(llm_chat_start_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer(session_id="my-session-123")
    action = producer.translate(llm_chat_start_event)
    assert action.context.session_id == "my-session-123"


def test_translate_no_parent_id():
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(
        {"class_name": "LLMChatStartEvent", "id_": "x", "model": "m"}
    )
    assert action.context.parent_action_id is None


def test_parameter_hash_is_set(llm_chat_start_event):
    from ancilis_llamaindex._producer import LlamaIndexProducer

    producer = LlamaIndexProducer()
    action = producer.translate(llm_chat_start_event)
    assert action.parameters.parameter_hash != ""
    assert len(action.parameters.parameter_hash) == 16


def test_producer_metadata():
    from ancilis_llamaindex._producer import LlamaIndexProducer

    assert LlamaIndexProducer.producer_type == "framework"
    assert LlamaIndexProducer.producer_version == "0.1.0"


def test_producer_does_not_import_llama_index():
    """The producer module must never import llama_index at import time."""
    import sys

    # Force a fresh import path scan and ensure the producer module loads
    # without referencing llama_index. (The fixture stubs llama_index out for
    # the handler, but the producer should be untouched.)
    import ancilis_llamaindex._producer as producer_mod

    src = open(producer_mod.__file__).read()
    assert "import llama_index" not in src
    assert "from llama_index" not in src
