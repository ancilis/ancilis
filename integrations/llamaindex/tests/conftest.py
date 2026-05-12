"""Shared test fixtures for ancilis-llamaindex tests."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Make the package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Provide a minimal llama_index stub if the framework isn't installed. Tests
# never depend on real llama_index — they pass duck-typed dicts directly.
if "llama_index" not in sys.modules:
    try:
        import llama_index  # noqa: F401
    except ImportError:
        stub = MagicMock()
        stub.core.instrumentation.event_handlers.BaseEventHandler = object
        sys.modules["llama_index"] = stub
        sys.modules["llama_index.core"] = stub.core
        sys.modules["llama_index.core.instrumentation"] = stub.core.instrumentation
        sys.modules["llama_index.core.instrumentation.event_handlers"] = (
            stub.core.instrumentation.event_handlers
        )


@pytest.fixture
def event_id() -> str:
    return "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def parent_id() -> str:
    return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def llm_chat_start_event(event_id, parent_id) -> dict[str, Any]:
    return {
        "class_name": "LLMChatStartEvent",
        "id_": event_id,
        "parent_id": parent_id,
        "timestamp": "2026-05-09T12:00:00Z",
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi"},
        ],
    }


@pytest.fixture
def llm_chat_end_event(event_id) -> dict[str, Any]:
    return {
        "class_name": "LLMChatEndEvent",
        "id_": event_id,
        "parent_id": None,
        "timestamp": "2026-05-09T12:00:01Z",
        "response": {
            "raw": {
                "model": "gpt-4o",
                "usage": {
                    "prompt_tokens": 42,
                    "completion_tokens": 18,
                    "total_tokens": 60,
                },
            }
        },
    }


@pytest.fixture
def embedding_start_event(event_id) -> dict[str, Any]:
    return {
        "class_name": "EmbeddingStartEvent",
        "id_": event_id,
        "model": "text-embedding-3-small",
        "chunks": ["chunk one", "chunk two", "chunk three"],
    }


@pytest.fixture
def retrieval_start_event(event_id) -> dict[str, Any]:
    return {
        "class_name": "RetrievalStartEvent",
        "id_": event_id,
        "retriever_name": "VectorStoreRetriever",
        "str_or_query_bundle": "What are the compliance requirements?",
    }


class _FakeInnerNode:
    def __init__(self) -> None:
        self.metadata = {"source": "doc.pdf", "page": 3}
        self.id_ = "node-abc"
        self.text = "Secret content that must not appear in evidence"


class _FakeNodeWithScore:
    def __init__(self) -> None:
        self.node = _FakeInnerNode()
        self.metadata = self.node.metadata
        self.score = 0.91


@pytest.fixture
def mock_node() -> Any:
    return _FakeNodeWithScore()


@pytest.fixture
def retrieval_end_event(event_id, mock_node) -> dict[str, Any]:
    return {
        "class_name": "RetrievalEndEvent",
        "id_": event_id,
        "retriever_name": "VectorStoreRetriever",
        "nodes": [mock_node, mock_node],
    }


@pytest.fixture
def agent_tool_call_event(event_id, parent_id) -> dict[str, Any]:
    return {
        "class_name": "AgentToolCallEvent",
        "id_": event_id,
        "parent_id": parent_id,
        "tool_name": "duckduckgo_search",
        "arguments": {"query": "ancilis runtime"},
    }


@pytest.fixture
def query_start_event(event_id) -> dict[str, Any]:
    return {
        "class_name": "QueryStartEvent",
        "id_": event_id,
        "query_engine_name": "RouterQueryEngine",
        "query": "Summarise the policy doc",
    }


class FakeEvent:
    """Duck-typed pydantic-like event with a ``dict()`` method."""

    def __init__(self, payload: dict[str, Any], class_name: str | None = None) -> None:
        self._payload = payload
        if class_name is not None:
            self._payload.setdefault("class_name", class_name)

    def dict(self) -> dict[str, Any]:
        return dict(self._payload)


@pytest.fixture
def fake_event_factory():
    return FakeEvent
