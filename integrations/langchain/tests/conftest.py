"""Shared test fixtures for ancilis-langchain tests."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Make the package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Provide a minimal langchain_core stub if langchain-core is not installed
try:
    import langchain_core  # noqa: F401
except ImportError:
    # Create a minimal stub so tests can run without the full dep
    langchain_core_stub = MagicMock()
    langchain_core_stub.callbacks.base.BaseCallbackHandler = object
    langchain_core_stub.outputs.LLMResult = dict
    sys.modules["langchain_core"] = langchain_core_stub
    sys.modules["langchain_core.callbacks"] = langchain_core_stub.callbacks
    sys.modules["langchain_core.callbacks.base"] = langchain_core_stub.callbacks.base
    sys.modules["langchain_core.outputs"] = langchain_core_stub.outputs


@pytest.fixture
def run_id() -> uuid.UUID:
    return uuid.UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def parent_run_id() -> uuid.UUID:
    return uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


@pytest.fixture
def serialized_llm() -> dict[str, Any]:
    return {
        "id": ["langchain", "chat_models", "openai", "ChatOpenAI"],
        "name": "ChatOpenAI",
        "kwargs": {"model_name": "gpt-4o", "temperature": 0.7},
    }


@pytest.fixture
def serialized_tool() -> dict[str, Any]:
    return {
        "id": ["langchain", "tools", "DuckDuckGoSearchRun"],
        "name": "duckduckgo_search",
    }


@pytest.fixture
def serialized_retriever() -> dict[str, Any]:
    return {
        "id": ["langchain", "vectorstores", "FAISS"],
        "name": "FAISSRetriever",
    }


@pytest.fixture
def llm_result_dict() -> dict[str, Any]:
    return {
        "llm_output": {
            "token_usage": {
                "prompt_tokens": 42,
                "completion_tokens": 18,
                "total_tokens": 60,
            },
            "model_name": "gpt-4o",
        },
        "generations": [[{"text": "Hello world", "generation_info": None}]],
    }


@pytest.fixture
def mock_doc() -> Any:
    """A fake Document-like object with metadata."""
    doc = MagicMock()
    doc.metadata = {"source": "doc.pdf", "page": 3}
    doc.page_content = "Secret content that must not appear in evidence"
    return doc
