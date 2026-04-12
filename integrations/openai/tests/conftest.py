"""Shared fixtures for ancilis-openai tests."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

import pytest

# Make package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def _make_openai_stub() -> ModuleType:
    """Create a minimal openai stub for testing without the real package."""
    openai = MagicMock()
    openai.chat = MagicMock()
    openai.chat.completions = MagicMock()
    return openai


@pytest.fixture(autouse=True)
def reset_patch_state():
    """Ensure patch state is clean before and after each test."""
    import ancilis_openai.patch as patch_mod

    patch_mod._patched = False
    patch_mod._originals.clear()
    yield
    patch_mod._patched = False
    patch_mod._originals.clear()


@pytest.fixture
def openai_stub() -> Any:
    """Minimal openai stub installed in sys.modules."""
    stub = _make_openai_stub()
    sys.modules["openai"] = stub
    yield stub
    sys.modules.pop("openai", None)


@pytest.fixture
def response_dict() -> dict[str, Any]:
    return {
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 30,
            "completion_tokens": 15,
            "total_tokens": 45,
        },
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "content": "Hello from GPT-4o",
                    "tool_calls": [],
                },
            }
        ],
    }


@pytest.fixture
def tool_call_response_dict() -> dict[str, Any]:
    return {
        "model": "gpt-4o",
        "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "content": None,
                    "tool_calls": [
                        {"function": {"name": "get_weather", "arguments": '{"city": "NYC"}'}},
                        {"function": {"name": "search", "arguments": '{"query": "rain"}'}},
                    ],
                },
            }
        ],
    }


@pytest.fixture
def stream_chunks() -> list[Any]:
    """Fake streaming chunks."""
    chunks = []
    for i, word in enumerate(["Hello", " ", "world"]):
        ch = MagicMock()
        ch.choices = [MagicMock()]
        ch.choices[0].delta = MagicMock()
        ch.choices[0].delta.content = word
        ch.choices[0].delta.tool_calls = None
        ch.choices[0].finish_reason = "stop" if i == 2 else None
        chunks.append(ch)
    return chunks
