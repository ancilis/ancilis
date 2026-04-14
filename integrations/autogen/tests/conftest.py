"""Shared fixtures for ancilis-autogen tests."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Make package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# Minimal AutoGen stubs (no real pyautogen dependency in tests)
# ---------------------------------------------------------------------------


class _FakeAgent:
    """Minimal ConversableAgent stub with register_reply support."""

    def __init__(self, name: str = "assistant") -> None:
        self.name = name
        self._reply_funcs: list[Any] = []

    def register_reply(
        self,
        trigger: Any,
        reply_func: Any,
        position: int = 0,
        config: Any = None,
    ) -> None:
        self._reply_funcs.insert(position, (trigger, reply_func, config))

    def generate_reply(
        self,
        messages: list[dict[str, Any]],
        sender: Any = None,
    ) -> str | None:
        """Simulate reply generation — runs registered hooks first."""
        for _trigger, func, config in self._reply_funcs:
            handled, reply = func(self, messages, sender, config)
            if handled:
                return reply
        return "default reply"


class _FakeGroupChat:
    def __init__(self, agents: list[Any]) -> None:
        self.agents = agents
        self.messages: list[dict[str, Any]] = []


class _FakeGroupChatManager(_FakeAgent):
    def __init__(self, groupchat: _FakeGroupChat) -> None:
        super().__init__(name="GroupChatManager")
        self.groupchat = groupchat


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def agent() -> _FakeAgent:
    return _FakeAgent("assistant")


@pytest.fixture
def user_agent() -> _FakeAgent:
    return _FakeAgent("user_proxy")


@pytest.fixture
def groupchat(agent, user_agent) -> _FakeGroupChat:
    return _FakeGroupChat(agents=[agent, user_agent])


@pytest.fixture
def groupchat_manager(groupchat) -> _FakeGroupChatManager:
    return _FakeGroupChatManager(groupchat=groupchat)


@pytest.fixture
def simple_messages() -> list[dict[str, Any]]:
    return [
        {"role": "user", "content": "What is the weather today?", "name": "user_proxy"},
        {"role": "assistant", "content": "I'll check that for you.", "name": "assistant"},
    ]


@pytest.fixture
def function_call_messages() -> list[dict[str, Any]]:
    return [
        {
            "role": "assistant",
            "content": None,
            "function_call": {"name": "get_weather", "arguments": '{"city": "NYC"}'},
        }
    ]


@pytest.fixture
def tool_call_messages() -> list[dict[str, Any]]:
    return [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "type": "function",
                    "function": {"name": "search_web", "arguments": '{"query": "rain forecast"}'},
                }
            ],
        }
    ]
