"""Tests for AncilisConversationLogger."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_attach_registers_reply_hook(agent):
    """attach() registers a reply hook on the agent."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    logger.attach(agent)
    assert len(agent._reply_funcs) == 1


def test_attach_idempotent(agent):
    """Attaching the same agent twice only registers once."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    logger.attach(agent)
    logger.attach(agent)
    assert len(agent._reply_funcs) == 1


def test_reply_hook_returns_false_none(agent, simple_messages):
    """The reply hook always returns (False, None) to not block normal replies."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()

    with patch("ancilis_autogen.logger._emit"):
        logger.attach(agent)

    _trigger, hook_func, config = agent._reply_funcs[0]
    handled, reply = hook_func(agent, simple_messages, None, config)
    assert handled is False
    assert reply is None


def test_hook_emits_message_event(agent, simple_messages):
    """Reply hook emits a message event for the last message."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    emitted: list[dict] = []

    def capture(prod, raw):
        emitted.append(dict(raw))

    with patch("ancilis_autogen.logger._emit", side_effect=capture):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        hook_func(agent, simple_messages, None, config)

    assert len(emitted) >= 1
    assert emitted[0]["event"] == "message"


def test_hook_emits_function_call_for_function_call_message(agent, function_call_messages):
    """A message with function_call triggers both message and function_call events."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    emitted: list[dict] = []

    def capture(prod, raw):
        emitted.append(dict(raw))

    with patch("ancilis_autogen.logger._emit", side_effect=capture):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        hook_func(agent, function_call_messages, None, config)

    events = [e["event"] for e in emitted]
    assert "message" in events
    assert "function_call" in events


def test_hook_emits_function_call_for_tool_calls(agent, tool_call_messages):
    """A message with tool_calls also emits function_call events."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    emitted: list[dict] = []

    def capture(prod, raw):
        emitted.append(dict(raw))

    with patch("ancilis_autogen.logger._emit", side_effect=capture):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        hook_func(agent, tool_call_messages, None, config)

    events = [e["event"] for e in emitted]
    assert "function_call" in events
    fc = next(e for e in emitted if e["event"] == "function_call")
    assert fc["function_name"] == "search_web"


def test_message_index_increments(agent, simple_messages):
    """message_index increments across successive hook calls."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    indices: list[int] = []

    def capture(prod, raw):
        if raw["event"] == "message":
            indices.append(raw["message_index"])

    with patch("ancilis_autogen.logger._emit", side_effect=capture):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        hook_func(agent, [simple_messages[0]], None, config)
        hook_func(agent, [simple_messages[1]], None, config)

    assert indices == [0, 1]


def test_conversation_id_consistent(agent, simple_messages):
    """All events from a single logger share the same conversation_id."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    conv_ids: set[str] = set()

    def capture(prod, raw):
        conv_ids.add(raw["conversation_id"])

    with patch("ancilis_autogen.logger._emit", side_effect=capture):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        hook_func(agent, [simple_messages[0]], None, config)
        hook_func(agent, [simple_messages[1]], None, config)

    assert len(conv_ids) == 1


def test_attach_all_instruments_groupchat_agents(groupchat_manager, groupchat):
    """attach_all() instruments all agents in the GroupChatManager."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    with patch("ancilis_autogen.logger._emit"):
        logger.attach_all(groupchat_manager)

    for a in groupchat.agents:
        assert len(a._reply_funcs) >= 1


def test_log_conversation_end(agent):
    """log_conversation_end() emits a conversation_end event."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()
    emitted: list[dict] = []

    def capture(prod, raw):
        emitted.append(dict(raw))

    with patch("ancilis_autogen.logger._emit", side_effect=capture):
        logger.log_conversation_end(turn_count=10, reason="max_turns")

    assert len(emitted) == 1
    assert emitted[0]["event"] == "conversation_end"
    assert emitted[0]["turn_count"] == 10
    assert emitted[0]["termination_reason"] == "max_turns"


def test_emit_errors_never_propagate(agent, simple_messages):
    """Errors in _emit must not propagate to the agent's reply pipeline."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger()

    with patch("ancilis_autogen.logger._emit", side_effect=RuntimeError("boom")):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        # Should not raise
        handled, reply = hook_func(agent, simple_messages, None, config)

    assert handled is False
    assert reply is None


def test_no_hook_if_no_register_reply():
    """Gracefully handles agents without register_reply (non-standard agents)."""
    from ancilis_autogen.logger import AncilisConversationLogger

    class BareAgent:
        name = "bare"
        # No register_reply

    logger = AncilisConversationLogger()
    bare = BareAgent()
    # Should not raise
    logger.attach(bare)
    assert bare not in logger._attached_agents


def test_agent_id_propagated_to_actions(agent, simple_messages):
    """agent_id passed to logger is propagated through producer to Action."""
    from ancilis_autogen.logger import AncilisConversationLogger

    logger = AncilisConversationLogger(agent_id="pipeline-42")
    actions: list[Any] = []

    with patch("ancilis_autogen.logger._safe_submit", side_effect=actions.append):
        logger.attach(agent)
        _trigger, hook_func, config = agent._reply_funcs[0]
        hook_func(agent, [simple_messages[0]], None, config)

    assert len(actions) > 0
    assert actions[0].agent_id == "pipeline-42"
