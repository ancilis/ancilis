"""Tests for AncilisEventHandler."""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock


def _make_handler(**kwargs) -> Any:
    from ancilis_llamaindex.handler import AncilisEventHandler

    return AncilisEventHandler(**kwargs)


def test_handler_instantiation_observe_only():
    h = _make_handler(agent_id="test-agent")
    assert h._producer.agent_id == "test-agent"
    assert h._session_id is not None
    assert h._engine is None
    assert h._evidence_store is None


def test_class_name_static_identifier():
    from ancilis_llamaindex.handler import AncilisEventHandler

    assert AncilisEventHandler.class_name() == "AncilisEventHandler"


def test_handle_dict_event_captures_action(llm_chat_start_event):
    h = _make_handler()
    h.handle(llm_chat_start_event)

    actions = h.captured_actions
    assert len(actions) == 1
    assert actions[0].tool.name == "llama_index:llm:gpt-4o"


def test_handle_pydantic_like_event(fake_event_factory, llm_chat_end_event):
    """Events exposing .dict() should also be captured."""
    h = _make_handler()
    h.handle(fake_event_factory(llm_chat_end_event))

    actions = h.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["token_usage"]["total_tokens"] == 60


def test_handle_object_with_attrs():
    """Events that are plain objects with __dict__ should still translate."""
    h = _make_handler()

    class _Event:
        class_name = "AgentToolCallEvent"
        id_ = "evt-99"
        tool_name = "calculator"
        arguments = {"x": 1}

    h.handle(_Event())
    assert h.captured_actions[0].tool.name == "llama_index:tool:calculator"


def test_handle_with_engine_evaluates(llm_chat_start_event):
    engine = MagicMock()
    engine.evaluate.return_value = MagicMock(name="EvaluationResult")
    h = _make_handler(engine=engine)
    h.handle(llm_chat_start_event)

    engine.evaluate.assert_called_once()
    submitted = engine.evaluate.call_args[0][0]
    assert submitted.tool.name == "llama_index:llm:gpt-4o"


def test_handle_with_engine_and_store_persists(llm_chat_start_event):
    engine = MagicMock()
    eval_result = MagicMock(name="EvaluationResult")
    engine.evaluate.return_value = eval_result
    store = MagicMock()
    h = _make_handler(engine=engine, evidence_store=store)
    h.handle(llm_chat_start_event)

    store.store.assert_called_once()
    args, kwargs = store.store.call_args
    assert args[0] is eval_result
    assert "llama_index:llm:gpt-4o" in args


def test_store_skipped_when_engine_returns_none(llm_chat_start_event):
    """If engine.evaluate returns None, the store must not be called."""
    engine = MagicMock()
    engine.evaluate.return_value = None
    store = MagicMock()
    h = _make_handler(engine=engine, evidence_store=store)
    h.handle(llm_chat_start_event)

    store.store.assert_not_called()


def test_store_only_no_engine(llm_chat_start_event):
    """An evidence_store without an engine is a no-op (no evaluation to store)."""
    store = MagicMock()
    h = _make_handler(evidence_store=store)
    h.handle(llm_chat_start_event)

    # No engine → nothing to store; store stays untouched.
    store.store.assert_not_called()
    # But the action is still captured for inspection.
    assert len(h.captured_actions) == 1


def test_handle_engine_error_does_not_propagate(llm_chat_start_event):
    """Engine.evaluate raising must never crash the handler."""
    engine = MagicMock()
    engine.evaluate.side_effect = RuntimeError("engine exploded")
    h = _make_handler(engine=engine)
    h.handle(llm_chat_start_event)  # should not raise

    assert len(h.captured_actions) == 1


def test_handle_translation_error_does_not_propagate():
    """A bogus event must not crash the handler — log + continue."""
    h = _make_handler()

    class _BoomEvent:
        class_name = "LLMChatStartEvent"

        def dict(self):  # noqa: D401
            raise RuntimeError("bad event")

        @property
        def __dict__(self):  # type: ignore[override]
            raise RuntimeError("no vars")

    # Should not raise
    h.handle(_BoomEvent())


def test_thread_safety(llm_chat_start_event):
    h = _make_handler()
    errors: list[Exception] = []

    def fire():
        try:
            h.handle(dict(llm_chat_start_event))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=fire) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(h.captured_actions) == 20


def test_captured_actions_returns_copy(llm_chat_start_event):
    h = _make_handler()
    h.handle(llm_chat_start_event)

    a = h.captured_actions
    b = h.captured_actions
    assert a is not b
    assert a == b


def test_session_id_passthrough(llm_chat_start_event):
    h = _make_handler(session_id="fixed-session")
    h.handle(llm_chat_start_event)

    assert h._session_id == "fixed-session"
    assert h.captured_actions[0].context.session_id == "fixed-session"
