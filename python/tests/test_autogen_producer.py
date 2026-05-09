"""Tests for AutoGenActionProducer (send / receive hooks + attach)."""

from __future__ import annotations

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.autogen import (
    AutoGenActionProducer,
    AutoGenEvent,
    _agent_name,
    _serializable_message,
)
from ancilis.producers.protocol import ActionProducer, ProducerType


def _config() -> object:
    raw = {"agent": {"name": "ag-agent", "owner": "test-owner"}}
    return load_config(raw=raw)


def _make() -> tuple[AutoGenActionProducer, EvidenceStore]:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    return AutoGenActionProducer(config=config, engine=Engine(config), evidence_store=store), store


class _AgentLike:
    def __init__(self, name: str) -> None:
        self.name = name


class _RegisterHookAgent:
    """Stand-in for AutoGen's ConversableAgent (newer register_hook API)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._hooks: dict[str, list] = {}

    def register_hook(self, hookable_method: str, hook) -> None:
        self._hooks.setdefault(hookable_method, []).append(hook)


class _HookListsAgent:
    """Stand-in for AutoGen's older ``hook_lists`` dict-based API."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.hook_lists: dict[str, list] = {}


class _BareAgent:
    """Stand-in with neither register_hook nor hook_lists — fallback path."""

    def __init__(self, name: str) -> None:
        self.name = name


class TestAgentName:
    def test_uses_name_attribute(self) -> None:
        assert _agent_name(_AgentLike("alice"), "fb") == "alice"

    def test_falls_back_when_no_name(self) -> None:
        class NoName:
            def __str__(self) -> str:
                return "stringified"

        assert _agent_name(NoName(), "fb") == "stringified"

    def test_fallback_when_none(self) -> None:
        assert _agent_name(None, "fb") == "fb"


class TestSerializableMessage:
    def test_primitives_pass_through(self) -> None:
        assert _serializable_message("hi") == "hi"
        assert _serializable_message(42) == 42

    def test_dict_recurses(self) -> None:
        msg = {"role": "user", "content": "hello"}
        assert _serializable_message(msg) == msg

    def test_list_recurses(self) -> None:
        msgs = [{"role": "user"}, {"role": "assistant"}]
        assert _serializable_message(msgs) == msgs


class TestProducerProtocol:
    def test_satisfies_protocol(self) -> None:
        producer, _ = _make()
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    def test_translate_send_event(self) -> None:
        producer, _ = _make()
        action = producer.translate(
            AutoGenEvent(kind="send", sender="alice", recipient="bob", message={"role": "user", "content": "hi"})
        )
        assert action.tool.name == "autogen:send:alice->bob"
        assert action.action_type == "api_request"
        assert action.agent_id == "alice"


class TestSendReceiveHooks:
    def test_send_hook_records_and_returns_message(self) -> None:
        producer, store = _make()
        hook = producer.send_hook("alice")
        result = hook(
            sender=_AgentLike("alice"),
            message={"role": "user", "content": "hello"},
            recipient=_AgentLike("bob"),
            silent=False,
        )
        assert result == {"role": "user", "content": "hello"}
        assert store.get_summary()["total_evaluations"] == 1

    def test_receive_hook_extracts_last_message(self) -> None:
        producer, store = _make()
        hook = producer.receive_hook("bob")
        messages = [
            {"role": "user", "name": "alice", "content": "hi"},
            {"role": "assistant", "name": "bob", "content": "hello back"},
        ]
        result = hook(messages=messages)
        assert result == messages
        assert store.get_summary()["total_evaluations"] == 1

    def test_receive_hook_handles_empty_messages(self) -> None:
        producer, _ = _make()
        hook = producer.receive_hook("bob")
        # Should not raise even with empty/None
        hook(messages=[])
        hook(messages=None)


class TestAttach:
    def test_attach_uses_register_hook_when_available(self) -> None:
        producer, store = _make()
        agent = _RegisterHookAgent("alice")
        registered = producer.attach(agent)
        assert "process_message_before_send" in registered
        assert "process_last_received_message" in registered
        assert "process_message_before_send" in agent._hooks
        assert "process_last_received_message" in agent._hooks
        agent._hooks["process_message_before_send"][0](
            sender=_AgentLike("alice"),
            message="hi",
            recipient=_AgentLike("bob"),
            silent=False,
        )
        assert store.get_summary()["total_evaluations"] == 1

    def test_attach_uses_hook_lists_fallback(self) -> None:
        producer, store = _make()
        agent = _HookListsAgent("alice")
        registered = producer.attach(agent)
        assert "process_message_before_send" in registered
        assert agent.hook_lists["process_message_before_send"]
        agent.hook_lists["process_message_before_send"][0](
            sender=_AgentLike("alice"),
            message="hi",
            recipient=_AgentLike("bob"),
            silent=False,
        )
        assert store.get_summary()["total_evaluations"] == 1

    def test_attach_uses_attribute_fallback(self) -> None:
        producer, store = _make()
        agent = _BareAgent("alice")
        registered = producer.attach(agent)
        assert "process_message_before_send" in registered
        # Hook is now an attribute on the agent
        agent.process_message_before_send(  # type: ignore[attr-defined]
            sender=_AgentLike("alice"),
            message="hi",
            recipient=_AgentLike("bob"),
            silent=False,
        )
        assert store.get_summary()["total_evaluations"] == 1


class TestExportFromPackage:
    def test_lazy_re_export(self) -> None:
        from ancilis import producers as p

        assert p.AutoGenActionProducer is AutoGenActionProducer
        assert p.AutoGenEvent is AutoGenEvent
