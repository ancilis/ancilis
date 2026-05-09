"""Tests for LangChainActionProducer + LangChainCallbackHandler."""

from __future__ import annotations

from uuid import uuid4

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.langchain import (
    LangChainActionProducer,
    LangChainCallbackHandler,
    LangChainEvent,
    _name_from_serialized,
)
from ancilis.producers.protocol import ActionProducer, ProducerType


def _config(*, mode: str = "audit") -> object:
    raw = {"agent": {"name": "lc-agent", "owner": "test-owner"}, "security": {"mode": mode}}
    return load_config(raw=raw)


def _make_producer(mode: str = "audit") -> tuple[LangChainActionProducer, EvidenceStore]:
    config = _config(mode=mode)
    store = EvidenceStore(config, in_memory=True)
    producer = LangChainActionProducer(config=config, engine=Engine(config), evidence_store=store)
    return producer, store


def _make_handler(mode: str = "audit") -> tuple[LangChainCallbackHandler, EvidenceStore]:
    producer, store = _make_producer(mode=mode)
    return LangChainCallbackHandler(producer, agent_name="lc-agent"), store


class TestNameFromSerialized:
    def test_name_field_wins(self) -> None:
        assert _name_from_serialized({"name": "MyChain"}, "fallback") == "MyChain"

    def test_id_tail_used_when_no_name(self) -> None:
        assert _name_from_serialized({"id": ["langchain", "chains", "LLMChain"]}, "fb") == "LLMChain"

    def test_fallback_used_when_serialized_empty(self) -> None:
        assert _name_from_serialized(None, "fallback") == "fallback"
        assert _name_from_serialized({}, "fallback") == "fallback"


class TestProducerProtocol:
    def test_satisfies_protocol(self) -> None:
        producer, _ = _make_producer()
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    def test_translate_tool_event_emits_tool_call_action(self) -> None:
        producer, _ = _make_producer()
        action = producer.translate(
            LangChainEvent(
                kind="tool",
                name="search",
                agent_name="lc-agent",
                inputs={"input": "weather in NYC"},
                serialized={"name": "search"},
            )
        )
        assert action.action_type == "tool_call"
        assert action.tool.name == "langchain:tool:search"

    def test_translate_llm_event_emits_api_request(self) -> None:
        producer, _ = _make_producer()
        action = producer.translate(
            LangChainEvent(
                kind="llm",
                name="ChatAnthropic",
                agent_name="lc-agent",
            )
        )
        assert action.action_type == "api_request"
        assert action.tool.name == "langchain:llm:ChatAnthropic"


class TestCallbackHandler:
    def test_on_llm_start_records_evidence(self) -> None:
        handler, store = _make_handler()
        handler.on_llm_start(
            {"name": "OpenAI"},
            ["What is 2+2?"],
            run_id=uuid4(),
        )
        summary = store.get_summary()
        assert summary["total_evaluations"] == 1

    def test_on_chat_model_start_records_evidence(self) -> None:
        handler, store = _make_handler()
        handler.on_chat_model_start(
            {"id": ["langchain", "chat_models", "ChatAnthropic"]},
            [["HumanMessage(content='hi')"]],
            run_id=uuid4(),
        )
        assert store.get_summary()["total_evaluations"] == 1

    def test_on_tool_start_records_evidence(self) -> None:
        handler, store = _make_handler()
        handler.on_tool_start({"name": "search"}, "weather in NYC", run_id=uuid4())
        assert store.get_summary()["total_evaluations"] == 1

    def test_on_chain_start_records_evidence(self) -> None:
        handler, store = _make_handler()
        handler.on_chain_start(
            {"name": "RunnableSequence"},
            {"question": "ping"},
            run_id=uuid4(),
        )
        assert store.get_summary()["total_evaluations"] == 1

    def test_multiple_callbacks_accumulate_evidence(self) -> None:
        handler, store = _make_handler()
        handler.on_chain_start({"name": "Top"}, {"q": "x"})
        handler.on_llm_start({"name": "OpenAI"}, ["x"])
        handler.on_tool_start({"name": "calc"}, "1+1")
        assert store.get_summary()["total_evaluations"] == 3

    def test_handler_exposes_langchain_compatible_flags(self) -> None:
        handler, _ = _make_handler()
        # These are the flag attributes LangChain BaseCallbackHandler exposes;
        # subclasses/duck types must define them or LangChain will skip events.
        assert handler.raise_error is False
        assert handler.ignore_llm is False
        assert handler.ignore_chain is False
        assert handler.ignore_chat_model is False
        assert handler.ignore_agent is False
        assert handler.ignore_retriever is False

    def test_noop_callbacks_return_none(self) -> None:
        handler, store = _make_handler()
        # None of these should raise or record evidence (only on_*_start does).
        handler.on_llm_end(None)
        handler.on_llm_new_token("token")
        handler.on_llm_error(Exception("x"))
        handler.on_chain_end({})
        handler.on_chain_error(Exception("x"))
        handler.on_tool_end("output")
        handler.on_tool_error(Exception("x"))
        handler.on_text("text")
        handler.on_agent_action(None)
        handler.on_agent_finish(None)
        handler.on_retriever_start({}, "query")
        handler.on_retriever_end([])
        handler.on_retriever_error(Exception("x"))
        assert store.get_summary()["total_evaluations"] == 0


class TestExportFromPackage:
    def test_lazy_re_export(self) -> None:
        from ancilis import producers as p

        assert p.LangChainActionProducer is LangChainActionProducer
        assert p.LangChainCallbackHandler is LangChainCallbackHandler
        assert p.LangChainEvent is LangChainEvent
