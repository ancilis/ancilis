"""Tests for SemanticKernelActionProducer (filter-based)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.semantic_kernel import (
    SemanticKernelActionProducer,
    SemanticKernelEvent,
    _arguments_value,
    _function_metadata,
)


def _config() -> object:
    raw = {"agent": {"name": "sk-agent", "owner": "test-owner"}}
    return load_config(raw=raw)


def _make() -> tuple[SemanticKernelActionProducer, EvidenceStore]:
    config = _config()
    store = EvidenceStore(config, in_memory=True)
    return (
        SemanticKernelActionProducer(config=config, engine=Engine(config), evidence_store=store),
        store,
    )


@dataclass
class _SKFunction:
    name: str
    plugin_name: str


@dataclass
class _SKContext:
    function: _SKFunction
    arguments: dict


@dataclass
class _SKContextWithDirectAttrs:
    function_name: str
    plugin_name: str
    arguments: dict


class _PydanticishArgs:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def model_dump(self) -> dict:
        return self.payload


class TestFunctionMetadata:
    def test_extract_via_function_attribute(self) -> None:
        ctx = _SKContext(function=_SKFunction(name="search", plugin_name="WebPlugin"), arguments={})
        assert _function_metadata(ctx) == ("search", "WebPlugin")

    def test_extract_via_direct_attributes(self) -> None:
        ctx = _SKContextWithDirectAttrs(function_name="summarize", plugin_name="TextPlugin", arguments={})
        assert _function_metadata(ctx) == ("summarize", "TextPlugin")

    def test_falls_back_to_defaults(self) -> None:
        ctx = object()
        assert _function_metadata(ctx) == ("unknown-function", "default")


class TestArgumentsValue:
    def test_dict_passes_through(self) -> None:
        ctx = _SKContext(function=_SKFunction(name="x", plugin_name="p"), arguments={"q": "weather"})
        assert _arguments_value(ctx) == {"q": "weather"}

    def test_pydantic_like_model_dump_used(self) -> None:
        ctx = _SKContext(function=_SKFunction(name="x", plugin_name="p"), arguments=_PydanticishArgs({"k": 1}))
        assert _arguments_value(ctx) == {"k": 1}

    def test_returns_none_when_no_arguments(self) -> None:
        class Bare:
            pass

        assert _arguments_value(Bare()) is None


class TestProducerProtocol:
    def test_satisfies_protocol(self) -> None:
        producer, _ = _make()
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    def test_translate_function_invocation_emits_tool_call(self) -> None:
        producer, _ = _make()
        action = producer.translate(
            SemanticKernelEvent(
                kind="function_invocation",
                function_name="search",
                plugin_name="WebPlugin",
                agent_name="sk-agent",
            )
        )
        assert action.action_type == "tool_call"
        assert action.tool.name == "semantic-kernel:function_invocation:WebPlugin.search"

    def test_translate_prompt_rendering_emits_api_request(self) -> None:
        producer, _ = _make()
        action = producer.translate(
            SemanticKernelEvent(
                kind="prompt_rendering",
                function_name="ChatPrompt",
                plugin_name="default",
                agent_name="sk-agent",
            )
        )
        assert action.action_type == "api_request"

    def test_translate_auto_function_invocation_emits_tool_call(self) -> None:
        producer, _ = _make()
        action = producer.translate(
            SemanticKernelEvent(
                kind="auto_function_invocation",
                function_name="lookup",
                plugin_name="UtilsPlugin",
                agent_name="sk-agent",
            )
        )
        assert action.action_type == "tool_call"


class TestFilterFactories:
    def test_function_invocation_filter_observes_and_calls_next(self) -> None:
        producer, store = _make()
        filter_fn = producer.function_invocation_filter()

        ctx = _SKContext(
            function=_SKFunction(name="search", plugin_name="WebPlugin"),
            arguments={"q": "ancilis"},
        )

        next_called = {"count": 0, "ctx": None}

        async def fake_next(received_ctx):
            next_called["count"] += 1
            next_called["ctx"] = received_ctx
            return "result"

        async def run():
            return await filter_fn(ctx, fake_next)

        result = asyncio.run(run())
        assert result == "result"
        assert next_called["count"] == 1
        assert next_called["ctx"] is ctx
        assert store.get_summary()["total_evaluations"] == 1

    def test_prompt_rendering_filter_records_evidence(self) -> None:
        producer, store = _make()
        filter_fn = producer.prompt_rendering_filter()

        ctx = _SKContextWithDirectAttrs(function_name="ChatPrompt", plugin_name="default", arguments={})

        async def fake_next(_):
            return None

        asyncio.run(filter_fn(ctx, fake_next))
        assert store.get_summary()["total_evaluations"] == 1

    def test_auto_function_invocation_filter_records_evidence(self) -> None:
        producer, store = _make()
        filter_fn = producer.auto_function_invocation_filter()
        ctx = _SKContext(function=_SKFunction(name="lookup", plugin_name="Utils"), arguments={})

        async def fake_next(_):
            return None

        asyncio.run(filter_fn(ctx, fake_next))
        assert store.get_summary()["total_evaluations"] == 1

    def test_filter_chain_records_one_event_per_call(self) -> None:
        producer, store = _make()
        filter_fn = producer.function_invocation_filter()
        ctx = _SKContext(function=_SKFunction(name="x", plugin_name="p"), arguments={})

        async def fake_next(_):
            return None

        async def run():
            await filter_fn(ctx, fake_next)
            await filter_fn(ctx, fake_next)
            await filter_fn(ctx, fake_next)

        asyncio.run(run())
        assert store.get_summary()["total_evaluations"] == 3


class TestExportFromPackage:
    def test_lazy_re_export(self) -> None:
        from ancilis import producers as p

        assert p.SemanticKernelActionProducer is SemanticKernelActionProducer
        assert p.SemanticKernelEvent is SemanticKernelEvent
