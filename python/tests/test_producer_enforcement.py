"""Regression tests for enforce-mode honesty across producers (audit finding F6).

Each producer declares an ENFORCEMENT capability. Observe-only producers warn
when constructed under security.mode='enforce'. The Semantic Kernel filter is
enforce-capable: it raises on a BLOCK decision before awaiting next_fn.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest

from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.producers.autogen import AutoGenActionProducer
from ancilis.producers.bedrock import BedrockActionProducer
from ancilis.producers.cli import CLIActionProducer
from ancilis.producers.crewai import CrewAIActionProducer
from ancilis.producers.enforcement import ENFORCE_CAPABLE, OBSERVE_ONLY, OPT_IN
from ancilis.producers.http import HTTPActionProducer
from ancilis.producers.langchain import LangChainActionProducer
from ancilis.producers.llm import AnthropicActionProducer, LLMActionProducer
from ancilis.producers.mcp import MCPActionProducer
from ancilis.producers.semantic_kernel import (
    SemanticKernelActionProducer,
    SemanticKernelEvent,
)
from ancilis.producers.tool import BlockedActionError, ToolActionProducer


def test_capability_flags_are_declared() -> None:
    expected = {
        ToolActionProducer: ENFORCE_CAPABLE,
        CLIActionProducer: ENFORCE_CAPABLE,
        MCPActionProducer: ENFORCE_CAPABLE,
        SemanticKernelActionProducer: ENFORCE_CAPABLE,
        HTTPActionProducer: OPT_IN,
        LLMActionProducer: OPT_IN,
        AnthropicActionProducer: OPT_IN,  # inherited
        BedrockActionProducer: OPT_IN,
        AutoGenActionProducer: OBSERVE_ONLY,
        CrewAIActionProducer: OBSERVE_ONLY,
        LangChainActionProducer: OBSERVE_ONLY,
    }
    for cls, cap in expected.items():
        assert cap == cls.ENFORCEMENT, cls.__name__


@pytest.mark.parametrize(
    "producer_cls",
    [LangChainActionProducer, CrewAIActionProducer, AutoGenActionProducer],
)
def test_observe_only_warns_under_enforce(producer_cls) -> None:
    config = load_config(raw={"agent": {"name": "t"}, "security": {"mode": "enforce"}})
    engine = Engine(config)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        producer_cls(config=config, engine=engine)
    msgs = [str(w.message) for w in caught]
    assert any("observe-only" in m and "enforce" in m for m in msgs), msgs


def _all_exported_adapter_producers():
    from ancilis.adapters.anthropic import AnthropicActionProducer
    from ancilis.adapters.azure_openai import AzureOpenAIActionProducer
    from ancilis.adapters.bedrock import BedrockActionProducer
    from ancilis.adapters.cloudflare_workers_ai import CloudflareWorkersAIActionProducer
    from ancilis.adapters.huggingface import HuggingFaceActionProducer
    from ancilis.adapters.openai_assistants import OpenAIAssistantsActionProducer
    from ancilis.adapters.openai_realtime import OpenAIRealtimeActionProducer
    from ancilis.adapters.replicate import ReplicateActionProducer
    from ancilis.adapters.vertex_ai import VertexAIActionProducer

    return [
        AnthropicActionProducer,
        AzureOpenAIActionProducer,
        BedrockActionProducer,
        CloudflareWorkersAIActionProducer,
        HuggingFaceActionProducer,
        OpenAIAssistantsActionProducer,
        OpenAIRealtimeActionProducer,
        ReplicateActionProducer,
        VertexAIActionProducer,
    ]


@pytest.mark.parametrize("cls", _all_exported_adapter_producers())
def test_exported_llm_adapters_are_observe_only_and_warn(cls) -> None:
    # The user-facing exported provider producers come from adapters/* and only
    # observe() — they must be honestly observe-only and warn under enforce.
    config = load_config(raw={"agent": {"name": "t"}, "security": {"mode": "enforce"}})
    engine = Engine(config)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cls(config=config, engine=engine)
    msgs = [str(w.message) for w in caught]
    assert any("observe-only" in m and "enforce" in m for m in msgs), (cls.__name__, msgs)
    # Adapters expose observe() but never a blocking execute().
    assert not hasattr(cls, "execute")


def test_observe_only_silent_in_audit_mode() -> None:
    config = load_config(raw={"agent": {"name": "t"}, "security": {"mode": "audit"}})
    engine = Engine(config)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CrewAIActionProducer(config=config, engine=engine)
    assert not [w for w in caught if "observe-only" in str(w.message)]


def test_semantic_kernel_blocks_on_block_decision() -> None:
    config = load_config(raw={"agent": {"name": "t"}, "security": {"mode": "enforce"}})
    engine = Engine(config)
    sk = SemanticKernelActionProducer(config=config, engine=engine)

    real_observe = sk.observe

    def forced_block(event: SemanticKernelEvent):
        obs = real_observe(event)
        obs.evaluation.decision = "BLOCK"
        return obs

    sk.observe = forced_block

    next_called = {"v": False}

    async def next_fn(_ctx):
        next_called["v"] = True
        return "ran"

    class Ctx:
        function_name = "danger"
        plugin_name = "p"
        arguments = {"x": 1}

    filt = sk.function_invocation_filter()
    with pytest.raises(BlockedActionError):
        asyncio.run(filt(Ctx(), next_fn))
    assert next_called["v"] is False  # blocked BEFORE awaiting next_fn


def test_semantic_kernel_observes_in_audit_mode() -> None:
    config = load_config(raw={"agent": {"name": "t"}, "security": {"mode": "audit"}})
    engine = Engine(config)
    sk = SemanticKernelActionProducer(config=config, engine=engine)
    ran = {"v": False}

    async def next_fn(_ctx):
        ran["v"] = True
        return "ran"

    class Ctx:
        function_name = "ok"
        plugin_name = "p"
        arguments = {}

    filt = sk.function_invocation_filter()
    result = asyncio.run(filt(Ctx(), next_fn))
    assert result == "ran"
    assert ran["v"] is True


def test_tool_producer_blocks_kwarg_destination_under_enforce() -> None:
    """June-2026 finding: blocked_destinations never fired on the wrap_tool
    path because the destination lived under raw["kwargs"]."""
    config = load_config(
        raw={
            "agent": {"name": "t"},
            "security": {
                "mode": "enforce",
                "tools": {"allowed": ["sender"]},
                "scope": {"blocked_destinations": ["evil.example.com"]},
            },
        }
    )
    engine = Engine(config)
    producer = ToolActionProducer(config=config, engine=engine)

    def sender(url: str, payload: str) -> str:
        return "sent"

    with pytest.raises(BlockedActionError):
        producer.execute(
            sender,
            agent_name="t",
            kwargs={"url": "evil.example.com", "payload": "hi"},
            tool_name="sender",
        )

    # Same call to an unblocked destination must not raise via PR-02.
    result = producer.execute(
        sender,
        agent_name="t",
        kwargs={"url": "ok.example.com", "payload": "hi"},
        tool_name="sender",
    )
    assert result.blocked is False
    assert result.return_value == "sent"


def _enforce_config(blocked: list[str]):
    return load_config(
        raw={
            "agent": {"name": "t"},
            "security": {
                "mode": "enforce",
                "tools": {"allowed": ["sender"]},
                "scope": {"blocked_destinations": blocked},
            },
        }
    )


def test_blocked_url_not_masked_by_second_destination_key() -> None:
    """Review finding: with both keys present, first-match extraction let
    {"url": blocked, "destination": allowed} through."""
    config = _enforce_config(["evil.example.com"])
    engine = Engine(config)
    producer = ToolActionProducer(config=config, engine=engine)

    def sender(url: str, destination: str) -> str:
        return "sent"

    with pytest.raises(BlockedActionError):
        producer.execute(
            sender,
            agent_name="t",
            kwargs={"url": "evil.example.com", "destination": "ok.example.com"},
            tool_name="sender",
        )
    with pytest.raises(BlockedActionError):
        producer.execute(
            sender,
            agent_name="t",
            kwargs={"url": "ok.example.com", "destination": "evil.example.com"},
            tool_name="sender",
        )


def test_blocked_kwarg_not_masked_by_allowed_url_in_positional_payload() -> None:
    config = _enforce_config(["evil.example.com"])
    engine = Engine(config)
    producer = ToolActionProducer(config=config, engine=engine)

    def sender(payload: dict, url: str) -> str:  # type: ignore[type-arg]
        return "sent"

    with pytest.raises(BlockedActionError):
        producer.execute(
            sender,
            agent_name="t",
            args=({"url": "ok.example.com"},),
            kwargs={"url": "evil.example.com"},
            tool_name="sender",
        )


def test_blocked_positional_destination_is_enforced() -> None:
    """Review finding: sender("evil.example", msg) passed all destination
    controls because positional strings had no parameter-name binding."""
    config = _enforce_config(["evil.example.com"])
    engine = Engine(config)
    producer = ToolActionProducer(config=config, engine=engine)

    def sender(url: str, message: str) -> str:
        return "sent"

    with pytest.raises(BlockedActionError):
        producer.execute(
            sender,
            agent_name="t",
            args=("evil.example.com", "hello"),
            tool_name="sender",
        )
