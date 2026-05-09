"""Tests for LLM SDK producers (Anthropic, OpenAI, Gemini)."""

from __future__ import annotations

import pytest

from ancilis.config import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.llm import (
    AnthropicActionProducer,
    CohereActionProducer,
    DeepSeekActionProducer,
    FireworksActionProducer,
    GeminiActionProducer,
    GroqActionProducer,
    LLMActionProducer,
    LLMInvocation,
    MistralActionProducer,
    OpenAIActionProducer,
    TogetherActionProducer,
    XAIActionProducer,
)
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.tool import BlockedActionError


def _config(*, mode: str = "audit", tools_allowed: list[str] | None = None) -> object:
    raw = {
        "agent": {"name": "llm-agent", "owner": "test-owner"},
        "security": {"mode": mode, "tools": {"allowed": tools_allowed or []}},
    }
    return load_config(raw=raw)


def _make(
    cls: type[LLMActionProducer], *, mode: str = "audit", tools_allowed: list[str] | None = None
) -> tuple[LLMActionProducer, EvidenceStore]:
    config = _config(mode=mode, tools_allowed=tools_allowed)
    store = EvidenceStore(config, in_memory=True)
    producer = cls(config=config, engine=Engine(config), evidence_store=store)
    return producer, store


_ALL_PRODUCER_CLASSES = [
    AnthropicActionProducer,
    OpenAIActionProducer,
    GeminiActionProducer,
    MistralActionProducer,
    CohereActionProducer,
    XAIActionProducer,
    GroqActionProducer,
    TogetherActionProducer,
    FireworksActionProducer,
    DeepSeekActionProducer,
]


class TestProtocolCompliance:
    @pytest.mark.parametrize("cls", _ALL_PRODUCER_CLASSES)
    def test_satisfies_action_producer_protocol(self, cls: type[LLMActionProducer]) -> None:
        producer, _ = _make(cls)
        assert isinstance(producer, ActionProducer)
        assert producer.producer_type is ProducerType.FRAMEWORK
        assert producer.producer_version == "0.1.0"

    @pytest.mark.parametrize(
        "cls,expected_provider",
        [
            (AnthropicActionProducer, "anthropic"),
            (OpenAIActionProducer, "openai"),
            (GeminiActionProducer, "gemini"),
            (MistralActionProducer, "mistral"),
            (CohereActionProducer, "cohere"),
            (XAIActionProducer, "xai"),
            (GroqActionProducer, "groq"),
            (TogetherActionProducer, "together"),
            (FireworksActionProducer, "fireworks"),
            (DeepSeekActionProducer, "deepseek"),
        ],
    )
    def test_provider_string(
        self, cls: type[LLMActionProducer], expected_provider: str
    ) -> None:
        producer, _ = _make(cls)
        assert producer.provider == expected_provider


class TestOpenAICompatibleInferenceSubclasses:
    """Groq/Together/Fireworks/DeepSeek share OpenAI's HTTP shape but each
    carries its own provider slug for evidence attribution."""

    @pytest.mark.parametrize(
        "cls,model",
        [
            (GroqActionProducer, "llama-3.3-70b-versatile"),
            (TogetherActionProducer, "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
            (FireworksActionProducer, "accounts/fireworks/models/llama-v3p3-70b"),
            (DeepSeekActionProducer, "deepseek-chat"),
        ],
    )
    def test_each_subclass_emits_distinct_provider_tool_name(
        self, cls: type[LLMActionProducer], model: str
    ) -> None:
        producer, store = _make(cls)
        observation = producer.observe(
            LLMInvocation(model=model, agent_name="llm-agent", messages=[{"role": "user", "content": "hi"}])
        )
        assert observation.action.tool.name == f"llm:{producer.provider}:{model}"
        assert store.get_summary()["total_evaluations"] == 1

    def test_groq_uses_openai_input_normalization(self) -> None:
        producer, _ = _make(GroqActionProducer)
        invocation = producer._extract_invocation(
            {"model": "llama-3.3-70b-versatile", "input": "ping"},
            agent_name="llm-agent",
        )
        assert invocation.messages == [{"role": "user", "content": "ping"}]


class TestObserve:
    def test_anthropic_observe_records_action(self) -> None:
        producer, store = _make(AnthropicActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="claude-sonnet-4-6",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "hello"}],
            )
        )
        assert observation.action.action_type == "api_request"
        assert observation.action.tool.name == "llm:anthropic:claude-sonnet-4-6"
        assert observation.action.tool.server == "anthropic"
        assert store.get_summary()["total_evaluations"] == 1

    def test_openai_observe_records_action(self) -> None:
        producer, store = _make(OpenAIActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="gpt-4o",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "ping"}],
            )
        )
        assert observation.action.tool.name == "llm:openai:gpt-4o"
        assert store.get_summary()["total_evaluations"] == 1

    def test_gemini_observe_records_action(self) -> None:
        producer, store = _make(GeminiActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="gemini-2.5-flash",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "hi"}],
            )
        )
        assert observation.action.tool.name == "llm:gemini:gemini-2.5-flash"
        assert store.get_summary()["total_evaluations"] == 1

    def test_unknown_model_falls_back_safely(self) -> None:
        producer, _ = _make(AnthropicActionProducer)
        observation = producer.observe(
            LLMInvocation(model="", agent_name="llm-agent")
        )
        assert observation.action.tool.name == "llm:anthropic:unknown-model"


class TestExtractInvocation:
    def test_anthropic_extracts_messages_and_system(self) -> None:
        producer, _ = _make(AnthropicActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "claude-sonnet-4-6",
                "messages": [{"role": "user", "content": "hi"}],
                "system": "you are helpful",
                "tools": [{"name": "search"}],
                "max_tokens": 1024,
            },
            agent_name="llm-agent",
        )
        assert invocation.model == "claude-sonnet-4-6"
        assert invocation.system == "you are helpful"
        assert invocation.tools == [{"name": "search"}]
        assert invocation.metadata == {"max_tokens": 1024}

    def test_openai_responses_input_string_normalized_to_messages(self) -> None:
        producer, _ = _make(OpenAIActionProducer)
        invocation = producer._extract_invocation(
            {"model": "gpt-4o", "input": "summarize this"},
            agent_name="llm-agent",
        )
        assert invocation.messages == [{"role": "user", "content": "summarize this"}]

    def test_openai_responses_input_list_kept(self) -> None:
        producer, _ = _make(OpenAIActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "gpt-4o",
                "input": [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}],
            },
            agent_name="llm-agent",
        )
        assert len(invocation.messages) == 2

    def test_openai_instructions_treated_as_system(self) -> None:
        producer, _ = _make(OpenAIActionProducer)
        invocation = producer._extract_invocation(
            {"model": "gpt-4o", "input": "x", "instructions": "be terse"},
            agent_name="llm-agent",
        )
        assert invocation.system == "be terse"

    def test_gemini_contents_string_normalized(self) -> None:
        producer, _ = _make(GeminiActionProducer)
        invocation = producer._extract_invocation(
            {"model": "gemini-2.5-flash", "contents": "hello"},
            agent_name="llm-agent",
        )
        assert invocation.messages == [{"role": "user", "content": "hello"}]

    def test_gemini_config_dict_extracts_system_and_tools(self) -> None:
        producer, _ = _make(GeminiActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "gemini-2.5-flash",
                "contents": "x",
                "config": {
                    "system_instruction": "be terse",
                    "tools": [{"name": "search"}],
                },
            },
            agent_name="llm-agent",
        )
        assert invocation.system == "be terse"
        assert invocation.tools == [{"name": "search"}]

    def test_mistral_uses_default_extractor(self) -> None:
        producer, _ = _make(MistralActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "mistral-large-latest",
                "messages": [{"role": "user", "content": "bonjour"}],
                "system": "be helpful",
            },
            agent_name="llm-agent",
        )
        assert invocation.model == "mistral-large-latest"
        assert invocation.system == "be helpful"

    def test_cohere_folds_message_and_chat_history(self) -> None:
        producer, _ = _make(CohereActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "command-r-plus",
                "message": "ping",
                "chat_history": [{"role": "user", "message": "earlier"}],
                "preamble": "be terse",
            },
            agent_name="llm-agent",
        )
        assert len(invocation.messages) == 2
        assert invocation.messages[-1] == {"role": "user", "content": "ping"}
        assert invocation.system == "be terse"

    def test_cohere_messages_kwarg_takes_priority(self) -> None:
        producer, _ = _make(CohereActionProducer)
        invocation = producer._extract_invocation(
            {
                "model": "command-r",
                "messages": [{"role": "user", "content": "via messages"}],
                "message": "ignored",
            },
            agent_name="llm-agent",
        )
        assert invocation.messages == [{"role": "user", "content": "via messages"}]

    def test_xai_uses_openai_compatible_extraction(self) -> None:
        producer, _ = _make(XAIActionProducer)
        invocation = producer._extract_invocation(
            {"model": "grok-4", "input": "what is 2+2?"},
            agent_name="llm-agent",
        )
        # OpenAI's input-string normalization promotes to messages[0]
        assert invocation.messages == [{"role": "user", "content": "what is 2+2?"}]


class TestNewProvidersTokens:
    def test_mistral_observe(self) -> None:
        producer, store = _make(MistralActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="mistral-large-latest",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "bonjour"}],
            )
        )
        assert observation.action.tool.name == "llm:mistral:mistral-large-latest"
        assert store.get_summary()["total_evaluations"] == 1

    def test_cohere_observe(self) -> None:
        producer, store = _make(CohereActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="command-r-plus",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "ping"}],
            )
        )
        assert observation.action.tool.name == "llm:cohere:command-r-plus"
        assert store.get_summary()["total_evaluations"] == 1

    def test_xai_observe(self) -> None:
        producer, store = _make(XAIActionProducer)
        observation = producer.observe(
            LLMInvocation(
                model="grok-4",
                agent_name="llm-agent",
                messages=[{"role": "user", "content": "ping"}],
            )
        )
        assert observation.action.tool.name == "llm:xai:grok-4"
        assert store.get_summary()["total_evaluations"] == 1


class TestExecuteAndWrap:
    def test_execute_returns_transport_response_in_audit(self) -> None:
        producer, store = _make(AnthropicActionProducer, mode="audit")

        def fake_create(**_: object) -> dict[str, str]:
            return {"id": "msg_1"}

        result = producer.execute(
            LLMInvocation(model="claude-sonnet-4-6", agent_name="llm-agent"),
            transport=fake_create,
            transport_kwargs={"model": "claude-sonnet-4-6"},
        )
        assert result.response == {"id": "msg_1"}
        assert result.blocked is False
        assert store.get_summary()["total_evaluations"] == 1

    def test_enforce_blocks_disallowed_model(self) -> None:
        allowed = "llm:anthropic:claude-sonnet-4-6"
        producer, _ = _make(
            AnthropicActionProducer, mode="enforce", tools_allowed=[allowed]
        )

        calls: list[str] = []

        def fake_create(**kwargs: object) -> dict[str, str]:
            calls.append(str(kwargs.get("model")))
            return {"id": "msg_1"}

        wrapped = producer.wrap_create(fake_create, agent_name="llm-agent", enforce=True)
        ok = wrapped(model="claude-sonnet-4-6", messages=[{"role": "user", "content": "hi"}])
        assert ok.response == {"id": "msg_1"}
        assert calls == ["claude-sonnet-4-6"]

        with pytest.raises(BlockedActionError):
            wrapped(model="claude-opus-4", messages=[{"role": "user", "content": "hi"}])
        assert calls == ["claude-sonnet-4-6"]

    def test_wrap_create_observe_first_default(self) -> None:
        producer, store = _make(
            OpenAIActionProducer,
            mode="enforce",
            tools_allowed=["llm:openai:gpt-4o"],
        )

        called = {"count": 0}

        def fake_create(**_: object) -> dict[str, str]:
            called["count"] += 1
            return {"id": "resp_1"}

        wrapped = producer.wrap_create(fake_create, agent_name="llm-agent")
        result = wrapped(model="gpt-4o-mini", messages=[{"role": "user", "content": "x"}])
        assert result.response == {"id": "resp_1"}
        assert called["count"] == 1
        assert result.evaluation.decision == "BLOCK"
        assert store.get_summary()["total_evaluations"] == 1

    def test_session_id_is_unique_per_instance(self) -> None:
        a, _ = _make(AnthropicActionProducer)
        b, _ = _make(AnthropicActionProducer)
        assert a.session_id != b.session_id

    def test_session_id_propagates_to_action_and_evidence(self) -> None:
        """Regression: producer.session_id must reach Action.context.session_id
        so evidence.get_summary(session_id=...) can filter to a single run."""
        producer, store = _make(AnthropicActionProducer)
        observation = producer.observe(
            LLMInvocation(model="claude-sonnet-4-6", agent_name="llm-agent")
        )
        # Action carries the producer's session_id in its context.
        assert observation.action.context.session_id == producer.session_id
        # And the evidence store can look up by that session_id.
        filtered = store.get_summary(session_id=producer.session_id)
        assert filtered["total_evaluations"] == 1
        # A different (random) session_id finds nothing.
        empty = store.get_summary(session_id="nonexistent-session-id")
        assert empty["total_evaluations"] == 0


class TestExportsAndLazyImport:
    def test_lazy_re_export_from_producers_package(self) -> None:
        from ancilis import producers as producers_pkg

        assert producers_pkg.AnthropicActionProducer is AnthropicActionProducer
        assert producers_pkg.OpenAIActionProducer is OpenAIActionProducer
        assert producers_pkg.GeminiActionProducer is GeminiActionProducer
        assert producers_pkg.MistralActionProducer is MistralActionProducer
        assert producers_pkg.CohereActionProducer is CohereActionProducer
        assert producers_pkg.XAIActionProducer is XAIActionProducer
        assert producers_pkg.LLMInvocation is LLMInvocation
