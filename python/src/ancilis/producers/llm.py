"""LLM SDK producers for Anthropic, OpenAI, and Google Gemini.

Producers wrap LLM SDK calls in the user's runtime so each invocation becomes
an Action object the engine can evaluate. Mirrors HTTPActionProducer in shape:
observe-first, optional enforce, optional client wrapping. Duck-typed against
the upstream SDKs — the producer never imports anthropic / openai / google-genai,
so it works whether or not the SDK is installed.
"""

from __future__ import annotations

import functools
import hashlib
import json
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ParamSpec, TypeVar

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ProducerType
from ancilis.producers.tool import BlockedActionError
from ancilis.telemetry import record_adapter_used

P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class LLMInvocation:
    """Provider-agnostic representation of an LLM SDK call."""

    model: str
    agent_name: str
    messages: list[Any] = field(default_factory=list)
    system: Any = None
    tools: list[Any] | None = None
    response: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMObservation:
    action: Action
    evaluation: EvaluationResult


@dataclass
class LLMExecutionResult:
    action: Action
    evaluation: EvaluationResult
    blocked: bool
    response: Any = None


class LLMActionProducer:
    """Base producer for LLM SDK calls.

    Subclasses set ``provider`` and may override ``_extract_invocation`` to
    normalize provider-specific kwargs into ``LLMInvocation``. The default
    extractor handles the common Anthropic/OpenAI shape (``model``,
    ``messages``, ``system``, ``tools``).
    """

    provider: str = "llm"

    def __init__(
        self,
        config: ResolvedConfig,
        engine: Engine,
        registry: ToolRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(config)
        self._session_id = str(uuid.uuid4())
        record_adapter_used(self.provider)

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return "0.1.0"

    def _tool_name(self, invocation: LLMInvocation) -> str:
        model = invocation.model or "unknown-model"
        return f"llm:{self.provider}:{model}"

    def _payload(self, invocation: LLMInvocation) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": invocation.model,
            "messages": invocation.messages,
            "system": invocation.system,
            "tools": invocation.tools or [],
            "metadata": invocation.metadata,
        }

    def translate(self, raw_invocation: LLMInvocation) -> Action:
        payload = self._payload(raw_invocation)
        param_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=repr).encode()
        ).hexdigest()
        tool_name = self._tool_name(raw_invocation)
        entry = self._registry.lookup(tool_name)
        dc_codes: list[str] = []
        for codes in self._config.data_classifications.values():
            for code in codes:
                if code not in dc_codes:
                    dc_codes.append(code)
        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=raw_invocation.agent_name,
            source_type=self.producer_type.value,
            agent_owner=self._config.agent_owner or None,
            action_type="api_request",
            tool=ToolInfo(
                name=tool_name,
                server=self.provider,
                description_hash=entry.description_hash if entry else None,
            ),
            parameters=ActionParameters(raw=payload, parameter_hash=param_hash),
            context=ActionContext(
                data_classifications=dc_codes,
                active_overlays=list(self._config.active_overlays.keys()),
            ),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        return [entry.name for entry in registry.get_all()]

    def _ensure_registered(self, invocation: LLMInvocation) -> str:
        tool_name = self._tool_name(invocation)
        if self._registry.lookup(tool_name) is None:
            status = (
                ToolStatus.APPROVED
                if tool_name in self._config.tools_allowed
                else ToolStatus.OBSERVED
            )
            self._registry.register(
                ToolEntry(
                    name=tool_name,
                    description_hash=self.compute_tool_hash(tool_name),
                    status=status,
                    approved_by="config" if status == ToolStatus.APPROVED else None,
                )
            )
        return tool_name

    def observe(self, invocation: LLMInvocation) -> LLMObservation:
        tool_name = self._ensure_registered(invocation)
        action = self.translate(invocation)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return LLMObservation(action=action, evaluation=evaluation)

    def execute(
        self,
        invocation: LLMInvocation,
        *,
        transport: Callable[P, R],
        transport_args: tuple[Any, ...] = (),
        transport_kwargs: dict[str, Any] | None = None,
        enforce: bool = False,
    ) -> LLMExecutionResult:
        observation = self.observe(invocation)
        if enforce and observation.evaluation.decision == "BLOCK":
            raise BlockedActionError(observation.action.tool.name, observation.evaluation)
        response = transport(*transport_args, **(transport_kwargs or {}))
        return LLMExecutionResult(
            action=observation.action,
            evaluation=observation.evaluation,
            blocked=False,
            response=response,
        )

    def _extract_invocation(
        self, kwargs: Mapping[str, Any], *, agent_name: str
    ) -> LLMInvocation:
        return LLMInvocation(
            model=str(kwargs.get("model") or "unknown-model"),
            agent_name=agent_name,
            messages=list(kwargs.get("messages") or []),
            system=kwargs.get("system"),
            tools=list(kwargs.get("tools") or []) or None,
            metadata={
                k: v
                for k, v in kwargs.items()
                if k not in {"model", "messages", "system", "tools"}
            },
        )

    def wrap_create(
        self,
        create: Callable[..., Any],
        *,
        agent_name: str | None = None,
        enforce: bool = False,
    ) -> Callable[..., LLMExecutionResult]:
        """Wrap an SDK ``create``-style callable so each invocation is observed.

        Works with ``client.messages.create`` (Anthropic),
        ``client.chat.completions.create`` and ``client.responses.create``
        (OpenAI), and ``client.models.generate_content`` (Gemini, when called
        with keyword args).
        """

        @functools.wraps(create)
        def wrapped(*args: Any, **kwargs: Any) -> LLMExecutionResult:
            invocation = self._extract_invocation(
                kwargs, agent_name=agent_name or self._config.agent_name
            )
            return self.execute(
                invocation,
                transport=create,
                transport_args=args,
                transport_kwargs=kwargs,
                enforce=enforce,
            )

        return wrapped


class AnthropicActionProducer(LLMActionProducer):
    """Producer for the Anthropic Python SDK (``messages.create``)."""

    provider = "anthropic"


class OpenAIActionProducer(LLMActionProducer):
    """Producer for the OpenAI Python SDK.

    Handles both ``chat.completions.create`` (``messages``) and
    ``responses.create`` (``input``) by normalizing ``input`` to ``messages``
    when present.
    """

    provider = "openai"

    def _extract_invocation(
        self, kwargs: Mapping[str, Any], *, agent_name: str
    ) -> LLMInvocation:
        messages = kwargs.get("messages")
        if messages is None and "input" in kwargs:
            raw_input = kwargs["input"]
            if isinstance(raw_input, str):
                messages = [{"role": "user", "content": raw_input}]
            elif isinstance(raw_input, Iterable):
                messages = list(raw_input)
            else:
                messages = [raw_input]
        return LLMInvocation(
            model=str(kwargs.get("model") or "unknown-model"),
            agent_name=agent_name,
            messages=list(messages or []),
            system=kwargs.get("instructions") or kwargs.get("system"),
            tools=list(kwargs.get("tools") or []) or None,
            metadata={
                k: v
                for k, v in kwargs.items()
                if k not in {"model", "messages", "system", "tools", "input", "instructions"}
            },
        )


class GeminiActionProducer(LLMActionProducer):
    """Producer for the Google Gemini SDK (``google-genai``).

    Normalizes ``contents`` (Gemini) to ``messages`` and exposes
    ``system_instruction`` as ``system``.
    """

    provider = "gemini"

    def _extract_invocation(
        self, kwargs: Mapping[str, Any], *, agent_name: str
    ) -> LLMInvocation:
        contents = kwargs.get("contents")
        if isinstance(contents, str):
            messages: list[Any] = [{"role": "user", "content": contents}]
        elif isinstance(contents, Iterable):
            messages = list(contents)
        else:
            messages = [contents] if contents is not None else []
        config = kwargs.get("config") or {}
        if isinstance(config, Mapping):
            system = config.get("system_instruction") or kwargs.get("system_instruction")
            tools = config.get("tools") or kwargs.get("tools")
        else:
            system = kwargs.get("system_instruction")
            tools = kwargs.get("tools")
        return LLMInvocation(
            model=str(kwargs.get("model") or "unknown-model"),
            agent_name=agent_name,
            messages=messages,
            system=system,
            tools=list(tools or []) or None,
            metadata={
                k: v
                for k, v in kwargs.items()
                if k not in {"model", "contents", "system_instruction", "tools", "config"}
            },
        )


class MistralActionProducer(LLMActionProducer):
    """Producer for the Mistral La Plateforme SDK (``mistralai``).

    Mistral's ``client.chat.complete(model, messages, ...)`` shape mirrors
    OpenAI/Anthropic, so the base extractor covers it.
    """

    provider = "mistral"


class CohereActionProducer(LLMActionProducer):
    """Producer for the Cohere SDK.

    Cohere's chat API uses ``message`` (single string) and ``chat_history``
    (list of role/text dicts). This extractor folds both into ``messages``
    so downstream evaluators see the same shape as other providers.
    """

    provider = "cohere"

    def _extract_invocation(
        self, kwargs: Mapping[str, Any], *, agent_name: str
    ) -> LLMInvocation:
        messages = list(kwargs.get("messages") or [])
        if not messages:
            history = kwargs.get("chat_history") or []
            if isinstance(history, Iterable):
                messages = list(history)
            current = kwargs.get("message")
            if current is not None:
                messages.append({"role": "user", "content": current})
        return LLMInvocation(
            model=str(kwargs.get("model") or "unknown-model"),
            agent_name=agent_name,
            messages=messages,
            system=kwargs.get("preamble") or kwargs.get("system"),
            tools=list(kwargs.get("tools") or []) or None,
            metadata={
                k: v
                for k, v in kwargs.items()
                if k
                not in {
                    "model",
                    "messages",
                    "message",
                    "chat_history",
                    "preamble",
                    "system",
                    "tools",
                }
            },
        )


class XAIActionProducer(OpenAIActionProducer):
    """Producer for the xAI Grok API.

    xAI exposes an OpenAI-compatible chat API, so this subclasses
    ``OpenAIActionProducer`` and changes only the provider slug.
    """

    provider = "xai"


# --- OpenAI-compatible serverless inference platforms ---
#
# Per Q2 2026 research, the consolidated serverless inference market
# (Together, Fireworks, Anyscale, Groq, Cerebras, Replicate, OctoAI) all
# expose OpenAI-compatible endpoints. The producers below are thin
# subclasses that change only the provider slug so evidence is correctly
# attributed; they reuse the OpenAI extractor for messages/input handling.


class GroqActionProducer(OpenAIActionProducer):
    """Producer for Groq's LPU-backed OpenAI-compatible API."""

    provider = "groq"


class TogetherActionProducer(OpenAIActionProducer):
    """Producer for Together AI's OpenAI-compatible inference API."""

    provider = "together"


class FireworksActionProducer(OpenAIActionProducer):
    """Producer for Fireworks AI's OpenAI-compatible inference API."""

    provider = "fireworks"


class DeepSeekActionProducer(OpenAIActionProducer):
    """Producer for the DeepSeek OpenAI-compatible API."""

    provider = "deepseek"
