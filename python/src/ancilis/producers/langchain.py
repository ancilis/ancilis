"""LangChain / LangGraph framework producer.

Exposes ``LangChainCallbackHandler``, a callback handler that conforms to the
LangChain ``BaseCallbackHandler`` interface by duck-typing — it has the
expected ``on_llm_start`` / ``on_chat_model_start`` / ``on_tool_start`` /
``on_chain_start`` methods plus the ``raise_error`` / ``ignore_*`` flags. Each
callback emits an Action via the underlying ``LangChainActionProducer``.

Works whether or not ``langchain_core`` is installed: LangChain accepts any
object with the right method names. Pass an instance into the ``callbacks=``
list of any LangChain Runnable, Chain, or LLM. Same handler covers LangGraph
nodes since LangGraph reuses the LangChain callback bus.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.enforcement import OBSERVE_ONLY, warn_if_enforce_unsupported
from ancilis.producers.protocol import ProducerType
from ancilis.telemetry import record_adapter_used

PROVIDER = "langchain"
PRODUCER_VERSION = "0.1.0"


@dataclass
class LangChainEvent:
    """Normalized LangChain callback event."""

    kind: str  # "llm" | "chat_model" | "tool" | "chain"
    name: str
    agent_name: str
    inputs: Any = None
    serialized: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LangChainObservation:
    action: Action
    evaluation: EvaluationResult


def _name_from_serialized(serialized: dict[str, Any] | None, fallback: str) -> str:
    if not isinstance(serialized, dict):
        return fallback
    name = serialized.get("name")
    if isinstance(name, str) and name:
        return name
    ids = serialized.get("id")
    if isinstance(ids, Sequence) and not isinstance(ids, str) and ids:
        return str(ids[-1])
    return fallback


class LangChainActionProducer:
    """Underlying producer that translates ``LangChainEvent`` objects into Actions.

    Observe-only: LangChain/LangGraph callbacks fire around execution and cannot
    block, so ``security.mode: enforce`` does not prevent calls through this
    producer (a warning is emitted at construction if enforce is set).
    """

    ENFORCEMENT = OBSERVE_ONLY

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
        record_adapter_used(PROVIDER)
        warn_if_enforce_unsupported(type(self).__name__, self.ENFORCEMENT, config)

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return PRODUCER_VERSION

    def _tool_name(self, event: LangChainEvent) -> str:
        return f"{PROVIDER}:{event.kind}:{event.name}"

    def translate(self, raw_invocation: LangChainEvent) -> Action:
        payload = {
            "provider": PROVIDER,
            "kind": raw_invocation.kind,
            "name": raw_invocation.name,
            "inputs": raw_invocation.inputs,
            "serialized": raw_invocation.serialized,
            "metadata": raw_invocation.metadata,
        }
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
            action_type="tool_call" if raw_invocation.kind == "tool" else "api_request",
            tool=ToolInfo(
                name=tool_name,
                server=PROVIDER,
                description_hash=entry.description_hash if entry else None,
            ),
            parameters=ActionParameters(raw=payload, parameter_hash=param_hash),
            context=ActionContext(
                data_classifications=dc_codes,
                active_overlays=list(self._config.active_overlays.keys()),
                session_id=self._session_id,
            ),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        return [entry.name for entry in registry.get_all()]

    def _ensure_registered(self, event: LangChainEvent) -> str:
        name = self._tool_name(event)
        if self._registry.lookup(name) is None:
            status = (
                ToolStatus.APPROVED
                if name in self._config.tools_allowed
                else ToolStatus.OBSERVED
            )
            self._registry.register(
                ToolEntry(
                    name=name,
                    description_hash=self.compute_tool_hash(name),
                    status=status,
                    approved_by="config" if status == ToolStatus.APPROVED else None,
                )
            )
        return name

    def observe(self, event: LangChainEvent) -> LangChainObservation:
        tool_name = self._ensure_registered(event)
        action = self.translate(event)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return LangChainObservation(action=action, evaluation=evaluation)


class LangChainCallbackHandler:
    """Drop-in callback handler for LangChain Runnables, Chains, and LLMs.

    Conforms to the LangChain ``BaseCallbackHandler`` interface by duck-typing.
    Drop into any LangChain construct via ``callbacks=[handler]``.

    Also works with LangGraph nodes (LangGraph forwards through the same
    callback bus).
    """

    raise_error: bool = False
    ignore_llm: bool = False
    ignore_chain: bool = False
    ignore_agent: bool = False
    ignore_retriever: bool = False
    ignore_chat_model: bool = False
    ignore_custom_event: bool = True

    def __init__(
        self,
        producer: LangChainActionProducer,
        *,
        agent_name: str | None = None,
    ) -> None:
        self._producer = producer
        self._agent_name = agent_name

    @property
    def producer(self) -> LangChainActionProducer:
        return self._producer

    def _agent(self) -> str:
        return self._agent_name or self._producer._config.agent_name

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        event = LangChainEvent(
            kind="llm",
            name=_name_from_serialized(serialized, "llm"),
            agent_name=self._agent(),
            inputs={"prompts": list(prompts or [])},
            serialized=serialized or {},
            metadata={"run_id": str(run_id) if run_id else None, **kwargs},
        )
        self._producer.observe(event)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        event = LangChainEvent(
            kind="chat_model",
            name=_name_from_serialized(serialized, "chat_model"),
            agent_name=self._agent(),
            inputs={"messages": [[str(m) for m in batch] for batch in (messages or [])]},
            serialized=serialized or {},
            metadata={"run_id": str(run_id) if run_id else None, **kwargs},
        )
        self._producer.observe(event)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        event = LangChainEvent(
            kind="tool",
            name=_name_from_serialized(serialized, "tool"),
            agent_name=self._agent(),
            inputs={"input": input_str},
            serialized=serialized or {},
            metadata={"run_id": str(run_id) if run_id else None, **kwargs},
        )
        self._producer.observe(event)

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        event = LangChainEvent(
            kind="chain",
            name=_name_from_serialized(serialized, "chain"),
            agent_name=self._agent(),
            inputs=dict(inputs) if isinstance(inputs, dict) else {"inputs": inputs},
            serialized=serialized or {},
            metadata={"run_id": str(run_id) if run_id else None, **kwargs},
        )
        self._producer.observe(event)

    # --- noop handlers required for full BaseCallbackHandler shape ---

    def on_llm_end(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_llm_new_token(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_llm_error(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_chain_end(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_chain_error(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_tool_end(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_tool_error(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_text(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_agent_action(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_agent_finish(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_retriever_start(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_retriever_end(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None

    def on_retriever_error(self, *_: Any, **__: Any) -> None:  # pragma: no cover - noop
        return None
