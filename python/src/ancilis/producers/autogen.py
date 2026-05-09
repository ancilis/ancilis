"""AutoGen / AG2 framework producer.

Wraps Microsoft AutoGen / AG2 ``ConversableAgent`` hook lifecycle so each
inter-agent message and agent reply becomes an Action object. Duck-typed
against ``autogen`` / ``ag2`` — the producer does not import either, so the
SDK is not required at runtime.

Typical wiring::

    from autogen import ConversableAgent
    from ancilis.producers import AutoGenActionProducer

    producer = AutoGenActionProducer(config=cfg, engine=engine)
    user = ConversableAgent("user", ...)
    assistant = ConversableAgent("assistant", ...)
    producer.attach(assistant)  # registers send/receive hooks
    user.initiate_chat(assistant, message="hello")

The ``attach`` method registers hooks against the AutoGen-documented hook
names: ``process_message_before_send`` and ``process_last_received_message``.
For environments where you'd rather wire the closures yourself, use
``send_hook(agent_name=...)`` and ``receive_hook(agent_name=...)`` directly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ProducerType
from ancilis.telemetry import record_adapter_used

PROVIDER = "autogen"
PRODUCER_VERSION = "0.1.0"


@dataclass
class AutoGenEvent:
    """Normalized AutoGen hook event (send / receive / reply)."""

    kind: str  # "send" | "receive" | "reply"
    sender: str
    recipient: str
    message: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AutoGenObservation:
    action: Action
    evaluation: EvaluationResult


def _agent_name(agent: Any, fallback: str) -> str:
    if agent is None:
        return fallback
    name = getattr(agent, "name", None)
    if isinstance(name, str) and name:
        return name
    return str(agent)


def _serializable_message(message: Any) -> Any:
    if message is None or isinstance(message, (str, int, float, bool)):
        return message
    if isinstance(message, dict):
        return {k: _serializable_message(v) for k, v in message.items()}
    if isinstance(message, list):
        return [_serializable_message(m) for m in message]
    for attr in ("model_dump", "dict", "to_dict"):
        method = getattr(message, attr, None)
        if callable(method):
            try:
                return method()
            except Exception:  # pragma: no cover - upstream object misbehaving
                continue
    return repr(message)


class AutoGenActionProducer:
    """Underlying producer that translates ``AutoGenEvent`` objects into Actions."""

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

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return PRODUCER_VERSION

    def _tool_name(self, event: AutoGenEvent) -> str:
        return f"{PROVIDER}:{event.kind}:{event.sender}->{event.recipient}"

    def translate(self, raw_invocation: AutoGenEvent) -> Action:
        payload = {
            "provider": PROVIDER,
            "kind": raw_invocation.kind,
            "sender": raw_invocation.sender,
            "recipient": raw_invocation.recipient,
            "message": _serializable_message(raw_invocation.message),
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
            agent_id=raw_invocation.sender,
            source_type=self.producer_type.value,
            agent_owner=self._config.agent_owner or None,
            action_type="api_request",
            tool=ToolInfo(
                name=tool_name,
                server=PROVIDER,
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

    def _ensure_registered(self, event: AutoGenEvent) -> str:
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

    def observe(self, event: AutoGenEvent) -> AutoGenObservation:
        tool_name = self._ensure_registered(event)
        action = self.translate(event)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return AutoGenObservation(action=action, evaluation=evaluation)

    # --- AutoGen-shaped hook factories ---

    def send_hook(
        self, agent_name: str | None = None
    ) -> Callable[..., Any]:
        """Hook with AutoGen's ``process_message_before_send`` signature.

        Signature: ``(sender, message, recipient, silent) -> message``. Returns
        the message unchanged so AutoGen forwards it as-is.
        """

        fallback = agent_name or self._config.agent_name

        def hook(sender: Any = None, message: Any = None, recipient: Any = None, silent: bool = False) -> Any:
            event = AutoGenEvent(
                kind="send",
                sender=_agent_name(sender, fallback),
                recipient=_agent_name(recipient, "unknown"),
                message=message,
                metadata={"silent": bool(silent)},
            )
            self.observe(event)
            return message

        return hook

    def receive_hook(
        self, agent_name: str | None = None
    ) -> Callable[..., Any]:
        """Hook with AutoGen's ``process_last_received_message`` signature.

        Signature: ``(messages) -> messages``. The hook treats ``messages[-1]``
        as the latest received message and emits a ``receive`` event for it.
        """

        fallback = agent_name or self._config.agent_name

        def hook(messages: Any = None) -> Any:
            last_message: Any = None
            sender = "unknown"
            if isinstance(messages, list) and messages:
                last_message = messages[-1]
                if isinstance(last_message, dict):
                    sender = str(last_message.get("name") or last_message.get("role") or "unknown")
            event = AutoGenEvent(
                kind="receive",
                sender=sender,
                recipient=fallback,
                message=last_message,
                metadata={},
            )
            self.observe(event)
            return messages

        return hook

    def attach(
        self,
        agent: Any,
        *,
        agent_name: str | None = None,
    ) -> dict[str, Callable[..., Any]]:
        """Register send + receive hooks on a ``ConversableAgent``-shaped object.

        Returns the dict of hook callables registered, keyed by AutoGen hook
        name. Works against both the older ``hook_lists`` dict and the newer
        ``register_hook`` method on AG2; falls back to direct attribute
        assignment if neither is found.
        """

        send = self.send_hook(agent_name=agent_name or _agent_name(agent, self._config.agent_name))
        receive = self.receive_hook(agent_name=agent_name or _agent_name(agent, self._config.agent_name))
        registered: dict[str, Callable[..., Any]] = {
            "process_message_before_send": send,
            "process_last_received_message": receive,
        }

        register_hook = getattr(agent, "register_hook", None)
        if callable(register_hook):
            for hook_name, fn in registered.items():
                try:
                    register_hook(hookable_method=hook_name, hook=fn)
                except TypeError:
                    register_hook(hook_name, fn)
            return registered

        hook_lists = getattr(agent, "hook_lists", None)
        if isinstance(hook_lists, dict):
            for hook_name, fn in registered.items():
                hook_lists.setdefault(hook_name, []).append(fn)
            return registered

        # Fallback: bare attributes — useful in tests.
        for hook_name, fn in registered.items():
            setattr(agent, hook_name, fn)
        return registered
