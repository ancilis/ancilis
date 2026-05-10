"""CrewAI framework producer.

Wraps CrewAI ``step_callback`` / ``task_callback`` / ``Crew`` callback hooks
so each agent step, task completion, and crew run becomes an Action object.
Duck-typed against ``crewai`` — the producer does not import crewai, so the
SDK is not required at runtime.

Typical wiring::

    from crewai import Agent, Task, Crew
    from ancilis.producers import CrewAIActionProducer

    producer = CrewAIActionProducer(config=cfg, engine=engine)
    agent = Agent(role="researcher", step_callback=producer.step_callback("researcher"))
    task = Task(description="...", agent=agent, callback=producer.task_callback("research"))
    crew = Crew(agents=[agent], tasks=[task], step_callback=producer.step_callback("crew"))
    crew.kickoff()
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

PROVIDER = "crewai"
PRODUCER_VERSION = "0.1.0"


@dataclass
class CrewAIEvent:
    """Normalized CrewAI hook event (step / task / crew)."""

    kind: str  # "step" | "task" | "crew"
    name: str
    agent_name: str
    output: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CrewAIObservation:
    action: Action
    evaluation: EvaluationResult


def _first_string_attr(obj: Any, attrs: tuple[str, ...]) -> str | None:
    for attr in attrs:
        value = getattr(obj, attr, None)
        if isinstance(value, str) and value:
            return value
    return None


def _first_string_key(mapping: Any, keys: tuple[str, ...]) -> str | None:
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _step_name(step_output: Any, fallback: str) -> str:
    """Pull a useful identifier off a CrewAI step output object."""
    keys = ("tool", "tool_name", "agent_role", "agent", "name")
    return (
        _first_string_attr(step_output, keys)
        or _first_string_key(step_output, keys)
        or fallback
    )


def _task_name(task_output: Any, fallback: str) -> str:
    keys = ("description", "task_id", "name", "agent_role")
    return (
        _first_string_attr(task_output, keys)
        or _first_string_key(task_output, keys)
        or fallback
    )


def _crew_name(crew_output: Any, fallback: str) -> str:
    keys = ("name", "id", "crew_id")
    return (
        _first_string_attr(crew_output, keys)
        or _first_string_key(crew_output, keys)
        or fallback
    )


def _serializable(value: Any) -> Any:
    """Best-effort conversion for objects that may not JSON-encode."""
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    for attr in ("model_dump", "dict", "to_dict"):
        method = getattr(value, attr, None)
        if callable(method):
            try:
                return method()
            except Exception:  # pragma: no cover - upstream object misbehaving
                continue
    return repr(value)


class CrewAIActionProducer:
    """Underlying producer that translates ``CrewAIEvent`` objects into Actions.

    Use the ``step_callback`` / ``task_callback`` / ``crew_callback`` factories
    to obtain closures with the signatures CrewAI expects.
    """

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

    def _tool_name(self, event: CrewAIEvent) -> str:
        return f"{PROVIDER}:{event.kind}:{event.name}"

    def translate(self, raw_invocation: CrewAIEvent) -> Action:
        payload = {
            "provider": PROVIDER,
            "kind": raw_invocation.kind,
            "name": raw_invocation.name,
            "output": _serializable(raw_invocation.output),
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
            action_type="tool_call" if raw_invocation.kind == "step" else "api_request",
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

    def _ensure_registered(self, event: CrewAIEvent) -> str:
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

    def observe(self, event: CrewAIEvent) -> CrewAIObservation:
        tool_name = self._ensure_registered(event)
        action = self.translate(event)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return CrewAIObservation(action=action, evaluation=evaluation)

    # --- CrewAI-shaped callback factories ---

    def step_callback(self, agent_name: str | None = None) -> Callable[[Any], None]:
        """Return a function with the signature CrewAI expects for ``step_callback``.

        CrewAI calls ``step_callback(step_output)`` after each ReAct-style step.
        """

        agent = agent_name or self._config.agent_name

        def callback(step_output: Any) -> None:
            event = CrewAIEvent(
                kind="step",
                name=_step_name(step_output, "step"),
                agent_name=agent,
                output=step_output,
            )
            self.observe(event)

        return callback

    def task_callback(self, agent_name: str | None = None) -> Callable[[Any], None]:
        """Return a function for the per-Task ``callback=`` argument."""

        agent = agent_name or self._config.agent_name

        def callback(task_output: Any) -> None:
            event = CrewAIEvent(
                kind="task",
                name=_task_name(task_output, "task"),
                agent_name=agent,
                output=task_output,
            )
            self.observe(event)

        return callback

    def crew_callback(self, agent_name: str | None = None) -> Callable[[Any], None]:
        """Return a function suitable for crew-level step or completion callbacks."""

        agent = agent_name or self._config.agent_name

        def callback(crew_output: Any) -> None:
            event = CrewAIEvent(
                kind="crew",
                name=_crew_name(crew_output, "crew"),
                agent_name=agent,
                output=crew_output,
            )
            self.observe(event)

        return callback
