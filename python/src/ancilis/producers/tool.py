"""Generic Python function/tool producer following ADR-005 semantics."""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ParamSpec, TypeVar, cast
from collections.abc import Callable

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.enforcement import ENFORCE_CAPABLE
from ancilis.producers.protocol import ProducerType

P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class ToolInvocation:
    func: Callable[..., Any]
    agent_name: str
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] | None = None
    tool_name: str | None = None


@dataclass
class ToolExecutionResult:
    action: Action
    evaluation: EvaluationResult
    blocked: bool
    return_value: Any = None


class BlockedActionError(Exception):
    """Raised when a producer blocks execution before the wrapped action runs."""

    def __init__(self, tool_name: str, evaluation: EvaluationResult):
        self.tool_name = tool_name
        self.evaluation = evaluation
        failed = [r for r in evaluation.control_results if r.result in ("FAIL", "ERROR")]
        display = ", ".join((r.display_name or r.control_name).lower() for r in failed) or "policy violation"
        self.display_message = (
            f"Ancilis [blocked]: Action '{tool_name}' blocked — {display}.\n"
            f"  To approve: ancilis approve-tool {tool_name}\n"
            f"  To review: ancilis status"
        )
        super().__init__(self.display_message)


class ToolActionProducer:
    """Produces Action objects from Python function/tool invocations.

    Two first-class modes are supported:
    - decorator/wrapper mode for developer-owned tool definitions
    - explicit evaluate/execute mode for framework-owned registrations

    Enforce-capable: ``execute`` raises ``BlockedActionError`` on a BLOCK
    decision before the wrapped callable runs.
    """

    ENFORCEMENT = ENFORCE_CAPABLE

    def __init__(self, config: ResolvedConfig, engine: Engine, registry: ToolRegistry | None = None, evidence_store: EvidenceStore | None = None) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(config)
        self._session_id: str = str(uuid.uuid4())

    @property
    def session_id(self) -> str:
        """Unique identifier for this producer instance (one per agent run)."""
        return self._session_id

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return "0.1.0"

    def _qualified_name(self, func: Callable[..., Any], tool_name: str | None = None) -> str:
        if tool_name:
            return tool_name
        module = getattr(func, "__module__", "__main__")
        qualname = getattr(func, "__qualname__", getattr(func, "__name__", "tool"))
        return f"tool:{module}.{qualname}"

    def translate(self, raw_invocation: ToolInvocation) -> Action:
        kwargs = raw_invocation.kwargs or {}
        tool_name = self._qualified_name(raw_invocation.func, raw_invocation.tool_name)
        payload = {"args": list(raw_invocation.args), "kwargs": kwargs}
        param_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=repr).encode()).hexdigest()
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
            action_type="tool_call",
            tool=ToolInfo(name=tool_name, description_hash=entry.description_hash if entry else None),
            parameters=ActionParameters(raw=payload, parameter_hash=param_hash),
            context=ActionContext(data_classifications=dc_codes, active_overlays=list(self._config.active_overlays.keys()), session_id=self._session_id),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def compute_tool_hash(self, tool_identifier: Callable[..., Any] | str) -> str:
        if callable(tool_identifier):
            func = tool_identifier
            try:
                source = inspect.getsource(func)
            except (OSError, TypeError):
                source = getattr(func, "__qualname__", repr(func))
            ident = f"{getattr(func, '__module__', '__main__')}:{getattr(func, '__qualname__', getattr(func, '__name__', 'tool'))}:{source}"
        else:
            ident = str(tool_identifier)
        return hashlib.sha256(ident.encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        return [entry.name for entry in registry.get_all()]

    def _ensure_registered(self, func: Callable[..., Any], tool_name: str) -> None:
        if self._registry.lookup(tool_name) is not None:
            return
        status = ToolStatus.APPROVED if tool_name in self._config.tools_allowed else ToolStatus.OBSERVED
        self._registry.register(ToolEntry(name=tool_name, description_hash=self.compute_tool_hash(func), status=status, approved_by="config" if status == ToolStatus.APPROVED else None))

    def evaluate(self, func: Callable[..., Any], *, agent_name: str, args: tuple[Any, ...] = (), kwargs: dict[str, Any] | None = None, tool_name: str | None = None) -> tuple[Action, EvaluationResult]:
        """Evaluate a function invocation without executing it."""
        resolved_name = self._qualified_name(func, tool_name)
        self._ensure_registered(func, resolved_name)
        action = self.translate(ToolInvocation(func=func, agent_name=agent_name, args=args, kwargs=kwargs, tool_name=resolved_name))
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=resolved_name)
        return action, evaluation

    def execute(self, func: Callable[P, R], *, agent_name: str, args: tuple[Any, ...] = (), kwargs: dict[str, Any] | None = None, tool_name: str | None = None) -> ToolExecutionResult:
        """Evaluate a function invocation and then execute it when allowed."""
        action, evaluation = self.evaluate(func, agent_name=agent_name, args=args, kwargs=kwargs, tool_name=tool_name)
        if evaluation.decision == "BLOCK":
            raise BlockedActionError(action.tool.name, evaluation)
        result = func(*args, **(kwargs or {}))
        return ToolExecutionResult(action=action, evaluation=evaluation, blocked=False, return_value=result)

    def wrap_tool(self, func: Callable[P, R], *, agent_name: str | None = None, tool_name: str | None = None) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            resolved_agent = agent_name or self._config.agent_name
            result = self.execute(func, agent_name=resolved_agent, args=tuple(args), kwargs=dict(kwargs), tool_name=tool_name)
            return cast(R, result.return_value)
        return wrapped


def wrap_tool(func: Callable[P, R], *, producer: ToolActionProducer, agent_name: str | None = None, tool_name: str | None = None) -> Callable[P, R]:
    return producer.wrap_tool(func, agent_name=agent_name, tool_name=tool_name)


def tool(*, producer: ToolActionProducer, agent_name: str | None = None, tool_name: str | None = None) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        return producer.wrap_tool(func, agent_name=agent_name, tool_name=tool_name)
    return decorator


def evaluate_and_execute(func: Callable[P, R], *, producer: ToolActionProducer, agent_name: str, args: tuple[Any, ...] = (), kwargs: dict[str, Any] | None = None, tool_name: str | None = None) -> ToolExecutionResult:
    return producer.execute(func, agent_name=agent_name, args=args, kwargs=kwargs, tool_name=tool_name)
