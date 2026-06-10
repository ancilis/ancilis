"""Microsoft Semantic Kernel framework producer.

Semantic Kernel uses a *filters* pipeline for kernel function invocation,
prompt rendering, and auto-function-invocation. Each filter has the signature
``async def filter(context, next): await next(context)``. This producer
supplies filter callables that observe each invocation as it passes through
the pipeline. Duck-typed against ``semantic_kernel`` — the SDK is not
required at runtime.

Typical wiring::

    from semantic_kernel import Kernel
    from ancilis.producers import SemanticKernelActionProducer

    producer = SemanticKernelActionProducer(config=cfg, engine=engine)
    kernel = Kernel()
    kernel.add_filter("function_invocation", producer.function_invocation_filter())
    kernel.add_filter("prompt_rendering", producer.prompt_rendering_filter())

Three filter factories are exposed, one per Semantic Kernel filter slot.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.enforcement import ENFORCE_CAPABLE
from ancilis.producers.protocol import ProducerType
from ancilis.producers.tool import BlockedActionError
from ancilis.telemetry import record_adapter_used

PROVIDER = "semantic-kernel"
PRODUCER_VERSION = "0.1.0"

FunctionInvocationFilter = Callable[[Any, Callable[[Any], Awaitable[Any]]], Awaitable[Any]]


@dataclass
class SemanticKernelEvent:
    """Normalized Semantic Kernel filter event."""

    kind: str  # "function_invocation" | "prompt_rendering" | "auto_function_invocation"
    function_name: str
    plugin_name: str
    agent_name: str
    arguments: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticKernelObservation:
    action: Action
    evaluation: EvaluationResult


def _string_attr(obj: Any, attrs: tuple[str, ...]) -> str | None:
    for attr in attrs:
        value = getattr(obj, attr, None)
        if isinstance(value, str) and value:
            return value
    return None


def _function_metadata(context: Any) -> tuple[str, str]:
    """Extract (function_name, plugin_name) from a Semantic Kernel context."""
    function_name = (
        _string_attr(context, ("function_name",))
        or _string_attr(getattr(context, "function", None), ("name", "function_name"))
        or "unknown-function"
    )
    plugin_name = (
        _string_attr(context, ("plugin_name",))
        or _string_attr(getattr(context, "function", None), ("plugin_name",))
        or "default"
    )
    return function_name, plugin_name


def _arguments_value(context: Any) -> Any:
    """Best-effort extraction of arguments from a SK FilterContext."""
    args = getattr(context, "arguments", None)
    if args is None:
        return None
    if isinstance(args, (dict, list, str, int, float, bool)):
        return args
    for attr in ("model_dump", "dict", "to_dict"):
        method = getattr(args, attr, None)
        if callable(method):
            try:
                return method()
            except Exception:  # pragma: no cover - upstream object misbehaving
                continue
    # Fall back to converting iterables of kv pairs (KernelArguments behaves
    # dict-like).
    try:
        return dict(args)
    except (TypeError, ValueError):
        return repr(args)


class SemanticKernelActionProducer:
    """Producer for Microsoft Semantic Kernel (Python SDK).

    Enforce-capable: the SK filter pipeline lets the filter refuse a call by
    raising before awaiting ``next_fn``, so in enforce mode a BLOCK decision
    stops the function invocation rather than merely recording it.
    """

    ENFORCEMENT = ENFORCE_CAPABLE

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

    def _tool_name(self, event: SemanticKernelEvent) -> str:
        return f"{PROVIDER}:{event.kind}:{event.plugin_name}.{event.function_name}"

    def translate(self, raw_invocation: SemanticKernelEvent) -> Action:
        payload = {
            "provider": PROVIDER,
            "kind": raw_invocation.kind,
            "function_name": raw_invocation.function_name,
            "plugin_name": raw_invocation.plugin_name,
            "arguments": raw_invocation.arguments,
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
        action_type = (
            "tool_call"
            if raw_invocation.kind in {"function_invocation", "auto_function_invocation"}
            else "api_request"
        )
        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=raw_invocation.agent_name,
            source_type=self.producer_type.value,
            agent_owner=self._config.agent_owner or None,
            action_type=action_type,
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

    def _ensure_registered(self, event: SemanticKernelEvent) -> str:
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

    def observe(self, event: SemanticKernelEvent) -> SemanticKernelObservation:
        tool_name = self._ensure_registered(event)
        action = self.translate(event)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return SemanticKernelObservation(action=action, evaluation=evaluation)

    # --- Filter factories ---

    def _make_filter(
        self, kind: str, *, agent_name: str | None
    ) -> FunctionInvocationFilter:
        agent = agent_name or self._config.agent_name

        async def filter_fn(context: Any, next_fn: Callable[[Any], Awaitable[Any]]) -> Any:
            function_name, plugin_name = _function_metadata(context)
            event = SemanticKernelEvent(
                kind=kind,
                function_name=function_name,
                plugin_name=plugin_name,
                agent_name=agent,
                arguments=_arguments_value(context),
            )
            observation = self.observe(event)
            # Enforce-capable surface: refuse the invocation on a BLOCK decision
            # by raising BEFORE awaiting next_fn, so enforce mode actually
            # prevents the call instead of only recording it.
            if (
                self._config.mode == "enforce"
                and observation.evaluation.decision == "BLOCK"
            ):
                raise BlockedActionError(
                    observation.action.tool.name, observation.evaluation
                )
            return await next_fn(context)

        return filter_fn

    def function_invocation_filter(
        self, *, agent_name: str | None = None
    ) -> FunctionInvocationFilter:
        """Return a filter for the ``function_invocation`` slot."""
        return self._make_filter("function_invocation", agent_name=agent_name)

    def prompt_rendering_filter(
        self, *, agent_name: str | None = None
    ) -> FunctionInvocationFilter:
        """Return a filter for the ``prompt_rendering`` slot."""
        return self._make_filter("prompt_rendering", agent_name=agent_name)

    def auto_function_invocation_filter(
        self, *, agent_name: str | None = None
    ) -> FunctionInvocationFilter:
        """Return a filter for the ``auto_function_invocation`` slot."""
        return self._make_filter("auto_function_invocation", agent_name=agent_name)
