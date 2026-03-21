"""Explicit HTTP/API producer with observe-first support."""

from __future__ import annotations

import functools
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, ParamSpec, TypeVar
from urllib.parse import urlparse

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ProducerType
from ancilis.producers.tool import BlockedActionError

P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class HTTPRequest:
    method: str
    url: str
    agent_name: str
    headers: dict[str, str] | None = None
    body: Any = None
    service_name: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class HTTPObservation:
    action: Action
    evaluation: EvaluationResult


@dataclass
class HTTPExecutionResult:
    action: Action
    evaluation: EvaluationResult
    blocked: bool
    response: Any = None


class HTTPActionProducer:
    """Produces Action objects for outbound HTTP requests.

    Observe/report mode is the primary path. Explicit transport wrapping can
    optionally enforce pre-request blocking, but it is opt-in by design.
    """

    def __init__(self, config: ResolvedConfig, engine: Engine, registry: ToolRegistry | None = None, evidence_store: EvidenceStore | None = None) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(config)

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.HTTP

    @property
    def producer_version(self) -> str:
        return "0.1.0"

    def _tool_name(self, request: HTTPRequest) -> str:
        parsed = urlparse(request.url)
        host = parsed.netloc or "unknown-host"
        method = request.method.upper()
        return f"http:{method}:{host}"

    def translate(self, raw_invocation: HTTPRequest) -> Action:
        payload = {
            "method": raw_invocation.method.upper(),
            "url": raw_invocation.url,
            "headers": raw_invocation.headers or {},
            "body": raw_invocation.body,
            "metadata": raw_invocation.metadata or {},
        }
        tool_name = self._tool_name(raw_invocation)
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
            action_type="api_request",
            tool=ToolInfo(name=tool_name, server=raw_invocation.service_name or urlparse(raw_invocation.url).netloc, description_hash=entry.description_hash if entry else None),
            parameters=ActionParameters(raw=payload, parameter_hash=param_hash),
            context=ActionContext(data_classifications=dc_codes, active_overlays=list(self._config.active_overlays.keys())),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        return [entry.name for entry in registry.get_all()]

    def _ensure_registered(self, request: HTTPRequest) -> str:
        tool_name = self._tool_name(request)
        if self._registry.lookup(tool_name) is None:
            status = ToolStatus.APPROVED if tool_name in self._config.tools_allowed else ToolStatus.OBSERVED
            self._registry.register(ToolEntry(name=tool_name, description_hash=self.compute_tool_hash(tool_name), status=status, approved_by="config" if status == ToolStatus.APPROVED else None))
        return tool_name

    def observe(self, request: HTTPRequest) -> HTTPObservation:
        tool_name = self._ensure_registered(request)
        action = self.translate(request)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return HTTPObservation(action=action, evaluation=evaluation)

    def execute(self, request: HTTPRequest, *, transport: Callable[P, R], transport_args: tuple[Any, ...] = (), transport_kwargs: dict[str, Any] | None = None, enforce: bool = False) -> HTTPExecutionResult:
        observation = self.observe(request)
        if enforce and observation.evaluation.decision == "BLOCK":
            raise BlockedActionError(observation.action.tool.name, observation.evaluation)
        response = transport(*transport_args, **(transport_kwargs or {}))
        return HTTPExecutionResult(action=observation.action, evaluation=observation.evaluation, blocked=False, response=response)

    def wrap_transport(self, transport: Callable[P, R], *, agent_name: str | None = None, service_name: str | None = None, enforce: bool = False) -> Callable[..., HTTPExecutionResult]:
        @functools.wraps(transport)
        def wrapped(method: str, url: str, *args: Any, **kwargs: Any) -> HTTPExecutionResult:
            request = HTTPRequest(method=method, url=url, agent_name=agent_name or self._config.agent_name, headers=kwargs.get("headers"), body=kwargs.get("data") or kwargs.get("json"), service_name=service_name)
            return self.execute(request, transport=transport, transport_args=(method, url, *args), transport_kwargs=kwargs, enforce=enforce)
        return wrapped
