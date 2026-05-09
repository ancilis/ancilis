"""AWS Bedrock SDK producer (parity with the TypeScript ``BedrockActionProducer``).

Wraps boto3 ``bedrock-runtime`` calls (``InvokeModel``,
``InvokeModelWithResponseStream``) so each invocation becomes an Action object.
Duck-typed against boto3 — the producer does not import boto3, so the SDK is
not required at runtime.

Mirrors the public API of ``typescript/src/ancilis/producers/bedrock.ts``:
``BedrockInvocation`` / ``BedrockObservation`` / ``BedrockExecutionResult``.
Streaming chunk normalization is intentionally lighter than the TS version;
the common observe→evaluate→execute path is fully covered.
"""

from __future__ import annotations

import functools
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
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

PROVIDER = "aws-bedrock"
PRODUCER_VERSION = "0.1.0"
DEFAULT_OPERATION = "InvokeModel"
STREAM_OPERATION = "InvokeModelWithResponseStream"


@dataclass
class BedrockInvocation:
    """Provider-agnostic shape covering the boto3 bedrock-runtime call surface."""

    operation: str = DEFAULT_OPERATION
    model_id: str = "unknown-model"
    region: str | None = None
    agent_id: str | None = None
    request_body: Any = None
    response_body: Any = None
    stream_chunks: list[Any] | None = None
    http_status: int | None = None
    request_id: str | None = None
    latency_ms: float | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    response_metadata: dict[str, Any] = field(default_factory=dict)
    auth_mode: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BedrockObservation:
    action: Action
    evaluation: EvaluationResult


@dataclass
class BedrockExecutionResult:
    action: Action
    evaluation: EvaluationResult
    blocked: bool
    response: Any = None


def _first_present(mapping: Mapping[str, Any] | None, *keys: str) -> Any:
    if not mapping:
        return None
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _model_metadata(model_id: str) -> dict[str, str]:
    """Derive provider/family from a Bedrock model id or inference-profile ARN."""
    inference_profile_arn = model_id if ":inference-profile/" in model_id else None
    model_reference = (
        model_id.rsplit("/", 1)[-1] if inference_profile_arn else model_id
    )
    if model_reference.startswith("us."):
        model_reference = model_reference[3:]
    provider = model_reference.split(".", 1)[0] if "." in model_reference else "unknown"
    if model_reference.startswith("anthropic.claude"):
        family = "anthropic.claude"
    elif model_reference.startswith("amazon.titan"):
        family = "amazon.titan"
    elif "." in model_reference:
        parts = model_reference.split(".")
        family = ".".join(parts[:2])
    else:
        family = "unknown"
    out = {"id": model_id, "provider": provider, "family": family}
    if inference_profile_arn:
        out["inference_profile_arn"] = inference_profile_arn
    return out


def _endpoint_for(region: str | None) -> str:
    return f"bedrock-runtime.{region}.amazonaws.com" if region else "bedrock-runtime.amazonaws.com"


def _body_keys(body: Any) -> list[str]:
    if isinstance(body, Mapping):
        return sorted(body.keys())
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return []
        if isinstance(parsed, Mapping):
            return sorted(parsed.keys())
    return []


def _extract_usage(body: Any) -> dict[str, int]:
    parsed: Any = body
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return {}
    if not isinstance(parsed, Mapping):
        return {}
    usage_candidate = parsed.get("usage")
    usage_obj: Mapping[str, Any] = (
        usage_candidate if isinstance(usage_candidate, Mapping) else parsed
    )
    out: dict[str, int] = {}
    for key, aliases in (
        ("input_tokens", ("input_tokens", "inputTokens", "inputTokenCount", "inputTextTokenCount")),
        ("output_tokens", ("output_tokens", "outputTokens", "outputTokenCount")),
    ):
        for alias in aliases:
            if alias in usage_obj and isinstance(usage_obj[alias], (int, float)):
                out[key] = int(usage_obj[alias])
                break
    return out


def _normalize_invocation(
    raw: BedrockInvocation | Mapping[str, Any] | None, default_agent_id: str
) -> BedrockInvocation:
    if isinstance(raw, BedrockInvocation):
        if not raw.agent_id:
            raw.agent_id = default_agent_id
        if not raw.operation:
            raw.operation = DEFAULT_OPERATION
        if not raw.model_id:
            raw.model_id = "unknown-model"
        return raw
    raw_map: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    response_metadata = _first_present(
        raw_map, "responseMetadata", "response_metadata", "ResponseMetadata"
    )
    if not isinstance(response_metadata, Mapping):
        response_metadata = {}
    headers = _first_present(raw_map, "headers", "request_headers")
    if not isinstance(headers, Mapping):
        headers = response_metadata.get("HTTPHeaders") or response_metadata.get("httpHeaders") or {}
    operation = _first_present(raw_map, "operation", "operationName", "operation_name") or DEFAULT_OPERATION
    model_id = _first_present(raw_map, "modelId", "model_id", "model") or "unknown-model"
    request_id = _first_present(raw_map, "requestId", "request_id")
    if request_id is None and isinstance(response_metadata, Mapping):
        request_id = response_metadata.get("RequestId") or response_metadata.get("requestId")
    http_status = _first_present(raw_map, "httpStatus", "http_status", "status_code")
    if http_status is None and isinstance(response_metadata, Mapping):
        http_status = response_metadata.get("HTTPStatusCode") or response_metadata.get("httpStatusCode")
    return BedrockInvocation(
        operation=str(operation),
        model_id=str(model_id),
        region=_first_present(raw_map, "region", "regionName", "region_name"),
        agent_id=_first_present(raw_map, "agentId", "agent_id", "agent", "agent_name") or default_agent_id,
        request_body=_first_present(raw_map, "requestBody", "request_body", "body"),
        response_body=_first_present(raw_map, "responseBody", "response_body"),
        stream_chunks=_first_present(raw_map, "streamChunks", "stream_chunks", "responseStream", "response_stream"),
        http_status=int(http_status) if isinstance(http_status, (int, float)) else None,
        request_id=str(request_id) if request_id else None,
        latency_ms=_first_present(raw_map, "latencyMs", "latency_ms", "duration_ms"),
        headers=dict(headers) if isinstance(headers, Mapping) else {},
        response_metadata=dict(response_metadata) if isinstance(response_metadata, Mapping) else {},
        auth_mode=_first_present(raw_map, "authMode", "auth_mode"),
        metadata={
            k: v
            for k, v in raw_map.items()
            if k not in {
                "operation", "operationName", "operation_name",
                "modelId", "model_id", "model",
                "region", "regionName", "region_name",
                "agentId", "agent_id", "agent", "agent_name",
                "requestBody", "request_body", "body",
                "responseBody", "response_body",
                "streamChunks", "stream_chunks", "responseStream", "response_stream",
                "httpStatus", "http_status", "status_code",
                "requestId", "request_id",
                "latencyMs", "latency_ms", "duration_ms",
                "headers", "request_headers",
                "responseMetadata", "response_metadata", "ResponseMetadata",
                "authMode", "auth_mode",
            }
        },
    )


def _tool_name_for(operation: str) -> str:
    return f"{PROVIDER}:{operation}"


class BedrockActionProducer:
    """Produces Action objects for AWS Bedrock SDK calls.

    Pairs with the TypeScript ``BedrockActionProducer``. Use ``observe`` for
    a fully-formed invocation already collected from the SDK; ``execute`` to
    wrap a transport callable; ``wrap_invoke_model`` to wrap a boto3 client's
    ``invoke_model`` method.
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

    def translate(self, raw_invocation: BedrockInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        usage = _extract_usage(invocation.response_body)
        endpoint = _endpoint_for(invocation.region)
        model = _model_metadata(invocation.model_id)
        is_streaming = invocation.operation == STREAM_OPERATION or invocation.stream_chunks is not None

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "model_id": invocation.model_id,
            "region": invocation.region,
            "destination": endpoint,
            "http_status": invocation.http_status,
            "request_id": invocation.request_id,
            "latency_ms": invocation.latency_ms,
            "streaming": is_streaming,
            "model": model,
            "deployment": {
                "provider": PROVIDER,
                "region": invocation.region,
                "model_id": invocation.model_id,
                "model_family": model["family"],
            },
            "request": {
                "body_present": invocation.request_body is not None,
                "body_keys": _body_keys(invocation.request_body),
            },
            "response": {
                "body_present": invocation.response_body is not None,
                "body_keys": _body_keys(invocation.response_body),
            },
        }
        if "inference_profile_arn" in model:
            payload["deployment"]["inference_profile_arn"] = model["inference_profile_arn"]
        if invocation.auth_mode:
            payload["auth_mode"] = invocation.auth_mode
        if "input_tokens" in usage:
            payload["input_tokens"] = usage["input_tokens"]
        if "output_tokens" in usage:
            payload["output_tokens"] = usage["output_tokens"]
        if is_streaming and invocation.stream_chunks is not None:
            payload["stream"] = {"chunk_count": len(invocation.stream_chunks)}

        tool_name = _tool_name_for(invocation.operation)
        entry = self._registry.lookup(tool_name)
        param_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=repr).encode()
        ).hexdigest()
        dc_codes: list[str] = []
        for codes in self._config.data_classifications.values():
            for code in codes:
                if code not in dc_codes:
                    dc_codes.append(code)

        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=invocation.agent_id or self._config.agent_name,
            source_type=self.producer_type.value,
            agent_owner=self._config.agent_owner or None,
            action_type="api_request",
            tool=ToolInfo(
                name=tool_name,
                server=endpoint,
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
        registered: list[str] = []
        for operation in (DEFAULT_OPERATION, STREAM_OPERATION):
            name = _tool_name_for(operation)
            if registry.lookup(name) is None:
                registry.register(
                    ToolEntry(
                        name=name,
                        description_hash=self.compute_tool_hash(name),
                        status=ToolStatus.OBSERVED,
                    )
                )
            registered.append(name)
        return registered

    def _ensure_registered(self, operation: str) -> str:
        name = _tool_name_for(operation)
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

    def observe(
        self, raw_invocation: BedrockInvocation | Mapping[str, Any]
    ) -> BedrockObservation:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(invocation.operation)
        action = self.translate(invocation)
        evaluation = self._engine.evaluate(action)
        self._evidence_store.store(evaluation, tool_name=tool_name)
        return BedrockObservation(action=action, evaluation=evaluation)

    def execute(
        self,
        raw_invocation: BedrockInvocation | Mapping[str, Any],
        *,
        transport: Callable[P, R],
        transport_args: tuple[Any, ...] = (),
        transport_kwargs: dict[str, Any] | None = None,
        enforce: bool = False,
    ) -> BedrockExecutionResult:
        observation = self.observe(raw_invocation)
        if enforce and observation.evaluation.decision == "BLOCK":
            raise BlockedActionError(observation.action.tool.name, observation.evaluation)
        response = transport(*transport_args, **(transport_kwargs or {}))
        return BedrockExecutionResult(
            action=observation.action,
            evaluation=observation.evaluation,
            blocked=False,
            response=response,
        )

    def wrap_invoke_model(
        self,
        invoke_model: Callable[..., Any],
        *,
        agent_name: str | None = None,
        operation: str = DEFAULT_OPERATION,
        enforce: bool = False,
    ) -> Callable[..., BedrockExecutionResult]:
        """Wrap a boto3 ``client.invoke_model`` so each call is observed first."""

        @functools.wraps(invoke_model)
        def wrapped(*args: Any, **kwargs: Any) -> BedrockExecutionResult:
            invocation = BedrockInvocation(
                operation=operation,
                model_id=str(kwargs.get("modelId") or kwargs.get("model_id") or "unknown-model"),
                agent_id=agent_name or self._config.agent_name,
                request_body=kwargs.get("body"),
            )
            return self.execute(
                invocation,
                transport=invoke_model,
                transport_args=args,
                transport_kwargs=kwargs,
                enforce=enforce,
            )

        return wrapped


# Alias matches the TS export.
BedrockAdapter = BedrockActionProducer
