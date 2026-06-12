"""Native Anthropic API adapter for dependency-free invocation envelopes."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import ParseResult, urlparse

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.enforcement import OBSERVE_ONLY, warn_if_enforce_unsupported
from ancilis.producers.protocol import ProducerType
from ancilis.telemetry import record_adapter_used

PROVIDER = "anthropic"
PRODUCER_VERSION = "0.1.0"

DEFAULT_ENDPOINT_HOST = "api.anthropic.com"

_SAFE_AUTH_MODES = {"api_key", "bearer", "oauth"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "anthropic-api-key",
    "anthropic_api_key",
    "api_key",
    "api-key",
    "authorization",
    "client_secret",
    "credential",
    "oauth",
    "refresh_token",
    "secret",
    "session_token",
    "x-api-key",
)


@dataclass
class AnthropicInvocation:
    """Raw Anthropic API invocation before translation to an Action."""

    operation: str
    model: str | None = None
    request_body: Any = None
    response_body: Any = None
    stream_chunks: Sequence[Any] | None = None
    http_status: int | None = None
    request_id: str | None = None
    latency_ms: float | None = None
    headers: Mapping[str, Any] | None = None
    response_metadata: Mapping[str, Any] | None = None
    agent_id: str | None = None
    auth_mode: str | None = None
    base_url: str | None = None


@dataclass
class AnthropicObservation:
    """Action, evaluation, and evidence record for an observed Anthropic call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    model: str
    request_body: Any
    response_body: Any
    stream_chunks: Sequence[Any] | None
    http_status: int | None
    request_id: str | None
    latency_ms: float | None
    headers: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    agent_id: str
    auth_mode: str | None
    base_url: str | None


class AnthropicActionProducer:
    """Produces Action objects from native Anthropic API invocations.

    The adapter accepts plain dictionaries or AnthropicInvocation objects so the
    SDK stays importable without the ``anthropic`` Python package installed.
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
        # Observe-only: this provider adapter records evidence but cannot block.
        warn_if_enforce_unsupported(type(self).__name__, OBSERVE_ONLY, config)

    @property
    def session_id(self) -> str:
        """Unique identifier for this producer instance."""
        return self._session_id

    @property
    def producer_type(self) -> ProducerType:
        return ProducerType.FRAMEWORK

    @property
    def producer_version(self) -> str:
        return PRODUCER_VERSION

    def translate(self, raw_invocation: AnthropicInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        usage = _extract_usage(invocation.response_body)
        stream_usage: dict[str, int] = {}
        stream_request_id: str | None = None
        stream_model: str | None = None
        stream_chunk_count = 0
        if invocation.stream_chunks is not None:
            (
                stream_usage,
                stream_request_id,
                stream_model,
                stream_chunk_count,
            ) = _extract_stream_usage(invocation.stream_chunks)
            for key, value in stream_usage.items():
                # Stream chunks deliver usage incrementally; later chunks
                # overwrite earlier values (Anthropic emits cumulative counts
                # in message_delta events).
                usage[key] = value

        request_id = (
            invocation.request_id
            or stream_request_id
            or _header_value(invocation.headers, "request-id")
            or _header_value(invocation.headers, "x-request-id")
            or _header_value(invocation.headers, "anthropic-request-id")
        )

        endpoint = _endpoint(invocation.base_url)
        custom_endpoint = endpoint != DEFAULT_ENDPOINT_HOST
        resolved_model = invocation.model or stream_model or _response_model(invocation.response_body)
        model_metadata = _model_metadata(resolved_model)
        auth_mode = _resolve_auth_mode(invocation)

        streaming = (
            invocation.operation == "Messages.stream"
            or invocation.stream_chunks is not None
        )

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "model": resolved_model,
            "model_id": resolved_model,
            "endpoint_host": endpoint,
            "destination": endpoint,
            "custom_base_url": custom_endpoint,
            "http_status": invocation.http_status,
            "request_id": request_id,
            "latency_ms": invocation.latency_ms,
            "streaming": streaming,
            "model_metadata": model_metadata,
            "deployment": {
                "provider": PROVIDER,
                "endpoint_host": endpoint,
                "model": resolved_model,
                "model_family": model_metadata["family"],
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
        if auth_mode:
            payload["auth_mode"] = auth_mode
        if "input_tokens" in usage:
            payload["input_tokens"] = usage["input_tokens"]
        if "output_tokens" in usage:
            payload["output_tokens"] = usage["output_tokens"]
        if "cache_creation_input_tokens" in usage:
            payload["cache_creation_input_tokens"] = usage["cache_creation_input_tokens"]
        if "cache_read_input_tokens" in usage:
            payload["cache_read_input_tokens"] = usage["cache_read_input_tokens"]
        if streaming:
            payload["stream"] = {"chunk_count": stream_chunk_count}

        tool_name = _tool_name(invocation.operation)
        entry = self._registry.lookup(tool_name)
        param_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=repr).encode()
        ).hexdigest()

        return Action(
            action_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=invocation.agent_id,
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
                session_id=self._session_id,
                data_classifications=_data_classification_codes(self._config),
                active_overlays=list(self._config.active_overlays.keys()),
            ),
            producer_type=self.producer_type.value,
            producer_version=self.producer_version,
        )

    def observe(
        self, raw_invocation: AnthropicInvocation | Mapping[str, Any]
    ) -> AnthropicObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.operation)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return AnthropicObservation(action=action, evaluation=evaluation, evidence=evidence)

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for operation in ("Messages.create", "Messages.stream"):
            tool_name = _tool_name(operation)
            registry.register(
                ToolEntry(
                    name=tool_name,
                    description_hash=self.compute_tool_hash(tool_name),
                    status=ToolStatus.OBSERVED,
                )
            )
            registered.append(tool_name)
        return registered

    def _ensure_registered(self, operation: str) -> str:
        tool_name = _tool_name(operation)
        if self._registry.lookup(tool_name) is not None:
            return tool_name
        status = ToolStatus.APPROVED if tool_name in self._config.tools_allowed else ToolStatus.OBSERVED
        self._registry.register(
            ToolEntry(
                name=tool_name,
                description_hash=self.compute_tool_hash(tool_name),
                status=status,
                approved_by="config" if status == ToolStatus.APPROVED else None,
            )
        )
        return tool_name


AnthropicAdapter = AnthropicActionProducer


def _normalize_invocation(
    raw_invocation: AnthropicInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, AnthropicInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            model=raw_invocation.model or "unknown-model",
            request_body=raw_invocation.request_body,
            response_body=raw_invocation.response_body,
            stream_chunks=raw_invocation.stream_chunks,
            http_status=raw_invocation.http_status
            or _metadata_status_code(response_metadata),
            request_id=raw_invocation.request_id
            or _metadata_request_id(response_metadata),
            latency_ms=raw_invocation.latency_ms,
            headers=dict(raw_invocation.headers or {}),
            response_metadata=response_metadata,
            agent_id=raw_invocation.agent_id or default_agent_id,
            auth_mode=raw_invocation.auth_mode,
            base_url=raw_invocation.base_url,
        )

    response = _mapping_value(raw_invocation, "response")
    response_metadata = _first_mapping(
        _mapping_value(raw_invocation, "response_metadata"),
        _mapping_value(raw_invocation, "responseMetadata"),
        _mapping_value(response, "metadata"),
    )
    headers = _first_mapping(
        _mapping_value(raw_invocation, "headers"),
        _mapping_value(raw_invocation, "request_headers"),
        _mapping_value(raw_invocation, "requestHeaders"),
    )
    request_body = _first_present(
        raw_invocation,
        "request_body",
        "requestBody",
        "request",
        "body",
    )
    response_body = _first_present(
        raw_invocation, "response_body", "responseBody", "output"
    )
    if response_body is None and isinstance(response, Mapping):
        response_body = _first_present(response, "body", "response_body", "responseBody")
        if response_body is None:
            response_body = response

    return _NormalizedInvocation(
        operation=str(
            _first_present(raw_invocation, "operation", "method", "operationName")
            or "Messages.create"
        ),
        model=str(
            _first_present(raw_invocation, "model", "model_id", "modelId")
            or _response_model(response_body)
            or "unknown-model"
        ),
        request_body=request_body,
        response_body=response_body,
        stream_chunks=_as_sequence(
            _first_present(
                raw_invocation,
                "stream_chunks",
                "streamChunks",
                "chunks",
                "events",
            )
        ),
        http_status=_optional_int(
            _first_present(raw_invocation, "http_status", "httpStatus", "status_code")
            or _metadata_status_code(response_metadata)
        ),
        request_id=_optional_str(
            _first_present(raw_invocation, "request_id", "requestId")
            or _metadata_request_id(response_metadata)
        ),
        latency_ms=_optional_float(
            _first_present(raw_invocation, "latency_ms", "latencyMs", "duration_ms")
        ),
        headers=headers,
        response_metadata=response_metadata,
        agent_id=str(
            _first_present(raw_invocation, "agent_id", "agent", "agent_name")
            or default_agent_id
        ),
        auth_mode=_optional_str(
            _first_present(raw_invocation, "auth_mode", "authMode")
            or _nested_auth_mode(raw_invocation)
        ),
        base_url=_optional_str(
            _first_present(
                raw_invocation,
                "base_url",
                "baseURL",
                "baseUrl",
                "endpoint",
                "host",
            )
        ),
    )


def _tool_name(operation: str) -> str:
    return f"{PROVIDER}:{operation}"


def _endpoint(base_url: str | None) -> str:
    host = _host_from_endpoint(base_url)
    return host or DEFAULT_ENDPOINT_HOST


def _host_from_endpoint(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    parsed = urlparse(endpoint)
    host = _host_from_parsed_url(parsed)
    if host is not None:
        return host
    candidate = endpoint.split("/", 1)[0].rsplit("@", 1)[-1]
    return candidate or None


def _host_from_parsed_url(parsed: ParseResult) -> str | None:
    if parsed.hostname is None:
        return None
    if parsed.port is None:
        return parsed.hostname
    return f"{parsed.hostname}:{parsed.port}"


def _model_metadata(model: str | None) -> dict[str, Any]:
    if not model:
        return {"id": None, "provider": PROVIDER, "family": "unknown", "resolved": False}
    family = "unknown"
    reference = model.lower()
    if reference.startswith("claude-opus"):
        family = "claude-opus"
    elif reference.startswith("claude-sonnet") or "claude-3-5-sonnet" in reference or "claude-3-7-sonnet" in reference or "claude-3-sonnet" in reference:
        family = "claude-sonnet"
    elif reference.startswith("claude-haiku") or "claude-3-haiku" in reference or "claude-3-5-haiku" in reference:
        family = "claude-haiku"
    elif reference.startswith("claude-3"):
        family = "claude-3"
    elif reference.startswith("claude-"):
        family = "claude"
    return {
        "id": model,
        "provider": PROVIDER,
        "family": family,
        "resolved": True,
    }


def _response_model(body: Any) -> str | None:
    parsed = _parse_body(body)
    if isinstance(parsed, Mapping):
        return _optional_str(_first_present(parsed, "model", "model_id", "modelId"))
    return None


def _extract_usage(body: Any) -> dict[str, int]:
    parsed = _parse_body(body)
    if not isinstance(parsed, Mapping):
        return {}
    usage = _mapping_value(parsed, "usage")
    if isinstance(usage, Mapping):
        return _token_usage(usage)
    return _token_usage(parsed)


def _extract_stream_usage(
    chunks: Sequence[Any],
) -> tuple[dict[str, int], str | None, str | None, int]:
    usage: dict[str, int] = {}
    request_id: str | None = None
    model: str | None = None
    count = 0
    for chunk in chunks:
        count += 1
        parsed_chunk = _parse_stream_chunk(chunk)
        if not isinstance(parsed_chunk, Mapping):
            continue

        chunk_type = _optional_str(_mapping_value(parsed_chunk, "type"))
        message = _mapping_value(parsed_chunk, "message")
        if isinstance(message, Mapping):
            model = model or _optional_str(_mapping_value(message, "model"))
            request_id = request_id or _optional_str(
                _first_present(message, "id", "request_id", "requestId")
            )
            message_usage = _mapping_value(message, "usage")
            if isinstance(message_usage, Mapping):
                for key, value in _token_usage(message_usage).items():
                    usage[key] = value

        delta_usage = _mapping_value(parsed_chunk, "usage")
        if isinstance(delta_usage, Mapping):
            for key, value in _token_usage(delta_usage).items():
                usage[key] = value

        if chunk_type == "message_delta":
            # message_delta carries the running output_tokens total
            delta = _mapping_value(parsed_chunk, "delta")
            if isinstance(delta, Mapping):
                delta_inner_usage = _mapping_value(delta, "usage")
                if isinstance(delta_inner_usage, Mapping):
                    for key, value in _token_usage(delta_inner_usage).items():
                        usage[key] = value

        chunk_request_id = _optional_str(
            _first_present(parsed_chunk, "request_id", "requestId")
        )
        if chunk_request_id:
            request_id = request_id or chunk_request_id
        chunk_model = _optional_str(_mapping_value(parsed_chunk, "model"))
        if chunk_model:
            model = model or chunk_model
    return usage, request_id, model, count


def _parse_stream_chunk(chunk: Any) -> Any:
    if isinstance(chunk, Mapping):
        if "data" in chunk and not _mapping_value(chunk, "type"):
            return _parse_body(_mapping_value(chunk, "data"))
        return chunk
    return _parse_body(chunk)


def _parse_body(body: Any) -> Any:
    if body is None:
        return None
    if isinstance(body, Mapping):
        return body
    if isinstance(body, (bytes, bytearray)):
        try:
            return json.loads(bytes(body).decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    return None


def _body_keys(body: Any) -> list[str]:
    parsed = _parse_body(body)
    if isinstance(parsed, Mapping):
        return sorted(str(key) for key in parsed if not _is_sensitive_key(str(key)))
    return []


def _token_usage(data: Mapping[str, Any]) -> dict[str, int]:
    usage: dict[str, int] = {}
    mapping = (
        ("input_tokens", ("input_tokens", "inputTokens", "prompt_tokens", "promptTokens")),
        (
            "output_tokens",
            ("output_tokens", "outputTokens", "completion_tokens", "completionTokens"),
        ),
        (
            "cache_creation_input_tokens",
            (
                "cache_creation_input_tokens",
                "cacheCreationInputTokens",
                "cache_creation_tokens",
                "cacheCreationTokens",
            ),
        ),
        (
            "cache_read_input_tokens",
            (
                "cache_read_input_tokens",
                "cacheReadInputTokens",
                "cache_read_tokens",
                "cacheReadTokens",
            ),
        ),
    )
    for canonical, candidates in mapping:
        value = _first_int(data, candidates)
        if value is not None:
            usage[canonical] = value
    return usage


def _first_int(data: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = _optional_int(_mapping_value(data, key))
        if value is not None:
            return value
    return None


def _resolve_auth_mode(invocation: _NormalizedInvocation) -> str | None:
    if invocation.auth_mode:
        explicit = _safe_auth_mode(invocation.auth_mode)
        if explicit is not None:
            return explicit
    if _header_value(invocation.headers, "x-api-key") or _header_value(
        invocation.headers, "anthropic-api-key"
    ):
        return "api_key"
    authorization = _header_value(invocation.headers, "authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return "bearer"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("-", "_")
    if mode in {"apikey", "api"}:
        mode = "api_key"
    return mode if mode in _SAFE_AUTH_MODES else None


def _nested_auth_mode(raw: Mapping[str, Any]) -> str | None:
    auth = _mapping_value(raw, "auth")
    if isinstance(auth, Mapping):
        return _optional_str(_first_present(auth, "mode", "auth_mode", "authMode"))
    return None


def _metadata_status_code(metadata: Mapping[str, Any]) -> int | None:
    return _optional_int(
        _first_present(
            metadata,
            "HTTPStatusCode",
            "http_status",
            "httpStatus",
            "status_code",
            "statusCode",
        )
    )


def _metadata_request_id(metadata: Mapping[str, Any]) -> str | None:
    return _optional_str(
        _first_present(metadata, "RequestId", "request_id", "requestId")
    )


def _header_value(headers: Mapping[str, Any], key: str) -> str | None:
    for header_key, value in headers.items():
        if str(header_key).lower() == key.lower():
            return str(value)
    return None


def _mapping_value(data: Any, key: str) -> Any:
    if not isinstance(data, Mapping):
        return None
    for candidate_key, value in data.items():
        if str(candidate_key) == key:
            return value
    return None


def _first_present(data: Any, *keys: str) -> Any:
    if not isinstance(data, Mapping):
        return None
    for key in keys:
        if key in data:
            return data[key]
    return None


def _first_mapping(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, Mapping):
            return {str(key): item for key, item in value.items()}
    return {}


def _as_sequence(value: Any) -> Sequence[Any] | None:
    if value is None:
        return None
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part.replace("-", "_") in lowered for part in _SENSITIVE_KEY_PARTS)


def _data_classification_codes(config: ResolvedConfig) -> list[str]:
    codes: list[str] = []
    for values in config.data_classifications.values():
        for code in values:
            if code not in codes:
                codes.append(code)
    return codes


def _output_summary(action: Action) -> str:
    raw = action.parameters.raw
    model = raw.get("model") or "unknown-model"
    return f"{raw['provider']} {raw['operation']} {model}"
