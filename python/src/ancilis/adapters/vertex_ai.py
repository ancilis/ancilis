"""Google Vertex AI adapter for dependency-free invocation envelopes."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ProducerType

PROVIDER = "google-vertex-ai"
PRODUCER_VERSION = "0.1.0"

_SAFE_AUTH_MODES = {"adc", "api-key", "service-account", "workload-identity"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "oauth",
    "private_key",
    "refresh_token",
    "signed_jwt",
    "token",
    "x_goog_api_key",
)


@dataclass
class VertexAIInvocation:
    """Raw Vertex AI invocation before translation to an Action."""

    method: str
    project_id: str | None = None
    location: str | None = None
    endpoint_id: str | None = None
    publisher_model_id: str | None = None
    request_body: Any = None
    response_body: Any = None
    http_status: int | None = None
    request_id: str | None = None
    latency_ms: float | None = None
    endpoint_host: str | None = None
    headers: Mapping[str, Any] | None = None
    response_metadata: Mapping[str, Any] | None = None
    agent_id: str | None = None
    auth_mode: str | None = None


@dataclass
class VertexAIObservation:
    """Action, evaluation, and evidence record for an observed Vertex AI call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    method: str
    project_id: str | None
    location: str | None
    endpoint_id: str | None
    publisher_model_id: str | None
    request_body: Any
    response_body: Any
    http_status: int | None
    request_id: str | None
    latency_ms: float | None
    endpoint_host: str | None
    headers: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    agent_id: str
    auth_mode: str | None


class VertexAIActionProducer:
    """Produces Action objects from Google Vertex AI invocations.

    The adapter accepts plain dictionaries or VertexAIInvocation objects so the
    SDK stays importable without google-cloud-aiplatform or google-genai installed.
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

    def translate(self, raw_invocation: VertexAIInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        usage = _extract_usage(invocation.response_body)
        request_id = invocation.request_id or _metadata_request_id(invocation.response_metadata)
        http_status = invocation.http_status or _metadata_status_code(invocation.response_metadata)
        endpoint = _endpoint(invocation.location, invocation.endpoint_host)
        model_metadata = _model_metadata(invocation.endpoint_id, invocation.publisher_model_id)
        model_id = model_metadata["id"]
        auth_mode = _resolve_auth_mode(invocation)

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.method,
            "model_id": model_id,
            "project_id": invocation.project_id,
            "location": invocation.location,
            "endpoint_id": invocation.endpoint_id,
            "publisher_model_id": invocation.publisher_model_id,
            "destination": endpoint,
            "http_status": http_status,
            "request_id": request_id,
            "latency_ms": invocation.latency_ms,
            "model": model_metadata,
            "deployment": {
                "provider": PROVIDER,
                "project_id": invocation.project_id,
                "location": invocation.location,
                "endpoint_id": invocation.endpoint_id,
                "publisher_model_id": invocation.publisher_model_id,
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

        tool_name = _tool_name(invocation.method)
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
        self, raw_invocation: VertexAIInvocation | Mapping[str, Any]
    ) -> VertexAIObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.method)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return VertexAIObservation(action=action, evaluation=evaluation, evidence=evidence)

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for method in ("predict", "generateContent"):
            tool_name = _tool_name(method)
            registry.register(
                ToolEntry(
                    name=tool_name,
                    description_hash=self.compute_tool_hash(tool_name),
                    status=ToolStatus.OBSERVED,
                )
            )
            registered.append(tool_name)
        return registered

    def _ensure_registered(self, method: str) -> str:
        tool_name = _tool_name(method)
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


VertexAIAdapter = VertexAIActionProducer


def _normalize_invocation(
    raw_invocation: VertexAIInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, VertexAIInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        endpoint_id = raw_invocation.endpoint_id
        project_id = raw_invocation.project_id
        location = raw_invocation.location
        return _NormalizedInvocation(
            method=raw_invocation.method,
            project_id=project_id,
            location=location,
            endpoint_id=endpoint_id,
            publisher_model_id=raw_invocation.publisher_model_id,
            request_body=raw_invocation.request_body,
            response_body=raw_invocation.response_body,
            http_status=raw_invocation.http_status or _metadata_status_code(response_metadata),
            request_id=raw_invocation.request_id or _metadata_request_id(response_metadata),
            latency_ms=raw_invocation.latency_ms,
            endpoint_host=raw_invocation.endpoint_host,
            headers=dict(raw_invocation.headers or {}),
            response_metadata=response_metadata,
            agent_id=raw_invocation.agent_id or default_agent_id,
            auth_mode=raw_invocation.auth_mode,
        )

    response = _mapping_value(raw_invocation, "response")
    response_metadata = _first_mapping(
        _mapping_value(raw_invocation, "response_metadata"),
        _mapping_value(raw_invocation, "responseMetadata"),
        _mapping_value(raw_invocation, "ResponseMetadata"),
        _mapping_value(response, "response_metadata"),
        _mapping_value(response, "responseMetadata"),
        _mapping_value(response, "ResponseMetadata"),
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
    response_body = _first_present(raw_invocation, "response_body", "responseBody", "output")
    if response_body is None and isinstance(response, Mapping):
        response_body = _first_present(response, "body", "response_body", "responseBody")
        if response_body is None:
            response_body = response

    endpoint_reference = _optional_str(
        _first_present(raw_invocation, "endpoint", "endpoint_name", "endpointName")
    )
    project_id = _optional_str(
        _first_present(raw_invocation, "project_id", "projectId")
        or _project_from_resource(endpoint_reference)
    )
    location = _optional_str(
        _first_present(raw_invocation, "location", "region")
        or _location_from_resource(endpoint_reference)
    )
    endpoint_id = _optional_str(
        _first_present(raw_invocation, "endpoint_id", "endpointId")
        or _endpoint_id_from_resource(endpoint_reference)
    )
    publisher_model_id = _optional_str(
        _first_present(
            raw_invocation,
            "publisher_model_id",
            "publisherModelId",
            "model_id",
            "modelId",
            "model",
        )
    )

    return _NormalizedInvocation(
        method=str(_first_present(raw_invocation, "method", "operation") or "predict"),
        project_id=project_id,
        location=location,
        endpoint_id=endpoint_id,
        publisher_model_id=publisher_model_id,
        request_body=request_body,
        response_body=response_body,
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
        endpoint_host=_optional_str(
            _first_present(
                raw_invocation,
                "endpoint_host",
                "endpointHost",
                "api_endpoint",
                "apiEndpoint",
                "host",
            )
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
    )


def _tool_name(method: str) -> str:
    return f"{PROVIDER}:{method}"


def _endpoint(location: str | None, endpoint_host: str | None) -> str:
    if endpoint_host:
        return endpoint_host.removeprefix("https://").removeprefix("http://").split("/", 1)[0]
    if location:
        return f"{location}-aiplatform.googleapis.com"
    return "aiplatform.googleapis.com"


def _model_metadata(endpoint_id: str | None, publisher_model_id: str | None) -> dict[str, Any]:
    model_id = publisher_model_id or endpoint_id or "unknown-model"
    family = _model_family(model_id, endpoint_id is not None and publisher_model_id is None)
    metadata: dict[str, Any] = {
        "id": model_id,
        "provider": "google",
        "family": family,
    }
    if endpoint_id:
        metadata["endpoint_id"] = endpoint_id
    if publisher_model_id:
        metadata["publisher_model_id"] = publisher_model_id
    return metadata


def _model_family(model_id: str, endpoint_backed: bool) -> str:
    if endpoint_backed:
        return "vertex-endpoint"
    model_reference = model_id.rsplit("/", 1)[-1]
    if model_reference.startswith("gemini"):
        return "gemini"
    if "-" in model_reference:
        return model_reference.split("-", 1)[0]
    return model_reference or "unknown"


def _extract_usage(body: Any) -> dict[str, int]:
    parsed = _parse_body(body)
    if not isinstance(parsed, Mapping):
        return {}

    usage_metadata = _first_mapping(
        _mapping_value(parsed, "usageMetadata"),
        _mapping_value(parsed, "usage_metadata"),
        _mapping_value(parsed, "usage"),
    )
    usage = _token_usage(
        usage_metadata or parsed,
        input_keys=("promptTokenCount", "inputTokenCount", "input_tokens", "inputTokens"),
        output_keys=(
            "candidatesTokenCount",
            "outputTokenCount",
            "output_tokens",
            "outputTokens",
        ),
        total_keys=("totalTokenCount", "total_tokens", "totalTokens"),
    )
    if usage:
        return usage

    metadata = _mapping_value(parsed, "metadata")
    token_metadata = _first_mapping(
        _mapping_value(parsed, "tokenMetadata"),
        _mapping_value(metadata, "tokenMetadata"),
        _mapping_value(metadata, "token_metadata"),
    )
    return _token_usage(
        token_metadata,
        input_keys=("inputTokenCount", "input_token_count"),
        output_keys=("outputTokenCount", "output_token_count"),
        total_keys=("totalTokenCount", "total_token_count"),
    )


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


def _token_usage(
    data: Mapping[str, Any],
    *,
    input_keys: Sequence[str],
    output_keys: Sequence[str],
    total_keys: Sequence[str],
) -> dict[str, int]:
    usage: dict[str, int] = {}
    input_tokens = _first_token_count(data, input_keys)
    output_tokens = _first_token_count(data, output_keys)
    total_tokens = _first_token_count(data, total_keys)
    if input_tokens is not None:
        usage["input_tokens"] = input_tokens
    if output_tokens is not None:
        usage["output_tokens"] = output_tokens
    elif total_tokens is not None and input_tokens is not None:
        usage["output_tokens"] = max(total_tokens - input_tokens, 0)
    return usage


def _first_token_count(data: Mapping[str, Any], keys: Sequence[str]) -> int | None:
    for key in keys:
        value = _token_count(_mapping_value(data, key))
        if value is not None:
            return value
    return None


def _token_count(value: Any) -> int | None:
    direct = _optional_int(value)
    if direct is not None:
        return direct
    if isinstance(value, Mapping):
        return _optional_int(
            _first_present(value, "totalTokens", "total_tokens", "count", "tokens")
        )
    return None


def _resolve_auth_mode(invocation: _NormalizedInvocation) -> str | None:
    if invocation.auth_mode:
        explicit_mode = _safe_auth_mode(invocation.auth_mode)
        if explicit_mode is not None:
            return explicit_mode
    if _header_value(invocation.headers, "x-goog-api-key"):
        return "api-key"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("_", "-")
    return mode if mode in _SAFE_AUTH_MODES else None


def _nested_auth_mode(raw: Mapping[str, Any]) -> str | None:
    auth = _mapping_value(raw, "auth")
    if isinstance(auth, Mapping):
        return _optional_str(_first_present(auth, "mode", "auth_mode", "authMode"))
    return None


def _metadata_status_code(metadata: Mapping[str, Any]) -> int | None:
    return _optional_int(
        _first_present(metadata, "HTTPStatusCode", "http_status", "httpStatus", "statusCode")
    )


def _metadata_request_id(metadata: Mapping[str, Any]) -> str | None:
    return _optional_str(_first_present(metadata, "RequestId", "request_id", "requestId"))


def _header_value(headers: Mapping[str, Any], key: str) -> str | None:
    for header_key, value in headers.items():
        if str(header_key).lower() == key.lower():
            return str(value)
    return None


def _project_from_resource(resource: str | None) -> str | None:
    return _resource_segment(resource, "projects")


def _location_from_resource(resource: str | None) -> str | None:
    return _resource_segment(resource, "locations")


def _endpoint_id_from_resource(resource: str | None) -> str | None:
    return _resource_segment(resource, "endpoints")


def _resource_segment(resource: str | None, segment: str) -> str | None:
    if not resource:
        return None
    parts = resource.strip("/").split("/")
    for index, part in enumerate(parts[:-1]):
        if part == segment:
            return parts[index + 1]
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
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _data_classification_codes(config: ResolvedConfig) -> list[str]:
    codes: list[str] = []
    for values in config.data_classifications.values():
        for code in values:
            if code not in codes:
                codes.append(code)
    return codes


def _output_summary(action: Action) -> str:
    raw = action.parameters.raw
    return f"{raw['provider']} {raw['operation']} {raw['model_id']}"
