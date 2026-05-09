"""Azure OpenAI adapter for dependency-free invocation envelopes."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import ParseResult, parse_qs, urlparse

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.engine.result import EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.protocol import ProducerType
from ancilis.telemetry import record_adapter_used

PROVIDER = "azure-openai"
PRODUCER_VERSION = "0.1.0"

_SAFE_AUTH_MODES = {"api-key", "azure-ad", "managed-identity"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api_key",
    "api-key",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "oauth",
    "refresh_token",
    "secret",
    "token",
    "token_provider",
)


@dataclass
class AzureOpenAIInvocation:
    """Raw Azure OpenAI invocation before translation to an Action."""

    operation: str
    azure_deployment: str | None = None
    endpoint_host: str | None = None
    api_version: str | None = None
    region: str | None = None
    request_body: Any = None
    response_body: Any = None
    http_status: int | None = None
    request_id: str | None = None
    latency_ms: float | None = None
    headers: Mapping[str, Any] | None = None
    response_metadata: Mapping[str, Any] | None = None
    agent_id: str | None = None
    auth_mode: str | None = None
    url: str | None = None


@dataclass
class AzureOpenAIObservation:
    """Action, evaluation, and evidence record for an observed Azure OpenAI call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    azure_deployment: str | None
    endpoint_host: str | None
    api_version: str | None
    region: str | None
    request_body: Any
    response_body: Any
    http_status: int | None
    request_id: str | None
    latency_ms: float | None
    headers: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    agent_id: str
    auth_mode: str | None
    url: str | None


class AzureOpenAIActionProducer:
    """Produces Action objects from Azure OpenAI request/response envelopes.

    The adapter accepts plain dictionaries or AzureOpenAIInvocation objects so
    the SDK stays importable without the OpenAI Python package installed.
    """

    def __init__(
        self,
        config: ResolvedConfig,
        engine: Engine,
        registry: ToolRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
        deployment_model_map: Mapping[str, str] | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(config)
        self._deployment_model_map = dict(deployment_model_map or {})
        self._session_id = str(uuid.uuid4())
        record_adapter_used(PROVIDER)

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

    def translate(self, raw_invocation: AzureOpenAIInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        usage = _extract_usage(invocation.response_body)
        endpoint = _endpoint(invocation.endpoint_host, invocation.url)
        auth_mode = _resolve_auth_mode(invocation)
        model_metadata = _model_metadata(
            invocation.azure_deployment,
            invocation.response_body,
            self._deployment_model_map,
            raw_invocation,
        )

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "deployment_name": invocation.azure_deployment,
            "model_id": model_metadata["id"],
            "endpoint_host": endpoint,
            "api_version": invocation.api_version,
            "region": invocation.region,
            "destination": endpoint,
            "http_status": invocation.http_status,
            "request_id": invocation.request_id,
            "latency_ms": invocation.latency_ms,
            "model": model_metadata,
            "deployment": {
                "provider": PROVIDER,
                "name": invocation.azure_deployment,
                "endpoint_host": endpoint,
                "api_version": invocation.api_version,
                "region": invocation.region,
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
        self, raw_invocation: AzureOpenAIInvocation | Mapping[str, Any]
    ) -> AzureOpenAIObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.operation)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return AzureOpenAIObservation(action=action, evaluation=evaluation, evidence=evidence)

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for operation in ("chat.completions.create", "completions.create", "responses.create"):
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


AzureOpenAIAdapter = AzureOpenAIActionProducer


def _normalize_invocation(
    raw_invocation: AzureOpenAIInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, AzureOpenAIInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            azure_deployment=raw_invocation.azure_deployment
            or _deployment_from_url(raw_invocation.url),
            endpoint_host=_host_from_endpoint(raw_invocation.endpoint_host)
            or _host_from_url(raw_invocation.url),
            api_version=raw_invocation.api_version or _api_version_from_url(raw_invocation.url),
            region=raw_invocation.region,
            request_body=raw_invocation.request_body,
            response_body=raw_invocation.response_body,
            http_status=raw_invocation.http_status or _metadata_status_code(response_metadata),
            request_id=raw_invocation.request_id or _metadata_request_id(response_metadata),
            latency_ms=raw_invocation.latency_ms,
            headers=dict(raw_invocation.headers or {}),
            response_metadata=response_metadata,
            agent_id=raw_invocation.agent_id or default_agent_id,
            auth_mode=raw_invocation.auth_mode,
            url=raw_invocation.url,
        )

    response = _mapping_value(raw_invocation, "response")
    response_metadata = _first_mapping(
        _mapping_value(raw_invocation, "response_metadata"),
        _mapping_value(raw_invocation, "responseMetadata"),
        _mapping_value(raw_invocation, "ResponseMetadata"),
        _mapping_value(response, "response_metadata"),
        _mapping_value(response, "responseMetadata"),
        _mapping_value(response, "ResponseMetadata"),
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
    response_body = _first_present(raw_invocation, "response_body", "responseBody", "output")
    if response_body is None and isinstance(response, Mapping):
        response_body = _first_present(response, "body", "response_body", "responseBody")
        if response_body is None:
            response_body = response

    url = _optional_str(_first_present(raw_invocation, "url", "request_url", "requestUrl"))
    endpoint_reference = _optional_str(
        _first_present(
            raw_invocation,
            "endpoint_host",
            "endpointHost",
            "endpoint",
            "api_base",
            "apiBase",
            "base_url",
            "baseURL",
            "azure_endpoint",
            "azureEndpoint",
            "host",
        )
    )
    endpoint_host = _host_from_endpoint(endpoint_reference) or _host_from_url(url)
    operation = str(
        _first_present(raw_invocation, "operation", "method")
        or _operation_from_url(url)
        or "chat.completions.create"
    )

    return _NormalizedInvocation(
        operation=operation,
        azure_deployment=_optional_str(
            _first_present(
                raw_invocation,
                "azure_deployment",
                "azureDeployment",
                "deployment",
                "deployment_name",
                "deploymentName",
            )
            or _deployment_from_url(url)
        ),
        endpoint_host=endpoint_host,
        api_version=_optional_str(
            _first_present(raw_invocation, "api_version", "apiVersion")
            or _api_version_from_url(url)
        ),
        region=_optional_str(_first_present(raw_invocation, "region", "location")),
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
        url=url,
    )


def _tool_name(operation: str) -> str:
    return f"{PROVIDER}:{operation}"


def _endpoint(endpoint_host: str | None, url: str | None) -> str:
    return endpoint_host or _host_from_url(url) or "openai.azure.com"


def _model_metadata(
    deployment_name: str | None,
    response_body: Any,
    deployment_model_map: Mapping[str, str],
    raw_invocation: AzureOpenAIInvocation | Mapping[str, Any],
) -> dict[str, Any]:
    explicit_model = _explicit_model_id(raw_invocation)
    response_model = _response_model_id(response_body)
    mapped_model = deployment_model_map.get(deployment_name or "")
    if explicit_model:
        model_id = explicit_model
        resolved_from = "invocation"
    elif response_model:
        model_id = response_model
        resolved_from = "response"
    elif mapped_model:
        model_id = mapped_model
        resolved_from = "deployment_model_map"
    else:
        model_id = None
        resolved_from = None

    metadata: dict[str, Any] = {
        "id": model_id,
        "provider": "openai",
        "family": _model_family(model_id),
        "resolved": model_id is not None,
    }
    if resolved_from:
        metadata["resolved_from"] = resolved_from
    return metadata


def _explicit_model_id(raw_invocation: AzureOpenAIInvocation | Mapping[str, Any]) -> str | None:
    if isinstance(raw_invocation, AzureOpenAIInvocation):
        return None
    return _optional_str(_first_present(raw_invocation, "model_id", "modelId", "model"))


def _response_model_id(body: Any) -> str | None:
    parsed = _parse_body(body)
    if isinstance(parsed, Mapping):
        return _optional_str(_first_present(parsed, "model", "model_id", "modelId"))
    return None


def _model_family(model_id: str | None) -> str:
    if not model_id:
        return "unknown"
    model_reference = model_id.rsplit("/", 1)[-1]
    if model_reference.startswith("gpt-4.1"):
        return "gpt-4.1"
    if model_reference.startswith("gpt-4o"):
        return "gpt-4o"
    if model_reference.startswith("gpt-4"):
        return "gpt-4"
    if model_reference.startswith("gpt-35"):
        return "gpt-35"
    if "-" in model_reference:
        return model_reference.split("-", 1)[0]
    return model_reference or "unknown"


def _extract_usage(body: Any) -> dict[str, int]:
    parsed = _parse_body(body)
    if not isinstance(parsed, Mapping):
        return {}
    usage = _first_mapping(
        _mapping_value(parsed, "usage"),
        _mapping_value(parsed, "usage_metadata"),
        _mapping_value(parsed, "usageMetadata"),
    )
    return _token_usage(
        usage or parsed,
        input_keys=("prompt_tokens", "input_tokens", "inputTokens", "promptTokens"),
        output_keys=(
            "completion_tokens",
            "output_tokens",
            "outputTokens",
            "completionTokens",
        ),
        total_keys=("total_tokens", "totalTokens"),
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
    input_keys: tuple[str, ...],
    output_keys: tuple[str, ...],
    total_keys: tuple[str, ...],
) -> dict[str, int]:
    usage: dict[str, int] = {}
    input_tokens = _first_int(data, input_keys)
    output_tokens = _first_int(data, output_keys)
    total_tokens = _first_int(data, total_keys)
    if input_tokens is not None:
        usage["input_tokens"] = input_tokens
    if output_tokens is not None:
        usage["output_tokens"] = output_tokens
    elif total_tokens is not None and input_tokens is not None:
        usage["output_tokens"] = max(total_tokens - input_tokens, 0)
    return usage


def _first_int(data: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = _optional_int(_mapping_value(data, key))
        if value is not None:
            return value
    return None


def _resolve_auth_mode(invocation: _NormalizedInvocation) -> str | None:
    if invocation.auth_mode:
        explicit_mode = _safe_auth_mode(invocation.auth_mode)
        if explicit_mode is not None:
            return explicit_mode
    if _header_value(invocation.headers, "api-key"):
        return "api-key"
    authorization = _header_value(invocation.headers, "authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return "azure-ad"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("_", "-")
    if mode in {"aad", "entra-id", "entra"}:
        mode = "azure-ad"
    return mode if mode in _SAFE_AUTH_MODES else None


def _nested_auth_mode(raw: Mapping[str, Any]) -> str | None:
    auth = _mapping_value(raw, "auth")
    if isinstance(auth, Mapping):
        return _optional_str(_first_present(auth, "mode", "auth_mode", "authMode"))
    return None


def _metadata_status_code(metadata: Mapping[str, Any]) -> int | None:
    return _optional_int(
        _first_present(metadata, "HTTPStatusCode", "http_status", "httpStatus", "status_code", "statusCode")
    )


def _metadata_request_id(metadata: Mapping[str, Any]) -> str | None:
    return _optional_str(_first_present(metadata, "RequestId", "request_id", "requestId"))


def _header_value(headers: Mapping[str, Any], key: str) -> str | None:
    for header_key, value in headers.items():
        if str(header_key).lower() == key.lower():
            return str(value)
    return None


def _host_from_endpoint(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    parsed = urlparse(endpoint)
    host = _host_from_parsed_url(parsed)
    if host is not None:
        return host
    return endpoint.split("/", 1)[0].rsplit("@", 1)[-1]


def _host_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    return _host_from_parsed_url(parsed)


def _host_from_parsed_url(parsed: ParseResult) -> str | None:
    if parsed.hostname is None:
        return None
    if parsed.port is None:
        return parsed.hostname
    return f"{parsed.hostname}:{parsed.port}"


def _api_version_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    values = parse_qs(parsed.query).get("api-version")
    return values[0] if values else None


def _deployment_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlparse(url).path.strip("/").split("/")
    for index, part in enumerate(parts[:-1]):
        if part == "deployments":
            return parts[index + 1]
    return None


def _operation_from_url(url: str | None) -> str | None:
    if not url:
        return None
    parts = urlparse(url).path.strip("/").split("/")
    if "deployments" in parts:
        start = parts.index("deployments") + 2
        operation_parts = parts[start:]
    elif "openai" in parts:
        start = parts.index("openai") + 1
        operation_parts = parts[start:]
    else:
        operation_parts = parts
    operation = ".".join(part for part in operation_parts if part)
    if operation == "chat.completions":
        return "chat.completions.create"
    if operation == "completions":
        return "completions.create"
    if operation == "responses":
        return "responses.create"
    return operation or None


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
    model_or_deployment = raw["model_id"] or raw["deployment_name"] or "unknown-model"
    return f"{raw['provider']} {raw['operation']} {model_or_deployment}"
