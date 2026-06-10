"""AWS Bedrock Runtime adapter for boto3-style invocation envelopes."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from collections.abc import Mapping, Sequence

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

PROVIDER = "aws-bedrock"
PRODUCER_VERSION = "0.1.0"

_SENSITIVE_KEY_PARTS = (
    "access_key",
    "accesskey",
    "authorization",
    "canonical_request",
    "credential",
    "secret",
    "security_token",
    "session_token",
    "signature",
    "signed_headers",
    "x-amz-security-token",
)
_SAFE_AUTH_MODES = {"iam", "session", "role"}


@dataclass
class BedrockInvocation:
    """Raw Bedrock Runtime invocation before translation to an Action."""

    operation: str
    model_id: str | None = None
    region: str | None = None
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


@dataclass
class BedrockObservation:
    """Action, evaluation, and evidence record for an observed Bedrock call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    model_id: str
    region: str | None
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


class BedrockActionProducer:
    """Produces Action objects from AWS Bedrock Runtime invocations.

    The adapter accepts plain dictionaries or BedrockInvocation objects so the
    SDK stays importable without boto3 or botocore installed.
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

    def translate(self, raw_invocation: BedrockInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        usage = _extract_usage(invocation.response_body)
        stream_usage: dict[str, int] = {}
        stream_request_id: str | None = None
        stream_chunk_count = 0
        if invocation.stream_chunks is not None:
            stream_usage, stream_request_id, stream_chunk_count = _extract_stream_usage(
                invocation.stream_chunks
            )
            usage.update(stream_usage)

        request_id = (
            invocation.request_id
            or stream_request_id
            or _metadata_request_id(invocation.response_metadata)
            or _header_value(invocation.headers, "x-amzn-requestid")
        )
        region = invocation.region or _region_from_model_id(invocation.model_id)
        endpoint = _endpoint(region)
        model_metadata = _model_metadata(invocation.model_id)
        auth_mode = _resolve_auth_mode(invocation, invocation.headers)

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "model_id": invocation.model_id,
            "region": region,
            "destination": endpoint,
            "http_status": invocation.http_status,
            "request_id": request_id,
            "latency_ms": invocation.latency_ms,
            "streaming": invocation.operation == "InvokeModelWithResponseStream"
            or invocation.stream_chunks is not None,
            "model": model_metadata,
            "deployment": {
                "provider": PROVIDER,
                "region": region,
                "model_id": invocation.model_id,
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
        if model_metadata.get("inference_profile_arn"):
            payload["deployment"]["inference_profile_arn"] = model_metadata[
                "inference_profile_arn"
            ]
        if auth_mode:
            payload["auth_mode"] = auth_mode
        if "input_tokens" in usage:
            payload["input_tokens"] = usage["input_tokens"]
        if "output_tokens" in usage:
            payload["output_tokens"] = usage["output_tokens"]
        if payload["streaming"]:
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

    def observe(self, raw_invocation: BedrockInvocation | Mapping[str, Any]) -> BedrockObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.operation)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return BedrockObservation(action=action, evaluation=evaluation, evidence=evidence)

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for operation in ("InvokeModel", "InvokeModelWithResponseStream"):
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


BedrockAdapter = BedrockActionProducer


def _normalize_invocation(
    raw_invocation: BedrockInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, BedrockInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            model_id=raw_invocation.model_id or "unknown-model",
            region=raw_invocation.region,
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
        )

    response = _mapping_value(raw_invocation, "response")
    response_metadata = _first_mapping(
        _mapping_value(raw_invocation, "response_metadata"),
        _mapping_value(raw_invocation, "ResponseMetadata"),
        _mapping_value(response, "ResponseMetadata"),
    )
    headers = _first_mapping(
        _mapping_value(raw_invocation, "headers"),
        _mapping_value(raw_invocation, "request_headers"),
        _mapping_value(response_metadata, "HTTPHeaders"),
    )
    response_body = _first_present(
        raw_invocation,
        "response_body",
        "responseBody",
        "output",
    )
    if response_body is None:
        response_body = _first_present(response, "body", "response_body")

    return _NormalizedInvocation(
        operation=str(
            _first_present(raw_invocation, "operation", "operation_name", "operationName")
            or "InvokeModel"
        ),
        model_id=str(
            _first_present(raw_invocation, "model_id", "modelId", "model")
            or "unknown-model"
        ),
        region=_optional_str(
            _first_present(raw_invocation, "region", "region_name", "regionName")
        ),
        request_body=_first_present(raw_invocation, "request_body", "requestBody", "body"),
        response_body=response_body,
        stream_chunks=_as_sequence(
            _first_present(
                raw_invocation,
                "stream_chunks",
                "response_stream",
                "responseStream",
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
    )


def _tool_name(operation: str) -> str:
    return f"{PROVIDER}:{operation}"


def _endpoint(region: str | None) -> str:
    if region:
        return f"bedrock-runtime.{region}.amazonaws.com"
    return "bedrock-runtime.amazonaws.com"


def _model_metadata(model_id: str) -> dict[str, Any]:
    inference_profile_arn = model_id if ":inference-profile/" in model_id else None
    model_reference = model_id.rsplit("/", 1)[-1] if inference_profile_arn else model_id
    if model_reference.startswith("us."):
        model_reference = model_reference[3:]
    provider = model_reference.split(".", 1)[0] if "." in model_reference else "unknown"
    family = "unknown"
    if model_reference.startswith("anthropic.claude"):
        family = "anthropic.claude"
    elif model_reference.startswith("amazon.titan"):
        family = "amazon.titan"
    elif "." in model_reference:
        family = ".".join(model_reference.split(".")[:2])

    metadata: dict[str, Any] = {
        "id": model_id,
        "provider": provider,
        "family": family,
    }
    if inference_profile_arn:
        metadata["inference_profile_arn"] = inference_profile_arn
    return metadata


def _extract_usage(body: Any) -> dict[str, int]:
    parsed = _parse_body(body)
    if not isinstance(parsed, Mapping):
        return {}

    usage = _mapping_value(parsed, "usage")
    if isinstance(usage, Mapping):
        return _token_usage(
            usage,
            input_keys=("input_tokens", "inputTokens", "inputTokenCount"),
            output_keys=("output_tokens", "outputTokens", "outputTokenCount"),
        )

    token_usage = _token_usage(
        parsed,
        input_keys=("input_tokens", "inputTokens", "inputTokenCount", "inputTextTokenCount"),
        output_keys=("output_tokens", "outputTokens", "outputTokenCount"),
    )
    if "output_tokens" not in token_usage:
        results = _mapping_value(parsed, "results")
        if isinstance(results, Sequence) and not isinstance(results, (str, bytes, bytearray)):
            output_tokens = 0
            found = False
            for item in results:
                if not isinstance(item, Mapping):
                    continue
                token_count = _optional_int(_mapping_value(item, "tokenCount"))
                if token_count is not None:
                    output_tokens += token_count
                    found = True
            if found:
                token_usage["output_tokens"] = output_tokens
    return token_usage


def _extract_stream_usage(chunks: Sequence[Any]) -> tuple[dict[str, int], str | None, int]:
    usage: dict[str, int] = {}
    request_id: str | None = None
    count = 0
    for chunk in chunks:
        count += 1
        parsed_chunk = _parse_stream_chunk(chunk)
        if not isinstance(parsed_chunk, Mapping):
            continue
        candidate_usage = _extract_usage(parsed_chunk)
        if not candidate_usage:
            metrics = _mapping_value(parsed_chunk, "amazon-bedrock-invocationMetrics")
            if isinstance(metrics, Mapping):
                candidate_usage = _token_usage(
                    metrics,
                    input_keys=("inputTokenCount", "input_tokens"),
                    output_keys=("outputTokenCount", "output_tokens"),
                )
        usage.update(candidate_usage)
        metadata = _mapping_value(parsed_chunk, "metadata")
        if isinstance(metadata, Mapping):
            metadata_usage = _extract_usage(metadata)
            usage.update(metadata_usage)
            request_id = request_id or _optional_str(
                _first_present(metadata, "request_id", "requestId", "RequestId")
            )
    return usage, request_id, count


def _parse_stream_chunk(chunk: Any) -> Any:
    if isinstance(chunk, Mapping):
        if "metadata" in chunk:
            return chunk
        chunk_payload = _mapping_value(chunk, "chunk")
        if isinstance(chunk_payload, Mapping) and "bytes" in chunk_payload:
            return _parse_body(_mapping_value(chunk_payload, "bytes"))
        if "bytes" in chunk:
            return _parse_body(_mapping_value(chunk, "bytes"))
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


def _token_usage(
    data: Mapping[str, Any],
    *,
    input_keys: Sequence[str],
    output_keys: Sequence[str],
) -> dict[str, int]:
    usage: dict[str, int] = {}
    input_tokens = _first_int(data, input_keys)
    output_tokens = _first_int(data, output_keys)
    if input_tokens is not None:
        usage["input_tokens"] = input_tokens
    if output_tokens is not None:
        usage["output_tokens"] = output_tokens
    return usage


def _first_int(data: Mapping[str, Any], keys: Sequence[str]) -> int | None:
    for key in keys:
        value = _optional_int(_mapping_value(data, key))
        if value is not None:
            return value
    return None


def _resolve_auth_mode(
    invocation: _NormalizedInvocation,
    headers: Mapping[str, Any],
) -> str | None:
    if invocation.auth_mode:
        explicit_mode = _safe_auth_mode(invocation.auth_mode)
        if explicit_mode is not None:
            return explicit_mode
    if _header_value(headers, "x-amz-security-token"):
        return "session"
    authorization = _header_value(headers, "authorization")
    if authorization and "AWS4-HMAC-SHA256" in authorization:
        return "iam"
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
    return _optional_int(_first_present(metadata, "HTTPStatusCode", "http_status"))


def _metadata_request_id(metadata: Mapping[str, Any]) -> str | None:
    return _optional_str(_first_present(metadata, "RequestId", "request_id", "requestId"))


def _header_value(headers: Mapping[str, Any], key: str) -> str | None:
    for header_key, value in headers.items():
        if str(header_key).lower() == key.lower():
            return str(value)
    return None


def _region_from_model_id(model_id: str) -> str | None:
    if model_id.startswith("arn:"):
        parts = model_id.split(":")
        if len(parts) > 3 and parts[3]:
            return parts[3]
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
