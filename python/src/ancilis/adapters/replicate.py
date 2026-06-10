"""Replicate adapter for fine-tuned and content-generative model invocations.

Replicate hosts user-supplied and first-party models (Stable Diffusion, Flux,
Whisper, MusicGen, Llama, etc.). Predictions can be image, audio, video, or
text generative; outputs are typically delivered as URLs hosted on
``replicate.delivery``. The adapter sanitises both inputs (which often carry
PII-bearing text prompts) and outputs (URLs that themselves are exfiltration
surfaces) before constructing an :class:`Action` envelope.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

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

PROVIDER = "replicate"
PRODUCER_VERSION = "0.1.0"

DEFAULT_ENDPOINT_HOST = "api.replicate.com"
DEFAULT_OUTPUT_HOST = "replicate.delivery"

_SAFE_AUTH_MODES = {"api_token", "bearer"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api_key",
    "api_token",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "oauth",
    "refresh_token",
    "replicate_api_token",
    "secret",
    "token",
)

# Owner allow-list for first-party / curated organisations on Replicate.
_FIRST_PARTY_OWNERS = frozenset(
    {
        "anthropic",
        "black-forest-labs",
        "cjwbw",
        "google",
        "google-deepmind",
        "lucataco",
        "meta",
        "mistralai",
        "openai",
        "openai-gpt2-fine-tunes",
        "replicate",
        "runwayml",
        "stability-ai",
    }
)

# Owner names that look like generated/anonymous accounts (heuristic).
_UNVERIFIED_OWNER_PATTERNS = ("user-", "tmp-", "anon-")

_OPERATIONS = ("Predictions.create", "Predictions.get", "Trainings.create")

# Input-key heuristics for content-type classification.
_IMAGE_INPUT_KEYS = frozenset({"image", "images", "init_image", "mask", "control_image"})
_AUDIO_INPUT_KEYS = frozenset({"audio", "audio_input", "voice", "speaker"})
_VIDEO_INPUT_KEYS = frozenset({"video", "video_input", "frames"})
_TEXT_INPUT_KEYS = frozenset({"prompt", "text", "system_prompt", "messages"})


@dataclass
class ReplicateInvocation:
    """Raw Replicate API invocation before translation to an Action."""

    operation: str
    model_owner: str | None = None
    model_name: str | None = None
    version: str | None = None
    request_body: Any = None
    response_body: Any = None
    http_status: int | None = None
    request_id: str | None = None
    latency_ms: float | None = None
    headers: Mapping[str, Any] | None = None
    response_metadata: Mapping[str, Any] | None = None
    agent_id: str | None = None
    auth_mode: str | None = None
    base_url: str | None = None


@dataclass
class ReplicateObservation:
    """Action, evaluation, and evidence record for an observed Replicate call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    model_owner: str | None
    model_name: str | None
    version: str | None
    request_body: Any
    response_body: Any
    http_status: int | None
    request_id: str | None
    latency_ms: float | None
    headers: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    agent_id: str
    auth_mode: str | None
    base_url: str | None


class ReplicateActionProducer:
    """Produces Action objects from native Replicate API invocations.

    Accepts both :class:`ReplicateInvocation` instances and plain dictionaries
    so the SDK remains importable without the ``replicate`` Python package.
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

    def translate(self, raw_invocation: ReplicateInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)

        request_parsed = _parse_body(invocation.request_body)
        response_parsed = _parse_body(invocation.response_body)

        owner, name, version = _resolve_model_identity(invocation, request_parsed, response_parsed)
        owner_kind = _classify_owner(owner)

        # Status / lifecycle (Replicate uses: starting, processing, succeeded,
        # failed, canceled).
        status = _status(response_parsed)
        captured = status in {"succeeded", "failed", "canceled", "processing", "starting"}

        # Input-key heuristics.
        request_input = _input_mapping(request_parsed)
        input_keys = _safe_keys(request_input)
        input_count = len(request_input) if isinstance(request_input, Mapping) else 0
        input_value_hash = _hash_joined_values(request_input)
        content_type = _content_type_heuristic(input_keys)

        # Output: only count + first delivery host (NEVER full URLs).
        output_value = _output_value(response_parsed)
        output_url_count, output_first_host = _output_summary_fields(output_value)

        # Webhook (async exfiltration surface — captured under PR-05).
        webhook_url = _webhook_url(request_parsed)
        webhook_present = webhook_url is not None
        webhook_host = _host_from_url(webhook_url) if webhook_url else None

        # Logs / error sanitisation (model output text frequently appears in
        # logs; truncate + hash so we never persist raw content).
        logs_summary = _truncate_and_hash(_string_field(response_parsed, "logs"))
        error_summary = _truncate_and_hash(_string_field(response_parsed, "error"))

        # Predict time + lifecycle timestamps.
        metrics = _mapping_value(response_parsed, "metrics")
        predict_time = _optional_float(_mapping_value(metrics, "predict_time")) if isinstance(metrics, Mapping) else None
        created_at = _optional_str(_mapping_value(response_parsed, "created_at")) if isinstance(response_parsed, Mapping) else None
        started_at = _optional_str(_mapping_value(response_parsed, "started_at")) if isinstance(response_parsed, Mapping) else None
        completed_at = _optional_str(_mapping_value(response_parsed, "completed_at")) if isinstance(response_parsed, Mapping) else None

        prediction_id = _optional_str(_mapping_value(response_parsed, "id")) if isinstance(response_parsed, Mapping) else None
        urls_section = _mapping_value(response_parsed, "urls") if isinstance(response_parsed, Mapping) else None
        get_url_host = None
        if isinstance(urls_section, Mapping):
            get_url_host = _host_from_url(_optional_str(_mapping_value(urls_section, "get")))

        request_id = (
            invocation.request_id
            or _header_value(invocation.headers, "request-id")
            or _header_value(invocation.headers, "x-request-id")
            or _metadata_request_id(invocation.response_metadata)
        )

        endpoint = _endpoint(invocation.base_url)
        custom_endpoint = endpoint != DEFAULT_ENDPOINT_HOST
        auth_mode = _resolve_auth_mode(invocation)

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "endpoint_host": endpoint,
            "destination": endpoint,
            "custom_base_url": custom_endpoint,
            "http_status": invocation.http_status,
            "request_id": request_id,
            "latency_ms": invocation.latency_ms,
            "model_owner": owner,
            "model_name": name,
            "model_version": version,
            "model_id": _model_id(owner, name, version),
            "owner_kind": owner_kind,
            "status": status,
            "captured": captured,
            "content_type": content_type,
            "deployment": {
                "provider": PROVIDER,
                "endpoint_host": endpoint,
                "model_owner": owner,
                "model_name": name,
                "owner_kind": owner_kind,
            },
            "request": {
                "body_present": invocation.request_body is not None,
                "body_keys": _body_keys(request_parsed),
                "input_keys": input_keys,
                "input_count": input_count,
                "input_value_hash": input_value_hash,
                "webhook_present": webhook_present,
                "webhook_host": webhook_host,
            },
            "response": {
                "body_present": invocation.response_body is not None,
                "body_keys": _body_keys(response_parsed),
                "prediction_id": prediction_id,
                "output_url_count": output_url_count,
                "output_host": output_first_host,
                "get_url_host": get_url_host,
                "logs_summary": logs_summary,
                "error_summary": error_summary,
            },
        }
        if predict_time is not None:
            payload["predict_time"] = predict_time
        if created_at is not None:
            payload["created_at"] = created_at
        if started_at is not None:
            payload["started_at"] = started_at
        if completed_at is not None:
            payload["completed_at"] = completed_at
        if auth_mode:
            payload["auth_mode"] = auth_mode

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
        self, raw_invocation: ReplicateInvocation | Mapping[str, Any]
    ) -> ReplicateObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.operation)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return ReplicateObservation(action=action, evaluation=evaluation, evidence=evidence)

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for operation in _OPERATIONS:
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


ReplicateAdapter = ReplicateActionProducer


# --------------------------------------------------------------------------- #
# Normalization                                                                #
# --------------------------------------------------------------------------- #


def _normalize_invocation(
    raw_invocation: ReplicateInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, ReplicateInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            model_owner=raw_invocation.model_owner,
            model_name=raw_invocation.model_name,
            version=raw_invocation.version,
            request_body=raw_invocation.request_body,
            response_body=raw_invocation.response_body,
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
        raw_invocation, "response_body", "responseBody", "output_body"
    )
    if response_body is None and isinstance(response, Mapping):
        response_body = _first_present(response, "body", "response_body", "responseBody")
        if response_body is None:
            response_body = response

    return _NormalizedInvocation(
        operation=str(
            _first_present(raw_invocation, "operation", "method", "operationName")
            or "Predictions.create"
        ),
        model_owner=_optional_str(
            _first_present(raw_invocation, "model_owner", "modelOwner", "owner")
        ),
        model_name=_optional_str(
            _first_present(raw_invocation, "model_name", "modelName", "name")
        ),
        version=_optional_str(_first_present(raw_invocation, "version", "model_version")),
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


# --------------------------------------------------------------------------- #
# Translation helpers                                                          #
# --------------------------------------------------------------------------- #


def _tool_name(operation: str) -> str:
    return f"{PROVIDER}:{operation}"


def _endpoint(base_url: str | None) -> str:
    host = _host_from_url(base_url)
    return host or DEFAULT_ENDPOINT_HOST


def _host_from_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.hostname:
        if parsed.port is None:
            return parsed.hostname
        return f"{parsed.hostname}:{parsed.port}"
    candidate = value.split("/", 1)[0].rsplit("@", 1)[-1]
    return candidate or None


def _resolve_model_identity(
    invocation: _NormalizedInvocation,
    request_parsed: Any,
    response_parsed: Any,
) -> tuple[str | None, str | None, str | None]:
    owner = invocation.model_owner
    name = invocation.model_name
    version = invocation.version

    # Try to recover identity from request body's `model` field
    # (formatted as "owner/name" or "owner/name:version").
    if (owner is None or name is None) and isinstance(request_parsed, Mapping):
        model_field = _optional_str(_mapping_value(request_parsed, "model"))
        parsed_owner, parsed_name, parsed_version = _split_model_identifier(model_field)
        owner = owner or parsed_owner
        name = name or parsed_name
        version = version or parsed_version
        if version is None:
            version = _optional_str(_mapping_value(request_parsed, "version"))

    # Response carries `version` (the immutable hash) and may carry `model`.
    if isinstance(response_parsed, Mapping):
        if version is None:
            version = _optional_str(_mapping_value(response_parsed, "version"))
        if owner is None or name is None:
            model_field = _optional_str(_mapping_value(response_parsed, "model"))
            parsed_owner, parsed_name, _parsed_version = _split_model_identifier(model_field)
            owner = owner or parsed_owner
            name = name or parsed_name

    return owner, name, version


def _split_model_identifier(value: str | None) -> tuple[str | None, str | None, str | None]:
    if not value:
        return None, None, None
    version: str | None = None
    if ":" in value:
        value, version = value.rsplit(":", 1)
    if "/" in value:
        owner, name = value.split("/", 1)
        return owner or None, name or None, version
    return None, value or None, version


def _classify_owner(owner: str | None) -> str:
    if not owner:
        return "unverified"
    lowered = owner.lower()
    if lowered in _FIRST_PARTY_OWNERS:
        return "first_party"
    if any(lowered.startswith(prefix) for prefix in _UNVERIFIED_OWNER_PATTERNS):
        return "unverified"
    return "custom"


def _model_id(owner: str | None, name: str | None, version: str | None) -> str | None:
    if not owner and not name:
        return None
    base = f"{owner or 'unknown'}/{name or 'unknown'}"
    if version:
        return f"{base}:{version}"
    return base


def _input_mapping(request_parsed: Any) -> Mapping[str, Any]:
    if not isinstance(request_parsed, Mapping):
        return {}
    nested = _mapping_value(request_parsed, "input")
    if isinstance(nested, Mapping):
        return nested
    return {}


def _safe_keys(mapping: Mapping[str, Any]) -> list[str]:
    if not isinstance(mapping, Mapping):
        return []
    return sorted(str(key) for key in mapping if not _is_sensitive_key(str(key)))


def _hash_joined_values(mapping: Mapping[str, Any]) -> str | None:
    if not isinstance(mapping, Mapping) or not mapping:
        return None
    parts: list[str] = []
    for key in sorted(mapping):
        if _is_sensitive_key(str(key)):
            continue
        parts.append(f"{key}={_value_signature(mapping[key])}")
    if not parts:
        return None
    digest = hashlib.sha256("\x1e".join(parts).encode()).hexdigest()
    return digest


def _value_signature(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, bytes, bytearray)):
        try:
            text = value.decode() if isinstance(value, (bytes, bytearray)) else value
        except UnicodeDecodeError:
            text = str(value)
        return f"len={len(text)}"
    if isinstance(value, Mapping):
        return f"mapping={len(value)}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return f"seq={len(value)}"
    return type(value).__name__


def _content_type_heuristic(input_keys: Sequence[str]) -> str:
    keys = {key.lower() for key in input_keys}
    if keys & _VIDEO_INPUT_KEYS:
        return "video-generation"
    if keys & _IMAGE_INPUT_KEYS:
        return "image-generation"
    if keys & _AUDIO_INPUT_KEYS:
        return "audio-generation"
    if keys & _TEXT_INPUT_KEYS:
        return "text-generation"
    return "unknown"


def _output_value(response_parsed: Any) -> Any:
    if not isinstance(response_parsed, Mapping):
        return None
    return _mapping_value(response_parsed, "output")


def _output_summary_fields(output: Any) -> tuple[int | None, str | None]:
    if output is None:
        return None, None
    if isinstance(output, str):
        host = _host_from_url(output)
        return (1 if host else 0), host
    if isinstance(output, Sequence) and not isinstance(output, (str, bytes, bytearray)):
        urls = [str(item) for item in output if isinstance(item, str)]
        first_host = _host_from_url(urls[0]) if urls else None
        return len(urls), first_host
    if isinstance(output, Mapping):
        # Some models return a dict (e.g. {"image": "url", "seed": 123}).
        return None, None
    return None, None


def _webhook_url(request_parsed: Any) -> str | None:
    if not isinstance(request_parsed, Mapping):
        return None
    return _optional_str(_mapping_value(request_parsed, "webhook"))


def _string_field(parsed: Any, key: str) -> str | None:
    if not isinstance(parsed, Mapping):
        return None
    value = _mapping_value(parsed, key)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return None


def _truncate_and_hash(value: str | None, limit: int = 200) -> dict[str, Any] | None:
    if value is None:
        return None
    truncated = value[:limit]
    digest = hashlib.sha256(value.encode()).hexdigest()
    return {
        "preview": truncated,
        "length": len(value),
        "sha256": digest,
        "truncated": len(value) > limit,
    }


def _status(response_parsed: Any) -> str | None:
    if not isinstance(response_parsed, Mapping):
        return None
    return _optional_str(_mapping_value(response_parsed, "status"))


def _resolve_auth_mode(invocation: _NormalizedInvocation) -> str | None:
    if invocation.auth_mode:
        explicit = _safe_auth_mode(invocation.auth_mode)
        if explicit is not None:
            return explicit
    authorization = _header_value(invocation.headers, "authorization")
    if authorization:
        lowered = authorization.lower()
        if lowered.startswith("token "):
            return "api_token"
        if lowered.startswith("bearer "):
            return "bearer"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("-", "_")
    if mode in {"token", "apitoken", "replicate_token"}:
        mode = "api_token"
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


def _body_keys(parsed: Any) -> list[str]:
    if isinstance(parsed, Mapping):
        return sorted(str(key) for key in parsed if not _is_sensitive_key(str(key)))
    return []


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
    model_id = raw.get("model_id") or "unknown-model"
    status = raw.get("status") or "unknown"
    return f"{raw['provider']} {raw['operation']} {model_id} status={status}"
