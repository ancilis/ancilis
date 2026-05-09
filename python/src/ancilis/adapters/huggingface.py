"""HuggingFace Inference adapter for serverless, dedicated, and provider-routed inference.

HuggingFace serves the dominant fraction of open-weight model inference for
agents using Llama, Mistral, BAAI embeddings, sentence-transformers, etc. The
platform exposes three architecturally distinct surfaces, each with a different
posture profile:

* **Serverless Inference API** (``api-inference.huggingface.co``) — shared,
  unpinned model versions. The same model id can mutate between calls; this is
  a PR-05 reproducibility risk by default.
* **Inference Endpoints** (``*.endpoints.huggingface.cloud``) — user-deployed
  dedicated GPUs with their own auth tokens. BYO-infra audit surface.
* **Inference Providers** (HF routes through ``replicate``, ``together``,
  ``fireworks-ai``, ``nebius``, ``sambanova``, ``hyperbolic``, etc.) — the
  request looks like a HF call but inference happens on a third party. Cached
  responses may have transited a provider with different data-residency than
  HF itself.

The adapter classifies the surface from the base URL / routing-provider header,
captures usage telemetry from the ``x-compute-*`` and ``x-cached`` headers, and
sanitises both inputs and outputs per task type (text-generation, embeddings,
speech-to-text, classification, image-gen, conversational, etc.) so that the
SDK never persists raw prompts, transcripts, generated text, or binary blobs.

The adapter accepts plain dictionaries or :class:`HuggingFaceInvocation` so the
SDK stays importable without ``huggingface-hub``.
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
from ancilis.producers.protocol import ProducerType
from ancilis.telemetry import record_adapter_used

PROVIDER = "huggingface"
PRODUCER_VERSION = "0.1.0"

DEFAULT_ENDPOINT_HOST = "api-inference.huggingface.co"
DEDICATED_ENDPOINT_SUFFIX = ".endpoints.huggingface.cloud"

DEFAULT_LONG_GENERATION_TOKENS = 1000

_SAFE_AUTH_MODES = {"api_token", "bearer", "dedicated_endpoint_token"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api_key",
    "api_token",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "hf_token",
    "huggingface_token",
    "oauth",
    "refresh_token",
    "secret",
    "token",
)

# Trusted / first-party orgs on HuggingFace. Anything outside this set is
# treated as ``community`` (or ``unverified`` when the owner is missing) so
# supply-chain provenance is captured under PR-03.
_TRUSTED_OWNERS = frozenset(
    {
        "baai",
        "black-forest-labs",
        "deepseek-ai",
        "facebook",
        "google",
        "google-bert",
        "huggingface",
        "intfloat",
        "meta",
        "meta-llama",
        "microsoft",
        "mistralai",
        "openai",
        "openai-community",
        "qwen",
        "sentence-transformers",
        "stabilityai",
        "tiiuae",
    }
)

# Known Inference-Provider routes. When the ``x-routing-provider`` header is
# set by HF, the request travelled through a third-party provider before
# hitting weights — captured for data-residency posture.
_INFERENCE_PROVIDERS = frozenset(
    {
        "fal-ai",
        "fireworks-ai",
        "hyperbolic",
        "nebius",
        "novita",
        "replicate",
        "sambanova",
        "together",
    }
)

_TASK_TYPES = (
    "text-generation",
    "text-to-image",
    "text-to-speech",
    "speech-to-text",
    "image-classification",
    "image-to-text",
    "embeddings",
    "text-classification",
    "token-classification",
    "question-answering",
    "summarization",
    "translation",
    "fill-mask",
    "zero-shot-classification",
    "conversational",
    "unknown",
)

# Heuristics linking a request shape to a task type when none is supplied.
_TEXT_GENERATION_KEYS = frozenset({"inputs", "messages"})


@dataclass
class HuggingFaceInvocation:
    """Raw HuggingFace Inference invocation before translation to an Action."""

    operation: str = "Models.run"
    model_owner: str | None = None
    model_name: str | None = None
    model_revision: str | None = None
    task_type: str | None = None
    endpoint_kind: str | None = None
    routing_provider: str | None = None
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
class HuggingFaceObservation:
    """Action, evaluation, and evidence record for an observed HF call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    model_owner: str | None
    model_name: str | None
    model_revision: str | None
    task_type: str | None
    endpoint_kind: str | None
    routing_provider: str | None
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


class HuggingFaceActionProducer:
    """Produces Action objects from native HuggingFace Inference invocations.

    Accepts both :class:`HuggingFaceInvocation` instances and plain dictionaries
    so the SDK remains importable without the ``huggingface-hub`` package.
    """

    def __init__(
        self,
        config: ResolvedConfig,
        engine: Engine,
        registry: ToolRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
        long_generation_tokens: int = DEFAULT_LONG_GENERATION_TOKENS,
    ) -> None:
        self._config = config
        self._engine = engine
        self._registry = registry or engine.registry
        self._evidence_store = evidence_store if evidence_store is not None else EvidenceStore(config)
        self._session_id = str(uuid.uuid4())
        self._long_generation_tokens = long_generation_tokens
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

    def translate(self, raw_invocation: HuggingFaceInvocation | Mapping[str, Any]) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)

        request_parsed = _parse_body(invocation.request_body)
        response_parsed = _parse_body(invocation.response_body)

        owner, name, revision = _resolve_model_identity(invocation, request_parsed)
        owner_kind = _classify_owner(owner)

        # Surface classification: serverless / dedicated_endpoint /
        # inference_provider. Resolves from explicit hint, base URL host suffix,
        # and the ``x-routing-provider`` header.
        routing_provider = _resolve_routing_provider(invocation)
        endpoint_kind = _resolve_endpoint_kind(invocation, routing_provider)
        endpoint = _endpoint(invocation.base_url)

        task_type = _resolve_task_type(invocation, request_parsed, invocation.base_url)

        # Telemetry from x-compute-* / x-cached / x-model-inference-status.
        compute_type = _normalize_compute_type(
            _header_value(invocation.headers, "x-compute-type")
        )
        compute_time_ms = _optional_float(
            _header_value(invocation.headers, "x-compute-time")
        )
        cache_hit = _normalize_cache_hit(
            _header_value(invocation.headers, "x-cached")
        )
        inference_status = _header_value(invocation.headers, "x-model-inference-status")

        request_id = (
            invocation.request_id
            or _header_value(invocation.headers, "x-request-id")
            or _metadata_request_id(invocation.response_metadata)
        )

        latency_ms = invocation.latency_ms
        if latency_ms is None and compute_time_ms is not None:
            latency_ms = compute_time_ms

        custom_endpoint = (
            endpoint != DEFAULT_ENDPOINT_HOST
            and not endpoint.endswith(DEDICATED_ENDPOINT_SUFFIX)
        )
        auth_mode = _resolve_auth_mode(invocation, endpoint_kind)

        # Sanitised request body — never raw prompts.
        request_summary = _request_summary(request_parsed, task_type)

        # Sanitised response body — task-specific shape only.
        response_summary = _response_summary(response_parsed, task_type)

        # Token usage (HF chat-completions surface mirrors OpenAI).
        usage = _extract_usage(response_parsed) if task_type in {"text-generation", "conversational"} else {}

        # Flag computation.
        flags: list[str] = []

        # PR-05: serverless inference without a pinned revision is not
        # reproducible — the same model id can change underneath you.
        if endpoint_kind == "serverless" and not revision:
            flags.append("unpinned_model_revision")

        # PR-05: conversational request lacking an explicit system message
        # cannot be grounded for audit purposes.
        if task_type == "conversational" and not request_summary.get("has_system_message"):
            flags.append("conversational_no_system_message")

        # PR-03: text generation on CPU past the long-generation threshold is
        # almost always degraded inference — captured.
        completion_tokens = (
            usage.get("completion_tokens")
            or usage.get("output_tokens")
            or response_summary.get("generated_text_length")
        )
        if (
            task_type == "text-generation"
            and compute_type == "cpu"
            and isinstance(completion_tokens, int)
            and completion_tokens > self._long_generation_tokens
        ):
            flags.append("cpu_on_long_text_generation")

        # PR-04: cached responses on inference-provider routes have crossed
        # vendor boundaries — data-residency consideration.
        if cache_hit and endpoint_kind == "inference_provider":
            flags.append("inference_provider_cache_hit")

        if endpoint_kind == "dedicated_endpoint" and auth_mode == "dedicated_endpoint_token":
            flags.append("dedicated_endpoint_byo_auth")

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "task_type": task_type,
            "endpoint_kind": endpoint_kind,
            "routing_provider": routing_provider,
            "endpoint_host": endpoint,
            "destination": endpoint,
            "custom_base_url": custom_endpoint,
            "http_status": invocation.http_status,
            "request_id": request_id,
            "latency_ms": latency_ms,
            "model_owner": owner,
            "model_name": name,
            "model_revision": revision,
            "model_id": _model_id(owner, name, revision),
            "owner_kind": owner_kind,
            "compute_type": compute_type,
            "cache_hit": cache_hit,
            "inference_status": inference_status,
            "captured": True,
            "flags": flags,
            "deployment": {
                "provider": PROVIDER,
                "endpoint_host": endpoint,
                "endpoint_kind": endpoint_kind,
                "routing_provider": routing_provider,
                "model_owner": owner,
                "model_name": name,
                "model_revision": revision,
                "owner_kind": owner_kind,
                "compute_type": compute_type,
            },
            "request": {
                "body_present": invocation.request_body is not None,
                "body_keys": _body_keys(request_parsed),
                **request_summary,
            },
            "response": {
                "body_present": invocation.response_body is not None,
                "body_keys": _body_keys(response_parsed),
                **response_summary,
            },
        }
        if usage:
            for key, value in usage.items():
                payload[key] = value
        if auth_mode:
            payload["auth_mode"] = auth_mode

        tool_name = _tool_name(task_type)
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
        self, raw_invocation: HuggingFaceInvocation | Mapping[str, Any]
    ) -> HuggingFaceObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        request_parsed = _parse_body(normalized.request_body)
        task_type = _resolve_task_type(normalized, request_parsed, normalized.base_url)
        tool_name = self._ensure_registered(task_type)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return HuggingFaceObservation(action=action, evaluation=evaluation, evidence=evidence)

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for task in _TASK_TYPES:
            tool_name = _tool_name(task)
            registry.register(
                ToolEntry(
                    name=tool_name,
                    description_hash=self.compute_tool_hash(tool_name),
                    status=ToolStatus.OBSERVED,
                )
            )
            registered.append(tool_name)
        return registered

    def _ensure_registered(self, task_type: str) -> str:
        tool_name = _tool_name(task_type)
        if self._registry.lookup(tool_name) is not None:
            return tool_name
        status = (
            ToolStatus.APPROVED
            if tool_name in self._config.tools_allowed
            else ToolStatus.OBSERVED
        )
        self._registry.register(
            ToolEntry(
                name=tool_name,
                description_hash=self.compute_tool_hash(tool_name),
                status=status,
                approved_by="config" if status == ToolStatus.APPROVED else None,
            )
        )
        return tool_name


HuggingFaceAdapter = HuggingFaceActionProducer


# --------------------------------------------------------------------------- #
# Normalization                                                                #
# --------------------------------------------------------------------------- #


def _normalize_invocation(
    raw_invocation: HuggingFaceInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, HuggingFaceInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            model_owner=raw_invocation.model_owner,
            model_name=raw_invocation.model_name,
            model_revision=raw_invocation.model_revision,
            task_type=raw_invocation.task_type,
            endpoint_kind=raw_invocation.endpoint_kind,
            routing_provider=raw_invocation.routing_provider,
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
            or "Models.run"
        ),
        model_owner=_optional_str(
            _first_present(raw_invocation, "model_owner", "modelOwner", "owner")
        ),
        model_name=_optional_str(
            _first_present(raw_invocation, "model_name", "modelName", "name")
        ),
        model_revision=_optional_str(
            _first_present(
                raw_invocation,
                "model_revision",
                "modelRevision",
                "revision",
                "model_version",
                "modelVersion",
            )
        ),
        task_type=_optional_str(
            _first_present(raw_invocation, "task_type", "taskType", "task")
        ),
        endpoint_kind=_optional_str(
            _first_present(raw_invocation, "endpoint_kind", "endpointKind")
        ),
        routing_provider=_optional_str(
            _first_present(raw_invocation, "routing_provider", "routingProvider")
        ),
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


def _tool_name(task_type: str) -> str:
    return f"{PROVIDER}:Models.run:{task_type}"


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


def _resolve_routing_provider(invocation: _NormalizedInvocation) -> str | None:
    if invocation.routing_provider:
        normalized = invocation.routing_provider.strip().lower()
        return normalized or None
    header = _header_value(invocation.headers, "x-routing-provider")
    if header:
        normalized = header.strip().lower()
        if normalized:
            return normalized
    return None


def _resolve_endpoint_kind(
    invocation: _NormalizedInvocation,
    routing_provider: str | None,
) -> str:
    if invocation.endpoint_kind:
        explicit = invocation.endpoint_kind.strip().lower().replace("-", "_")
        if explicit in {"serverless", "dedicated_endpoint", "inference_provider"}:
            return explicit
    if routing_provider:
        return "inference_provider"
    host = _host_from_url(invocation.base_url)
    if host:
        lowered = host.lower()
        if lowered.endswith(DEDICATED_ENDPOINT_SUFFIX):
            return "dedicated_endpoint"
        if lowered == DEFAULT_ENDPOINT_HOST:
            return "serverless"
    return "serverless"


def _resolve_task_type(
    invocation: _NormalizedInvocation,
    request_parsed: Any,
    base_url: str | None,
) -> str:
    if invocation.task_type:
        normalized = invocation.task_type.strip().lower().replace("_", "-")
        if normalized in _TASK_TYPES:
            return normalized
        # Allow alternate spellings.
        if normalized in {"asr", "automatic-speech-recognition"}:
            return "speech-to-text"
        if normalized in {"text2image", "text-to-img"}:
            return "text-to-image"
        if normalized in {"chat", "chat-completion", "chat-completions"}:
            return "conversational"
        if normalized in {"feature-extraction", "embedding"}:
            return "embeddings"
    # Try to recover from URL path: /pipeline/<task>/<model>.
    if base_url:
        path = urlsplit(base_url).path or ""
        segments = [seg for seg in path.split("/") if seg]
        if "pipeline" in segments:
            try:
                idx = segments.index("pipeline")
                if idx + 1 < len(segments):
                    candidate = segments[idx + 1].strip().lower()
                    if candidate in _TASK_TYPES:
                        return candidate
                    if candidate == "automatic-speech-recognition":
                        return "speech-to-text"
                    if candidate == "feature-extraction":
                        return "embeddings"
            except ValueError:
                pass
    # Heuristic from request shape.
    if isinstance(request_parsed, Mapping):
        if "messages" in request_parsed:
            return "conversational"
        if "question" in request_parsed and "context" in request_parsed:
            return "question-answering"
        if "candidate_labels" in request_parsed:
            return "zero-shot-classification"
        params = _mapping_value(request_parsed, "parameters")
        if isinstance(params, Mapping):
            for key in ("candidate_labels",):
                if key in params:
                    return "zero-shot-classification"
        inputs = _mapping_value(request_parsed, "inputs")
        if isinstance(inputs, Mapping) and "question" in inputs and "context" in inputs:
            return "question-answering"
        if "inputs" in request_parsed:
            return "text-generation"
    return "unknown"


def _resolve_model_identity(
    invocation: _NormalizedInvocation,
    request_parsed: Any,
) -> tuple[str | None, str | None, str | None]:
    owner = invocation.model_owner
    name = invocation.model_name
    revision = invocation.model_revision

    # Try recovering from the request body's model field
    # (chat-completions style).
    if (owner is None or name is None) and isinstance(request_parsed, Mapping):
        model_field = _optional_str(_mapping_value(request_parsed, "model"))
        parsed_owner, parsed_name, parsed_revision = _split_model_identifier(model_field)
        owner = owner or parsed_owner
        name = name or parsed_name
        revision = revision or parsed_revision

    # Try recovering from the URL path: /models/<owner>/<name>.
    if (owner is None or name is None) and invocation.base_url:
        path = urlsplit(invocation.base_url).path or ""
        segments = [seg for seg in path.split("/") if seg]
        if "models" in segments:
            try:
                idx = segments.index("models")
                if idx + 1 < len(segments):
                    parsed_owner, parsed_name, parsed_revision = _split_model_identifier(
                        "/".join(segments[idx + 1 : idx + 3])
                    )
                    owner = owner or parsed_owner
                    name = name or parsed_name
                    revision = revision or parsed_revision
            except ValueError:
                pass

    return owner, name, revision


def _split_model_identifier(value: str | None) -> tuple[str | None, str | None, str | None]:
    if not value:
        return None, None, None
    revision: str | None = None
    if "@" in value:
        value, revision = value.rsplit("@", 1)
    elif ":" in value:
        value, revision = value.rsplit(":", 1)
    if "/" in value:
        owner, name = value.split("/", 1)
        return owner or None, name or None, revision
    return None, value or None, revision


def _classify_owner(owner: str | None) -> str:
    if not owner:
        return "unverified"
    lowered = owner.lower()
    if lowered in _TRUSTED_OWNERS:
        return "first_party"
    return "community"


def _model_id(owner: str | None, name: str | None, revision: str | None) -> str | None:
    if not owner and not name:
        return None
    base = f"{owner or 'unknown'}/{name or 'unknown'}"
    if revision:
        return f"{base}@{revision}"
    return base


def _normalize_compute_type(value: str | None) -> str | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    return lowered or None


def _normalize_cache_hit(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"true", "1", "yes", "hit"}


def _request_summary(request_parsed: Any, task_type: str) -> dict[str, Any]:
    """Sanitise the request body. Never persist raw prompt / message text.

    For each task type we surface structural shape only (length + sha256 of
    canonical content). Image / audio inputs are flagged but the binary itself
    is never recorded.
    """
    summary: dict[str, Any] = {
        "inputs_present": False,
        "messages_present": False,
        "has_system_message": False,
    }
    if not isinstance(request_parsed, Mapping):
        return summary

    inputs = _mapping_value(request_parsed, "inputs")
    if isinstance(inputs, str):
        summary["inputs_present"] = True
        summary["inputs_kind"] = "string"
        summary["inputs_length"] = len(inputs)
        summary["inputs_sha256"] = hashlib.sha256(inputs.encode()).hexdigest()
    elif isinstance(inputs, Mapping):
        summary["inputs_present"] = True
        summary["inputs_kind"] = "object"
        summary["inputs_keys"] = sorted(
            str(k) for k in inputs if not _is_sensitive_key(str(k))
        )
        # question-answering: inputs.question + inputs.context
        question = _mapping_value(inputs, "question")
        context = _mapping_value(inputs, "context")
        if isinstance(question, str):
            summary["inputs_question_length"] = len(question)
        if isinstance(context, str):
            summary["inputs_context_length"] = len(context)
    elif isinstance(inputs, Sequence) and not isinstance(inputs, (str, bytes, bytearray)):
        summary["inputs_present"] = True
        summary["inputs_kind"] = "array"
        summary["inputs_count"] = len(inputs)
        canonical_parts: list[str] = []
        total = 0
        for item in inputs:
            if isinstance(item, str):
                total += len(item)
                canonical_parts.append(item)
        if canonical_parts:
            summary["inputs_total_length"] = total
            summary["inputs_sha256"] = hashlib.sha256(
                "\x1e".join(canonical_parts).encode()
            ).hexdigest()
    elif isinstance(inputs, (bytes, bytearray)):
        summary["inputs_present"] = True
        summary["inputs_kind"] = "binary"
        summary["inputs_byte_length"] = len(inputs)
        summary["inputs_sha256"] = hashlib.sha256(bytes(inputs)).hexdigest()

    messages = _mapping_value(request_parsed, "messages")
    if isinstance(messages, Sequence) and not isinstance(messages, (str, bytes, bytearray)):
        summary["messages_present"] = True
        summary["messages_count"] = len(messages)
        roles: dict[str, int] = {}
        canonical_parts = []
        per_message: list[dict[str, Any]] = []
        for item in messages:
            if isinstance(item, Mapping):
                role = _optional_str(_mapping_value(item, "role")) or "unknown"
                roles[role] = roles.get(role, 0) + 1
                content = _mapping_value(item, "content")
                if isinstance(content, str):
                    per_message.append({"role": role, "length": len(content)})
                    canonical_parts.append(f"{role}:{len(content)}:{content}")
                else:
                    per_message.append({"role": role, "kind": type(content).__name__})
                    canonical_parts.append(f"{role}:{type(content).__name__}")
                if role == "system":
                    summary["has_system_message"] = True
        summary["messages_role_distribution"] = dict(sorted(roles.items()))
        summary["messages_per_message"] = per_message
        if canonical_parts:
            summary["messages_sha256"] = hashlib.sha256(
                "\x1e".join(canonical_parts).encode()
            ).hexdigest()

    # Generation parameters (max_tokens, temperature, etc.) — record presence
    # only.
    parameters = _mapping_value(request_parsed, "parameters")
    if isinstance(parameters, Mapping):
        summary["parameters_keys"] = sorted(
            str(k) for k in parameters if not _is_sensitive_key(str(k))
        )

    return summary


def _response_summary(response_parsed: Any, task_type: str) -> dict[str, Any]:
    """Task-aware sanitised response summary. Never raw text or binary."""
    summary: dict[str, Any] = {"result_present": response_parsed is not None}
    if response_parsed is None:
        return summary

    if task_type == "text-generation":
        text = _extract_generated_text(response_parsed)
        if isinstance(text, str):
            summary["generated_text_length"] = len(text)
            summary["generated_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    elif task_type == "conversational":
        text = _extract_conversational_text(response_parsed)
        if isinstance(text, str):
            summary["generated_text_length"] = len(text)
            summary["generated_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    elif task_type == "embeddings":
        dims, count = _embedding_shape(response_parsed)
        if count is not None:
            summary["embeddings_count"] = count
        if dims is not None:
            summary["embedding_dim"] = dims
    elif task_type in {"text-to-image", "text-to-speech"}:
        binary = _extract_binary(response_parsed)
        if binary is not None:
            summary["binary_byte_length"] = len(binary)
            summary["binary_sha256"] = hashlib.sha256(binary).hexdigest()
    elif task_type in {"image-classification", "text-classification", "zero-shot-classification"}:
        labels, top_label = _classification_shape(response_parsed)
        if labels is not None:
            summary["label_count"] = labels
        if top_label is not None:
            summary["top_label"] = top_label
    elif task_type == "speech-to-text":
        transcript = _extract_transcript(response_parsed)
        if isinstance(transcript, str):
            summary["transcript_length"] = len(transcript)
            summary["transcript_sha256"] = hashlib.sha256(transcript.encode()).hexdigest()
    elif task_type == "image-to-text":
        text = _extract_generated_text(response_parsed)
        if isinstance(text, str):
            summary["generated_text_length"] = len(text)
            summary["generated_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    elif task_type == "summarization":
        text = _extract_summary_text(response_parsed)
        if isinstance(text, str):
            summary["summary_text_length"] = len(text)
            summary["summary_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    elif task_type == "translation":
        text = _extract_translation_text(response_parsed)
        if isinstance(text, str):
            summary["translation_text_length"] = len(text)
            summary["translation_text_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    elif task_type == "token-classification":
        if isinstance(response_parsed, Sequence) and not isinstance(
            response_parsed, (str, bytes, bytearray)
        ):
            summary["token_count"] = len(response_parsed)
    elif task_type == "fill-mask":
        if isinstance(response_parsed, Sequence) and not isinstance(
            response_parsed, (str, bytes, bytearray)
        ):
            summary["candidate_count"] = len(response_parsed)
    elif task_type == "question-answering":
        if isinstance(response_parsed, Mapping):
            answer = _mapping_value(response_parsed, "answer")
            if isinstance(answer, str):
                summary["answer_length"] = len(answer)
                summary["answer_sha256"] = hashlib.sha256(answer.encode()).hexdigest()

    # Generic shape descriptor (kind + size).
    if isinstance(response_parsed, Mapping):
        summary["response_kind"] = "object"
    elif isinstance(response_parsed, Sequence) and not isinstance(
        response_parsed, (str, bytes, bytearray)
    ):
        summary["response_kind"] = "array"
        summary["response_count"] = len(response_parsed)
    elif isinstance(response_parsed, (bytes, bytearray)):
        summary["response_kind"] = "binary"
        summary["response_byte_length"] = len(response_parsed)
    elif isinstance(response_parsed, str):
        summary["response_kind"] = "string"
        summary["response_length"] = len(response_parsed)
    return summary


def _extract_generated_text(parsed: Any) -> str | None:
    if isinstance(parsed, Mapping):
        text = _mapping_value(parsed, "generated_text")
        if isinstance(text, str):
            return text
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
        for item in parsed:
            if isinstance(item, Mapping):
                text = _mapping_value(item, "generated_text")
                if isinstance(text, str):
                    return text
    return None


def _extract_conversational_text(parsed: Any) -> str | None:
    """Pull assistant text from a chat-completion-shaped response."""
    if not isinstance(parsed, Mapping):
        return None
    choices = _mapping_value(parsed, "choices")
    if isinstance(choices, Sequence) and not isinstance(choices, (str, bytes, bytearray)):
        for choice in choices:
            if isinstance(choice, Mapping):
                message = _mapping_value(choice, "message")
                if isinstance(message, Mapping):
                    content = _mapping_value(message, "content")
                    if isinstance(content, str):
                        return content
                delta = _mapping_value(choice, "delta")
                if isinstance(delta, Mapping):
                    content = _mapping_value(delta, "content")
                    if isinstance(content, str):
                        return content
    # Conversational pipeline shape: { "generated_text": ..., "conversation": {...} }
    text = _mapping_value(parsed, "generated_text")
    if isinstance(text, str):
        return text
    return None


def _embedding_shape(parsed: Any) -> tuple[int | None, int | None]:
    """Return (embedding_dim, vector_count) for an embedding response."""
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
        if not parsed:
            return None, 0
        first = parsed[0]
        if isinstance(first, Sequence) and not isinstance(first, (str, bytes, bytearray)):
            # List of vectors.
            return len(first), len(parsed)
        if isinstance(first, (int, float)):
            # Single flat vector.
            return len(parsed), 1
    if isinstance(parsed, Mapping):
        embeddings = _mapping_value(parsed, "embeddings") or _mapping_value(parsed, "data")
        if isinstance(embeddings, Sequence) and not isinstance(
            embeddings, (str, bytes, bytearray)
        ):
            return _embedding_shape(embeddings)
    return None, None


def _extract_binary(parsed: Any) -> bytes | None:
    if isinstance(parsed, (bytes, bytearray)):
        return bytes(parsed)
    return None


def _classification_shape(parsed: Any) -> tuple[int | None, str | None]:
    """Return (label_count, top_label) for a classification response."""
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
        if not parsed:
            return 0, None
        first = parsed[0]
        # HF wraps classification in a one-deep array: [[{"label","score"},...]].
        if isinstance(first, Sequence) and not isinstance(first, (str, bytes, bytearray)):
            return _classification_shape(first)
        if isinstance(first, Mapping):
            label = _optional_str(_mapping_value(first, "label"))
            return len(parsed), label
    if isinstance(parsed, Mapping):
        labels = _mapping_value(parsed, "labels")
        if isinstance(labels, Sequence) and not isinstance(labels, (str, bytes, bytearray)):
            top = labels[0] if labels else None
            return len(labels), _optional_str(top) if top is not None else None
    return None, None


def _extract_transcript(parsed: Any) -> str | None:
    if isinstance(parsed, Mapping):
        text = _mapping_value(parsed, "text")
        if isinstance(text, str):
            return text
    return None


def _extract_summary_text(parsed: Any) -> str | None:
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
        for item in parsed:
            if isinstance(item, Mapping):
                text = _mapping_value(item, "summary_text")
                if isinstance(text, str):
                    return text
    if isinstance(parsed, Mapping):
        text = _mapping_value(parsed, "summary_text")
        if isinstance(text, str):
            return text
    return None


def _extract_translation_text(parsed: Any) -> str | None:
    if isinstance(parsed, Sequence) and not isinstance(parsed, (str, bytes, bytearray)):
        for item in parsed:
            if isinstance(item, Mapping):
                text = _mapping_value(item, "translation_text")
                if isinstance(text, str):
                    return text
    if isinstance(parsed, Mapping):
        text = _mapping_value(parsed, "translation_text")
        if isinstance(text, str):
            return text
    return None


def _extract_usage(body: Any) -> dict[str, int]:
    parsed = _parse_body(body) if not isinstance(body, Mapping) else body
    if not isinstance(parsed, Mapping):
        return {}
    usage_section: Any = _mapping_value(parsed, "usage")
    if not isinstance(usage_section, Mapping):
        return {}
    usage: dict[str, int] = {}
    mapping = (
        ("prompt_tokens", ("prompt_tokens", "promptTokens", "input_tokens")),
        ("completion_tokens", ("completion_tokens", "completionTokens", "output_tokens")),
        ("total_tokens", ("total_tokens", "totalTokens")),
    )
    for canonical, candidates in mapping:
        value = _first_int(usage_section, candidates)
        if value is not None:
            usage[canonical] = value
    return usage


def _first_int(data: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = _optional_int(_mapping_value(data, key))
        if value is not None:
            return value
    return None


def _resolve_auth_mode(
    invocation: _NormalizedInvocation,
    endpoint_kind: str,
) -> str | None:
    if invocation.auth_mode:
        explicit = _safe_auth_mode(invocation.auth_mode)
        if explicit is not None:
            return explicit
    authorization = _header_value(invocation.headers, "authorization")
    if authorization:
        lowered = authorization.lower()
        if lowered.startswith("bearer "):
            token_remainder = authorization.split(" ", 1)[1] if " " in authorization else ""
            if endpoint_kind == "dedicated_endpoint":
                return "dedicated_endpoint_token"
            if token_remainder.startswith("hf_"):
                return "api_token"
            return "bearer"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("-", "_")
    if mode in {"token", "apitoken", "hf_token", "hf_api_token"}:
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
        _first_present(metadata, "RequestId", "request_id", "requestId", "x-request-id")
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
            return bytes(body)
    if isinstance(body, str):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body
    if isinstance(body, Sequence):
        return body
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
    task = raw.get("task_type") or "unknown"
    surface = raw.get("endpoint_kind") or "unknown"
    return f"{raw['provider']} {raw['operation']} {model_id} task={task} surface={surface}"
