"""Cloudflare Workers AI adapter for edge-inference evidence.

Cloudflare Workers AI runs model inference at edge POPs (points of presence)
worldwide, which produces a different evidence shape than centralized clouds:

* The serving POP determines geographic data-residency. A request originating
  from the US that gets handled by a Frankfurt POP transits EU territory and
  may need to be captured under GDPR. The adapter records ``cf-ipcountry`` and
  ``cf-iata`` so posture reports can answer "where did this inference run".
* The optional AI Gateway (``gateway.ai.cloudflare.com``) sits in front of any
  upstream provider and adds caching / fallback / rate-limiting. Cached hits
  may return content from a *prior* session — we capture both the gateway id
  and ``cf-cache-status`` so cache hits are traceable.
* Models are namespaced by publisher (``@cf/meta/...``, ``@cf/mistral/...``).
  We classify the publisher into a ``first_party`` allow-list and treat user
  / community publishers as ``community`` (parallel to Replicate's owner
  classification) for supply-chain provenance.

The adapter accepts plain dictionaries or :class:`CloudflareWorkersAIInvocation`
so the SDK stays importable without the ``cloudflare`` package.
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

PROVIDER = "cloudflare-workers-ai"
PRODUCER_VERSION = "0.1.0"

DEFAULT_ENDPOINT_HOST = "api.cloudflare.com"
GATEWAY_ENDPOINT_HOST = "gateway.ai.cloudflare.com"

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
    "secret",
    "token",
    "x-auth-email",
    "x-auth-key",
)

# Publishers Cloudflare ships first-party / curated weights for. Anything else
# (user-supplied LoRAs, community fine-tunes) is treated as ``community`` so
# supply-chain provenance is captured.
_FIRST_PARTY_PUBLISHERS = frozenset(
    {
        "baai",
        "black-forest-labs",
        "deepseek-ai",
        "google",
        "huggingface",
        "meta",
        "microsoft",
        "mistral",
        "openai",
        "stabilityai",
        "thebloke",
    }
)

# Community / unverified publishers seen in the catalogue (e.g. lykon LCM
# variants, defog text-to-SQL, etc.). The default for unknown publishers is
# ``community``.
_COMMUNITY_PUBLISHERS = frozenset(
    {
        "defog",
        "fblgit",
        "lykon",
        "nexusflow",
        "tinyllama",
    }
)

# Supported operations — Workers AI exposes a single inference endpoint per
# model, but we register one tool per model-kind for posture grouping.
_MODEL_KINDS = (
    "llm",
    "embedding",
    "image-gen",
    "speech-to-text",
    "image-classification",
    "classification",
    "translation",
    "unknown",
)

_CACHE_HIT_STATUSES = frozenset({"hit", "stale", "revalidated"})


@dataclass
class CloudflareWorkersAIInvocation:
    """Raw Cloudflare Workers AI invocation before translation to an Action."""

    operation: str
    model_id: str | None = None
    account_id: str | None = None
    gateway_id: str | None = None
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
class CloudflareWorkersAIObservation:
    """Action, evaluation, and evidence record for an observed Workers AI call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    model_id: str | None
    account_id: str | None
    gateway_id: str | None
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


class CloudflareWorkersAIActionProducer:
    """Produces Action objects from native Cloudflare Workers AI invocations."""

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

    def translate(
        self, raw_invocation: CloudflareWorkersAIInvocation | Mapping[str, Any]
    ) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)

        request_parsed = _parse_body(invocation.request_body)
        response_parsed = _parse_body(invocation.response_body)

        publisher, model_basename = _split_model_id(invocation.model_id)
        model_kind = _classify_model_kind(invocation.model_id)
        owner_kind = _classify_owner(publisher)

        # POP / geo-routing fields. ``cf-ipcountry`` records the *resolved*
        # serving POP country (Cloudflare also accepts "XX" for unknown).
        pop_country = _header_value(invocation.headers, "cf-ipcountry")
        pop_iata = _header_value(invocation.headers, "cf-iata")
        cache_status = _normalize_cache_status(
            _header_value(invocation.headers, "cf-cache-status")
        )
        cf_ray = _header_value(invocation.headers, "cf-ray")

        request_id = (
            invocation.request_id
            or cf_ray
            or _header_value(invocation.headers, "x-request-id")
            or _metadata_request_id(invocation.response_metadata)
        )

        endpoint = _endpoint(invocation.base_url, invocation.gateway_id)
        custom_endpoint = endpoint not in {DEFAULT_ENDPOINT_HOST, GATEWAY_ENDPOINT_HOST}
        auth_mode = _resolve_auth_mode(invocation)

        # Gateway-mediated cache hit — privileged evidence because cache
        # responses may have been generated in a prior session under different
        # data-classification posture.
        gateway_present = invocation.gateway_id is not None
        cache_hit = (
            gateway_present
            and cache_status is not None
            and cache_status.lower() in _CACHE_HIT_STATUSES
        )

        # Sanitised request body summary. We never persist prompt / message
        # content — only structural shape + a sha256 over canonical content.
        request_summary = _request_summary(request_parsed, model_kind)

        # Sanitised response. Response result is structural-only — never raw
        # text or binary.
        response_summary = _response_summary(response_parsed)

        success = _resolve_success(response_parsed, invocation.http_status)
        errors_summary = _errors_summary(response_parsed) if not success else None

        # Streaming detection — Workers AI supports SSE streaming via the
        # ``stream: true`` request flag or the ``stream`` operation suffix.
        is_streaming = _detect_streaming(invocation.operation, request_parsed)

        # Token usage when LLM (Workers AI returns ``usage`` keyed by
        # ``prompt_tokens`` / ``completion_tokens`` / ``total_tokens``).
        usage = _extract_usage(response_parsed) if model_kind == "llm" else {}

        payload: dict[str, Any] = {
            "provider": PROVIDER,
            "operation": invocation.operation,
            "model": invocation.model_id,
            "model_id": invocation.model_id,
            "model_basename": model_basename,
            "model_kind": model_kind,
            "publisher": publisher,
            "owner_kind": owner_kind,
            "account_id": invocation.account_id,
            "gateway_id": invocation.gateway_id,
            "gateway_present": gateway_present,
            "endpoint_host": endpoint,
            "destination": endpoint,
            "custom_base_url": custom_endpoint,
            "http_status": invocation.http_status,
            "request_id": request_id,
            "cf_ray": cf_ray,
            "latency_ms": invocation.latency_ms,
            "pop_country": pop_country,
            "pop_iata": pop_iata,
            "cache_status": cache_status,
            "cache_hit": cache_hit,
            "success": success,
            "is_streaming": is_streaming,
            "deployment": {
                "provider": PROVIDER,
                "endpoint_host": endpoint,
                "model_id": invocation.model_id,
                "publisher": publisher,
                "model_kind": model_kind,
                "owner_kind": owner_kind,
                "account_id": invocation.account_id,
                "gateway_id": invocation.gateway_id,
                "pop_country": pop_country,
                "pop_iata": pop_iata,
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
        if errors_summary is not None:
            payload["errors_summary"] = errors_summary
        if auth_mode:
            payload["auth_mode"] = auth_mode

        tool_name = _tool_name(model_kind)
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
        self,
        raw_invocation: CloudflareWorkersAIInvocation | Mapping[str, Any],
    ) -> CloudflareWorkersAIObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        model_kind = _classify_model_kind(normalized.model_id)
        tool_name = self._ensure_registered(model_kind)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return CloudflareWorkersAIObservation(
            action=action, evaluation=evaluation, evidence=evidence
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for kind in _MODEL_KINDS:
            tool_name = _tool_name(kind)
            registry.register(
                ToolEntry(
                    name=tool_name,
                    description_hash=self.compute_tool_hash(tool_name),
                    status=ToolStatus.OBSERVED,
                )
            )
            registered.append(tool_name)
        return registered

    def _ensure_registered(self, model_kind: str) -> str:
        tool_name = _tool_name(model_kind)
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


CloudflareWorkersAIAdapter = CloudflareWorkersAIActionProducer


# --------------------------------------------------------------------------- #
# Normalization                                                                #
# --------------------------------------------------------------------------- #


def _normalize_invocation(
    raw_invocation: CloudflareWorkersAIInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, CloudflareWorkersAIInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            model_id=raw_invocation.model_id,
            account_id=raw_invocation.account_id,
            gateway_id=raw_invocation.gateway_id,
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
        model_id=_optional_str(
            _first_present(raw_invocation, "model_id", "modelId", "model")
        ),
        account_id=_optional_str(
            _first_present(raw_invocation, "account_id", "accountId")
        ),
        gateway_id=_optional_str(
            _first_present(raw_invocation, "gateway_id", "gatewayId")
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


def _tool_name(model_kind: str) -> str:
    return f"{PROVIDER}:Models.run:{model_kind}"


def _endpoint(base_url: str | None, gateway_id: str | None) -> str:
    explicit_host = _host_from_url(base_url)
    if explicit_host:
        return explicit_host
    if gateway_id:
        return GATEWAY_ENDPOINT_HOST
    return DEFAULT_ENDPOINT_HOST


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


def _split_model_id(model_id: str | None) -> tuple[str | None, str | None]:
    """Split ``@cf/<publisher>/<basename>`` into (publisher, basename).

    Returns (None, None) when the model id is missing or not recognisable.
    """
    if not model_id:
        return None, None
    candidate = model_id
    if candidate.startswith("@cf/"):
        candidate = candidate[len("@cf/"):]
    if "/" not in candidate:
        return None, candidate or None
    publisher, _, basename = candidate.partition("/")
    return publisher.lower() or None, basename or None


def _classify_model_kind(model_id: str | None) -> str:
    if not model_id:
        return "unknown"
    publisher, basename = _split_model_id(model_id)
    base_lower = (basename or "").lower()

    # Specific overrides first (publisher-agnostic basename hints).
    if "whisper" in base_lower:
        return "speech-to-text"
    if base_lower.startswith("resnet") or "image-classification" in base_lower:
        return "image-classification"
    if base_lower.startswith("m2m100") or "nllb" in base_lower:
        return "translation"
    if "embed" in base_lower or base_lower.startswith("bge"):
        return "embedding"
    if (
        "flux" in base_lower
        or "stable-diffusion" in base_lower
        or "dreamshaper" in base_lower
        or "sdxl" in base_lower
        or base_lower.endswith("-lcm")
    ):
        return "image-gen"
    if "distilbert" in base_lower or base_lower.startswith("sst") or "sentiment" in base_lower:
        return "classification"

    # Fall back to publisher-level heuristics.
    if publisher in {"meta", "mistral", "deepseek-ai", "thebloke", "fblgit", "tinyllama", "nexusflow"}:
        return "llm"
    if publisher == "baai":
        return "embedding"
    if publisher == "black-forest-labs":
        return "image-gen"
    if publisher == "openai":
        # @cf/openai/whisper-* — whisper handled above; default to STT for
        # other openai-namespaced models on Workers AI.
        return "speech-to-text"
    if publisher == "microsoft":
        return "image-classification"
    if publisher == "lykon":
        return "image-gen"
    if publisher == "huggingface":
        # Mixed catalogue — default to classification, since most curated
        # huggingface @cf/ models are sentiment / topic classifiers.
        return "classification"
    return "unknown"


def _classify_owner(publisher: str | None) -> str:
    if not publisher:
        return "unverified"
    lowered = publisher.lower()
    if lowered in _FIRST_PARTY_PUBLISHERS:
        return "first_party"
    if lowered in _COMMUNITY_PUBLISHERS:
        return "community"
    return "community"


def _normalize_cache_status(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().lower() or None


def _detect_streaming(operation: str, request_parsed: Any) -> bool:
    op = (operation or "").lower()
    if "stream" in op:
        return True
    if isinstance(request_parsed, Mapping):
        flag = _mapping_value(request_parsed, "stream")
        if isinstance(flag, bool) and flag:
            return True
    return False


def _resolve_success(response_parsed: Any, http_status: int | None) -> bool:
    if isinstance(response_parsed, Mapping):
        flag = _mapping_value(response_parsed, "success")
        if isinstance(flag, bool):
            return flag
    if http_status is not None:
        return 200 <= http_status < 400
    return True


def _errors_summary(response_parsed: Any) -> list[dict[str, Any]] | None:
    if not isinstance(response_parsed, Mapping):
        return None
    errors = _mapping_value(response_parsed, "errors")
    if not isinstance(errors, Sequence) or isinstance(errors, (str, bytes, bytearray)):
        return None
    summary: list[dict[str, Any]] = []
    for entry in errors:
        if isinstance(entry, Mapping):
            message = _optional_str(_mapping_value(entry, "message")) or ""
            code = _mapping_value(entry, "code")
            summary.append(
                {
                    "code": _optional_int(code) if code is not None else None,
                    "preview": message[:200],
                    "length": len(message),
                    "sha256": hashlib.sha256(message.encode()).hexdigest()
                    if message
                    else None,
                    "truncated": len(message) > 200,
                }
            )
        elif isinstance(entry, str):
            summary.append(
                {
                    "code": None,
                    "preview": entry[:200],
                    "length": len(entry),
                    "sha256": hashlib.sha256(entry.encode()).hexdigest(),
                    "truncated": len(entry) > 200,
                }
            )
    return summary or None


def _request_summary(request_parsed: Any, model_kind: str) -> dict[str, Any]:
    """Produce a sanitised, structural-only summary of the request body.

    Never persists prompt / message / image / audio content. We capture:
    - prompt length + sha256 (no raw text)
    - messages: count + role distribution + sha256
    - input array (embeddings): item count + total length + sha256
    - presence flags for binary inputs (image, audio)
    """
    summary: dict[str, Any] = {
        "prompt_present": False,
        "messages_present": False,
        "input_present": False,
        "image_input_present": False,
        "audio_input_present": False,
    }
    if not isinstance(request_parsed, Mapping):
        return summary

    prompt = _mapping_value(request_parsed, "prompt")
    if isinstance(prompt, str):
        summary["prompt_present"] = True
        summary["prompt_length"] = len(prompt)
        summary["prompt_sha256"] = hashlib.sha256(prompt.encode()).hexdigest()

    messages = _mapping_value(request_parsed, "messages")
    if isinstance(messages, Sequence) and not isinstance(messages, (str, bytes, bytearray)):
        summary["messages_present"] = True
        summary["messages_count"] = len(messages)
        roles: dict[str, int] = {}
        canonical_parts: list[str] = []
        for item in messages:
            if isinstance(item, Mapping):
                role = _optional_str(_mapping_value(item, "role")) or "unknown"
                roles[role] = roles.get(role, 0) + 1
                content = _mapping_value(item, "content")
                if isinstance(content, str):
                    canonical_parts.append(f"{role}:{len(content)}:{content}")
                else:
                    canonical_parts.append(f"{role}:{type(content).__name__}")
        summary["messages_role_distribution"] = dict(sorted(roles.items()))
        if canonical_parts:
            digest = hashlib.sha256("\x1e".join(canonical_parts).encode()).hexdigest()
            summary["messages_sha256"] = digest

    input_value = _mapping_value(request_parsed, "text")
    if input_value is None:
        # Embeddings endpoints accept a single string or list of strings under
        # ``text`` (BGE) or ``input`` (some adapter clients).
        input_value = _mapping_value(request_parsed, "input")
    if isinstance(input_value, str):
        summary["input_present"] = True
        summary["input_count"] = 1
        summary["input_total_length"] = len(input_value)
        summary["input_sha256"] = hashlib.sha256(input_value.encode()).hexdigest()
    elif isinstance(input_value, Sequence) and not isinstance(
        input_value, (str, bytes, bytearray)
    ):
        summary["input_present"] = True
        summary["input_count"] = len(input_value)
        total = 0
        canonical_parts = []
        for item in input_value:
            if isinstance(item, str):
                total += len(item)
                canonical_parts.append(item)
        if canonical_parts:
            summary["input_total_length"] = total
            summary["input_sha256"] = hashlib.sha256(
                "\x1e".join(canonical_parts).encode()
            ).hexdigest()

    if _mapping_value(request_parsed, "image") is not None:
        summary["image_input_present"] = True
    if _mapping_value(request_parsed, "audio") is not None:
        summary["audio_input_present"] = True
    if model_kind == "image-gen" and summary.get("prompt_present"):
        # ``prompt`` already covered above; surface the dedicated flag too.
        summary["image_gen_prompt_present"] = True

    return summary


def _response_summary(response_parsed: Any) -> dict[str, Any]:
    """Structural-only summary of the response — never raw text or binary."""
    summary: dict[str, Any] = {
        "result_present": False,
    }
    if not isinstance(response_parsed, Mapping):
        return summary
    result = _mapping_value(response_parsed, "result")
    if result is None:
        return summary
    summary["result_present"] = True
    if isinstance(result, Mapping):
        summary["result_keys"] = sorted(
            str(k) for k in result if not _is_sensitive_key(str(k))
        )
        summary["result_kind"] = "object"
        # Common Workers AI result fields — capture *shape only*.
        response_value = _mapping_value(result, "response")
        if isinstance(response_value, str):
            summary["result_response_length"] = len(response_value)
        elif response_value is not None:
            summary["result_response_kind"] = type(response_value).__name__
        data_value = _mapping_value(result, "data")
        if isinstance(data_value, Sequence) and not isinstance(
            data_value, (str, bytes, bytearray)
        ):
            summary["result_data_count"] = len(data_value)
        translated = _mapping_value(result, "translated_text")
        if isinstance(translated, str):
            summary["result_translation_length"] = len(translated)
        text_value = _mapping_value(result, "text")
        if isinstance(text_value, str):
            summary["result_text_length"] = len(text_value)
    elif isinstance(result, Sequence) and not isinstance(
        result, (str, bytes, bytearray)
    ):
        summary["result_kind"] = "array"
        summary["result_count"] = len(result)
    elif isinstance(result, str):
        summary["result_kind"] = "string"
        summary["result_length"] = len(result)
    elif isinstance(result, (bytes, bytearray)):
        summary["result_kind"] = "binary"
        summary["result_byte_length"] = len(result)
    else:
        summary["result_kind"] = type(result).__name__
    return summary


def _extract_usage(body: Any) -> dict[str, int]:
    parsed = _parse_body(body) if not isinstance(body, Mapping) else body
    if not isinstance(parsed, Mapping):
        return {}
    usage_section: Any = _mapping_value(parsed, "usage")
    if not isinstance(usage_section, Mapping):
        result = _mapping_value(parsed, "result")
        if isinstance(result, Mapping):
            usage_section = _mapping_value(result, "usage")
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


def _resolve_auth_mode(invocation: _NormalizedInvocation) -> str | None:
    if invocation.auth_mode:
        explicit = _safe_auth_mode(invocation.auth_mode)
        if explicit is not None:
            return explicit
    authorization = _header_value(invocation.headers, "authorization")
    if authorization:
        lowered = authorization.lower()
        if lowered.startswith("bearer "):
            return "api_token"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("-", "_")
    if mode in {"token", "apitoken", "cf_api_token"}:
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
        _first_present(metadata, "RequestId", "request_id", "requestId", "cf_ray", "cf-ray")
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
    pop = raw.get("pop_country") or "??"
    return f"{raw['provider']} {raw['operation']} {model_id} pop={pop}"
