# mypy: disable-error-code="union-attr,arg-type,attr-defined,index,assignment,operator,no-redef,no-any-return,call-overload,return-value,type-var"
"""OpenAI Assistants v2 adapter for hosted-agent run envelopes.

The Assistants v2 API exposes stateful threads, hosted tools (code_interpreter,
file_search, function), file attachments, and Run objects. This adapter
translates Run-level invocations into Ancilis Action envelopes so policy
controls can inspect hosted-agent activity (PR-03 arbitrary code execution
surface, PR-04 RAG-over-files exfiltration surface, PR-05 audit completeness,
DE-01 baseline detection on terminal/error states).
"""

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

PROVIDER = "openai-assistants"
PRODUCER_VERSION = "0.1.0"

DEFAULT_ENDPOINT_HOST = "api.openai.com"
DEFAULT_BASE_URL = "https://api.openai.com/v1"

_SAFE_AUTH_MODES = {"api_key", "bearer", "bring_your_own"}
_SENSITIVE_KEY_PARTS = (
    "access_token",
    "api-key",
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "oauth",
    "openai-api-key",
    "openai_api_key",
    "refresh_token",
    "secret",
    "session_token",
    "x-api-key",
)
_TERMINAL_STATUSES = {"failed", "expired", "cancelled", "incomplete"}
_AUDIT_FLAG_TRUNCATIONS = {"last_messages"}
_REGISTERED_OPERATIONS = (
    "Runs.create",
    "Runs.retrieve",
    "Runs.steps.list",
    "Runs.cancel",
    "Threads.messages.create",
)


@dataclass
class OpenAIAssistantsInvocation:
    """Raw OpenAI Assistants v2 invocation before translation to an Action.

    Mirrors the surface of an Assistants v2 SDK call so the SDK is importable
    without the ``openai`` Python package being installed.
    """

    operation: str
    thread_id: str | None = None
    assistant_id: str | None = None
    run_id: str | None = None
    run_body: Any = None
    steps: Sequence[Any] | None = None
    http_status: int | None = None
    request_id: str | None = None
    latency_ms: float | None = None
    headers: Mapping[str, Any] | None = None
    response_metadata: Mapping[str, Any] | None = None
    agent_id: str | None = None
    auth_mode: str | None = None
    base_url: str | None = None


@dataclass
class OpenAIAssistantsObservation:
    """Action, evaluation, and evidence record for an observed Assistants call."""

    action: Action
    evaluation: EvaluationResult
    evidence: EvidenceRecord


@dataclass
class _NormalizedInvocation:
    operation: str
    thread_id: str | None
    assistant_id: str | None
    run_id: str | None
    run_body: Any
    steps: Sequence[Any] | None
    http_status: int | None
    request_id: str | None
    latency_ms: float | None
    headers: Mapping[str, Any]
    response_metadata: Mapping[str, Any]
    agent_id: str
    auth_mode: str | None
    base_url: str | None


class OpenAIAssistantsActionProducer:
    """Produces Action objects from OpenAI Assistants v2 invocations.

    The adapter accepts plain dictionaries or OpenAIAssistantsInvocation
    objects so the SDK stays importable without the ``openai`` Python package
    installed. It surfaces hosted-tool usage and Run terminal-state signals
    that downstream controls (PR-03/PR-04/PR-05/DE-01) consume.
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
        self._evidence_store = (
            evidence_store if evidence_store is not None else EvidenceStore(config)
        )
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
        self, raw_invocation: OpenAIAssistantsInvocation | Mapping[str, Any]
    ) -> Action:
        invocation = _normalize_invocation(raw_invocation, self._config.agent_name)
        run_body = _parse_body(invocation.run_body)
        run_mapping = run_body if isinstance(run_body, Mapping) else None

        endpoint = _endpoint(invocation.base_url)
        custom_endpoint = endpoint != DEFAULT_ENDPOINT_HOST
        auth_mode = _resolve_auth_mode(invocation, custom_endpoint)
        request_id = (
            invocation.request_id
            or _header_value(invocation.headers, "x-request-id")
            or _header_value(invocation.headers, "openai-request-id")
        )

        resolved_model = _optional_str(
            _first_present(run_mapping, "model", "model_id") if run_mapping else None
        )
        model_metadata = _model_metadata(resolved_model)
        status = _optional_str(
            _first_present(run_mapping, "status") if run_mapping else None
        )

        tools_list = (
            _mapping_value(run_mapping, "tools") if run_mapping else None
        ) or []
        tool_summary = _summarize_tools(tools_list)

        # Hosted-tool surfacing — drives PR-03 (code_interpreter = arbitrary
        # code execution surface) and PR-04 (file_search = RAG-over-user-files
        # exfiltration surface). The booleans are mirrored into the payload
        # under both flat and nested keys so simple control predicates and
        # nested overlays can both find them.
        code_interpreter_used = tool_summary["code_interpreter"]
        file_search_used = tool_summary["file_search"]
        function_tool_used = tool_summary["has_function"]

        usage = _extract_run_usage(run_mapping)
        step_summary = _summarize_steps(invocation.steps)
        if step_summary["usage"]:
            for key, value in step_summary["usage"].items():
                # Step-level usage is the authoritative aggregate when
                # individual steps report it. Run-level usage may not yet
                # reflect the final completion when sampled mid-run, so we
                # prefer the summed step view.
                usage[key] = value
        if step_summary["code_interpreter_executions"] > 0:
            code_interpreter_used = True
        if step_summary["file_search_invocations"] > 0:
            file_search_used = True
        if step_summary["function_tool_names"]:
            function_tool_used = True

        last_error = _summarize_last_error(
            _mapping_value(run_mapping, "last_error") if run_mapping else None
        )
        incomplete_details = _summarize_incomplete(
            _mapping_value(run_mapping, "incomplete_details") if run_mapping else None
        )

        truncation_strategy_type = _truncation_type(run_mapping)
        truncation_audit_flag = (
            truncation_strategy_type in _AUDIT_FLAG_TRUNCATIONS
            if truncation_strategy_type
            else False
        )

        instructions_summary = _summarize_instructions(
            _mapping_value(run_mapping, "instructions") if run_mapping else None
        )
        function_arg_summaries = _summarize_function_arguments(invocation.steps)

        parallel_tool_calls = _optional_bool(
            _mapping_value(run_mapping, "parallel_tool_calls") if run_mapping else None
        )
        response_format = _summarize_response_format(
            _mapping_value(run_mapping, "response_format") if run_mapping else None
        )

        # Build payload. Status/tool-mode flags surface as top-level booleans
        # so simple predicates in controls (PR-03, PR-04, PR-05, DE-01) can
        # evaluate them without traversing nested structures.
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
            "thread_id": invocation.thread_id
            or _optional_str(_mapping_value(run_mapping, "thread_id") if run_mapping else None),
            "assistant_id": invocation.assistant_id
            or _optional_str(
                _mapping_value(run_mapping, "assistant_id") if run_mapping else None
            ),
            "run_id": invocation.run_id
            or _optional_str(_mapping_value(run_mapping, "id") if run_mapping else None),
            "status": status,
            "terminal_status": status in _TERMINAL_STATUSES if status else False,
            "model_metadata": model_metadata,
            "deployment": {
                "provider": PROVIDER,
                "endpoint_host": endpoint,
                "model": resolved_model,
                "model_family": model_metadata["family"],
            },
            "tools": {
                "count": tool_summary["count"],
                "types": tool_summary["types"],
                "function_names": tool_summary["function_names"],
            },
            "code_interpreter_used": code_interpreter_used,
            "file_search_used": file_search_used,
            "function_tool_used": function_tool_used,
            "request": {
                "body_present": invocation.run_body is not None,
                "body_keys": _body_keys(invocation.run_body),
            },
            "response": {
                "body_present": run_mapping is not None,
                "body_keys": _body_keys(run_mapping),
            },
            "steps": {
                "count": step_summary["count"],
                "types": step_summary["types"],
                "code_interpreter_executions": step_summary["code_interpreter_executions"],
                "file_search_invocations": step_summary["file_search_invocations"],
                "file_search_total_results": step_summary["file_search_total_results"],
                "function_tool_names": step_summary["function_tool_names"],
                "step_errors": step_summary["errors"],
            },
        }

        if instructions_summary is not None:
            payload["instructions"] = instructions_summary
        if function_arg_summaries:
            payload["function_arguments"] = function_arg_summaries
        if last_error:
            payload["last_error"] = last_error
        if incomplete_details:
            payload["incomplete_details"] = incomplete_details
        if truncation_strategy_type:
            payload["truncation_strategy"] = {
                "type": truncation_strategy_type,
                "audit_completeness_flag": truncation_audit_flag,
            }
        if parallel_tool_calls is not None:
            payload["parallel_tool_calls"] = parallel_tool_calls
        if response_format is not None:
            payload["response_format"] = response_format
        if auth_mode:
            payload["auth_mode"] = auth_mode
        if "prompt_tokens" in usage:
            payload["prompt_tokens"] = usage["prompt_tokens"]
            payload["input_tokens"] = usage["prompt_tokens"]
        if "completion_tokens" in usage:
            payload["completion_tokens"] = usage["completion_tokens"]
            payload["output_tokens"] = usage["completion_tokens"]
        if "total_tokens" in usage:
            payload["total_tokens"] = usage["total_tokens"]

        # Surfacing flags — these are an explicit, machine-readable list of
        # control indicators the engine can pivot on without re-deriving
        # from the payload structure.
        surfacing: list[str] = []
        if status in {"failed", "expired"}:
            surfacing.append("DE-01")
            surfacing.append("PR-05")
        elif status == "cancelled":
            surfacing.append("PR-05")
        if code_interpreter_used:
            surfacing.append("PR-03")
        if file_search_used:
            surfacing.append("PR-04")
        if truncation_audit_flag:
            surfacing.append("PR-05")
        if surfacing:
            payload["control_surfacing"] = sorted(set(surfacing))

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
        self, raw_invocation: OpenAIAssistantsInvocation | Mapping[str, Any]
    ) -> OpenAIAssistantsObservation:
        normalized = _normalize_invocation(raw_invocation, self._config.agent_name)
        tool_name = self._ensure_registered(normalized.operation)
        action = self.translate(raw_invocation)
        evaluation = self._engine.evaluate(action)
        evidence = self._evidence_store.store(
            evaluation,
            tool_name=tool_name,
            output_summary=_output_summary(action),
        )
        return OpenAIAssistantsObservation(
            action=action, evaluation=evaluation, evidence=evidence
        )

    def compute_tool_hash(self, tool_identifier: Any) -> str:
        return hashlib.sha256(str(tool_identifier).encode()).hexdigest()

    def register_tools(self, registry: ToolRegistry) -> list[str]:
        registered: list[str] = []
        for operation in _REGISTERED_OPERATIONS:
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


OpenAIAssistantsAdapter = OpenAIAssistantsActionProducer


def _normalize_invocation(
    raw_invocation: OpenAIAssistantsInvocation | Mapping[str, Any],
    default_agent_id: str,
) -> _NormalizedInvocation:
    if isinstance(raw_invocation, OpenAIAssistantsInvocation):
        response_metadata = dict(raw_invocation.response_metadata or {})
        return _NormalizedInvocation(
            operation=raw_invocation.operation,
            thread_id=raw_invocation.thread_id,
            assistant_id=raw_invocation.assistant_id,
            run_id=raw_invocation.run_id,
            run_body=raw_invocation.run_body,
            steps=raw_invocation.steps,
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
    run_body = _first_present(
        raw_invocation,
        "run_body",
        "runBody",
        "run",
        "response_body",
        "responseBody",
        "body",
    )
    if run_body is None and isinstance(response, Mapping):
        run_body = _first_present(response, "body", "run_body", "runBody", "run") or response

    steps = _as_sequence(
        _first_present(raw_invocation, "steps", "run_steps", "runSteps")
    )

    return _NormalizedInvocation(
        operation=str(
            _first_present(raw_invocation, "operation", "method", "operationName")
            or "Runs.create"
        ),
        thread_id=_optional_str(
            _first_present(raw_invocation, "thread_id", "threadId")
        ),
        assistant_id=_optional_str(
            _first_present(raw_invocation, "assistant_id", "assistantId")
        ),
        run_id=_optional_str(_first_present(raw_invocation, "run_id", "runId")),
        run_body=run_body,
        steps=steps,
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
        return {"id": None, "provider": "openai", "family": "unknown", "resolved": False}
    family = _model_family(model)
    return {
        "id": model,
        "provider": "openai",
        "family": family,
        "resolved": True,
    }


def _model_family(model_id: str) -> str:
    reference = model_id.rsplit("/", 1)[-1].lower()
    if reference.startswith("gpt-4.1"):
        return "gpt-4.1"
    if reference.startswith("gpt-4o"):
        return "gpt-4o"
    if reference.startswith("gpt-4"):
        return "gpt-4"
    if reference.startswith("gpt-3.5") or reference.startswith("gpt-35"):
        return "gpt-3.5"
    if reference.startswith("o1") or reference.startswith("o3") or reference.startswith("o4"):
        return "openai-reasoning"
    if "-" in reference:
        return reference.split("-", 1)[0]
    return reference or "unknown"


def _summarize_tools(tools: Any) -> dict[str, Any]:
    """Summarize the run-level tools list.

    Returns a dict with bool flags for code_interpreter / file_search / has_function
    so the engine can react to tool-mode without reading the structured list.
    """
    summary = {
        "count": 0,
        "types": [],
        "function_names": [],
        "code_interpreter": False,
        "file_search": False,
        "has_function": False,
    }
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes, bytearray)):
        return summary
    for tool in tools:
        if not isinstance(tool, Mapping):
            continue
        summary["count"] += 1
        tool_type = _optional_str(_mapping_value(tool, "type"))
        if tool_type:
            summary["types"].append(tool_type)
            if tool_type == "code_interpreter":
                summary["code_interpreter"] = True
            elif tool_type == "file_search":
                summary["file_search"] = True
            elif tool_type == "function":
                summary["has_function"] = True
                function_def = _mapping_value(tool, "function")
                if isinstance(function_def, Mapping):
                    name = _optional_str(_mapping_value(function_def, "name"))
                    if name:
                        summary["function_names"].append(name)
    summary["types"] = sorted(set(summary["types"]))
    summary["function_names"] = sorted(set(summary["function_names"]))
    return summary


def _summarize_steps(steps: Sequence[Any] | None) -> dict[str, Any]:
    """Summarize run-step level tool use and aggregate per-step usage.

    Per the Assistants v2 API, run steps each carry an optional ``usage``
    block (prompt_tokens / completion_tokens / total_tokens). Summing step
    usage gives a strictly more accurate accounting than the run-level
    snapshot when the run is observed mid-stream.
    """
    summary: dict[str, Any] = {
        "count": 0,
        "types": [],
        "code_interpreter_executions": 0,
        "file_search_invocations": 0,
        "file_search_total_results": 0,
        "function_tool_names": [],
        "errors": 0,
        "usage": {},
    }
    if steps is None:
        return summary

    type_set: set[str] = set()
    function_name_set: set[str] = set()
    aggregated: dict[str, int] = {}

    for step in steps:
        if not isinstance(step, Mapping):
            continue
        summary["count"] += 1
        step_type = _optional_str(_mapping_value(step, "type"))
        if step_type:
            type_set.add(step_type)

        if _mapping_value(step, "last_error"):
            summary["errors"] += 1

        usage = _mapping_value(step, "usage")
        if isinstance(usage, Mapping):
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                value = _optional_int(_mapping_value(usage, key))
                if value is not None:
                    aggregated[key] = aggregated.get(key, 0) + value

        details = _mapping_value(step, "step_details")
        if not isinstance(details, Mapping):
            continue
        tool_calls = _mapping_value(details, "tool_calls")
        if not isinstance(tool_calls, Sequence) or isinstance(
            tool_calls, (str, bytes, bytearray)
        ):
            continue
        for tool_call in tool_calls:
            if not isinstance(tool_call, Mapping):
                continue
            tc_type = _optional_str(_mapping_value(tool_call, "type"))
            if tc_type == "code_interpreter":
                summary["code_interpreter_executions"] += 1
            elif tc_type == "file_search":
                summary["file_search_invocations"] += 1
                fs = _mapping_value(tool_call, "file_search")
                if isinstance(fs, Mapping):
                    results = _mapping_value(fs, "results")
                    if isinstance(results, Sequence) and not isinstance(
                        results, (str, bytes, bytearray)
                    ):
                        summary["file_search_total_results"] += len(results)
            elif tc_type == "function":
                fn = _mapping_value(tool_call, "function")
                if isinstance(fn, Mapping):
                    name = _optional_str(_mapping_value(fn, "name"))
                    if name:
                        function_name_set.add(name)

    summary["types"] = sorted(type_set)
    summary["function_tool_names"] = sorted(function_name_set)
    summary["usage"] = aggregated
    return summary


def _summarize_function_arguments(steps: Sequence[Any] | None) -> list[dict[str, Any]]:
    """Sanitize function-call arguments to {top_level_keys, sha256, length}.

    Function arguments are user/agent-provided JSON that may contain PII or
    secrets. We never store the raw values — only the top-level key set, the
    JSON length, and a SHA-256 of the raw string for tamper-evidence.
    """
    summaries: list[dict[str, Any]] = []
    if steps is None:
        return summaries
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        details = _mapping_value(step, "step_details")
        if not isinstance(details, Mapping):
            continue
        tool_calls = _mapping_value(details, "tool_calls")
        if not isinstance(tool_calls, Sequence) or isinstance(
            tool_calls, (str, bytes, bytearray)
        ):
            continue
        for tool_call in tool_calls:
            if not isinstance(tool_call, Mapping):
                continue
            if _optional_str(_mapping_value(tool_call, "type")) != "function":
                continue
            fn = _mapping_value(tool_call, "function")
            if not isinstance(fn, Mapping):
                continue
            name = _optional_str(_mapping_value(fn, "name"))
            args = _mapping_value(fn, "arguments")
            args_str = args if isinstance(args, str) else json.dumps(
                args, sort_keys=True, default=repr
            ) if args is not None else ""
            parsed = _parse_body(args_str) if args_str else None
            top_keys: list[str] = []
            if isinstance(parsed, Mapping):
                top_keys = sorted(str(k) for k in parsed)
            summaries.append(
                {
                    "name": name,
                    "top_level_keys": top_keys,
                    "argument_length": len(args_str),
                    "argument_sha256": hashlib.sha256(args_str.encode()).hexdigest()
                    if args_str
                    else None,
                }
            )
    return summaries


def _summarize_instructions(value: Any) -> dict[str, Any] | None:
    """Redact instruction text — store only length + SHA-256."""
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(
        value, sort_keys=True, default=repr
    )
    return {
        "length": len(text),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def _summarize_last_error(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "code": _optional_str(_mapping_value(value, "code")),
        "message_present": _mapping_value(value, "message") is not None,
        "message_length": len(str(_mapping_value(value, "message")))
        if _mapping_value(value, "message") is not None
        else 0,
    }


def _summarize_incomplete(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {"reason": _optional_str(_mapping_value(value, "reason"))}


def _truncation_type(run_mapping: Mapping[str, Any] | None) -> str | None:
    if run_mapping is None:
        return None
    truncation = _mapping_value(run_mapping, "truncation_strategy")
    if isinstance(truncation, Mapping):
        return _optional_str(_mapping_value(truncation, "type"))
    return None


def _summarize_response_format(value: Any) -> str | dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        rf_type = _optional_str(_mapping_value(value, "type"))
        if rf_type:
            return {"type": rf_type}
    return None


def _extract_run_usage(run_mapping: Mapping[str, Any] | None) -> dict[str, int]:
    if run_mapping is None:
        return {}
    usage = _mapping_value(run_mapping, "usage")
    if not isinstance(usage, Mapping):
        return {}
    result: dict[str, int] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = _optional_int(_mapping_value(usage, key))
        if value is not None:
            result[key] = value
    return result


def _resolve_auth_mode(
    invocation: _NormalizedInvocation, custom_endpoint: bool
) -> str | None:
    if invocation.auth_mode:
        explicit = _safe_auth_mode(invocation.auth_mode)
        if explicit is not None:
            return explicit
    api_key_header = _header_value(invocation.headers, "x-api-key") or _header_value(
        invocation.headers, "openai-api-key"
    )
    authorization = _header_value(invocation.headers, "authorization")
    if api_key_header and api_key_header.startswith("sk-"):
        # Custom (non-OpenAI) base URL accepting an sk-style key is still
        # bring-your-own — surfaces the fact that requests are not hitting
        # OpenAI's hosted endpoint.
        return "bring_your_own" if custom_endpoint else "api_key"
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token.startswith("sk-"):
            return "bring_your_own" if custom_endpoint else "api_key"
        return "bring_your_own" if custom_endpoint else "bearer"
    if api_key_header:
        return "bring_your_own" if custom_endpoint else "api_key"
    if custom_endpoint:
        return "bring_your_own"
    return None


def _safe_auth_mode(value: str) -> str | None:
    mode = value.strip().lower().replace("-", "_")
    if mode in {"apikey", "api"}:
        mode = "api_key"
    if mode in {"byok", "bring-your-own", "bring_your_own_key"}:
        mode = "bring_your_own"
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


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
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
    operation = raw["operation"]
    status = raw.get("status") or "no-status"
    model = raw.get("model") or "unknown-model"
    return f"{raw['provider']} {operation} {model} status={status}"
