"""PydanticAIProducer — translates raw Pydantic-AI run events into Ancilis Action objects.

This module never imports ``pydantic_ai`` at import time. The producer is
duck-typed — callers pass in plain dict events extracted from agent runs or
streaming iterators. This keeps the Ancilis evidence path independent of the
Pydantic-AI version installed (or absent) at runtime.

Security-critical guarantee: tool argument *values* are never stored raw. Only
argument key names and a sha256 digest of ``repr(value)`` are captured. Typed
agent runtimes commonly route Pydantic models containing PII, credentials, or
other sensitive structured payloads through tool calls — evidence must not
leak them.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


# Map raw Pydantic-AI event kinds to Ancilis action_type values.
_ACTION_TYPE_BY_KIND: dict[str, str] = {
    "model_response": "tool_call",
    "function_tool_call": "tool_call",
    "function_tool_result": "tool_call",
    "final_result": "tool_call",
    "run_result": "tool_call",
}


class PydanticAIProducer:
    """Translates raw Pydantic-AI event payloads into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(
        self,
        agent_id: str = "pydantic-ai-agent",
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw Pydantic-AI event dict into an Action.

        Expected keys (all optional except ``kind``):
          - kind: "model_response" | "function_tool_call" |
                  "function_tool_result" | "final_result" | "run_result"
          - event_id: str — Pydantic-AI's per-event id (becomes action_id)
          - tool_name: str — tool function name (function_tool_*)
          - tool_args: dict[str, Any] — raw tool arg dict (sanitized; never stored raw)
          - model: str — model identifier (model_response / final_result)
          - usage: dict — Pydantic-AI Usage payload (input_tokens, output_tokens, total_tokens)
          - output: Any — tool result or final output (length-only capture)
          - error: dict | BaseException — error.type captured if present
          - parent_event_id: str — for stream-event correlation
        """
        kind = raw.get("kind", "unknown")
        action_type = _ACTION_TYPE_BY_KIND.get(kind, "tool_call")

        tool_or_model = _extract_tool_or_model_name(kind, raw)
        tool_name = f"pydantic_ai:{kind}:{tool_or_model}"

        params = _build_params(kind, raw)
        param_hash = hashlib.sha256(str(sorted(params.items())).encode()).hexdigest()[:16]

        tool_desc = f"{kind}:{tool_or_model}"
        desc_hash = hashlib.sha256(tool_desc.encode()).hexdigest()[:16]

        action_id = str(raw.get("event_id") or f"pa-{int(time.time() * 1_000_000)}")
        parent_event_id = raw.get("parent_event_id")

        return Action(
            action_id=action_id,
            timestamp=_iso_now(),
            agent_id=self.agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=None,
                server="pydantic-ai",
                description_hash=desc_hash,
            ),
            parameters=ActionParameters(raw=params, parameter_hash=param_hash),
            context=ActionContext(
                session_id=self.session_id,
                parent_action_id=str(parent_event_id) if parent_event_id else None,
            ),
            source_type="agent",
            producer_type="framework",
            producer_version=self.producer_version,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_tool_or_model_name(kind: str, raw: dict[str, Any]) -> str:
    """Return a human label for the tool or model being acted on."""
    if kind in ("function_tool_call", "function_tool_result"):
        return str(raw.get("tool_name") or "tool")
    if kind in ("model_response", "final_result"):
        return str(raw.get("model") or raw.get("tool_name") or "model")
    if kind == "run_result":
        return str(raw.get("model") or "run")
    return str(raw.get("tool_name") or raw.get("model") or kind)


def _build_params(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Extract evidence-relevant fields. Tool argument values are sanitized."""
    params: dict[str, Any] = {"kind": kind}

    if kind == "model_response":
        if "model" in raw:
            params["model"] = str(raw.get("model") or "")
        usage = _normalise_usage(raw.get("usage"))
        if usage:
            params["usage"] = usage

    elif kind == "function_tool_call":
        params["tool_name"] = str(raw.get("tool_name") or "")
        sanitized = _sanitize_tool_args(raw.get("tool_args"))
        params["tool_arg_keys"] = sanitized["keys"]
        params["tool_arg_value_hashes"] = sanitized["value_hashes"]

    elif kind == "function_tool_result":
        params["tool_name"] = str(raw.get("tool_name") or "")
        output = raw.get("output")
        params["output_length"] = len(str(output)) if output is not None else 0
        err_type = _extract_error_type(raw.get("error"))
        if err_type is not None:
            params["error_type"] = err_type

    elif kind == "final_result":
        if "model" in raw:
            params["model"] = str(raw.get("model") or "")
        if "tool_name" in raw:
            params["tool_name"] = str(raw.get("tool_name") or "")
        output = raw.get("output")
        if output is not None:
            params["output_length"] = len(str(output))

    elif kind == "run_result":
        if "model" in raw:
            params["model"] = str(raw.get("model") or "")
        usage = _normalise_usage(raw.get("usage"))
        if usage:
            params["usage"] = usage
        output = raw.get("output")
        if output is not None:
            params["output_length"] = len(str(output))
        err_type = _extract_error_type(raw.get("error"))
        if err_type is not None:
            params["error_type"] = err_type

    # Universal correlation fields
    if "event_id" in raw and raw["event_id"] is not None:
        params["event_id"] = str(raw["event_id"])
    if "parent_event_id" in raw and raw["parent_event_id"] is not None:
        params["parent_event_id"] = str(raw["parent_event_id"])

    return params


def _sanitize_tool_args(tool_args: Any) -> dict[str, Any]:
    """Return ``{"keys": [...], "value_hashes": {key: sha256_hex}}``.

    Raw values are NEVER stored. Only key names and sha256(repr(value)) digests.
    Typed Pydantic-AI tools may pass Pydantic model instances containing
    sensitive structured data — this is the security boundary.
    """
    if not isinstance(tool_args, dict):
        return {"keys": [], "value_hashes": {}}
    keys = sorted(str(k) for k in tool_args.keys())
    value_hashes: dict[str, str] = {}
    for k in keys:
        try:
            digest = hashlib.sha256(repr(tool_args[k]).encode("utf-8", "replace")).hexdigest()
        except Exception:  # noqa: BLE001 — never let a weird __repr__ break evidence
            digest = hashlib.sha256(b"<unrepresentable>").hexdigest()
        value_hashes[k] = digest
    return {"keys": keys, "value_hashes": value_hashes}


def _normalise_usage(usage: Any) -> dict[str, int] | None:
    """Coerce a Pydantic-AI Usage object (or dict) to a plain dict of ints."""
    if usage is None:
        return None
    if isinstance(usage, dict):
        source = usage
    else:
        source = {}
        for attr in (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "request_tokens",
            "response_tokens",
            "requests",
        ):
            if hasattr(usage, attr):
                source[attr] = getattr(usage, attr)
    out: dict[str, int] = {}
    for key, value in source.items():
        try:
            out[str(key)] = int(value) if value is not None else 0
        except (TypeError, ValueError):
            continue
    return out or None


def _extract_error_type(error: Any) -> str | None:
    """Return a short error.type string, or None if no error is present."""
    if error is None:
        return None
    if isinstance(error, BaseException):
        return type(error).__name__
    if isinstance(error, dict):
        t = error.get("type") or error.get("error_type")
        if t:
            return str(t)
        return None
    if isinstance(error, str):
        return error or None
    return type(error).__name__


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
