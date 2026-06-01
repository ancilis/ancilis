"""LettaProducer — translates raw Letta events into Ancilis Action objects.

This module never imports ``letta_client`` at import time. The producer is
duck-typed — callers pass in plain dict events extracted from ``LettaResponse``
objects, server SSE events, or memory-CRUD operations. This keeps the Ancilis
evidence path independent of the letta-client version installed (or absent) at
runtime.

Security-critical guarantees:

1. **Tool argument values are never stored raw.** Only argument key names plus
   sha256 digests of each value.
2. **Memory-block content is never stored raw.** Letta persists user-supplied
   memory across sessions — this is the highest-PII surface in the stack.
   Only length and sha256(content) are captured.
3. **Message content is never stored raw.** Only role, length, and sha256.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


# Map raw Letta event ``kind`` strings to Ancilis (action_type, semantic_kind)
# pairs. ``semantic_kind`` is the second segment in the tool name pattern
# ``letta:{kind}:{name}`` and lets evaluators bucket events without parsing
# action_type back out.
_EVENT_MAP: dict[str, tuple[str, str]] = {
    # Message subtypes returned by agents.messages.create()
    "system_message": ("tool_call", "message"),
    "user_message": ("tool_call", "message"),
    "assistant_message": ("tool_call", "message"),
    "reasoning_message": ("tool_call", "message"),
    "tool_call_message": ("tool_call", "tool"),
    "tool_return_message": ("tool_call", "tool"),
    # Memory operations — every memory touch is a data-access event.
    "archival_memory_create": ("data_access", "archival_memory"),
    "archival_memory_update": ("data_access", "archival_memory"),
    "archival_memory_search": ("data_access", "archival_memory"),
    "archival_memory_delete": ("data_access", "archival_memory"),
    "core_memory_update": ("data_access", "core_memory"),
    # Streaming-only events
    "step_completed": ("tool_call", "step"),
    "usage_statistics": ("tool_call", "usage"),
}


class LettaProducer:
    """Translates raw Letta event dicts into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(
        self,
        agent_id: str = "letta-agent",
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw Letta event dict into an Action.

        Expected keys (all optional except ``kind``):
          - kind: one of the keys in ``_EVENT_MAP``
          - id / message_id / event_id: per-event identifier
          - agent_id: overrides the producer's default
          - tool_call: dict with ``name`` and ``arguments`` (JSON string or dict)
          - tool_call_id: ID linking call to return
          - content: message text (sanitized — never stored raw)
          - role: "user" | "assistant" | "system" | "tool"
          - block_label: core_memory block label
          - new_value / value / text: memory content (sanitized)
          - query: archival_memory_search query (sanitized)
          - results: archival_memory_search hits (count only)
          - model: model identifier
          - usage / usage_statistics: token usage payload
          - error: dict | BaseException
          - parent_id: parent action correlator
        """
        kind = str(raw.get("kind") or raw.get("message_type") or "unknown")
        action_type, semantic_kind = _EVENT_MAP.get(kind, ("tool_call", "unknown"))

        target_name = _extract_target_name(kind, raw)
        tool_name = f"letta:{semantic_kind}:{target_name}"

        params = _build_params(kind, semantic_kind, raw)
        param_hash = hashlib.sha256(
            json.dumps(_sortable(params), sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        desc = f"{kind}:{target_name}"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]

        action_id = str(
            raw.get("id")
            or raw.get("message_id")
            or raw.get("event_id")
            or f"letta-{int(time.time() * 1_000_000)}"
        )
        parent_id = raw.get("parent_id") or raw.get("parent_action_id")
        agent_id = str(raw.get("agent_id") or self.agent_id)

        return Action(
            action_id=action_id,
            timestamp=_iso_now(),
            agent_id=agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=None,
                server="letta",
                description_hash=desc_hash,
            ),
            parameters=ActionParameters(raw=params, parameter_hash=param_hash),
            context=ActionContext(
                session_id=self.session_id,
                parent_action_id=str(parent_id) if parent_id else None,
            ),
            source_type="agent",
            producer_type="framework",
            producer_version=self.producer_version,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_target_name(kind: str, raw: dict[str, Any]) -> str:
    """Pick the most informative identifier for the event subject."""
    if kind == "tool_call_message" or kind == "tool_return_message":
        tc = raw.get("tool_call") or {}
        if isinstance(tc, dict):
            name = tc.get("name") or tc.get("tool_name")
            if name:
                return str(name)
        return str(raw.get("tool_name") or raw.get("name") or "tool")

    if kind in ("archival_memory_create", "archival_memory_update", "archival_memory_delete"):
        return str(raw.get("memory_id") or raw.get("block_label") or "archival")

    if kind == "archival_memory_search":
        return "search"

    if kind == "core_memory_update":
        return str(raw.get("block_label") or raw.get("label") or "core")

    if kind in ("assistant_message", "user_message", "system_message", "reasoning_message"):
        return kind.replace("_message", "")

    if kind in ("step_completed", "usage_statistics"):
        return kind

    return str(raw.get("name") or kind)


def _build_params(kind: str, semantic_kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Extract evidence-relevant fields. Never capture raw text or memory content."""
    params: dict[str, Any] = {"kind": kind, "semantic_kind": semantic_kind}

    # Universal correlation fields
    for src, dst in (
        ("id", "event_id"),
        ("message_id", "message_id"),
        ("tool_call_id", "tool_call_id"),
        ("agent_id", "agent_id"),
        ("model", "model"),
    ):
        value = raw.get(src)
        if value is not None:
            params[dst] = str(value)

    parent_id = raw.get("parent_id") or raw.get("parent_action_id")
    if parent_id is not None:
        params["parent_id"] = str(parent_id)

    if kind == "tool_call_message":
        tc = raw.get("tool_call") or {}
        params["tool_name"] = str(_get(tc, "name") or raw.get("tool_name") or "")
        sanitized = _sanitize_tool_args(_get(tc, "arguments"))
        params["tool_arg_keys"] = sanitized["keys"]
        params["tool_arg_value_hashes"] = sanitized["value_hashes"]

    elif kind == "tool_return_message":
        tc = raw.get("tool_call") or {}
        params["tool_name"] = str(
            _get(tc, "name") or raw.get("tool_name") or raw.get("name") or ""
        )
        ret = raw.get("tool_return") if "tool_return" in raw else raw.get("return_value")
        if ret is None:
            ret = raw.get("content")
        if ret is not None:
            params["return_length"] = len(str(ret))
            params["return_sha256"] = hashlib.sha256(str(ret).encode()).hexdigest()
        status = raw.get("status")
        if status is not None:
            params["status"] = str(status)
        err_type = _extract_error_type(raw.get("error") or raw.get("stderr"))
        if err_type is not None:
            params["error_type"] = err_type

    elif kind in ("system_message", "user_message", "assistant_message", "reasoning_message"):
        role = raw.get("role") or kind.replace("_message", "")
        params["role"] = str(role)
        content = raw.get("content")
        if content is None and kind == "reasoning_message":
            content = raw.get("reasoning")
        if content is not None:
            text = _flatten_content(content)
            params["content_length"] = len(text)
            params["content_sha256"] = hashlib.sha256(text.encode()).hexdigest()

    elif kind in ("archival_memory_create", "archival_memory_update"):
        text = raw.get("text") or raw.get("content") or raw.get("value") or raw.get("new_value")
        if text is not None:
            text_str = str(text)
            params["content_length"] = len(text_str)
            params["content_sha256"] = hashlib.sha256(text_str.encode()).hexdigest()
        if "memory_id" in raw and raw["memory_id"] is not None:
            params["memory_id"] = str(raw["memory_id"])
        if "block_label" in raw and raw["block_label"] is not None:
            params["block_label"] = str(raw["block_label"])

    elif kind == "archival_memory_search":
        query = raw.get("query") or raw.get("text")
        if query is not None:
            q_str = str(query)
            params["query_length"] = len(q_str)
            params["query_sha256"] = hashlib.sha256(q_str.encode()).hexdigest()
        results = raw.get("results")
        if isinstance(results, list):
            params["result_count"] = len(results)
        elif isinstance(raw.get("count"), int):
            params["result_count"] = int(raw["count"])

    elif kind == "archival_memory_delete":
        if "memory_id" in raw and raw["memory_id"] is not None:
            params["memory_id"] = str(raw["memory_id"])

    elif kind == "core_memory_update":
        label = raw.get("block_label") or raw.get("label")
        if label is not None:
            params["block_label"] = str(label)
        new_value = raw.get("new_value") or raw.get("value")
        if new_value is not None:
            v_str = str(new_value)
            params["content_length"] = len(v_str)
            params["content_sha256"] = hashlib.sha256(v_str.encode()).hexdigest()

    elif kind == "step_completed":
        step_id = raw.get("step_id") or raw.get("step")
        if step_id is not None:
            params["step_id"] = str(step_id)

    elif kind == "usage_statistics":
        # Treated identically to a usage payload below.
        pass

    # Token usage capture (any event that carries ``usage`` or ``usage_statistics``).
    usage = _normalise_usage(raw.get("usage") or raw.get("usage_statistics"))
    if usage:
        params["usage"] = usage

    # Generic error capture for any event subtype.
    if kind != "tool_return_message":  # already captured above
        err_type = _extract_error_type(raw.get("error"))
        if err_type is not None:
            params["error_type"] = err_type

    return params


def _get(maybe_obj: Any, attr: str) -> Any:
    """Lookup ``attr`` on a dict OR an object — used for tool_call payloads."""
    if maybe_obj is None:
        return None
    if isinstance(maybe_obj, dict):
        return maybe_obj.get(attr)
    return getattr(maybe_obj, attr, None)


def _flatten_content(content: Any) -> str:
    """Letta message content is sometimes a list of {type, text} parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if text is not None:
                    parts.append(str(text))
                else:
                    parts.append(repr(item))
            elif isinstance(item, str):
                parts.append(item)
            else:
                text = getattr(item, "text", None) or getattr(item, "content", None)
                parts.append(str(text) if text is not None else repr(item))
        return "".join(parts)
    return str(content)


def _sanitize_tool_args(tool_args: Any) -> dict[str, Any]:
    """Return ``{"keys": [...], "value_hashes": {key: sha256_hex}}``.

    Tool arguments arrive from Letta as either a JSON string or already a dict.
    Raw values are NEVER stored. Only key names and sha256(repr(value)) digests.
    """
    parsed: Any = tool_args
    if isinstance(tool_args, str):
        try:
            parsed = json.loads(tool_args)
        except (ValueError, TypeError):
            # Non-JSON string — treat as a single opaque arg
            return {
                "keys": ["__raw__"],
                "value_hashes": {
                    "__raw__": hashlib.sha256(tool_args.encode("utf-8", "replace")).hexdigest()
                },
            }
    if not isinstance(parsed, dict):
        return {"keys": [], "value_hashes": {}}
    keys = sorted(str(k) for k in parsed)
    value_hashes: dict[str, str] = {}
    for k in keys:
        try:
            digest = hashlib.sha256(repr(parsed[k]).encode("utf-8", "replace")).hexdigest()
        except Exception:  # noqa: BLE001
            digest = hashlib.sha256(b"<unrepresentable>").hexdigest()
        value_hashes[k] = digest
    return {"keys": keys, "value_hashes": value_hashes}


def _normalise_usage(usage: Any) -> dict[str, int] | None:
    """Coerce a Letta usage_statistics object/dict to a plain dict of ints."""
    if usage is None:
        return None
    if isinstance(usage, dict):
        source = usage
    else:
        source = {}
        for attr in (
            "completion_tokens",
            "prompt_tokens",
            "total_tokens",
            "input_tokens",
            "output_tokens",
            "step_count",
            "run_ids",
        ):
            if hasattr(usage, attr):
                source[attr] = getattr(usage, attr)
    out: dict[str, int] = {}
    for key, value in source.items():
        if value is None:
            continue
        try:
            out[str(key)] = int(value)
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
        return str(t) if t else None
    if isinstance(error, str):
        return error or None
    return type(error).__name__


def _sortable(value: Any) -> Any:
    """Normalise a params dict into a JSON-serialisable, sortable structure."""
    if isinstance(value, dict):
        return {str(k): _sortable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sortable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
