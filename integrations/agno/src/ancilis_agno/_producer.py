"""AgnoProducer — translates raw Agno events into Ancilis Action objects.

This module never imports ``agno`` at module load. The producer is duck-typed —
callers pass plain dict events extracted from ``RunResponse`` objects, stream
events, or memory / knowledge operations. This keeps the Ancilis evidence path
independent of the agno version installed (or absent) at runtime.

Security-critical guarantees:

1. **Tool argument values are never stored raw.** Only argument key names plus
   sha256 digests of each value.
2. **Memory text is never stored raw.** Agno teams persist user-supplied memory
   across sessions — this is the highest-PII surface in any team-of-agents
   stack. Only length and sha256(content) are captured.
3. **Knowledge queries are never stored raw.** Length + sha256 only.
4. **Response content is never stored raw.** Only length and sha256.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


# Map raw Agno event ``kind`` strings to Ancilis (action_type, semantic_kind)
# pairs. ``semantic_kind`` is the second segment in the tool name pattern
# ``agno:{kind}:{name}`` and lets evaluators bucket events without parsing
# action_type back out.
_EVENT_MAP: dict[str, tuple[str, str]] = {
    # Run lifecycle events from Agent.run / arun / run_stream
    "RunStarted": ("tool_call", "run"),
    "RunResponse": ("tool_call", "run"),
    "RunCompleted": ("tool_call", "run"),
    # Tool-call events emitted during a run
    "ToolCallStarted": ("tool_call", "tool"),
    "ToolCallCompleted": ("tool_call", "tool"),
    # Team delegation events
    "MemberRunStarted": ("tool_call", "member"),
    "MemberRunCompleted": ("tool_call", "member"),
    # Memory operations — every memory touch is a data-access event.
    "add_user_memory": ("data_access", "memory"),
    "update_session_summary": ("data_access", "memory"),
    "search_user_memories": ("data_access", "memory"),
    "get_session_summary": ("data_access", "memory"),
    # Knowledge base operations
    "knowledge_search": ("data_access", "knowledge"),
    "knowledge_add": ("data_access", "knowledge"),
    "knowledge_update": ("data_access", "knowledge"),
}


class AgnoProducer:
    """Translates raw Agno event dicts into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(
        self,
        agent_id: str = "agno-agent",
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw Agno event dict into an Action.

        Expected keys (all optional except ``kind`` or ``event``):
          - kind / event: one of the keys in ``_EVENT_MAP``
          - id / event_id / run_id: per-event identifier
          - agent_id: overrides the producer's default
          - tool_name / tool_call: tool name + args (dict or JSON string)
          - tool_call_id: ID linking call to return
          - tool_args: dict of arguments (sanitized)
          - content: response text (sanitized — never stored raw)
          - model: model identifier
          - metrics / usage: dict carrying token / latency metrics
          - member_name / member_agent_id: team-delegation correlators
          - memory_text: memory write content (sanitized)
          - query: knowledge / memory search query (sanitized)
          - documents: knowledge.add documents (count only)
          - error: dict | BaseException
          - parent_id / parent_action_id: parent action correlator
        """
        kind = str(raw.get("kind") or raw.get("event") or "unknown")
        action_type, semantic_kind = _EVENT_MAP.get(kind, ("tool_call", "unknown"))

        target_name = _extract_target_name(kind, raw)
        tool_name = f"agno:{semantic_kind}:{target_name}"

        params = _build_params(kind, semantic_kind, raw)
        param_hash = hashlib.sha256(
            json.dumps(_sortable(params), sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        desc = f"{kind}:{target_name}"
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]

        action_id = str(
            raw.get("id")
            or raw.get("event_id")
            or raw.get("run_id")
            or f"agno-{int(time.time() * 1_000_000)}"
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
                server="agno",
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
    if kind in ("ToolCallStarted", "ToolCallCompleted"):
        tc = raw.get("tool_call") or {}
        if isinstance(tc, dict):
            name = tc.get("tool_name") or tc.get("name")
            if name:
                return str(name)
        return str(raw.get("tool_name") or raw.get("name") or "tool")

    if kind in ("MemberRunStarted", "MemberRunCompleted"):
        return str(
            raw.get("member_name")
            or raw.get("member_agent_id")
            or raw.get("name")
            or "member"
        )

    if kind in ("RunStarted", "RunResponse", "RunCompleted"):
        return str(raw.get("model") or raw.get("agent_id") or "run")

    if kind in (
        "add_user_memory",
        "update_session_summary",
        "search_user_memories",
        "get_session_summary",
    ):
        return kind.replace("_", "-")

    if kind in ("knowledge_search", "knowledge_add", "knowledge_update"):
        return kind.split("_", 1)[1]  # search / add / update

    return str(raw.get("name") or kind)


def _build_params(kind: str, semantic_kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Extract evidence-relevant fields. Never capture raw text or memory content."""
    params: dict[str, Any] = {"kind": kind, "semantic_kind": semantic_kind}

    # Universal correlation fields
    for src, dst in (
        ("id", "event_id"),
        ("event_id", "event_id"),
        ("run_id", "run_id"),
        ("tool_call_id", "tool_call_id"),
        ("agent_id", "agent_id"),
        ("model", "model"),
        ("session_id", "session_id"),
    ):
        value = raw.get(src)
        if value is not None:
            params[dst] = str(value)

    parent_id = raw.get("parent_id") or raw.get("parent_action_id")
    if parent_id is not None:
        params["parent_id"] = str(parent_id)

    if kind in ("ToolCallStarted", "ToolCallCompleted"):
        tc = raw.get("tool_call") or {}
        params["tool_name"] = str(
            _get(tc, "tool_name") or _get(tc, "name") or raw.get("tool_name") or ""
        )
        args = _get(tc, "tool_args")
        if args is None:
            args = _get(tc, "arguments")
        if args is None:
            args = raw.get("tool_args")
        sanitized = _sanitize_tool_args(args)
        params["tool_arg_keys"] = sanitized["keys"]
        params["tool_arg_value_hashes"] = sanitized["value_hashes"]

        if kind == "ToolCallCompleted":
            result = _get(tc, "result")
            if result is None:
                result = raw.get("result")
            if result is not None:
                r_str = str(result)
                params["result_length"] = len(r_str)
                params["result_sha256"] = hashlib.sha256(r_str.encode()).hexdigest()
            err_type = _extract_error_type(raw.get("error"))
            if err_type is not None:
                params["error_type"] = err_type

    elif kind in ("RunStarted", "RunResponse", "RunCompleted"):
        content = raw.get("content")
        if content is not None:
            text = _flatten_content(content)
            params["content_length"] = len(text)
            params["content_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        # Tool-call list summary for run-level events (some Agno run responses
        # carry an aggregated `tools` field — capture count + names only).
        tools = raw.get("tools")
        if isinstance(tools, list):
            params["tool_count"] = len(tools)
            tool_names: list[str] = []
            for t in tools:
                name = _get(t, "tool_name") or _get(t, "name")
                if name:
                    tool_names.append(str(name))
            if tool_names:
                params["tool_names"] = tool_names

    elif kind in ("MemberRunStarted", "MemberRunCompleted"):
        member_name = raw.get("member_name") or raw.get("name")
        member_agent_id = raw.get("member_agent_id") or raw.get("agent_id")
        if member_name is not None:
            params["member_name"] = str(member_name)
        if member_agent_id is not None:
            params["member_agent_id"] = str(member_agent_id)
        content = raw.get("content")
        if content is not None:
            text = _flatten_content(content)
            params["content_length"] = len(text)
            params["content_sha256"] = hashlib.sha256(text.encode()).hexdigest()

    elif kind in ("add_user_memory", "update_session_summary"):
        text = raw.get("memory_text") or raw.get("text") or raw.get("content")
        if text is not None:
            t_str = str(text)
            params["content_length"] = len(t_str)
            params["content_sha256"] = hashlib.sha256(t_str.encode()).hexdigest()
        if kind == "update_session_summary" and raw.get("session_id") is not None:
            params["session_id"] = str(raw["session_id"])

    elif kind in ("search_user_memories", "get_session_summary"):
        query = raw.get("query")
        if query is not None:
            q_str = str(query)
            params["query_length"] = len(q_str)
            params["query_sha256"] = hashlib.sha256(q_str.encode()).hexdigest()
        results = raw.get("results")
        if isinstance(results, list):
            params["result_count"] = len(results)
        elif isinstance(raw.get("count"), int):
            params["result_count"] = int(raw["count"])

    elif kind == "knowledge_search":
        query = raw.get("query")
        if query is not None:
            q_str = str(query)
            params["query_length"] = len(q_str)
            params["query_sha256"] = hashlib.sha256(q_str.encode()).hexdigest()
        if raw.get("limit") is not None:
            with contextlib.suppress(TypeError, ValueError):
                params["limit"] = int(raw["limit"])
        filters = raw.get("filters")
        if isinstance(filters, dict):
            params["filter_keys"] = sorted(str(k) for k in filters)
        results = raw.get("results")
        if isinstance(results, list):
            params["result_count"] = len(results)
        elif isinstance(raw.get("count"), int):
            params["result_count"] = int(raw["count"])

    elif kind in ("knowledge_add", "knowledge_update"):
        documents = raw.get("documents")
        if isinstance(documents, list):
            params["document_count"] = len(documents)

    # Token / latency metrics capture (any event that carries them).
    metrics = _normalise_metrics(raw.get("metrics") or raw.get("usage"))
    if metrics:
        params["metrics"] = metrics

    # Generic error capture for any event subtype not already handled above.
    if kind != "ToolCallCompleted":
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
    """Agno response content is sometimes a list of {type, text} parts."""
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

    Tool arguments arrive from Agno as either a JSON string or a dict.
    Raw values are NEVER stored. Only key names and sha256(repr(value)) digests.
    """
    parsed: Any = tool_args
    if isinstance(tool_args, str):
        try:
            parsed = json.loads(tool_args)
        except (ValueError, TypeError):
            return {
                "keys": ["__raw__"],
                "value_hashes": {
                    "__raw__": hashlib.sha256(
                        tool_args.encode("utf-8", "replace")
                    ).hexdigest()
                },
            }
    if not isinstance(parsed, dict):
        return {"keys": [], "value_hashes": {}}
    keys = sorted(str(k) for k in parsed)
    value_hashes: dict[str, str] = {}
    for k in keys:
        try:
            digest = hashlib.sha256(
                repr(parsed[k]).encode("utf-8", "replace")
            ).hexdigest()
        except Exception:  # noqa: BLE001
            digest = hashlib.sha256(b"<unrepresentable>").hexdigest()
        value_hashes[k] = digest
    return {"keys": keys, "value_hashes": value_hashes}


def _normalise_metrics(metrics: Any) -> dict[str, Any] | None:
    """Coerce an Agno metrics object/dict to a plain dict of scalars.

    Captures the canonical Agno metric fields where present:
    ``time_to_first_token``, ``total_tokens``, ``tokens_per_second``,
    ``input_tokens``, ``output_tokens``, ``prompt_tokens``,
    ``completion_tokens``, ``total_time``.
    """
    if metrics is None:
        return None
    if isinstance(metrics, dict):
        source = metrics
    else:
        source = {}
        for attr in (
            "time_to_first_token",
            "total_tokens",
            "tokens_per_second",
            "input_tokens",
            "output_tokens",
            "prompt_tokens",
            "completion_tokens",
            "total_time",
        ):
            if hasattr(metrics, attr):
                source[attr] = getattr(metrics, attr)
    out: dict[str, Any] = {}
    for key, value in source.items():
        if value is None:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out[str(key)] = value
            continue
        try:
            out[str(key)] = float(value)
        except (TypeError, ValueError):
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
