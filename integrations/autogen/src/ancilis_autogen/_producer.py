"""AutoGenProducer — translates raw AutoGen conversation data into Ancilis Action objects."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


class AutoGenProducer:
    """Translates raw AutoGen event dicts into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(self, agent_id: str = "autogen-agent", session_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw AutoGen event dict into an Action.

        Expected keys:
          - event: "message" | "function_call" | "function_result" | "conversation_end"
          - sender_name: str — agent that sent the message
          - recipient_name: str — agent receiving the message
          - role: "user" | "assistant" | "function" | "system"
          - content: str (stored as length only)
          - function_name: str (for function_call / function_result events)
          - function_args: str (for function_call — stored truncated)
          - function_result: str (for function_result — stored as length)
          - message_index: int — position in conversation sequence
          - conversation_id: str — correlation id
          - turn_count: int — total turns so far (conversation_end)
          - termination_reason: str (conversation_end)
        """
        event = raw.get("event", "message")
        conversation_id = str(raw.get("conversation_id", "")) or f"ag-{int(time.time() * 1000)}"
        sender = raw.get("sender_name", "unknown")

        tool_name, action_type, desc_key = _classify_event(event, raw)
        params = _build_params(raw, event)
        param_hash = hashlib.sha256(str(sorted(params.items())).encode()).hexdigest()[:16]
        desc_hash = hashlib.sha256(desc_key.encode()).hexdigest()[:16]

        return Action(
            action_id=conversation_id,
            timestamp=_iso_now(),
            agent_id=self.agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=None,
                server="autogen",
                description_hash=desc_hash,
            ),
            parameters=ActionParameters(raw=params, parameter_hash=param_hash),
            context=ActionContext(session_id=self.session_id),
            source_type="agent",
            producer_type="framework",
            producer_version=self.producer_version,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _classify_event(event: str, raw: dict[str, Any]) -> tuple[str, str, str]:
    """Return (tool_name, action_type, desc_key)."""
    sender = raw.get("sender_name", "agent")
    func_name = raw.get("function_name", "function")

    if event == "message":
        return f"agent:{sender}", "tool_call", f"message:{sender}"
    if event == "function_call":
        return func_name, "tool_call", f"function_call:{func_name}"
    if event == "function_result":
        return func_name, "tool_call", f"function_result:{func_name}"
    if event == "conversation_end":
        return "conversation", "tool_call", "conversation_end"
    return event, "tool_call", f"unknown:{event}"


def _build_params(raw: dict[str, Any], event: str) -> dict[str, Any]:
    params: dict[str, Any] = {"event": event}

    # Common conversation fields
    for key in ("sender_name", "recipient_name", "role", "conversation_id", "message_index"):
        val = raw.get(key)
        if val is not None:
            params[key] = val

    if event == "message":
        content = raw.get("content", "") or ""
        # Store length only — never raw content (privacy)
        params["content_length"] = len(str(content))
        params["has_function_call"] = bool(raw.get("function_call"))

    elif event == "function_call":
        params["function_name"] = raw.get("function_name", "")
        # Truncate args at 512 chars
        args = str(raw.get("function_args", "") or "")
        params["function_args_preview"] = args[:512]
        params["function_args_length"] = len(args)

    elif event == "function_result":
        params["function_name"] = raw.get("function_name", "")
        result = str(raw.get("function_result", "") or "")
        params["result_length"] = len(result)

    elif event == "conversation_end":
        params["turn_count"] = raw.get("turn_count", 0)
        params["termination_reason"] = raw.get("termination_reason", "")

    return params


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
