"""AncilisConversationLogger — AutoGen conversation logging for Ancilis evidence capture.

## AutoGen Version Support

Targets **pyautogen >= 0.2.0** (the `pyautogen` / `autogen` package on PyPI).

AutoGen 0.2.x exposes `ConversableAgent.register_reply()` — a stable hook for
injecting logic before an agent's normal reply. This integration uses it to
observe every message exchange without modifying agent behavior.

AutoGen 0.4+ (`autogen-agentchat`) has a different API. Support for 0.4+ can be
added when the API stabilizes. Version detection is included but 0.4 is not
actively instrumented in this release.

## Integration Points

1. `AncilisConversationLogger(agent_id, session_id)` — create a logger instance
2. `logger.attach(agent)` — instrument one ConversableAgent
3. `logger.attach_all(groupchat_manager)` — instrument all agents in a GroupChat

The reply hook runs at position 0 (first) and always returns `(False, None)` so
it never interferes with the agent's normal reply pipeline.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from ancilis_autogen._producer import AutoGenProducer


def _safe_submit(action: Any) -> None:
    """Submit an Action to the Ancilis engine. Never raises."""
    try:
        from ancilis.config import load_config
        from ancilis.engine.engine import Engine

        config = load_config()
        engine = Engine(config)
        engine.evaluate(action)
    except Exception:  # noqa: BLE001
        pass


def _emit(producer: AutoGenProducer, raw: dict[str, Any]) -> None:
    """Translate and submit. Never raises."""
    try:
        action = producer.translate(raw)
        _safe_submit(action)
    except Exception:  # noqa: BLE001
        pass


class AncilisConversationLogger:
    """Attaches to AutoGen agents to capture conversation evidence.

    Usage::

        from ancilis_autogen import AncilisConversationLogger

        logger = AncilisConversationLogger(agent_id="my-pipeline")
        logger.attach(assistant)      # single agent
        # or
        logger.attach_all(manager)    # all agents in a GroupChatManager
    """

    def __init__(
        self,
        agent_id: str = "autogen-agent",
        session_id: str | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id
        self._producer = AutoGenProducer(agent_id=agent_id, session_id=session_id)
        self._conversation_id = str(uuid.uuid4())[:8]
        self._message_index = 0
        self._attached_agents: list[Any] = []

    def attach(self, agent: Any) -> None:
        """Instrument a single ConversableAgent with a reply hook.

        Safe to call multiple times on the same agent — only attaches once.
        Works with pyautogen >= 0.2.0.
        """
        if agent in self._attached_agents:
            return

        logger_ref = self  # closure reference

        def _logging_reply(
            recipient: Any,
            messages: Optional[list[dict[str, Any]]],
            sender: Any,
            config: Any,
        ) -> tuple[bool, None]:
            """Reply hook: observe the latest message and emit evidence."""
            try:
                if messages:
                    last_msg = messages[-1]
                    logger_ref._emit_message(
                        sender_name=_get_agent_name(sender),
                        recipient_name=_get_agent_name(recipient),
                        message=last_msg,
                    )
            except Exception:  # noqa: BLE001
                pass
            # Always return (False, None) — never intercept the reply pipeline
            return False, None

        # register_reply is the stable hook in pyautogen 0.2.x
        if hasattr(agent, "register_reply"):
            agent.register_reply(
                trigger=_AnyAgent,  # trigger on any sender
                reply_func=_logging_reply,
                position=0,
                config={"logger": self},
            )
            self._attached_agents.append(agent)

    def attach_all(self, groupchat_manager: Any) -> None:
        """Instrument all agents in an AutoGen GroupChatManager.

        Works with `autogen.GroupChatManager` from pyautogen 0.2.x.
        """
        # GroupChatManager has a .groupchat attribute with .agents
        groupchat = getattr(groupchat_manager, "groupchat", None)
        if groupchat is not None:
            agents = getattr(groupchat, "agents", []) or []
            for agent in agents:
                self.attach(agent)
        # Also attach to the manager itself
        self.attach(groupchat_manager)

    def log_conversation_end(self, turn_count: int = 0, reason: str = "") -> None:
        """Manually emit a conversation_end event."""
        try:
            _emit(self._producer, {
                "event": "conversation_end",
                "conversation_id": self._conversation_id,
                "turn_count": turn_count,
                "termination_reason": reason,
            })
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_message(
        self,
        sender_name: str,
        recipient_name: str,
        message: dict[str, Any],
    ) -> None:
        """Emit a message event for the given message dict."""
        content = message.get("content", "") or ""
        role = message.get("role", "user")

        # Check for function_call inside the message (OpenAI-style)
        function_call = message.get("function_call")
        tool_calls = message.get("tool_calls")

        raw: dict[str, Any] = {
            "event": "message",
            "conversation_id": self._conversation_id,
            "sender_name": sender_name,
            "recipient_name": recipient_name,
            "role": role,
            "content": content,
            "message_index": self._message_index,
            "function_call": bool(function_call or tool_calls),
        }
        self._message_index += 1
        _emit(self._producer, raw)

        # Emit function_call events separately
        if function_call:
            self._emit_function_call(function_call)
        elif tool_calls:
            for tc in (tool_calls if isinstance(tool_calls, list) else [tool_calls]):
                fn = _extract_tool_call(tc)
                if fn:
                    self._emit_function_call(fn)

    def _emit_function_call(self, function_call: Any) -> None:
        """Emit a function_call event."""
        if isinstance(function_call, dict):
            name = function_call.get("name", "")
            args = str(function_call.get("arguments", ""))
        else:
            name = getattr(function_call, "name", "")
            args = str(getattr(function_call, "arguments", ""))

        _emit(self._producer, {
            "event": "function_call",
            "conversation_id": self._conversation_id,
            "function_name": name,
            "function_args": args,
        })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AnyAgent:
    """Sentinel class used as trigger=_AnyAgent to match any sender type."""
    pass


def _get_agent_name(agent: Any) -> str:
    """Extract agent name safely."""
    if agent is None:
        return "unknown"
    name = getattr(agent, "name", None)
    if name:
        return str(name)
    return type(agent).__name__


def _extract_tool_call(tc: Any) -> dict[str, Any] | None:
    """Extract function info from an OpenAI-style tool_call object."""
    if isinstance(tc, dict):
        func = tc.get("function", {})
        return {
            "name": func.get("name", ""),
            "arguments": func.get("arguments", ""),
        }
    fn = getattr(tc, "function", None)
    if fn:
        return {
            "name": getattr(fn, "name", ""),
            "arguments": getattr(fn, "arguments", ""),
        }
    return None
