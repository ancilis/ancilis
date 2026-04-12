"""OpenAIProducer — translates raw OpenAI API payloads into Ancilis Action objects."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


class OpenAIProducer:
    """Translates raw OpenAI API request/response dicts into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(self, agent_id: str = "openai-agent", session_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw OpenAI event dict into an Action.

        Expected keys:
          - event: "request" | "response" | "stream_complete"
          - model: str
          - request: dict (the raw request kwargs)
          - response: dict (the raw response body, may be None for "request" events)
          - error: str (for error events)
        """
        event = raw.get("event", "request")
        model = raw.get("model", "unknown")
        request = raw.get("request", {}) or {}
        response = raw.get("response", {}) or {}

        params = _build_params(raw, event, model, request, response)
        param_hash = hashlib.sha256(str(sorted(str(params).encode())).encode()).hexdigest()[:16]
        desc_hash = hashlib.sha256(f"openai:{model}".encode()).hexdigest()[:16]

        action_id = raw.get("request_id") or f"oai-{int(time.time() * 1000)}"

        return Action(
            action_id=action_id,
            timestamp=_iso_now(),
            agent_id=self.agent_id,
            action_type="tool_call",
            tool=ToolInfo(
                name=model,
                version=None,
                server="openai",
                description_hash=desc_hash,
            ),
            parameters=ActionParameters(raw=params, parameter_hash=param_hash),
            context=ActionContext(session_id=self.session_id),
            source_type="agent",
            producer_type="framework",
            producer_version=self.producer_version,
        )


def _build_params(
    raw: dict[str, Any],
    event: str,
    model: str,
    request: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "event": event,
        "gen_ai.system": "openai",
        "gen_ai.request.model": model,
    }

    # Request fields
    messages = request.get("messages", []) or []
    params["message_count"] = len(messages)
    params["has_tools"] = bool(request.get("tools") or request.get("functions"))
    params["stream"] = bool(request.get("stream", False))
    if "temperature" in request:
        params["temperature"] = request["temperature"]
    if "max_tokens" in request:
        params["max_tokens"] = request["max_tokens"]

    if event in ("response", "stream_complete"):
        # Token usage
        usage = response.get("usage", {}) or {}
        if usage:
            params["prompt_tokens"] = usage.get("prompt_tokens", 0)
            params["completion_tokens"] = usage.get("completion_tokens", 0)
            params["total_tokens"] = usage.get("total_tokens", 0)

        choices = response.get("choices", []) or []
        params["choice_count"] = len(choices)

        if choices:
            first_choice = choices[0]
            message = first_choice.get("message", {}) or {}
            tool_calls = message.get("tool_calls", []) or []
            params["tool_call_count"] = len(tool_calls)
            if tool_calls:
                params["tool_names_called"] = [
                    tc.get("function", {}).get("name", "") for tc in tool_calls
                ]
            finish_reason = first_choice.get("finish_reason")
            if finish_reason:
                params["finish_reason"] = finish_reason
            # Output length (not content)
            content = message.get("content", "")
            params["output_length"] = len(content) if content else 0

        response_model = response.get("model", "")
        if response_model:
            params["response_model"] = response_model

    elif event == "error":
        params["error"] = raw.get("error", "")

    return params


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
