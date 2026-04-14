"""CrewAIProducer — translates raw CrewAI execution data into Ancilis Action objects."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo


class CrewAIProducer:
    """Translates raw CrewAI event dicts into Ancilis Action objects."""

    producer_type = "framework"
    producer_version = "0.1.0"

    def __init__(self, agent_id: str = "crewai-agent", session_id: str | None = None) -> None:
        self.agent_id = agent_id
        self.session_id = session_id

    def translate(self, raw: dict[str, Any]) -> Action:
        """Convert a raw CrewAI event dict into an Action.

        Expected keys:
          - event: "crew_start" | "crew_end" | "task_start" | "task_end" |
                   "agent_action" | "tool_use" | "delegation"
          - crew_name: str
          - agent_role: str (where applicable)
          - task_description: str (where applicable)
          - output: str (where applicable, task_end only — stored as length)
          - tool_name: str (tool_use / agent_action)
          - tool_input: str (tool_use — stored truncated)
          - from_agent: str (delegation)
          - to_agent: str (delegation)
          - execution_id: str  (correlation id for the crew run)
        """
        event = raw.get("event", "unknown")
        execution_id = str(raw.get("execution_id", "")) or f"crew-{int(time.time() * 1000)}"

        tool_name, action_type, desc = _classify_event(event, raw)
        params = _build_params(raw, event)
        param_hash = hashlib.sha256(str(sorted(params.items())).encode()).hexdigest()[:16]
        desc_hash = hashlib.sha256(desc.encode()).hexdigest()[:16]

        return Action(
            action_id=execution_id,
            timestamp=_iso_now(),
            agent_id=self.agent_id,
            action_type=action_type,
            tool=ToolInfo(
                name=tool_name,
                version=None,
                server="crewai",
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


def _classify_event(
    event: str, raw: dict[str, Any]
) -> tuple[str, str, str]:
    """Return (tool_name, action_type, desc_key) for the event."""
    crew_name = raw.get("crew_name", "crew")
    agent_role = raw.get("agent_role", "agent")
    tool_name_raw = raw.get("tool_name", "tool")

    if event in ("crew_start", "crew_end"):
        return crew_name, "tool_call", f"crew:{crew_name}"
    if event in ("task_start", "task_end"):
        return f"task:{agent_role}", "tool_call", f"task:{agent_role}"
    if event == "tool_use":
        return tool_name_raw, "tool_call", f"tool:{tool_name_raw}"
    if event == "agent_action":
        return f"agent:{agent_role}", "tool_call", f"agent:{agent_role}"
    if event == "delegation":
        from_agent = raw.get("from_agent", "unknown")
        to_agent = raw.get("to_agent", "unknown")
        return "delegation", "tool_call", f"delegation:{from_agent}->{to_agent}"
    return event, "tool_call", f"unknown:{event}"


def _build_params(raw: dict[str, Any], event: str) -> dict[str, Any]:
    params: dict[str, Any] = {"event": event}

    # Common fields
    for key in ("crew_name", "agent_role", "execution_id"):
        val = raw.get(key)
        if val is not None:
            params[key] = val

    if event == "crew_start":
        params["agent_count"] = raw.get("agent_count", 0)
        params["task_count"] = raw.get("task_count", 0)

    elif event == "crew_end":
        output = raw.get("output", "")
        params["output_length"] = len(str(output)) if output else 0
        params["agent_count"] = raw.get("agent_count", 0)
        params["task_count"] = raw.get("task_count", 0)

    elif event == "task_start":
        desc = raw.get("task_description", "")
        params["task_description_length"] = len(desc) if desc else 0
        params["expected_output_length"] = len(raw.get("expected_output", "") or "")

    elif event == "task_end":
        output = raw.get("output", "")
        params["output_length"] = len(str(output)) if output else 0
        desc = raw.get("task_description", "")
        params["task_description_length"] = len(desc) if desc else 0

    elif event == "tool_use":
        params["tool_name"] = raw.get("tool_name", "")
        # Truncate tool input to 512 chars — avoid capturing sensitive payloads
        tool_input = str(raw.get("tool_input", ""))
        params["tool_input_preview"] = tool_input[:512]
        params["tool_input_length"] = len(tool_input)

    elif event == "agent_action":
        params["thought_length"] = len(str(raw.get("thought", "") or ""))
        params["tool_name"] = raw.get("tool_name", "")

    elif event == "delegation":
        params["from_agent"] = raw.get("from_agent", "")
        params["to_agent"] = raw.get("to_agent", "")
        task_desc = raw.get("task_description", "")
        params["delegated_task_length"] = len(task_desc) if task_desc else 0

    return params


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
