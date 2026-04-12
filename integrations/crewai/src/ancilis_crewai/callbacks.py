"""AncilisCrewCallbacks — CrewAI callback hooks for zero-config evidence capture.

CrewAI (>=0.40) does not expose a stable first-class callback API at the Crew level,
so this module implements evidence capture via two complementary mechanisms:

1. **AncilisCrewCallbacks**: a callbacks dict you can pass to Crew(callbacks=...) in
   future CrewAI versions that support it, OR inject manually via _crew_callbacks.
2. **_wrap_crew**: low-level helper used by the @ancilis_crew decorator to intercept
   kickoff() / kickoff_async() and instrument agent step() methods.

All evidence paths go through CrewAIProducer.translate() → Ancilis engine.
"""

from __future__ import annotations

import functools
from typing import Any, Callable

from ancilis_crewai._producer import CrewAIProducer


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


def _emit(producer: CrewAIProducer, raw: dict[str, Any]) -> None:
    """Translate raw event dict and submit. Never raises."""
    try:
        action = producer.translate(raw)
        _safe_submit(action)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Crew-level wrappers (used by @ancilis_crew decorator)
# ---------------------------------------------------------------------------


def _wrap_crew(crew_instance: Any, producer: CrewAIProducer) -> Any:
    """Instrument a live Crew instance — wraps kickoff, kickoff_async, agents.

    This is non-destructive: original methods are stored and can be restored.
    CrewAI is not patched globally — only the single instance is affected.
    """
    crew_name = _get_crew_name(crew_instance)
    execution_id: list[str] = [""]  # mutable container for closure

    # --- instrument agents for step/tool interception ---
    _instrument_agents(crew_instance, producer, execution_id)

    # --- wrap kickoff (sync) ---
    original_kickoff = crew_instance.kickoff

    @functools.wraps(original_kickoff)
    def patched_kickoff(*args: Any, **kwargs: Any) -> Any:
        import uuid
        execution_id[0] = str(uuid.uuid4())[:8]

        agents = getattr(crew_instance, "agents", []) or []
        tasks = getattr(crew_instance, "tasks", []) or []

        try:
            _emit(producer, {
                "event": "crew_start",
                "crew_name": crew_name,
                "execution_id": execution_id[0],
                "agent_count": len(agents),
                "task_count": len(tasks),
            })
        except Exception:  # noqa: BLE001
            pass

        try:
            result = original_kickoff(*args, **kwargs)
        except Exception:
            raise
        else:
            output_str = str(result) if result is not None else ""
            try:
                _emit(producer, {
                    "event": "crew_end",
                    "crew_name": crew_name,
                    "execution_id": execution_id[0],
                    "output": output_str,
                    "agent_count": len(agents),
                    "task_count": len(tasks),
                })
            except Exception:  # noqa: BLE001
                pass
            return result

    crew_instance.kickoff = patched_kickoff

    # --- wrap kickoff_async (if present) ---
    if hasattr(crew_instance, "kickoff_async"):
        original_kickoff_async = crew_instance.kickoff_async

        @functools.wraps(original_kickoff_async)
        async def patched_kickoff_async(*args: Any, **kwargs: Any) -> Any:
            import uuid
            execution_id[0] = str(uuid.uuid4())[:8]

            agents = getattr(crew_instance, "agents", []) or []
            tasks = getattr(crew_instance, "tasks", []) or []

            try:
                _emit(producer, {
                    "event": "crew_start",
                    "crew_name": crew_name,
                    "execution_id": execution_id[0],
                    "agent_count": len(agents),
                    "task_count": len(tasks),
                })
            except Exception:  # noqa: BLE001
                pass

            try:
                result = await original_kickoff_async(*args, **kwargs)
            except Exception:
                raise
            else:
                output_str = str(result) if result is not None else ""
                try:
                    _emit(producer, {
                        "event": "crew_end",
                        "crew_name": crew_name,
                        "execution_id": execution_id[0],
                        "output": output_str,
                        "agent_count": len(agents),
                        "task_count": len(tasks),
                    })
                except Exception:  # noqa: BLE001
                    pass
                return result

        crew_instance.kickoff_async = patched_kickoff_async

    return crew_instance


def _instrument_agents(
    crew_instance: Any,
    producer: CrewAIProducer,
    execution_id: list[str],
) -> None:
    """Wrap each agent's execute_task to capture task start/end + tool usage."""
    agents = getattr(crew_instance, "agents", []) or []
    for agent in agents:
        _wrap_agent(agent, producer, execution_id)


def _wrap_agent(
    agent: Any,
    producer: CrewAIProducer,
    execution_id: list[str],
) -> None:
    """Wrap an agent's execute_task method to emit task_start / task_end events."""
    if not hasattr(agent, "execute_task"):
        return

    original_execute = agent.execute_task
    role = getattr(agent, "role", "agent")

    @functools.wraps(original_execute)
    def patched_execute(task: Any, *args: Any, **kwargs: Any) -> Any:
        task_desc = _get_task_description(task)
        expected_output = _get_expected_output(task)

        try:
            _emit(producer, {
                "event": "task_start",
                "crew_name": "",
                "agent_role": role,
                "execution_id": execution_id[0],
                "task_description": task_desc,
                "expected_output": expected_output,
            })
        except Exception:  # noqa: BLE001
            pass

        result = original_execute(task, *args, **kwargs)

        try:
            _emit(producer, {
                "event": "task_end",
                "crew_name": "",
                "agent_role": role,
                "execution_id": execution_id[0],
                "task_description": task_desc,
                "output": str(result) if result is not None else "",
            })
        except Exception:  # noqa: BLE001
            pass

        return result

    agent.execute_task = patched_execute


def _get_crew_name(crew_instance: Any) -> str:
    """Best-effort crew name extraction."""
    # CrewAI Crew objects don't have a .name attribute in all versions
    name = getattr(crew_instance, "name", None)
    if name:
        return str(name)
    return type(crew_instance).__name__


def _get_task_description(task: Any) -> str:
    """Extract task description safely."""
    desc = getattr(task, "description", None)
    return str(desc) if desc else ""


def _get_expected_output(task: Any) -> str:
    """Extract expected output safely."""
    exp = getattr(task, "expected_output", None)
    return str(exp) if exp else ""
