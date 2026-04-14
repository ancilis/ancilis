"""@ancilis_crew — class decorator for zero-config CrewAI evidence capture."""

from __future__ import annotations

from typing import Any, Type

from ancilis_crewai._producer import CrewAIProducer
from ancilis_crewai.callbacks import _wrap_crew


def ancilis_crew(
    cls: Type[Any] | None = None,
    *,
    agent_id: str = "crewai-agent",
    session_id: str | None = None,
) -> Any:
    """Decorate a Crew subclass to capture execution evidence automatically.

    Usage (simple)::

        from ancilis_crewai import ancilis_crew
        from crewai import Crew, Agent, Task

        @ancilis_crew
        class MyCrew(Crew):
            ...

    Usage (with options)::

        @ancilis_crew(agent_id="my-pipeline", session_id="run-42")
        class MyCrew(Crew):
            ...

    The decorator wraps ``kickoff()`` / ``kickoff_async()`` and each agent's
    ``execute_task()`` to emit Ancilis evidence for:

    - crew_start / crew_end (agent/task counts, output length)
    - task_start / task_end (per agent, task description + output length)

    Original behavior is preserved — the decorator is transparent.
    """
    def _decorate(klass: Type[Any]) -> Type[Any]:
        producer = CrewAIProducer(agent_id=agent_id, session_id=session_id)

        original_init = klass.__init__

        @_wrap_functools(original_init)
        def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
            original_init(self, *args, **kwargs)
            _wrap_crew(self, producer)

        klass.__init__ = patched_init
        return klass

    if cls is not None:
        # Called as @ancilis_crew (no parentheses)
        return _decorate(cls)

    # Called as @ancilis_crew(...) — return the actual decorator
    return _decorate


def _wrap_functools(original: Any) -> Any:
    """functools.wraps-style helper that handles __init__ (returns None)."""
    import functools
    return functools.wraps(original)
