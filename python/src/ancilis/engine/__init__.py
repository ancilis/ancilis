"""Control evaluation engine (Unit 2)."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
    from ancilis.engine.engine import Engine
    from ancilis.engine.registry import ToolEntry, ToolRegistry
    from ancilis.engine.result import ControlResult, EvaluationResult


_EXPORTS: dict[str, tuple[str, str]] = {
    "Action": ("ancilis.engine.action", "Action"),
    "ActionContext": ("ancilis.engine.action", "ActionContext"),
    "ActionParameters": ("ancilis.engine.action", "ActionParameters"),
    "ControlResult": ("ancilis.engine.result", "ControlResult"),
    "Engine": ("ancilis.engine.engine", "Engine"),
    "EvaluationResult": ("ancilis.engine.result", "EvaluationResult"),
    "ToolEntry": ("ancilis.engine.registry", "ToolEntry"),
    "ToolInfo": ("ancilis.engine.action", "ToolInfo"),
    "ToolRegistry": ("ancilis.engine.registry", "ToolRegistry"),
}


def __getattr__(name: str) -> object:
    """Lazy import engine exports to avoid package-level import cycles."""
    if name in _EXPORTS:
        module_name, attr_name = _EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_EXPORTS)
