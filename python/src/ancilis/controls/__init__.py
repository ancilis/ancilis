"""Control evaluators (Unit 5)."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ancilis.controls.custom import (
        CustomControlDefinition,
        CustomControlEvaluator,
        clear_custom_controls,
        list_custom_controls,
        load_custom_controls_from_directory,
        register_control,
    )
    from ancilis.controls.de01_baseline import (
        BaselineWindow,
        DE01BaselineEvaluator,
        DeviationFlag,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "BaselineWindow": ("ancilis.controls.de01_baseline", "BaselineWindow"),
    "CustomControlDefinition": (
        "ancilis.controls.custom",
        "CustomControlDefinition",
    ),
    "CustomControlEvaluator": ("ancilis.controls.custom", "CustomControlEvaluator"),
    "DE01BaselineEvaluator": (
        "ancilis.controls.de01_baseline",
        "DE01BaselineEvaluator",
    ),
    "DeviationFlag": ("ancilis.controls.de01_baseline", "DeviationFlag"),
    "clear_custom_controls": ("ancilis.controls.custom", "clear_custom_controls"),
    "list_custom_controls": ("ancilis.controls.custom", "list_custom_controls"),
    "load_custom_controls_from_directory": (
        "ancilis.controls.custom",
        "load_custom_controls_from_directory",
    ),
    "register_control": ("ancilis.controls.custom", "register_control"),
}


def __getattr__(name: str) -> object:
    """Lazy import control exports to avoid engine/control import cycles."""
    if name in _EXPORTS:
        module_name, attr_name = _EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_EXPORTS)
