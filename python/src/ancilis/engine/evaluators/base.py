"""Base interface for control evaluators."""

from __future__ import annotations

from typing import Protocol

from ancilis.config import ResolvedConfig
from ancilis.engine.action import Action
from ancilis.engine.result import ControlResult


class ControlEvaluator(Protocol):
    """Interface all control evaluators implement."""

    control_id: str
    control_name: str

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult: ...
