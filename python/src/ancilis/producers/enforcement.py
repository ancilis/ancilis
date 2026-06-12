"""Enforcement-capability declarations for action producers.

Whether a producer can actually *block* a tool call (versus only observe and
record it) is an honesty-critical property: ``security.mode: enforce`` only
prevents an action on an enforce-capable surface. Framework callback/observer
hooks fire *around* execution and cannot stop it, so declaring ``enforce`` on
one of those producers gives a false sense of protection.

Each producer carries an ``ENFORCEMENT`` class attribute set to one of the
constants below, and observe-only producers warn at construction when built
under ``security.mode == "enforce"``.
"""

from __future__ import annotations

import warnings
from typing import Any

# Intercepts the call and raises BlockedActionError before the action runs.
ENFORCE_CAPABLE = "enforce-capable"
# Blocks only when the producer is explicitly constructed with enforce=True.
OPT_IN = "opt-in"
# Records evidence and surfaces decisions but can never block.
OBSERVE_ONLY = "observe-only"


def warn_if_enforce_unsupported(
    producer_name: str, enforcement: str, config: Any
) -> None:
    """Warn when ``security.mode == "enforce"`` is set on an observe-only producer.

    No-op for enforce-capable and opt-in producers.
    """
    if enforcement == OBSERVE_ONLY and getattr(config, "mode", None) == "enforce":
        warnings.warn(
            f"{producer_name} is observe-only: it records evidence but cannot "
            f"block tool calls, so security.mode='enforce' will not prevent any "
            f"action through this producer. Use an enforce-capable producer "
            f"(MCP middleware, CLI, ToolActionProducer, or the Semantic Kernel "
            f"filter) where blocking is required.",
            stacklevel=3,
        )
