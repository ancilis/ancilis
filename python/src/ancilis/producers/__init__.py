"""Producer implementations for Ancilis runtime integrations."""

from ancilis.producers.cli import CLIActionProducer, CLIExecutionResult, CLIInvocation
from ancilis.producers.http import HTTPActionProducer, HTTPExecutionResult, HTTPObservation, HTTPRequest
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.tool import (
    BlockedActionError,
    ToolActionProducer,
    ToolExecutionResult,
    ToolInvocation,
    evaluate_and_execute,
    tool,
    wrap_tool,
)

__all__ = [
    "ActionProducer",
    "BlockedActionError",
    "CLIActionProducer",
    "CLIExecutionResult",
    "CLIInvocation",
    "HTTPActionProducer",
    "HTTPExecutionResult",
    "HTTPObservation",
    "HTTPRequest",
    "MCPActionProducer",
    "ProducerType",
    "RuntimeProducerSelection",
    "ToolActionProducer",
    "ToolExecutionResult",
    "ToolInvocation",
    "evaluate_and_execute",
    "resolve_runtime_producers",
    "tool",
    "translate_runtime_action",
    "wrap_tool",
]


def __getattr__(name: str) -> object:
    if name == "MCPActionProducer":
        from ancilis.producers.mcp import MCPActionProducer

        return MCPActionProducer
    if name in {
        "RuntimeProducerSelection",
        "resolve_runtime_producers",
        "translate_runtime_action",
    }:
        from importlib import import_module

        runtime = import_module("ancilis.producers.runtime")
        return getattr(runtime, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
