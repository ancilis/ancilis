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
    "ToolActionProducer",
    "ToolExecutionResult",
    "ToolInvocation",
    "evaluate_and_execute",
    "tool",
    "wrap_tool",
]


def __getattr__(name: str) -> object:
    if name == "MCPActionProducer":
        from ancilis.producers.mcp import MCPActionProducer

        return MCPActionProducer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
