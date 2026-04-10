"""Ancilis — runtime policy enforcement for AI agents."""

from ancilis.baselines import BaselineManager, DriftReport
from ancilis.config import load_config
from ancilis.deps.scanner import DependencyScanner
from ancilis.evidence import EvidenceRecord, EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.cli import CLIActionProducer, CLIExecutionResult, CLIInvocation
from ancilis.producers.tool import (
    BlockedActionError,
    ToolActionProducer,
    ToolExecutionResult,
    ToolInvocation,
    evaluate_and_execute,
    tool,
    wrap_tool,
)
from ancilis.producers.http import (
    HTTPActionProducer,
    HTTPExecutionResult,
    HTTPObservation,
    HTTPRequest,
)


def __getattr__(name: str) -> object:
    """Lazy import for MCP-dependent types to avoid hard mcp dependency at import time."""
    if name == "AncilisMiddleware":
        from ancilis.middleware.middleware import AncilisMiddleware

        return AncilisMiddleware
    if name == "MCPActionProducer":
        from ancilis.producers.mcp import MCPActionProducer

        return MCPActionProducer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ActionProducer",
    "AncilisMiddleware",
    "BaselineManager",
    "BlockedActionError",
    "DependencyScanner",
    "DriftReport",
    "CLIActionProducer",
    "CLIExecutionResult",
    "CLIInvocation",
    "EvidenceRecord",
    "EvidenceStore",
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
    "load_config",
    "tool",
    "wrap_tool",
]
