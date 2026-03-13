"""Ancilis — runtime policy enforcement for AI agents."""

from ancilis.config import load_config
from ancilis.evidence import EvidenceRecord, EvidenceStore
from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.cli import CLIActionProducer, CLIExecutionResult, CLIInvocation


def __getattr__(name: str):
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
    "CLIActionProducer",
    "CLIExecutionResult",
    "CLIInvocation",
    "EvidenceRecord",
    "EvidenceStore",
    "MCPActionProducer",
    "ProducerType",
    "load_config",
]
