"""Action Object Producer Protocol (ADR-005)."""

from ancilis.producers.protocol import ActionProducer, ProducerType
from ancilis.producers.cli import CLIActionProducer, CLIExecutionResult, CLIInvocation
from ancilis.producers.mcp import MCPActionProducer

__all__ = [
    "ActionProducer",
    "CLIActionProducer",
    "CLIExecutionResult",
    "CLIInvocation",
    "MCPActionProducer",
    "ProducerType",
]
