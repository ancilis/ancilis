"""Ancilis — runtime policy enforcement for AI agents."""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ancilis.adapters.bedrock import (
        BedrockActionProducer,
        BedrockAdapter,
        BedrockInvocation,
        BedrockObservation,
    )
    from ancilis.baselines import BaselineManager, DriftReport
    from ancilis.config import load_config
    from ancilis.deps.scanner import DependencyScanner
    from ancilis.evidence import EvidenceRecord, EvidenceStore
    from ancilis.middleware.middleware import AncilisMiddleware
    from ancilis.producers.cli import CLIActionProducer, CLIExecutionResult, CLIInvocation
    from ancilis.producers.http import (
        HTTPActionProducer,
        HTTPExecutionResult,
        HTTPObservation,
        HTTPRequest,
    )
    from ancilis.producers.mcp import MCPActionProducer
    from ancilis.producers.protocol import ActionProducer, ProducerType
    from ancilis.producers.runtime import (
        RuntimeProducerSelection,
        resolve_runtime_producers,
        translate_runtime_action,
    )
    from ancilis.producers.tool import (
        BlockedActionError,
        ToolActionProducer,
        ToolExecutionResult,
        ToolInvocation,
        evaluate_and_execute,
        tool,
        wrap_tool,
    )

try:
    __version__ = _pkg_version("ancilis")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

_EXPORTS: dict[str, tuple[str, str]] = {
    "ActionProducer": ("ancilis.producers.protocol", "ActionProducer"),
    "AncilisMiddleware": ("ancilis.middleware.middleware", "AncilisMiddleware"),
    "BaselineManager": ("ancilis.baselines", "BaselineManager"),
    "BedrockActionProducer": ("ancilis.adapters.bedrock", "BedrockActionProducer"),
    "BedrockAdapter": ("ancilis.adapters.bedrock", "BedrockAdapter"),
    "BedrockInvocation": ("ancilis.adapters.bedrock", "BedrockInvocation"),
    "BedrockObservation": ("ancilis.adapters.bedrock", "BedrockObservation"),
    "BlockedActionError": ("ancilis.producers.tool", "BlockedActionError"),
    "DependencyScanner": ("ancilis.deps.scanner", "DependencyScanner"),
    "DriftReport": ("ancilis.baselines", "DriftReport"),
    "CLIActionProducer": ("ancilis.producers.cli", "CLIActionProducer"),
    "CLIExecutionResult": ("ancilis.producers.cli", "CLIExecutionResult"),
    "CLIInvocation": ("ancilis.producers.cli", "CLIInvocation"),
    "EvidenceRecord": ("ancilis.evidence", "EvidenceRecord"),
    "EvidenceStore": ("ancilis.evidence", "EvidenceStore"),
    "HTTPActionProducer": ("ancilis.producers.http", "HTTPActionProducer"),
    "HTTPExecutionResult": ("ancilis.producers.http", "HTTPExecutionResult"),
    "HTTPObservation": ("ancilis.producers.http", "HTTPObservation"),
    "HTTPRequest": ("ancilis.producers.http", "HTTPRequest"),
    "MCPActionProducer": ("ancilis.producers.mcp", "MCPActionProducer"),
    "ProducerType": ("ancilis.producers.protocol", "ProducerType"),
    "RuntimeProducerSelection": ("ancilis.producers.runtime", "RuntimeProducerSelection"),
    "ToolActionProducer": ("ancilis.producers.tool", "ToolActionProducer"),
    "ToolExecutionResult": ("ancilis.producers.tool", "ToolExecutionResult"),
    "ToolInvocation": ("ancilis.producers.tool", "ToolInvocation"),
    "evaluate_and_execute": ("ancilis.producers.tool", "evaluate_and_execute"),
    "load_config": ("ancilis.config", "load_config"),
    "resolve_runtime_producers": ("ancilis.producers.runtime", "resolve_runtime_producers"),
    "tool": ("ancilis.producers.tool", "tool"),
    "translate_runtime_action": ("ancilis.producers.runtime", "translate_runtime_action"),
    "wrap_tool": ("ancilis.producers.tool", "wrap_tool"),
}


def __getattr__(name: str) -> object:
    """Lazy import public re-exports to keep package import side effects minimal."""
    if name in _EXPORTS:
        module_name, attr_name = _EXPORTS[name]
        value = getattr(import_module(module_name), attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_EXPORTS)
