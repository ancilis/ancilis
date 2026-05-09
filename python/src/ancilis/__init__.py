"""Ancilis — runtime policy enforcement for AI agents."""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ancilis.adapters.azure_openai import (
        AzureOpenAIActionProducer,
        AzureOpenAIAdapter,
        AzureOpenAIInvocation,
        AzureOpenAIObservation,
    )
    from ancilis.adapters.bedrock import (
        BedrockActionProducer,
        BedrockAdapter,
        BedrockInvocation,
        BedrockObservation,
    )
    from ancilis.adapters.vertex_ai import (
        VertexAIActionProducer,
        VertexAIAdapter,
        VertexAIInvocation,
        VertexAIObservation,
    )
    from ancilis.baselines import BaselineManager, DriftReport
    from ancilis.config import load_config
    from ancilis.controls.custom import CustomControlDefinition, register_control
    from ancilis.deps.scanner import DependencyScanner
    from ancilis.evidence import (
        EvidenceAdapter,
        EvidenceAdapterExport,
        EvidenceAdapterPayload,
        EvidenceAdapterQuery,
        EvidenceAdapterSelection,
        EvidenceRecord,
        EvidenceStore,
        SyncEngine,
        SyncResult,
        resolve_evidence_adapter,
    )
    from ancilis.platform import PlatformClient
    from ancilis.telemetry import (
        TelemetryConfig,
        TelemetryStatus,
        flush_telemetry_events,
        format_telemetry_status,
        read_telemetry_config,
        read_telemetry_status,
        record_adapter_used,
        record_telemetry_event,
        set_telemetry_enabled,
    )
    from ancilis.remediation import (
        RemediationGuide,
        RemediationRecommendation,
        build_remediation_recommendations,
        load_remediation_guides,
        render_remediation_recommendations,
    )
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
        RuntimeProducerSelection as RuntimeProducerSelection,
        resolve_runtime_producers as resolve_runtime_producers,
        translate_runtime_action as translate_runtime_action,
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
    "AzureOpenAIActionProducer": ("ancilis.adapters.azure_openai", "AzureOpenAIActionProducer"),
    "AzureOpenAIAdapter": ("ancilis.adapters.azure_openai", "AzureOpenAIAdapter"),
    "AzureOpenAIInvocation": ("ancilis.adapters.azure_openai", "AzureOpenAIInvocation"),
    "AzureOpenAIObservation": ("ancilis.adapters.azure_openai", "AzureOpenAIObservation"),
    "BaselineManager": ("ancilis.baselines", "BaselineManager"),
    "BedrockActionProducer": ("ancilis.adapters.bedrock", "BedrockActionProducer"),
    "BedrockAdapter": ("ancilis.adapters.bedrock", "BedrockAdapter"),
    "BedrockInvocation": ("ancilis.adapters.bedrock", "BedrockInvocation"),
    "BedrockObservation": ("ancilis.adapters.bedrock", "BedrockObservation"),
    "VertexAIActionProducer": ("ancilis.adapters.vertex_ai", "VertexAIActionProducer"),
    "VertexAIAdapter": ("ancilis.adapters.vertex_ai", "VertexAIAdapter"),
    "VertexAIInvocation": ("ancilis.adapters.vertex_ai", "VertexAIInvocation"),
    "VertexAIObservation": ("ancilis.adapters.vertex_ai", "VertexAIObservation"),
    "BlockedActionError": ("ancilis.producers.tool", "BlockedActionError"),
    "DependencyScanner": ("ancilis.deps.scanner", "DependencyScanner"),
    "DriftReport": ("ancilis.baselines", "DriftReport"),
    "CustomControlDefinition": ("ancilis.controls.custom", "CustomControlDefinition"),
    "EvidenceAdapter": ("ancilis.evidence", "EvidenceAdapter"),
    "EvidenceAdapterExport": ("ancilis.evidence", "EvidenceAdapterExport"),
    "EvidenceAdapterPayload": ("ancilis.evidence", "EvidenceAdapterPayload"),
    "EvidenceAdapterQuery": ("ancilis.evidence", "EvidenceAdapterQuery"),
    "EvidenceAdapterSelection": ("ancilis.evidence", "EvidenceAdapterSelection"),
    "CLIActionProducer": ("ancilis.producers.cli", "CLIActionProducer"),
    "CLIExecutionResult": ("ancilis.producers.cli", "CLIExecutionResult"),
    "CLIInvocation": ("ancilis.producers.cli", "CLIInvocation"),
    "EvidenceRecord": ("ancilis.evidence", "EvidenceRecord"),
    "EvidenceStore": ("ancilis.evidence", "EvidenceStore"),
    "SyncEngine": ("ancilis.evidence", "SyncEngine"),
    "SyncResult": ("ancilis.evidence", "SyncResult"),
    "HTTPActionProducer": ("ancilis.producers.http", "HTTPActionProducer"),
    "HTTPExecutionResult": ("ancilis.producers.http", "HTTPExecutionResult"),
    "HTTPObservation": ("ancilis.producers.http", "HTTPObservation"),
    "HTTPRequest": ("ancilis.producers.http", "HTTPRequest"),
    "MCPActionProducer": ("ancilis.producers.mcp", "MCPActionProducer"),
    "ProducerType": ("ancilis.producers.protocol", "ProducerType"),
    "PlatformClient": ("ancilis.platform", "PlatformClient"),
    "TelemetryConfig": ("ancilis.telemetry", "TelemetryConfig"),
    "TelemetryStatus": ("ancilis.telemetry", "TelemetryStatus"),
    "RemediationGuide": ("ancilis.remediation", "RemediationGuide"),
    "RemediationRecommendation": ("ancilis.remediation", "RemediationRecommendation"),
    "RuntimeProducerSelection": ("ancilis.producers.runtime", "RuntimeProducerSelection"),
    "ToolActionProducer": ("ancilis.producers.tool", "ToolActionProducer"),
    "ToolExecutionResult": ("ancilis.producers.tool", "ToolExecutionResult"),
    "ToolInvocation": ("ancilis.producers.tool", "ToolInvocation"),
    "build_remediation_recommendations": ("ancilis.remediation", "build_remediation_recommendations"),
    "evaluate_and_execute": ("ancilis.producers.tool", "evaluate_and_execute"),
    "flush_telemetry_events": ("ancilis.telemetry", "flush_telemetry_events"),
    "format_telemetry_status": ("ancilis.telemetry", "format_telemetry_status"),
    "load_config": ("ancilis.config", "load_config"),
    "read_telemetry_config": ("ancilis.telemetry", "read_telemetry_config"),
    "read_telemetry_status": ("ancilis.telemetry", "read_telemetry_status"),
    "record_adapter_used": ("ancilis.telemetry", "record_adapter_used"),
    "record_telemetry_event": ("ancilis.telemetry", "record_telemetry_event"),
    "register_control": ("ancilis.controls.custom", "register_control"),
    "resolve_evidence_adapter": ("ancilis.evidence", "resolve_evidence_adapter"),
    "resolve_runtime_producers": ("ancilis.producers.runtime", "resolve_runtime_producers"),
    "set_telemetry_enabled": ("ancilis.telemetry", "set_telemetry_enabled"),
    "load_remediation_guides": ("ancilis.remediation", "load_remediation_guides"),
    "render_remediation_recommendations": ("ancilis.remediation", "render_remediation_recommendations"),
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
