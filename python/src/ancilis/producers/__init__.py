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
    "AnthropicActionProducer",
    "AutoGenActionProducer",
    "AutoGenEvent",
    "AutoGenObservation",
    "BedrockActionProducer",
    "BedrockAdapter",
    "BedrockExecutionResult",
    "BedrockInvocation",
    "BedrockObservation",
    "BlockedActionError",
    "CLIActionProducer",
    "CLIExecutionResult",
    "CLIInvocation",
    "CrewAIActionProducer",
    "CrewAIEvent",
    "CrewAIObservation",
    "GeminiActionProducer",
    "HTTPActionProducer",
    "HTTPExecutionResult",
    "HTTPObservation",
    "HTTPRequest",
    "LangChainActionProducer",
    "LangChainCallbackHandler",
    "LangChainEvent",
    "LangChainObservation",
    "LLMActionProducer",
    "LLMExecutionResult",
    "LLMInvocation",
    "LLMObservation",
    "MCPActionProducer",
    "OpenAIActionProducer",
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


_LLM_EXPORTS = {
    "AnthropicActionProducer",
    "GeminiActionProducer",
    "LLMActionProducer",
    "LLMExecutionResult",
    "LLMInvocation",
    "LLMObservation",
    "OpenAIActionProducer",
}

_BEDROCK_EXPORTS = {
    "BedrockActionProducer",
    "BedrockAdapter",
    "BedrockExecutionResult",
    "BedrockInvocation",
    "BedrockObservation",
}

_LANGCHAIN_EXPORTS = {
    "LangChainActionProducer",
    "LangChainCallbackHandler",
    "LangChainEvent",
    "LangChainObservation",
}

_CREWAI_EXPORTS = {
    "CrewAIActionProducer",
    "CrewAIEvent",
    "CrewAIObservation",
}

_AUTOGEN_EXPORTS = {
    "AutoGenActionProducer",
    "AutoGenEvent",
    "AutoGenObservation",
}


def __getattr__(name: str) -> object:
    if name == "MCPActionProducer":
        from ancilis.producers.mcp import MCPActionProducer

        return MCPActionProducer
    if name in _LLM_EXPORTS:
        from importlib import import_module

        llm = import_module("ancilis.producers.llm")
        return getattr(llm, name)
    if name in _BEDROCK_EXPORTS:
        from importlib import import_module

        bedrock = import_module("ancilis.producers.bedrock")
        return getattr(bedrock, name)
    if name in _LANGCHAIN_EXPORTS:
        from importlib import import_module

        langchain = import_module("ancilis.producers.langchain")
        return getattr(langchain, name)
    if name in _CREWAI_EXPORTS:
        from importlib import import_module

        crewai = import_module("ancilis.producers.crewai")
        return getattr(crewai, name)
    if name in _AUTOGEN_EXPORTS:
        from importlib import import_module

        autogen = import_module("ancilis.producers.autogen")
        return getattr(autogen, name)
    if name in {
        "RuntimeProducerSelection",
        "resolve_runtime_producers",
        "translate_runtime_action",
    }:
        from importlib import import_module

        runtime = import_module("ancilis.producers.runtime")
        return getattr(runtime, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
