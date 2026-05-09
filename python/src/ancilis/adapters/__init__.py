"""Framework and provider adapters for Ancilis action production."""

from ancilis.adapters.anthropic import (
    AnthropicActionProducer,
    AnthropicAdapter,
    AnthropicInvocation,
    AnthropicObservation,
)
from ancilis.adapters.openai_assistants import (
    OpenAIAssistantsActionProducer,
    OpenAIAssistantsAdapter,
    OpenAIAssistantsInvocation,
    OpenAIAssistantsObservation,
)
from ancilis.adapters.openai_realtime import (
    OpenAIRealtimeActionProducer,
    OpenAIRealtimeAdapter,
    OpenAIRealtimeInvocation,
    OpenAIRealtimeObservation,
)
from ancilis.adapters.bedrock import (
    BedrockActionProducer,
    BedrockAdapter,
    BedrockInvocation,
    BedrockObservation,
)
from ancilis.adapters.azure_openai import (
    AzureOpenAIActionProducer,
    AzureOpenAIAdapter,
    AzureOpenAIInvocation,
    AzureOpenAIObservation,
)
from ancilis.adapters.cloudflare_workers_ai import (
    CloudflareWorkersAIActionProducer,
    CloudflareWorkersAIAdapter,
    CloudflareWorkersAIInvocation,
    CloudflareWorkersAIObservation,
)
from ancilis.adapters.vertex_ai import (
    VertexAIActionProducer,
    VertexAIAdapter,
    VertexAIInvocation,
    VertexAIObservation,
)
from ancilis.adapters.replicate import (
    ReplicateActionProducer,
    ReplicateAdapter,
    ReplicateInvocation,
    ReplicateObservation,
)

__all__ = [
    "AnthropicActionProducer",
    "AnthropicAdapter",
    "AnthropicInvocation",
    "AnthropicObservation",
    "OpenAIAssistantsActionProducer",
    "OpenAIAssistantsAdapter",
    "OpenAIAssistantsInvocation",
    "OpenAIAssistantsObservation",
    "OpenAIRealtimeActionProducer",
    "OpenAIRealtimeAdapter",
    "OpenAIRealtimeInvocation",
    "OpenAIRealtimeObservation",
    "BedrockActionProducer",
    "BedrockAdapter",
    "BedrockInvocation",
    "BedrockObservation",
    "AzureOpenAIActionProducer",
    "AzureOpenAIAdapter",
    "AzureOpenAIInvocation",
    "AzureOpenAIObservation",
    "CloudflareWorkersAIActionProducer",
    "CloudflareWorkersAIAdapter",
    "CloudflareWorkersAIInvocation",
    "CloudflareWorkersAIObservation",
    "VertexAIActionProducer",
    "VertexAIAdapter",
    "VertexAIInvocation",
    "VertexAIObservation",
    "ReplicateActionProducer",
    "ReplicateAdapter",
    "ReplicateInvocation",
    "ReplicateObservation",
]
