# Producers

Producers translate protocol-specific invocations into Action objects that the engine evaluates. The engine doesn't know or care about the source — it evaluates Actions the same way regardless of where they came from.

## Available producers

| Producer | Source | Use when |
|----------|--------|----------|
| `ToolActionProducer` | Python functions | Wrapping your own tool definitions |
| `AncilisMiddleware` | MCP client sessions | Wrapping MCP tool calls |
| `CLIActionProducer` | Shell commands | Wrapping subprocess execution |
| `HTTPActionProducer` | HTTP requests | Wrapping explicit HTTP/API calls |
| `BedrockActionProducer` | AWS Bedrock Runtime envelopes | Normalizing boto3-style Bedrock calls |
| `AnthropicActionProducer` | Anthropic SDK | Wrapping `messages.create` calls |
| `OpenAIActionProducer` | OpenAI SDK | Wrapping `chat.completions.create` and `responses.create` |
| `GeminiActionProducer` | Google `google-genai` SDK | Wrapping `generate_content` |
| `MistralActionProducer` | Mistral La Plateforme SDK | Wrapping `chat.complete` |
| `CohereActionProducer` | Cohere SDK | Wrapping `chat` (folds `message`/`chat_history`/`preamble`) |
| `XAIActionProducer` | xAI Grok (OpenAI-compatible) | Wrapping Grok chat calls |
| `GroqActionProducer` | Groq (OpenAI-compatible) | Wrapping Groq chat calls |
| `TogetherActionProducer` | Together AI (OpenAI-compatible) | Wrapping Together chat calls |
| `FireworksActionProducer` | Fireworks AI (OpenAI-compatible) | Wrapping Fireworks chat calls |
| `DeepSeekActionProducer` | DeepSeek (OpenAI-compatible) | Wrapping DeepSeek chat calls |
| `LangChainCallbackHandler` | LangChain / LangGraph | Drop-in `BaseCallbackHandler` for any Runnable/Chain/LLM |
| `CrewAIActionProducer` | CrewAI | `step_callback` / `task_callback` / crew-level callbacks |
| `AutoGenActionProducer` | AutoGen / AG2 | `process_message_before_send` + `process_last_received_message` hooks |
| `SemanticKernelActionProducer` | Microsoft Semantic Kernel | `function_invocation` / `prompt_rendering` / `auto_function_invocation` filters |
| `auto_register(config, engine)` | Any installed SDK with a detector slug | Auto-detect and instantiate one producer per detected SDK (xAI/DeepSeek and other OpenAI-compatible subclasses are not auto-detected — instantiate manually) |

All producers are duck-typed against their upstream SDKs — no hard import dependency. Tool-name convention is stable: `llm:{provider}:{model}` for direct LLM SDKs, `aws-bedrock:{operation}` for Bedrock, `{framework}:{kind}:{name}` for framework producers. Allowlists in `ancilis.yaml` reference these names directly.

## ToolActionProducer

The simplest integration path. Wraps plain Python functions with evaluation and evidence recording.

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = ToolActionProducer(config=config, engine=engine)
```

### Decorator mode

```python
def my_tool(arg: str) -> str:
    return f"result: {arg}"

# Wrap with evaluation
my_tool = producer.wrap_tool(my_tool, tool_name="my_tool")

# Use normally — evaluation is transparent
result = my_tool("hello")
```

### Explicit evaluate mode

When a framework owns tool registration and you can't use decorators:

```python
action, evaluation = producer.evaluate(
    my_tool,
    agent_name="my-agent",
    tool_name="my_tool",
    args=("hello",),
)
print(evaluation.decision)  # "ALLOW" or "BLOCK"
```

### Execute mode

Evaluate and execute in one call:

```python
from ancilis import BlockedActionError

try:
    result = producer.execute(
        my_tool,
        agent_name="my-agent",
        tool_name="my_tool",
        args=("hello",),
    )
    print(result.return_value)
except BlockedActionError as e:
    print(e.display_message)
```

### Tool naming

By default, `wrap_tool` generates names like `tool:module.function_name`. To match tools in your config's `security.tools.allowed` list, pass `tool_name` explicitly:

```python
# Config has: security.tools.allowed: [search_docs]
# This matches:
search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")
```

No dependencies beyond `pip install ancilis`.

## AncilisMiddleware (MCP)

Wraps an MCP `ClientSession` to intercept every `call_tool` invocation.

```python
from ancilis import AncilisMiddleware

middleware = AncilisMiddleware(session, config_path="ancilis.yaml")

# Auto-discover tools from the MCP server
await middleware.list_tools()

# Tool calls are intercepted, evaluated, and forwarded
result = await middleware.call_tool("get-status", {"subsystem": "all"})

# Summary line for your agent framework
print(middleware.get_summary_line())
# "Ancilis: 1 tool calls evaluated. 0 issues. Run `ancilis status` for details."
```

In enforce mode, unauthorized tool calls raise `BlockedToolCallError` before reaching the MCP server.

Requires `pip install "ancilis[mcp]"`.

See [examples/mcp-middleware/](../examples/mcp-middleware/) for a full walkthrough.

## CLIActionProducer

Wraps subprocess execution with evaluation. Commands are evaluated against policy before the shell is invoked.

```python
from ancilis import CLIActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = CLIActionProducer(config=config, engine=engine)

# Register tools from config allowlist
producer.register_tools(engine.registry)

# Execute with evaluation
result = producer.execute(
    command=["echo", "hello"],
    agent_name="my-agent",
)
print(result.stdout)    # "hello\n"
print(result.blocked)   # False
print(result.evaluation.decision)  # "ALLOW"
```

Tool names are prefixed with `cli:` (e.g., `cli:echo`). The scope evaluator handles prefix matching — bare `echo` in your config matches `cli:echo` at runtime.

Blocked commands in enforce mode are never executed — the subprocess is never called.

See [examples/cli-agent/](../examples/cli-agent/) for a full walkthrough.

## HTTPActionProducer

Wraps outbound HTTP requests with evaluation. This is **explicit wrapping** — Ancilis does not monkey-patch any HTTP library.

### Observe mode (default)

Record and evaluate HTTP activity without blocking:

```python
from ancilis import HTTPActionProducer, HTTPRequest, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = HTTPActionProducer(config=config, engine=engine)

observation = producer.observe(
    HTTPRequest(
        method="POST",
        url="https://api.example.com/data",
        agent_name="my-agent",
    )
)
print(observation.evaluation.decision)  # "ALLOW"
```

### Transport wrapping

Wrap a transport function for pre-request evaluation:

```python
import requests

wrapped = producer.wrap_transport(
    requests.request,
    agent_name="my-agent",
    enforce=True,  # opt-in to blocking
)
result = wrapped("GET", "https://example.com/healthz")
print(result.evaluation.decision)
```

With `enforce=True`, requests that fail policy evaluation raise `BlockedActionError` before the HTTP call is made.

No dependencies beyond `pip install ancilis`. Works with any HTTP library (`requests`, `httpx`, `aiohttp`) — you pass the transport function.

## BedrockActionProducer

Normalizes AWS Bedrock Runtime invocation envelopes into framework-sourced Actions. The adapter accepts plain dictionaries or `BedrockInvocation` objects, so importing `ancilis` and constructing other SDK components does not require `boto3` or `botocore`.

```python
from ancilis import BedrockActionProducer, BedrockInvocation, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = BedrockActionProducer(config=config, engine=engine)

observation = producer.observe(
    BedrockInvocation(
        operation="InvokeModel",
        model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        region="us-east-1",
        response_body={"usage": {"input_tokens": 12, "output_tokens": 34}},
        request_id="req-123",
        latency_ms=87.5,
    )
)

print(observation.evaluation.decision)
```

The recorded Action includes provider, operation, model id, region, request id, latency, token counts when inferable, and deployment metadata for Bedrock model ids or inference-profile ARNs. Request bodies, response bodies, streamed text chunks, access keys, session tokens, authorization headers, signed headers, and canonical request material are not persisted in the Action payload.

## LLM SDK producers

Direct LLM provider producers wrap the SDK call surface so each invocation becomes an evaluated, evidence-recorded Action. Same shape as `HTTPActionProducer` (observe-first, optional enforce, `wrap_create()` helper).

```python
from anthropic import Anthropic
from ancilis.producers import AnthropicActionProducer
from ancilis import load_config
from ancilis.engine import Engine

config = load_config()
producer = AnthropicActionProducer(config=config, engine=Engine(config))
client = Anthropic()

# Wrap once; every call goes through evaluation
wrapped = producer.wrap_create(client.messages.create, agent_name="support-bot")
response = wrapped(model="claude-sonnet-4-6", messages=[{"role": "user", "content": "..."}])
```

Available subclasses (all importable from `ancilis.producers`):

- `AnthropicActionProducer` — `client.messages.create`
- `OpenAIActionProducer` — `client.chat.completions.create` and `client.responses.create` (the responses-API `input` field is normalized into the same `messages` shape)
- `GeminiActionProducer` — `client.models.generate_content` with `config={"system_instruction": ...}` extracted into `system`
- `MistralActionProducer` — Mistral La Plateforme SDK
- `CohereActionProducer` — Cohere SDK; `message` + `chat_history` + `preamble` fold into the unified messages list
- `XAIActionProducer` — xAI Grok (OpenAI-compatible)
- `GroqActionProducer`, `TogetherActionProducer`, `FireworksActionProducer`, `DeepSeekActionProducer` — OpenAI-compatible serverless inference platforms; thin subclasses that change only the provider slug

Tool name format: `llm:{provider}:{model}` (e.g. `llm:anthropic:claude-sonnet-4-6`, `llm:openai:gpt-4o`). Use these names in `ancilis.yaml` allowlists.

In `enforce` mode, calls to disallowed models raise `BlockedActionError` before the upstream SDK is invoked.

## Agent framework producers

Framework producers attach to the framework's existing callback / hook / filter pipeline so every step the framework executes becomes an Action. None require their upstream package to be installed at import time.

### LangChain / LangGraph

Drop-in `BaseCallbackHandler`-shaped handler. Pass into any Runnable, Chain, or LLM via `callbacks=[handler]`. Same handler covers LangGraph through the shared callback bus.

```python
from langchain_anthropic import ChatAnthropic
from ancilis.producers import LangChainActionProducer, LangChainCallbackHandler

producer = LangChainActionProducer(config=config, engine=engine)
handler = LangChainCallbackHandler(producer)
llm = ChatAnthropic(callbacks=[handler])
# Every llm/tool/chain start emits an Action
```

Tool name format: `langchain:{kind}:{name}` where kind is `llm` / `chat_model` / `tool` / `chain`.

### CrewAI

Three callback factories matching CrewAI's Agent / Task / Crew callback signatures.

```python
from crewai import Agent, Task, Crew
from ancilis.producers import CrewAIActionProducer

producer = CrewAIActionProducer(config=config, engine=engine)
agent = Agent(role="researcher", step_callback=producer.step_callback("researcher"))
task = Task(description="...", agent=agent, callback=producer.task_callback("research"))
crew = Crew(agents=[agent], tasks=[task], step_callback=producer.crew_callback("market-research"))
crew.kickoff()
```

Tool name format: `crewai:{kind}:{name}` where kind is `step` / `task` / `crew`.

### AutoGen / AG2

Auto-attaches `process_message_before_send` and `process_last_received_message` hooks to a `ConversableAgent`-shaped object. Tries `register_hook` first (newer AG2), then `hook_lists` (older autogen), then bare attribute assignment.

```python
from autogen import ConversableAgent
from ancilis.producers import AutoGenActionProducer

producer = AutoGenActionProducer(config=config, engine=engine)
assistant = ConversableAgent("assistant", ...)
producer.attach(assistant)
# All assistant sends and receives now emit Actions
```

Tool name format: `autogen:{kind}:{sender}->{recipient}`.

### Microsoft Semantic Kernel

Three filter factories — one per Semantic Kernel filter slot. Filters match SK's `async def filter(context, next): await next(context)` signature.

```python
from semantic_kernel import Kernel
from ancilis.producers import SemanticKernelActionProducer

producer = SemanticKernelActionProducer(config=config, engine=engine)
kernel = Kernel()
kernel.add_filter("function_invocation", producer.function_invocation_filter())
kernel.add_filter("prompt_rendering", producer.prompt_rendering_filter())
kernel.add_filter("auto_function_invocation", producer.auto_function_invocation_filter())
```

Tool name format: `semantic-kernel:{kind}:{plugin_name}.{function_name}`.

## Auto-detection

`ancilis.producers.auto` removes per-SDK boilerplate. `auto_register(config, engine)` instantiates one producer per upstream SDK detected in the current environment via `importlib.util.find_spec` (no actual imports, no side effects).

```python
from ancilis import load_config
from ancilis.engine import Engine
from ancilis.producers import auto_register

config = load_config()
engine = Engine(config)
producers = auto_register(config, engine)
# producers == {"anthropic": AnthropicActionProducer(...), "openai": OpenAIActionProducer(...), ...}
```

Filters via `include=` / `exclude=`:

```python
producers = auto_register(config, engine, include={"anthropic", "openai"})
producers = auto_register(config, engine, exclude={"openai"})
```

Diagnostics-only helpers:

```python
from ancilis.producers import detect_installed_sdks, installed_provider_slugs

print(detect_installed_sdks())  # {"anthropic": True, "openai": False, "langchain": True, ...}
print(installed_provider_slugs())  # ["anthropic", "langchain"]
```

The detector table covers `anthropic`, `openai`, `gemini` (`google.genai` and `google.generativeai`), `mistral`, `cohere`, `groq`, `together`, `fireworks`, `aws-bedrock` (boto3), `langchain` (`langchain` or `langchain_core`), `crewai`, `autogen` (`autogen`, `autogen_agentchat`, `ag2`), and `semantic-kernel`.

## Common patterns

### Shared evidence store

All producers default to the same per-agent evidence store at `~/.ancilis/{agent}-{cwd_hash}/evidence.duckdb`. If you create multiple producers, they share the evidence chain.

### In-memory evidence

For testing or demos, use `in_memory=True`:

```python
from ancilis.evidence.store import EvidenceStore

evidence = EvidenceStore(config, in_memory=True)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)
```

### Custom evidence path

```python
evidence = EvidenceStore(config, db_path="/path/to/evidence.duckdb")
```
