# Producers

Producers translate protocol-specific invocations into Action objects that the engine evaluates. The engine doesn't know or care about the source — it evaluates Actions the same way regardless of where they came from.

## Available producers

| Producer | Source | Use when |
|----------|--------|----------|
| `ToolActionProducer` | Python functions | Wrapping your own tool definitions |
| `AncilisMiddleware` | MCP client sessions | Wrapping MCP tool calls |
| `CLIActionProducer` | Shell commands | Wrapping subprocess execution |
| `HTTPActionProducer` | HTTP requests | Wrapping explicit HTTP/API calls |

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
