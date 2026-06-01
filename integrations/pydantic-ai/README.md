# ancilis-pydantic-ai

Pydantic-AI integration for [Ancilis](https://ancilis.ai) — automatic evidence capture via `wrap_agent()`.

## Install

```bash
pip install ancilis-pydantic-ai
```

## Quickstart

```python
from pydantic_ai import Agent
from ancilis_pydantic_ai import wrap_agent

agent = Agent("openai:gpt-4o", system_prompt="You are helpful.")
agent = wrap_agent(agent, agent_id="my-agent")
result = await agent.run("What is the weather in Paris?")
```

That's it. Ancilis automatically translates each Pydantic-AI run, tool call, and stream event into cryptographically chained evidence — without ever storing the raw structured payloads typed agents pass around.

## What gets captured

| Event kind | action_type | Captured |
|------------|-------------|----------|
| `model_response` | `tool_call` | model name, usage tokens |
| `function_tool_call` | `tool_call` | tool name, sanitized arg keys + sha256 of arg values |
| `function_tool_result` | `tool_call` | tool name, output length, error.type if present |
| `final_result` | `tool_call` | model name, tool name |
| `run_result` | `tool_call` | usage tokens, output length, error.type if present |

## Privacy

Tool **argument values are never stored raw** — only the argument key names plus a sha256 digest of `repr(value)`. This is a security-critical guarantee for typed agent runtimes that may carry sensitive structured payloads (PII, credentials, etc.) inside Pydantic models.

## Configuration

`wrap_agent` accepts an optional `engine=` and `evidence_store=` for direct injection in tests. By default, the wrapped agent observes events without forwarding them — wire it up by passing your `Engine` and `EvidenceStore` instances.

## Compatibility

- Pydantic-AI: `>=0.0.10` (loose; producer is duck-typed and never imports pydantic_ai at module load)
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
