# Quickstart

Get Ancilis running in under 5 minutes.

## Install

```bash
pip install ancilis
```

For MCP middleware support:

```bash
pip install "ancilis[mcp]"
```

## Create a config

Create `ancilis.yaml` in your project root:

```yaml
agent:
  name: my-agent
```

That's the minimum. 26 baseline security controls activate. Every tool call your agent makes will be evaluated and evidence-recorded.

## Verify setup

```bash
ancilis doctor
```

```
Ancilis doctor — version 0.1.0
[OK] config: loaded for agent 'my-agent' in audit mode
[OK] assets: taxonomy 0.2, 26 controls available
[WARN] optional mcp extra: not installed (install with pip install ancilis[mcp] for MCP middleware)

Ready. Next steps:
  ancilis status                  — view current security posture
  ancilis config validate         — inspect resolved config details
```

## Wrap your tools

The simplest integration path is the ToolActionProducer — it wraps plain Python functions.

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = ToolActionProducer(config=config, engine=engine)

def search_docs(query: str) -> str:
    return f"Found 3 results for: {query}"

# Wrap the function
search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")

# Use it normally — evaluation happens transparently
result = search_docs("account billing")
print(result)  # "Found 3 results for: account billing"
```

Every call to `search_docs` now:
1. Builds an Action object with tool name, parameters, and agent identity
2. Evaluates it against all active controls (identity, scope, provenance, data exposure, audit trail, anomaly detection)
3. Records a hash-chained evidence record in DuckDB
4. Returns the function's result (or raises `BlockedActionError` in enforce mode)

## Check posture

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 26 active, all passing
  Tool calls: 1 evaluated, 0 blocked
```

## Add enforcement

When you're ready to block violations, set enforce mode:

```yaml
agent:
  name: my-agent
security:
  mode: enforce
  tools:
    allowed:
      - search_docs
      - send_reply
```

Now only `search_docs` and `send_reply` will execute. Any other tool call raises `BlockedActionError`.

```python
from ancilis import BlockedActionError

try:
    unapproved_tool("some args")
except BlockedActionError as e:
    print(e.display_message)
    # Ancilis [blocked]: Action 'unapproved_tool' blocked — scope enforcement.
    #   To approve: ancilis approve-tool unapproved_tool
    #   To review: ancilis status
```

## Add compliance

Declare what data your agent handles:

```yaml
agent:
  name: my-agent
my_agent_handles:
  - health_records
  - personal_info
```

HIPAA, GDPR, and SOC 2 overlays activate automatically. No additional code changes needed.

Or declare a certification target:

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
```

AIUC-1 controls activate. Run `ancilis report --format aiuc1-readiness` to see readiness.

## Next steps

- [Configuration reference](configuration.md) — every config field documented
- [Producers](producers.md) — MCP, CLI, HTTP, and tool wrapper integration paths
- [Evidence and reporting](evidence-and-reporting.md) — what evidence records contain, how to use reports
- [Examples](../examples/) — runnable examples for each integration path
