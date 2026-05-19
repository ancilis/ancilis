# Secure Your AI Agent in 5 Minutes

Ancilis is a runtime security layer for tool-using AI agents — it intercepts every tool call, evaluates it against security controls, and records cryptographically chained evidence. Drop it into any Python agent; compliance reports are a byproduct of the controls already running.

## 1. Install

```bash
pip install ancilis
```

For MCP middleware support: `pip install "ancilis[mcp]"`

## 2. Configure

Create `ancilis.yaml` in your project root:

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

That's enough to start. Baseline controls activate automatically — identity, scope, provenance, data exposure, audit trail, and anomaly detection. Use `mode: audit` to observe without blocking while you're getting started; switch to `enforce` when you're ready to block violations.

## 3. Wrap your agent

```python
from ancilis import ToolActionProducer, BlockedActionError, load_config
from ancilis.engine import Engine

config = load_config()          # reads ancilis.yaml
engine = Engine(config)
producer = ToolActionProducer(config=config, engine=engine)

def search_docs(query: str) -> str:
    return f"results for: {query}"

search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")
result = search_docs("billing history")  # evaluated and evidence-recorded
```

Each call builds an `Action`, runs it through all active controls, records a hash-chained entry in DuckDB, then returns the result. In enforce mode, any tool not in `allowed` raises `BlockedActionError`.

```python
try:
    unapproved_tool("some args")
except BlockedActionError as e:
    print(e.display_message)
    # Ancilis [blocked]: Action 'unapproved_tool' blocked — scope enforcement.
```

## 4. Run and see evidence

```python
from ancilis.evidence.store import EvidenceStore

evidence = EvidenceStore(config)
summary = evidence.get_summary()
print(summary["total_evaluations"])  # number of evaluated tool calls
print(summary["decisions"])          # {"allowed": N, "blocked": N}
print(summary["chain_valid"])        # True — hash chain integrity intact
evidence.close()
```

## 5. View with the CLI

```bash
ancilis doctor            # verify config and assets loaded correctly
ancilis status            # current posture — controls active, calls evaluated, violations
ancilis evidence list     # recent evidence records
ancilis evidence show <id-prefix>
ancilis certify --target soc2
ancilis report            # 30-day posture report in terminal format
ancilis report --format markdown --output report.md
```

## Next steps

- [Configuration reference](configuration.md) — every config field documented
- [Controls reference](controls-reference.md) — all 41 AKSI v0.6 controls and support levels
- [Data classification guide](data-classification.md) — declare `my_agent_handles`, get HIPAA/GDPR/SOC 2 overlays automatically
- [Producers](producers.md) — MCP, CLI, and HTTP integration paths
- [Examples](../examples/) — runnable examples for each integration path
