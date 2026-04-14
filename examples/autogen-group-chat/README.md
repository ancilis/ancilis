# AutoGen Group Chat + Ancilis

Compliance monitoring for a simulated AutoGen multi-agent group chat.
Three agents (Researcher, Analyst, Coordinator) share wrapped tools so every
tool call is attributed and recorded as evidence.

**Pattern:** Each agent wraps tools with `ToolActionProducer` before calling
them. The wrapping is framework-agnostic — the same code works whether tools
are invoked by AutoGen, CrewAI, or directly.

## Quick Start

```bash
make setup
make run
make scan
```

## What This Shows

| Agent       | Tools Used                     | Evidence Captured |
|-------------|--------------------------------|-------------------|
| Researcher  | `search_research` ×3           | 3 records         |
| Analyst     | `analyze_findings` ×2          | 2 records         |
| Coordinator | `compile_report`, `notify_stakeholder` | 2 records |

After `make run`, all 7 tool calls are recorded in DuckDB with per-call
attribution. `make scan` evaluates posture across SOC 2 (via `personal_info`
and `financial_records` declarations) and AIUC-1 certification controls.

## Integration Pattern

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

config = load_config()
engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

# Wrap each tool — works with AutoGen's function_map or any callable
my_tool = producer.wrap_tool(my_tool_impl, tool_name="my_tool")
```

With live AutoGen agents, pass the wrapped callables via `function_map` in
`UserProxyAgent` or `AssistantAgent` — Ancilis captures evidence for every
function call regardless of which agent initiates it.

## Live AutoGen Setup

```bash
cp .env.example .env
# Add your OPENAI_API_KEY to .env
```

See [docs.ancilis.ai](https://docs.ancilis.ai) for the full integration guide.
