# Ancilis — Automatic Compliance Controls & Evidence for AI Agents

[![CI](https://github.com/ancilis/ancilis/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/ancilis/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ancilis/ancilis/badge)](https://scorecard.dev/viewer/?uri=github.com/ancilis/ancilis)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ancilis.svg)](https://pypi.org/project/ancilis/)
[![npm](https://img.shields.io/npm/v/ancilis.svg)](https://www.npmjs.com/package/ancilis)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

**Turn what your agent handles and what you need to prove into active runtime controls.**

Ancilis is a Python-first compliance and trust intelligence SDK for AI agents.

Instead of manually choosing controls, analyzing frameworks, building crosswalks, and chasing evidence after the fact, Ancilis uses two inputs to decide what should apply:

- the **data your agent handles**
- the **certifications or trust standards you want to target**

From there, Ancilis evaluates agent actions at runtime, activates the right controls automatically, and records audit-ready evidence as the agent runs.

**No manual control selection.**
**No framework analysis.**
**No crosswalking spreadsheets.**
**No waiting for review cycles to know where you stand.**

---

## Why Ancilis exists

Most AI agent security tools stop at runtime policy enforcement.

That matters, but enterprise teams still get stuck with the harder problem:

- Which controls actually apply to this agent?
- Which frameworks matter based on the data it touches?
- What evidence do we have right now?
- Are we closer to certification, or just collecting logs?

Ancilis is built for that next step.

It turns runtime security into **automatic compliance control activation**, **continuous evidence generation**, and **certification readiness**.

## What makes Ancilis different

Ancilis is not just another runtime security layer.

It is a runtime control and evidence system that lets you declare business reality and let the platform do the compliance work:

- declare `health_records` and activate HIPAA, GDPR, and SOC 2 overlays automatically
- declare `credit_cards` and activate PCI-DSS controls automatically
- declare `ai_training_data` and activate ISO 42001 and EU AI Act overlays automatically
- declare `aiuc-1` as a certification target and generate readiness reporting automatically
- switch from `audit` to `enforce` when you are ready to block violations before execution

This means you do not start with a spreadsheet of frameworks.
You start with what your agent is, what it touches, and what you need to prove.

## How it works

```text
What your agent handles + what you need to certify
                ↓
Automatic control and overlay activation
                ↓
Runtime evaluation of tool calls and actions
                ↓
Tamper-evident evidence written locally
                ↓
Status, reports, and certification readiness output
```

Ancilis works with:

- MCP clients and middleware
- CLI agents
- explicit HTTP wrappers
- plain Python tool functions

## Quick start

Install Ancilis:

```bash
pip install ancilis
# optional MCP support
pip install "ancilis[mcp]"
```

Create `ancilis.yaml`:

```yaml
agent:
  name: my-agent

security:
  mode: audit
  tools:
    allowed:
      - search_docs

my_agent_handles:
  - health_records
  - personal_info

certification_targets:
  - aiuc-1
```

Wrap a tool:

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = ToolActionProducer(config=config, engine=engine)

def search_docs(query: str) -> str:
    return f"Found 3 results for: {query}"

search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")

result = search_docs("account billing")
print(result)
```

Check your current posture:

```bash
ancilis status
```

Example output:

```text
Ancilis — my-agent
  Mode: audit
  Controls: active and evaluating
  Tool calls: 1 evaluated, 0 blocked
  AIUC-1: active
  HIPAA Security Rule: active
  GDPR: active
  SOC 2 Type II: active
```

## You declare intent. Ancilis decides controls.

| You declare | Ancilis activates |
|---|---|
| `my_agent_handles: [health_records]` | HIPAA, GDPR, SOC 2 overlays |
| `my_agent_handles: [credit_cards]` | PCI-DSS overlay |
| `my_agent_handles: [ai_training_data]` | ISO 42001 and EU AI Act overlays |
| `certification_targets: [aiuc-1]` | AIUC-1 readiness reporting |
| `security.mode: enforce` | violations blocked before execution |

This is the core idea:

You should not have to manually select controls for every agent.
You should not have to interpret every framework from scratch.
You should not have to wait for an annual review to know whether your posture is drifting.

## Evidence you can actually use

Every evaluation produces audit-ready evidence.

Ancilis records:

- what action was attempted
- which control evaluated it
- whether it passed or failed
- why it passed or failed
- when it happened
- the evidence chain linking that event to the rest of the record

Evidence is stored locally in DuckDB with cryptographic hash chaining so you can inspect, report, and retain it without a hosted control plane.

## Common use cases

- **Automatic compliance activation** for agents that handle regulated data
- **Certification readiness** for teams targeting AIUC-1 and similar trust signals
- **Security reviews for enterprise buyers** that want proof of runtime controls and evidence
- **Continuous posture tracking** between audit cycles
- **Safer MCP and tool usage** for agents that call external systems
- **A compliance-ready control layer** for internal copilots and production agents

## Certification path

Add a certification target:

```yaml
certification_targets:
  - aiuc-1
```

Generate readiness output:

```bash
ancilis report --format aiuc1-readiness
```

This lets teams move from “we think we are covered” to a concrete, evidence-backed readiness view without building framework crosswalks by hand.

## Data classification path

Declare what your agent handles:

```yaml
my_agent_handles:
  - health_records
  - personal_info
```

Ancilis activates the relevant overlays automatically and extends evidence requirements where needed.

That means your compliance posture follows the agent’s real data exposure, not a static spreadsheet.

## Runtime security is the mechanism, not the whole product

Ancilis still does the runtime work:

- evaluates tool calls deterministically
- supports audit and enforce modes
- records every decision as evidence
- works across multiple producer types

But the differentiated value is not just “runtime security.”

The differentiated value is that runtime evaluation becomes the engine for:

- automatic control selection
- automatic overlay activation
- certification readiness
- continuous evidence generation
- lower compliance overhead for every new agent

## Examples

- `examples/certification-driven` — certification target to readiness reporting
- `examples/data-classification` — data declaration to automatic overlays
- `examples/mcp-middleware` — MCP tool-call evaluation in audit or enforce mode
- `examples/cli-agent` — command evaluation and blocking

## CLI

| Command | What it does |
|---|---|
| `ancilis status` | current posture in plain language |
| `ancilis status --verbose` | per-control detail with activation sources |
| `ancilis config validate` | validates config with actionable errors |
| `ancilis report` | terminal posture report |
| `ancilis report --format markdown` | markdown report for review |
| `ancilis report --format aiuc1-readiness` | AIUC-1 readiness report |
| `ancilis report --format pdf` | PDF report for procurement or audit |
| `ancilis doctor` | setup diagnostics and next steps |

## Current status

- Python is the primary supported path
- TypeScript is preview
- HTTP support is explicit wrapping, not universal interception
- evidence is tamper-evident, not tamper-proof
- some controls and overlays are deeper than others today

## Who this is for

Ancilis is for teams building AI agents that need to answer questions like:

- What controls apply to this agent?
- What evidence do we have right now?
- What changes when the agent touches regulated data?
- What do we need for certification or procurement?
- Can we prove the agent is operating inside approved boundaries?

## Security, contributing, and license

- Security disclosures: `security@ancilis.ai`
- Contributions welcome under the project license
- Licensed under **Business Source License 1.1**
