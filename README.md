# Ancilis

[![CI](https://github.com/ancilis/ancilis/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/ancilis/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ancilis/ancilis/badge)](https://scorecard.dev/viewer/?uri=github.com/ancilis/ancilis)
[![license](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ancilis.svg)](https://pypi.org/project/ancilis/)
[![npm](https://img.shields.io/npm/v/ancilis.svg)](https://www.npmjs.com/package/ancilis)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

Runtime security and compliance evidence for AI agents.

Ancilis evaluates every tool call your agent makes against a security policy, produces tamper-evident evidence records, and maps everything to the compliance frameworks your customers care about — SOC 2, HIPAA, PCI-DSS, EU AI Act, and 15 more. No manual framework crosswalking. Declare what data your agent handles; get the right controls automatically.

## Install

```bash
pip install ancilis
```

## 30-second setup

Create `ancilis.yaml` next to your agent code:

```yaml
agent:
  name: my-agent
security:
  tools:
    allowed:
      - search_docs
      - send_reply
```

Wrap your tools:

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = ToolActionProducer(config=config, engine=engine)

# Wrap any function — calls are now evaluated and evidence is recorded
search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")
result = search_docs("account billing")
```

Check posture:

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 26 active, all passing
  Tool calls: 1 evaluated, 0 blocked
```

That's it. Every tool call is evaluated against 26 security controls and recorded in a local evidence store with SHA-256 hash chaining.

## MCP agents

If your agent uses [Model Context Protocol](https://modelcontextprotocol.io), Ancilis wraps the MCP client session transparently — your agent and the MCP server don't know it's there:

```bash
pip install ancilis[mcp]
```

```python
from ancilis import AncilisMiddleware

# Wraps any MCP ClientSession — every tool call is now evaluated
async with AncilisMiddleware(mcp_session, config_path="ancilis.yaml") as middleware:
    result = await middleware.call_tool("query_database", {"sql": "SELECT ..."})
    # Tool call evaluated against policy, evidence recorded, then forwarded to MCP server
```

Works with any MCP server. Supports audit mode (log everything) and enforce mode (block policy violations before they reach the server). See [examples/mcp-middleware/](examples/mcp-middleware/) for a full walkthrough.

## CLI agents

If your agent runs shell commands — `kubectl`, `curl`, database queries, file operations — the CLI producer wraps subprocess execution with the same policy evaluation:

```python
from ancilis import CLIActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
producer = CLIActionProducer(config=config, engine=Engine(config))

# Evaluated against policy before execution — blocked commands never run
result = producer.execute(["kubectl", "get", "pods", "-n", "production"])
```

Allowed commands execute normally. Blocked commands are intercepted before the subprocess runs. Every evaluation is evidence-recorded. See [examples/cli-agent/](examples/cli-agent/).

## Add compliance

One line turns security controls into compliance evidence. Add a certification target to your config:

```yaml
agent:
  name: payment-agent
certification_targets:
  - soc2
my_agent_handles:
  - credit_cards
  - personal_info
```

SOC 2 and PCI-DSS overlays activate automatically from the data declaration. No framework selection, no crosswalk mapping.

```bash
ancilis status
```

```
Ancilis — payment-agent
  Mode: audit
  Controls: 26 active, all passing
  SOC 2 Type II: active — triggered by certification target
  PCI-DSS v4: active — triggered by credit_cards declaration
  GDPR: active — triggered by personal_info declaration
```

```bash
ancilis report --format markdown
```

Generates a compliance posture report with per-control results, evidence chain integrity verification, and framework-specific readiness scores.

## How it works

```
Your agent calls a tool
       ↓
Producer normalizes the call (MCP, CLI, HTTP, or direct wrapper)
       ↓
Engine evaluates against 26 AKSI security controls
       ↓
Evidence record written to local DuckDB (SHA-256 hash chain)
       ↓
CLI reads the store → posture reports, compliance readiness
```

Producers translate protocol-specific invocations into a common Action object. The engine evaluates every Action against active controls and writes the result. The CLI reads the evidence store to generate reports. No external services, no network calls, no data leaves your machine.

## Data types → compliance overlays

Declare what data your agent handles. The right regulatory overlays activate automatically.

| Data type | Overlays activated |
|-----------|-------------------|
| `credit_cards` | PCI-DSS v4 |
| `health_records` | HIPAA, GDPR, SOC 2 |
| `personal_info` | GDPR, SOC 2, CCPA |
| `ai_training_data` | EU AI Act, ISO 42001 |
| `financial_records` | GLBA, SOX, DORA |
| `controlled_unclassified` | CMMC L2 |
| `biometric_data` | EU AI Act |

23 data types supported across 19 overlay profiles. Full list in [docs/configuration.md](docs/configuration.md).

> **Roadmap: automatic classification.** Today you declare what data your agent handles in config. We're building runtime classification that detects data types automatically from tool call payloads and responses — regex patterns, Luhn checksums, co-occurrence analysis. When the SDK detects health records flowing through an agent you declared as general-purpose, it surfaces the finding for you to confirm. Confirmed findings activate the right overlays without config changes. Declaration gets you started; auto-classification keeps you accurate.

## CLI

```
ancilis status                    Current posture
ancilis status --verbose          Per-control detail
ancilis report                    Terminal report
ancilis report --format markdown  Markdown for review
ancilis report --format pdf       PDF for audit (requires pandoc)
ancilis config validate           Check your config
ancilis approve-tool <name>       Approve a discovered tool
ancilis doctor                    First-run setup check
```

## CI/CD

Check agent posture on every pull request with the [GitHub Action](https://github.com/ancilis/scan-action):

```yaml
- uses: ancilis/scan-action@v1
  with:
    fail-on: high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Posts posture results as a PR comment and fails the build if findings exceed your threshold. Or skip the action and call the CLI directly: `pip install ancilis && ancilis scan --ci`.

## Configuration levels

Each level adds one concept. You don't need level 2 to get value from level 1.

| Level | What you add | What you get |
|-------|-------------|-------------|
| 1 | `agent.name` + `tools.allowed` | 26 baseline security controls, evidence for every tool call |
| 2 | `certification_targets: [soc2]` | Certification readiness reporting |
| 3 | `my_agent_handles: [health_records]` | Automatic regulatory overlay activation |
| 4 | `security.mode: enforce` | Non-compliant tool calls blocked before execution |

## TypeScript

> Preview — Python is the primary path. TypeScript includes the core engine, evidence store, producers, CLI, and reporting.

```bash
npm install ancilis
npx ancilis doctor
```

```typescript
import { loadConfig, Engine, EvidenceStore, ToolActionProducer } from "ancilis";

const config = loadConfig({
  raw: {
    agent: { name: "my-agent" },
    security: { mode: "enforce", tools: { allowed: ["read_data"] } },
  },
});

const store = new EvidenceStore(config, { inMemory: true });
const producer = new ToolActionProducer(config, new Engine(config), undefined, store);
const result = await producer.execute(readData, "my-agent", ["id-123"], undefined, "read_data");
```

## What's honest

- **12 of 26 controls have runtime evaluators.** The other 14 are defined in the framework and appear in reports as SKIP until evaluators ship. No false positives.
- **19 overlay profiles, all mapping 26 controls.** SOC 2, HIPAA, PCI-DSS, EU AI Act, GDPR, CCPA, CMMC, GLBA, DORA, NIS2, FedRAMP, ISO 27001, ISO 42001, NIST CSF, NIST AI RMF, Colorado AI Act, Singapore IMDA MGF, Securities MNPI, MAS TRM.
- **Evidence integrity depends on protecting the DB.** The hash chain detects tampering after the fact. It doesn't prevent replacing the entire database.
- **HTTP wrapping is explicit.** Ancilis doesn't monkey-patch HTTP libraries. You wrap the calls you want evaluated.
- **PDF export requires pandoc and xelatex.** Falls back to markdown without them.

## Links

- [Examples](examples/) — certification-driven, data-classification, MCP middleware, CLI agent
- [Configuration reference](docs/configuration.md)
- [Security policy](SECURITY.md) — security@ancilis.ai
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE) — Business Source License 1.1 (Apache 2.0 on March 10, 2030)
