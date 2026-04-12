# Ancilis

[![CI](https://github.com/ancilis/ancilis/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/ancilis/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ancilis/ancilis/badge)](https://scorecard.dev/viewer/?uri=github.com/ancilis/ancilis)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ancilis.svg)](https://pypi.org/project/ancilis/)
[![npm](https://img.shields.io/npm/v/ancilis.svg)](https://www.npmjs.com/package/ancilis)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

Policy-driven runtime security for AI agents. Automated data type or certification security control selection based on what your agent needs. Audit-ready evidence. Start with security — unlock compliance when your market demands it. Never map or crosswalk control frameworks again.

---

## The problem

Your agents make tool calls. Those tool calls touch real data, hit real APIs, execute real commands. Right now, nothing evaluates those calls against a policy before they execute. Nothing produces evidence that they were evaluated. When a customer asks "how do you control what your agent does?" — you don't have an answer backed by data.

## What Ancilis does

- **Evaluates every tool call** against declared policy with deterministic pass/fail
- **Produces hash-chained evidence records** for every evaluation — local DuckDB, no external services
- **Auto-scopes regulatory overlays** from data classification — declare `health_records`, get HIPAA controls
- **Supports audit and enforce modes** — log everything first, block violations when ready
- **Works with MCP, CLI, HTTP, and plain Python tool calls** through pluggable producers

## Quick start

```bash
pip install ancilis
```

Create `ancilis.yaml`:

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

def search_docs(query: str) -> str:
    return f"Found 3 results for: {query}"

# Wrap the function — every call is now evaluated and evidence-recorded
search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")

result = search_docs("account billing")
# => "Found 3 results for: account billing"
# Evidence record written to ~/.ancilis/my-agent-{hash}/evidence.duckdb
```

Check your posture:

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 26 active, all passing
  Tool calls: 1 evaluated, 0 blocked
```

## The certification path

Add one line to your config. Get certification readiness assessment for free.

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
```

AIUC-1 is the first certifiable standard for AI agents. Enterprise buyers are starting to ask for it. Ancilis maps its requirements to 6 security controls that activate automatically from this single config line.

```bash
ancilis report --format aiuc1-readiness
```

```
AIUC-1 AI Agent Certification Standard Readiness
  Readiness: 85% (17 of 20 requirements passing)
  Coverage: 85% (17 automated, 3 operator)
  Evidence records: 8, hash chain intact
```

See the full walkthrough: [examples/certification-driven/](examples/certification-driven/)

## The data classification path

Declare what data your agent handles. Get the right compliance controls automatically.

```yaml
agent:
  name: health-agent
my_agent_handles:
  - health_records
  - personal_info
```

HIPAA, GDPR, and SOC 2 overlays activate. Evidence retention extends to 6 years per HIPAA requirements. No framework crosswalking, no manual mapping.

```bash
ancilis status
```

```
Ancilis — health-agent
  Mode: audit
  Controls: 26 active, all passing
  GDPR: active — triggered by health_records declaration
  HIPAA Security Rule: active — triggered by health_records declaration
  SOC 2 Type II: active — triggered by health_records declaration
```

See the full walkthrough: [examples/data-classification/](examples/data-classification/)

## Architecture

```
Producers (MCP, CLI, HTTP, Tool wrapper)
    ↓
Action Objects (protocol-agnostic)
    ↓
Engine (26 AKSI controls, deterministic evaluation)
    ↓
Evidence Store (DuckDB, SHA-256 hash chain)
    ↓
Reports (terminal, markdown, PDF, AIUC-1 readiness)
```

Producers translate protocol-specific invocations into Action objects. The engine doesn't know or care about the source protocol. Every evaluation is recorded in a local DuckDB evidence store with cryptographic hash chaining. The CLI reads that store to generate status output and compliance reports.

Policy data — controls, overlay profiles, data classifications — lives in `shared/` as JSON, consumed by both the Python and TypeScript SDKs.

## Examples

| Example | What it shows |
|---------|--------------|
| [certification-driven](examples/certification-driven/) | One config line → AIUC-1 readiness assessment |
| [data-classification](examples/data-classification/) | Declare data types → automatic regulatory overlays |
| [mcp-middleware](examples/mcp-middleware/) | MCP client wrapping with enforce/audit modes |
| [cli-agent](examples/cli-agent/) | Shell command evaluation and blocking |

Each example has its own README, config, and verified output.

## CLI

| Command | What it does |
|---------|-------------|
| `ancilis status` | Current security posture in plain language |
| `ancilis status --verbose` | Per-control detail with activation sources |
| `ancilis config validate` | Validate config with actionable error messages |
| `ancilis approve-tool <name>` | Add a tool to the approved list |
| `ancilis report` | Terminal posture report |
| `ancilis report --format markdown` | Markdown report for review |
| `ancilis report --format aiuc1-readiness` | AIUC-1 certification readiness |
| `ancilis report --format pdf` | PDF for procurement/audit (requires pandoc) |
| `ancilis doctor` | First-run setup check with next steps |

## Configuration

Each level adds one concept. You don't need level N to get value from level N-1.

| Level | Config addition | What activates |
|-------|----------------|----------------|
| 0 | Just `agent.name` | 26 baseline security controls |
| 1 | `certification_targets: [aiuc-1]` | AIUC-1 controls + readiness reporting |
| 2 | `my_agent_handles: [health_records]` | Regulatory overlays for declared data types |
| 3 | `security.mode: enforce` | Violations blocked before execution |

Full configuration reference: [docs/configuration.md](docs/configuration.md)

## Data types and overlays

| Data type | Overlays activated |
|-----------|-------------------|
| `credit_cards` | PCI-DSS v4 |
| `personal_info` | SOC 2 Type II, GDPR |
| `health_records` | SOC 2 Type II, HIPAA, GDPR |
| `patient_data` | SOC 2 Type II, HIPAA, GDPR |
| `ai_training_data` | ISO 42001, EU AI Act |
| `biometric_data` | EU AI Act |
| `financial_records` | SOC 2 Type II |
| `controlled_unclassified` | CMMC L2 |
| `government_cui` | CMMC L2 |
| `material_nonpublic` | Securities MNPI |
| `mnpi` | Securities MNPI |
| *(all data types)* | NIST CSF 2.0 (baseline) |

23 data types supported. 12 overlay profiles available. See [docs/configuration.md](docs/configuration.md) for the complete list.

## Limitations

Honest about what this is and isn't:

- **Python is the primary supported path.** TypeScript remains preview, but the current preview includes the core engine, evidence store, CLI/HTTP/tool producers, `doctor`, and report generation/rendering. Parity auditing and release hardening are still in progress.
- **HTTP is explicit wrapping, not universal interception.** Ancilis does not monkey-patch `requests`, `httpx`, or `aiohttp`. The HTTPActionProducer wraps calls you explicitly pass to it.
- **Evidence integrity depends on protecting the DB.** The hash chain detects tampering after the fact. It doesn't prevent an attacker with host access from replacing the entire database.
- **No GUI. No SaaS platform.** Ancilis is an SDK and CLI. The evidence store is local.
- **Controls without evaluators are recorded as SKIP.** 6 of 26 controls have runtime evaluators today (PR-01 through PR-05, DE-01). The others are defined in the control taxonomy and appear in reports but produce SKIP results until evaluators are implemented.
- **Overlay depth varies.** SOC 2 maps all 26 controls. HIPAA and GDPR map 6 controls each. PCI-DSS maps 6 controls. All overlays are functional and produce compliance posture — deeper mapping is planned.
- **PDF export requires pandoc and xelatex.** Without them, PDF falls back to markdown output.

See [docs/limitations.md](docs/limitations.md) for detailed scope boundaries.

## TypeScript

> **Preview.** The TypeScript SDK includes the core engine, config loading, evidence store, producers, `doctor`, and reporting, but Python remains the supported path for production use while TypeScript parity auditing and release hardening continue.

```bash
npm install ancilis
npx ancilis --help
npx ancilis doctor
```

### Quickstart

```typescript
import { loadConfig, Engine, EvidenceStore, ToolActionProducer, BlockedActionError } from "ancilis";

const config = loadConfig({
  raw: {
    agent: { name: "payment-agent" },
    security: { mode: "enforce", tools: { allowed: ["payments.read"], blocked: ["payments.delete"] } },
  },
});

const store = new EvidenceStore(config, { inMemory: true });
const producer = new ToolActionProducer(config, new Engine(config), undefined, store);

const readPayment = (id: string) => ({ id, amount: 42.0, status: "settled" });

const result = await producer.execute(readPayment, "payment-agent", ["pay_123"], undefined, "payments.read");
console.log(result.returnValue); // { id: 'pay_123', amount: 42, status: 'settled' }

const { valid } = await store.verifyChain();
console.log(`Chain integrity: ${valid ? "valid" : "broken"}`);
```

See [`examples/typescript/`](examples/typescript/) for a runnable end-to-end example.

## Contributing / Security / License

- Security disclosures: [SECURITY.md](SECURITY.md) — security@ancilis.ai
- [CONTRIBUTING.md](CONTRIBUTING.md)
- Business Source License 1.1 — see [LICENSE](LICENSE). Change Date: March 10, 2030. Change License: Apache 2.0.
