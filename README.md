# Ancilis

[![CI](https://github.com/ancilis/ancilis/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/ancilis/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ancilis/ancilis/badge)](https://scorecard.dev/viewer/?uri=github.com/ancilis/ancilis)
[![license](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ancilis.svg)](https://pypi.org/project/ancilis/)
[![npm](https://img.shields.io/npm/v/ancilis.svg)](https://www.npmjs.com/package/ancilis)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

Classification-driven controls, runtime security decisions, and audit-ready evidence for AI agents.

AKSI is Ancilis's common-control model for agents: a harmonized catalog of agent controls drawn from industry and regulatory frameworks, expressed as runtime checks, evidence requirements, and compliance overlays.

Ancilis starts from the two things compliance and security teams already care about: what data your agent handles, and which certification or regulatory targets it needs to support. Declare classifications such as `health_records`, `credit_cards`, or `personal_info`; add certification targets such as `soc2`; Ancilis activates the right AKSI controls and reporting overlays without manual framework crosswalking.

AI agents do real work now: they call tools, run shell commands, invoke MCP servers, and send requests to LLM providers. Ancilis gives those actions a policy decision before they become invisible operational risk. It evaluates each action against the active AKSI controls, records the result in a local tamper-evident evidence store, and turns the same evidence into compliance posture reports.

Use it when you need to answer:

- What did this agent do?
- Was the action allowed by policy?
- Which data classes or certification targets drove the controls?
- Which AKSI controls passed, failed, or need attestation?
- What evidence can we show for SOC 2, HIPAA, PCI-DSS, EU AI Act, DORA, and other readiness work?

Ancilis runs locally. Core evaluation does not require a hosted service, network calls, or sending agent payloads to Ancilis.

What AKSI gives you:

- **Classification-driven control activation**: data declarations such as `health_records` and `credit_cards` activate the controls and overlays that matter for that agent.
- **Certification-driven readiness**: targets such as `soc2` add framework-specific posture reporting without hand-maintained crosswalks.
- **Policy decisions at runtime**: audit mode observes every action; enforce mode blocks violations before execution.
- **Tamper-evident evidence**: each record is written to DuckDB with a SHA-256 hash chain.
- **Compliance posture from runtime evidence**: the same evaluated Actions feed security review, trust review, and audit-readiness reports.
- **Honest coverage**: direct evaluators, attestation-backed controls, and current TypeScript preview limits are called out below.

## See Value In 30 Seconds

Install Ancilis, name your agent, allow the tools it should use, and wrap the first callable surface. The first call creates an evaluated Action and a local evidence record.

```bash
pip install ancilis
```

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

Wrap a tool:

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
engine = Engine(config)
producer = ToolActionProducer(config=config, engine=engine)

search_docs = producer.wrap_tool(search_docs, tool_name="search_docs")
result = search_docs("account billing")
```

Check posture:

```bash
ancilis status
```

```text
Ancilis - my-agent
  Mode: audit
  Controls: 39 common controls active, 2 payment extension controls available
  Tool calls: 1 evaluated, 0 blocked
```

That is the adoption loop: define policy, evaluate real agent actions, and keep evidence that can be inspected later.

## Choose Your Integration Path

Ancilis normalizes different agent runtimes into the same Action model. Start with the surface your agent already uses.

### Plain Python Tools

Use `ToolActionProducer` when your agent calls Python functions directly. The wrapper preserves the function interface, evaluates each call, writes evidence, then returns the original result unless enforce mode blocks the action.

The 30-second setup above is the minimal path for plain tools. Use it first if you want to see the evidence chain working before instrumenting a larger framework.

### MCP Agents

If your agent uses [Model Context Protocol](https://modelcontextprotocol.io), Ancilis wraps the MCP client session transparently. Your agent and the MCP server do not need to know the policy layer is there.

```bash
pip install "ancilis[mcp]"
```

```python
from ancilis import AncilisMiddleware

async with AncilisMiddleware(mcp_session, config_path="ancilis.yaml") as middleware:
    result = await middleware.call_tool("query_database", {"sql": "SELECT ..."})
```

Works with any MCP server. Audit mode records every call; enforce mode blocks policy violations before they reach the server. See [examples/mcp-middleware/](examples/mcp-middleware/) for a full walkthrough.

### Cover MCP Server

`ancilis-cover` is the local MCP server for onboarding, gap assessment, and runtime posture inspection. It is read-only: no network calls, no LLM calls, no MCP sampling, and no file writes.

```bash
pip install "ancilis[mcp]"
ancilis-cover
```

Configure an MCP host to launch it over stdio:

```json
{
  "mcpServers": {
    "ancilis-cover": {
      "command": "ancilis-cover",
      "args": []
    }
  }
}
```

The `ancilis_assess_gap` tool accepts business language such as "we handle patient records and need HIPAA" and deterministically maps it to Ancilis targets like `health_records` and `hipaa`, then reports missing config, instrumentation, and evidence coverage. See [examples/cover-mcp-gap-assessment/](examples/cover-mcp-gap-assessment/) for a runnable demo.

### CLI And Subprocess Agents

If your agent runs shell commands, `kubectl`, `curl`, database queries, or file operations, the CLI producer wraps subprocess execution with the same policy evaluation.

```python
from ancilis import CLIActionProducer, load_config
from ancilis.engine import Engine

config = load_config()
producer = CLIActionProducer(config=config, engine=Engine(config))

result = producer.execute(["kubectl", "get", "pods", "-n", "production"])
```

Allowed commands execute normally. Blocked commands are intercepted before the subprocess runs. Every evaluation is evidence-recorded. See [examples/cli-agent/](examples/cli-agent/).

### LLM SDKs And Agent Frameworks

Ancilis ships producers for major LLM SDKs and agent frameworks. Each producer wraps the SDK call surface so model invocations, agent steps, or framework callbacks become evaluated, evidence-recorded Actions. The producers are duck-typed, so upstream SDKs only need to be installed when your application uses them.

Auto-wire whatever is installed in your environment:

```python
from ancilis import load_config
from ancilis.engine import Engine
from ancilis.producers import auto_register

config = load_config()
engine = Engine(config)
producers = auto_register(config, engine)
```

Use `include=` and `exclude=` to scope auto-registration.

Or wire an individual producer explicitly:

```python
from anthropic import Anthropic
from ancilis.producers import AnthropicActionProducer

producer = AnthropicActionProducer(config=config, engine=engine)
client = Anthropic()
wrapped = producer.wrap_create(client.messages.create, agent_name="support-bot")

response = wrapped(model="claude-sonnet-4-6", messages=[{"role": "user", "content": "..."}])
```

LangChain and LangGraph use a drop-in callback handler:

```python
from langchain_anthropic import ChatAnthropic
from ancilis.producers import LangChainActionProducer, LangChainCallbackHandler

producer = LangChainActionProducer(config=config, engine=engine)
handler = LangChainCallbackHandler(producer)

llm = ChatAnthropic(callbacks=[handler])
```

Supported producers:

| Category | Producers |
|----------|-----------|
| LLM provider direct APIs | Anthropic, OpenAI, Gemini, Mistral, Cohere, xAI |
| OpenAI-compatible inference | Groq, Together, Fireworks, DeepSeek |
| Cloud LLM gateway | AWS Bedrock |
| Agent frameworks | LangChain / LangGraph, CrewAI, AutoGen / AG2, Microsoft Semantic Kernel |
| Protocols | MCP, CLI, HTTP |

Tool-name convention is stable across providers: `llm:{provider}:{model}` for direct LLM SDKs, `aws-bedrock:{operation}` for Bedrock, and `{framework}:{kind}:{name}` for framework producers. Allowlists in `ancilis.yaml` use these names directly.

## Compliance And Trust

Compliance work starts with what your agent handles. Declare the data classes and certification targets that apply; Ancilis activates the matching overlays and reports posture from the evidence your runtime already produced.

```yaml
agent:
  name: payment-agent
certification_targets:
  - soc2
my_agent_handles:
  - credit_cards
  - personal_info
```

SOC 2 and PCI-DSS overlays activate automatically from the declaration. No framework selection spreadsheet and no manual crosswalk mapping are needed to start producing posture evidence.

```bash
ancilis status
```

```text
Ancilis - payment-agent
  Mode: audit
  Controls: 39 common controls active, all passing
  SOC 2 Type II: active - triggered by certification target
  PCI-DSS v4: active - triggered by credit_cards declaration
  GDPR: active - triggered by personal_info declaration
```

```bash
ancilis report --format markdown
```

Reports include per-control results, evidence chain integrity verification, and framework-specific readiness scores. They support compliance and trust reviews; they do not by themselves certify an organization.

Declare what data your agent handles. The right regulatory overlays activate automatically.

| Data type | Overlays activated |
|-----------|-------------------|
| `credit_cards` | PCI-DSS v4 |
| `health_records` | HIPAA, GDPR, SOC 2 |
| `personal_info` | GDPR, SOC 2, CCPA |
| `ai_training_data` | EU AI Act, ISO 42001 |
| `financial_records` | GLBA, DORA |
| `controlled_unclassified` | CMMC L2 |
| `biometric_data` | EU AI Act |

23 canonical data classes are supported across 19 overlay profiles. Full list in [docs/configuration.md](docs/configuration.md).

The DORA-RES operational resilience overlay is specified as the architectural anchor for v0.2 function-classification activation. It coexists with the existing `DC-FIN` DORA overlay: the existing overlay covers financial-data handling evidence, while DORA-RES covers AI workload resilience evidence for agents supporting critical or important functions. See [shared/overlays/dora-res/dora_res_overlay_spec.md](shared/overlays/dora-res/dora_res_overlay_spec.md).

> **Roadmap: runtime classification.** Today you declare what data your agent handles in config. We are building runtime classification that detects data types from tool call payloads and responses using regex patterns, Luhn checksums, and co-occurrence analysis. When the SDK detects health records flowing through an agent you declared as general-purpose, it will surface the finding for you to confirm. Confirmed findings will activate the right overlays without config changes. Declaration gets you started; future classification keeps you accurate.

## How It Works

```text
Your agent calls a tool
       |
Producer normalizes the call (MCP, CLI, HTTP, LLM SDK, or framework callback)
       |
Engine evaluates against AKSI v0.6 controls
       |
Evidence record written to local DuckDB (SHA-256 hash chain)
       |
CLI reads the store for posture reports and compliance readiness
```

Producers translate protocol-specific invocations into a common Action object. The engine evaluates every Action against active controls and writes the result. The CLI reads the evidence store to generate reports.

No external service is required for core evaluation. No data leaves your machine unless your own agent or integration sends it elsewhere.

## Configuration Levels

Each level adds one concept. You do not need level 2 to get value from level 1.

| Level | What you add | What you get |
|-------|-------------|-------------|
| 1 | `agent.name` + `tools.allowed` | 39 common controls, evidence for every tool call |
| 2 | `certification_targets: [soc2]` | Certification readiness reporting |
| 3 | `my_agent_handles: [health_records]` | Automatic regulatory overlay activation |
| 4 | `security.mode: enforce` | Policy-violating tool calls blocked before execution |

## CLI Reference

```text
ancilis-cover                     Local MCP server for onboarding and gap assessment
ancilis status                    Current posture
ancilis status --verbose          Per-control detail
ancilis report                    Terminal report
ancilis report --format markdown  Markdown for review
ancilis report --format pdf       PDF for audit (requires pandoc)
ancilis evidence list             Recent evidence records
ancilis evidence show <id>        Full evidence record by ID or prefix
ancilis evidence verify           Verify evidence hash chain integrity
ancilis certify --target soc2 --dry-run
                                  Framework coverage and gaps
ancilis config validate           Check your config
ancilis approve-tool <name>       Approve a discovered tool
ancilis doctor                    First-run setup check
```

Example evidence workflow:

```bash
ancilis evidence list --limit 10
ancilis evidence show 9f2a4c1
ancilis evidence verify
ancilis certify --target soc2 --dry-run
```

### CI/CD

Check agent posture on every pull request with the [GitHub Action](https://github.com/ancilis/scan-action):

```yaml
- uses: ancilis/scan-action@v1
  with:
    fail-on: high
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The action posts posture results as a PR comment and fails the build if findings exceed your threshold. You can also call the CLI directly: `pip install ancilis && ancilis scan --ci`.

## TypeScript Preview

Python is the primary path. TypeScript includes the core engine, evidence store, producers, CLI, and reporting, with full parity for the LLM SDK and agent framework producers.

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

LLM SDK and framework producers also ship in the TypeScript package: `AnthropicActionProducer`, `OpenAIActionProducer`, `GeminiActionProducer`, `LangChainCallbackHandler`, `CrewAIActionProducer`, `AutoGenActionProducer`, `SemanticKernelActionProducer`, and `autoRegister(config, engine)` for whichever upstream SDKs are installed. Same shape as the Python producers.

## What's Honest

- **41 AKSI v0.6 controls ship in the catalog.** 39 common controls activate by default; `PAY-01` and `PAY-02` activate only for `DC-PAY`, `AGENT_PAYMENTS`, or `X402`.
- **Python has 18 direct runtime evaluators plus 23 attestation-backed evaluators.** Attestation-backed controls return `SKIP` until required evidence is recorded with `ancilis attest`.
- **TypeScript has direct core runtime evaluators plus catalog-backed evaluators for the remaining AKSI controls.** Catalog-backed controls return `FLAG` until explicit manual attestation is supplied; keyword matches are hints, not proof.
- **19 overlay profiles ship today.** Existing overlays are preserved and reference known AKSI controls; v0.6 adds more catalog coverage than the current overlay depth can fully exercise.
- **Evidence integrity depends on protecting the DB.** The hash chain detects tampering after the fact. It does not prevent replacing the entire database.
- **HTTP wrapping is explicit.** Ancilis does not monkey-patch HTTP libraries. You wrap the calls you want evaluated.
- **PDF export requires pandoc and xelatex.** The CLI falls back to markdown without them.

## Links

- [Examples](examples/) - Cover MCP gap assessment, certification-driven, data-classification, MCP middleware, CLI agent
- [Quickstart](docs/quickstart.md)
- [Configuration reference](docs/configuration.md)
- [Controls reference](docs/controls-reference.md)
- [DORA-RES overlay specification](shared/overlays/dora-res/dora_res_overlay_spec.md)
- [Producers](docs/producers.md)
- [Security policy](SECURITY.md) - security@ancilis.ai
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE) — GNU Affero General Public License v3.0 or later. Commercial licensing available; contact licensing@ancilis.ai.
