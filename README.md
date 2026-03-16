# Ancilis

[![CI](https://github.com/ancilis/ancilis/actions/workflows/ci.yml/badge.svg)](https://github.com/ancilis/ancilis/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/ancilis.svg)](https://pypi.org/project/ancilis/)

Policy-driven runtime security for AI agents.

---

Your agent reads customer records, moves money, sends emails. Each action is a tool call. Nothing in your stack decides what's authorized, validates the tool hasn't changed, or keeps a tamper-proof record of what happened. Ancilis does — inline, at execution time.

## What It Does

- **Intercepts every tool call** before it reaches your MCP server
- **Evaluates against policy** — identity, scope, tool provenance, data exposure
- **Blocks violations** in enforce mode; logs everything in audit mode
- **Emits compliance-grade evidence** — SHA-256 chained records, queryable with SQL, export-ready

## Quick Start

```bash
pip install ancilis[mcp]
```

### Zero config: baseline security immediately

```python
from ancilis import AncilisMiddleware

# Wrap your MCP client — that's it
client = AncilisMiddleware(mcp_client)
```

Six security controls are now active. Default is audit mode — nothing blocked, everything logged.

```
Ancilis: 47 tool calls evaluated. 0 issues. Run `ancilis status` for details.
```

### Add a config file

Create `ancilis.yaml`:

```yaml
agent:
  name: my-agent
my_agent_handles:
  - credit_cards
  - personal_info
```

SOC 2 Type II and GDPR overlays activate automatically. Evidence fields are extended. No other changes needed.

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 6 active, all passing
  SOC 2 Type II: active (credit_cards, personal_info)
  GDPR: active (personal_info)
  Tool calls: 1,247 evaluated, 0 blocked
```

### Add a certification target

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
my_agent_handles:
  - credit_cards
  - personal_info
```

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

## What You Get

### Audit mode (default)

Nothing is blocked. Every evaluation is logged. Warnings surface what needs attention:

```
Ancilis — my-agent
  Mode: audit
  Controls: 6 active, all passing
  SOC 2 Type II: active
  Tool calls: 1,247 evaluated, 0 blocked

  Warnings:
    [scope] Agent called 'send_email' — not in approved tool list.
            To approve: ancilis approve-tool send_email
```

Every warning tells you what to do. Approve the tool and it resolves:

```bash
ancilis approve-tool send_email
```

### Enforce mode

Switch `security.mode` to `enforce`. Unauthorized calls are blocked before execution:

```
Ancilis [blocked]: Tool 'exfil-data' blocked — not in approved tool list.
  To approve: ancilis approve-tool exfil-data
  To review: ancilis status
```

### Evidence records

Every evaluation writes a DuckDB record with SHA-256 hash chain integrity. No external services. No data leaves your environment. Query directly with SQL when you need it.

### Posture reports

```bash
ancilis report --format pdf --period 90d
```

Framework-by-framework compliance coverage, evidence counts, hash chain verification. Hand it to your customer's procurement team.

## Configuration

Progressive disclosure — each level adds one concept.

**Baseline** — no config required, six controls active:

```yaml
agent:
  name: my-agent
```

**Certification target** — activates all controls, generates readiness report:

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
```

**Data classification** — activates framework overlays based on what your agent touches:

```yaml
agent:
  name: my-agent
my_agent_handles:
  - credit_cards        # SOC 2; PCI-DSS on roadmap
  - personal_info       # SOC 2, GDPR
  - ai_training_data    # SOC 2, EU AI Act
  - health_records      # SOC 2, HIPAA, GDPR
```

**Enforcement** — switch from observe to block:

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

## Supported Frameworks

| Framework | Activated by | Status |
|---|---|---|
| Baseline (6 controls) | Always active | v0.1 |
| SOC 2 Type II | Any data type declaration | v0.1 |
| GDPR | `personal_info`, `health_records`, `biometric_data` | v0.1 |
| EU AI Act | `ai_training_data`, `biometric_data` | v0.1 |
| HIPAA | `health_records`, `patient_data` | v0.1 |
| AIUC-1 certification | `certification_targets: [aiuc-1]` | v0.1 |
| PCI-DSS | `credit_cards` | Roadmap |
| GLBA, FedRAMP, CMMC, FERPA, COPPA | Various | Roadmap |

Roadmap frameworks surface a clear message when they would activate:

```
? pci-dss would be activated by DC-FIN-01 via credit_cards but is not yet available
  Baseline security controls are active for all data types.
```

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

## Architecture

MCP middleware intercepts every tool call before it reaches your server. Each call is evaluated by the control engine — identity (PR-01), scope (PR-02), provenance (PR-03), data exposure (PR-04), audit trail (PR-05), anomaly detection (DE-01) — then forwarded or blocked. Every decision is recorded in a local DuckDB evidence store with SHA-256 hash chain integrity.

Configuration is YAML. Policy data (controls, overlays, data classifications) lives in `shared/` as JSON, consumed by both the Python and TypeScript implementations.

```
python/          Python SDK  (pip install ancilis)
typescript/      TypeScript SDK  (npm install ancilis)
shared/          Controls, overlays, classifications, schemas
```

## TypeScript

Core control engine and MCP middleware are functional. Full parity with the Python SDK on trust model, evidence persistence, and reporting is the next milestone.

```bash
npm install ancilis
```

## Contributing / Security / License

- Security disclosures: [SECURITY.md](SECURITY.md) — security@ancilis.ai
- [CONTRIBUTING.md](CONTRIBUTING.md)
- Business Source License 1.1 — see [LICENSE](LICENSE). Change Date: March 10, 2030. Change License: Apache 2.0.
