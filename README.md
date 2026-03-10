# Ancilis

Runtime security for AI agents. Intercept, evaluate, and enforce security policy on every tool call — then hand your customer a compliance report you didn't have to build separately.

*Compliance should travel with the data, not against the innovation.*

Ancilis is a cross-platform SDK (Python + TypeScript) that sits between your AI agent and its tools via MCP middleware. Every tool call passes through a security evaluation engine that checks identity, permissions, tool provenance, and data exposure in real time. Enforcement actions produce structured evidence records automatically — compliance coverage is a natural byproduct of doing security right.

**Default mode is audit.** Install it, watch what your agent does, then decide what to lock down.

## Install

```bash
pip install ancilis
```

```bash
npm install ancilis
```

## Quick Start

### 1. Configure

Create `ancilis.yaml` in your project root:

```yaml
agent:
  name: my-agent
```

That's it. One field. Ancilis discovers tools at runtime from your MCP connection, auto-registers them, and applies baseline security controls with sensible defaults.

### 2. Add Middleware

**Python:**

```python
from ancilis import AncilisMiddleware

# Wrap your MCP client connection
client = AncilisMiddleware(mcp_client)
```

**TypeScript:**

```typescript
import { AncilisMiddleware } from 'ancilis';

// Wrap your MCP client connection
const client = new AncilisMiddleware(mcpClient);
```

Every tool call now flows through the security evaluation engine. In audit mode (the default), nothing is blocked — Ancilis observes, evaluates, and logs.

### 3. Observe

Check your agent's security posture:

```bash
ancilis status
```

The SDK evaluates every tool call against six baseline controls:

| Control | What It Does |
|---|---|
| Agent Identity & Authentication | Verifies agent presents valid credentials. No anonymous tool calls. |
| Permission Scope Enforcement | Constrains agent to authorized tools and action types. |
| Tool Provenance Verification | Verifies tool identity against registry. Checks version pin and description hash for drift. |
| Data Exposure Prevention | Scans outbound parameters for sensitive data patterns. Blocks/flags unauthorized transmission. |
| Audit Logging | Structured logging of every tool call evaluation with full context. |
| Behavioral Baseline | Tracks tool call frequency, scope patterns, timing. Flags deviations. |

In audit mode, you see what *would* have been blocked, what passed, and what patterns were detected — without disrupting your agent.

### 4. Configure (Optional)

Ancilis generates a recommended policy based on observed behavior: tools discovered, data patterns detected, scope boundaries inferred. Review it, adjust it, tighten what matters to you.

```bash
ancilis config validate
```

### 5. Enforce

When you trust the policy, flip to enforce mode:

```yaml
agent:
  name: my-agent
  mode: enforce
```

Unauthorized actions are now blocked.

### 6. Declare Data Types (Optional)

When you need compliance coverage, declare what data your agent handles:

```yaml
agent:
  name: my-agent
  mode: enforce
  data_handling:
    - health_records
    - personal_info
```

Ancilis translates these plain-English declarations into the appropriate regulatory overlays and adjusts control thresholds automatically. You never touch classification codes or framework mappings.

| You Declare | Compliance Coverage You Get |
|---|---|
| `health_records` | HIPAA, GDPR |
| `patient_data` | HIPAA, GDPR |
| `personal_info` | GDPR |
| `credit_cards` | PCI-DSS, SOC 2 |
| `financial_records` | GLBA, SOC 2 |
| `government_documents` | FedRAMP, CMMC |
| `childrens_data` | COPPA, FERPA |
| `public_data` | SOC 2 (baseline) |

### 7. Export Posture Report

```bash
ancilis report --format pdf --period 30d
```

Hand this to your customer's procurement team.

## Sample Posture Report

```
ANCILIS SECURITY POSTURE REPORT
================================
Agent: claims-processor    Period: 2026-02-08 to 2026-03-10
Mode: enforce

BASELINE SECURITY
-----------------
Controls Active:         6/6
Tool Calls Evaluated:    14,832
Tool Calls Blocked:      23
Tool Calls Flagged:      147

Tools Discovered:        12
  Provenance Verified:   11
  Provenance Unknown:    1 (jira-legacy-connector v0.3.1)

Data Patterns Detected:
  DC-PHI (health records):    4,201 calls
  DC-PII (personal info):     8,944 calls
  DC-FIN (financial):         1,687 calls

Behavioral Baseline:
  Deviation Alerts:      3
  Highest Severity:      MEDIUM (unusual call frequency spike, 2026-02-22)

COMPLIANCE COVERAGE
-------------------
Active Overlays:         HIPAA, GDPR, SOC 2
Activation Trigger:      data_handling: [health_records, personal_info]

HIPAA:
  Controls Mapped:       14/14
  Evidence Sufficient:   13/14
  Gap:                   PR-03 (tool provenance) — 1 unverified tool

GDPR:
  Controls Mapped:       11/11
  Evidence Sufficient:   11/11

SOC 2 (Type II):
  Controls Mapped:       18/18
  Evidence Sufficient:   17/18
  Gap:                   DE-01 (behavioral baseline) — insufficient observation period

RECOMMENDATIONS
---------------
1. Verify provenance for jira-legacy-connector or add to exception list
2. Extend observation period to 90 days for SOC 2 Type II evidence sufficiency
3. Review 3 behavioral deviation alerts for false positive tuning
```

## CLI

```bash
ancilis report --format pdf --period 30d    # Generate posture report
ancilis status                               # Current agent security posture
ancilis config validate                      # Validate configuration
```

## Why Ancilis?

**The status quo is broken.** AI agents are making tool calls — reading databases, sending emails, modifying records — with no runtime security layer. Teams bolt on compliance after the fact: manual audits, spreadsheet evidence collection, and retroactive policy checks that can't keep pace with autonomous systems.

**Security should be inline, not after-the-fact.** Ancilis evaluates every tool call at execution time against a structured control set. There's no gap between what your agent does and what your security policy allows.

**Compliance should be a byproduct, not a project.** When every tool call is evaluated and every enforcement decision is recorded with full context, you already have the evidence. You don't need a separate compliance workstream — you need a report export.

**Data classification should drive requirements.** Tell Ancilis your agent handles health records, and it activates HIPAA controls. Declare financial data, and PCI-DSS coverage appears. You describe your data in plain English; the SDK maps it to frameworks, adjusts thresholds, and tracks evidence — automatically.

**Zero-friction entry, progressive disclosure.** Start with one line of config and audit mode. See your agent's security posture. Tighten controls when you're ready. Add compliance coverage when your customer asks for it. Every step adds value without requiring the previous step to be exhaustive.

## Architecture

Ancilis is a monorepo with Python and TypeScript implementations sharing a common policy data layer:

```
python/          Python SDK (PyPI: ancilis)
typescript/      TypeScript SDK (npm: ancilis)
shared/          Language-agnostic control definitions, overlay profiles,
                 data classifications, and JSON schemas
```

The security controls, regulatory overlays, and data classification taxonomy live in `shared/` as JSON — consumed by both language implementations. The engines are language-specific; the policy data is not.

## Evidence Storage

All evidence records are stored in DuckDB — a local, embedded analytical database. No external services, no data leaving your environment. Query your security evidence with SQL when you need to.

## License

Business Source License 1.1 — see [LICENSE](LICENSE) for details.

The Licensed Work is the Ancilis SDK. The Change Date is March 10, 2030. The Change License is Apache License 2.0.

## Links

- [Documentation](docs/) (coming soon)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
