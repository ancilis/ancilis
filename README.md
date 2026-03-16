# Ancilis

Runtime security for AI agents. Intercept, evaluate, and enforce security policy on every tool call — then hand your customer a compliance report you didn't have to build separately.

*Compliance should travel with the data, not against the innovation.*

Ancilis is an SDK that sits between your AI agent and its tools. Every tool call passes through a security evaluation engine that checks identity, permissions, tool provenance, and data exposure in real time. Enforcement actions produce structured evidence records automatically — compliance coverage is a natural byproduct of doing security right.

**Default mode is audit.** Install it, watch what your agent does, then decide what to lock down.

## Language Support

**Python (primary):** Full implementation — three-state trust model, persistent evidence with hash chain, pattern detection, MCP middleware, CLI producer, posture-based readiness reporting.

```bash
pip install ancilis        # core SDK + CLI producer
pip install ancilis[mcp]   # with MCP middleware
```

**TypeScript (in progress):** Core control engine and MCP middleware functional. Trust model, evidence persistence, and reporting parity with Python is the next development milestone.

```bash
npm install ancilis
```

## Quick Start

### 1. Get AIUC-1 Certification Coverage

Your enterprise customer asked for AIUC-1 certification. Here's how to get coverage in under five minutes.

Create `ancilis.yaml` in your project root:

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
```

That's it. Two fields. Ancilis activates all six security controls, starts collecting evidence, and generates a readiness report mapping your agent's behavior to AIUC-1 requirements.

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

### 2. Add Middleware

```python
from ancilis import AncilisMiddleware

# Wrap your MCP client connection
client = AncilisMiddleware(mcp_client)
```

Every tool call now flows through the security evaluation engine. In audit mode (the default), nothing is blocked — Ancilis observes, evaluates, and logs. You'll see a single summary line:

```
Ancilis: 47 tool calls evaluated. 0 issues. Run `ancilis status` for details.
```

### 3. Check Status

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 6 active, all passing
  AIUC-1: active
  Tool calls: 1,247 evaluated, 0 blocked

  Warnings:
    [scope] Agent called 'send_email' — not in approved tool list.
            To approve: ancilis approve-tool send_email
```

Every warning includes what to do about it. Approve the tool and the warning resolves:

```bash
ancilis approve-tool send_email
```

### 4. Deepen Coverage with Data Declarations

When your agent handles regulated data, declare it for overlay activation:

```yaml
agent:
  name: my-agent
certification_targets:
  - aiuc-1
my_agent_handles:
  - health_records
  - personal_info
```

One line added, compliance posture measurably improved. Ancilis activates HIPAA and GDPR overlays, tightens control thresholds, and adds framework-specific evidence fields — zero compliance knowledge required.

### Regulatory Coverage

#### SOC 2 Type II

The universal B2B SaaS compliance baseline. Activated by declaring any data type your agent handles.

```yaml
agent:
  name: my-agent
my_agent_handles:
  - personal_info
```

Ancilis maps all six controls to Trust Services Criteria and adds SOC 2-specific evidence fields to every record:

| Control | Trust Services Criteria |
|---|---|
| PR-01 Identity | CC6.1, CC6.2 |
| PR-02 Scope | CC6.1, CC6.3 |
| PR-03 Provenance | CC8.1 |
| PR-04 Exposure | CC6.7, CC6.1 |
| PR-05 Audit Trail | CC7.2, CC7.1 |
| DE-01 Detection | CC7.2, CC7.3, CC9.2 |

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 6 active, all passing
  SOC 2 Type II: active (personal_info)
  Tool calls: 1,247 evaluated, 0 blocked
```

SOC 2 activates on any of the 16 supported data types — if your agent touches any user or business data, declare it and SOC 2 coverage is automatic.

---

#### EU AI Act

For high-risk AI systems handling AI training data or biometric data. Activates strict thresholds, human oversight requirements, and 10-year evidence retention.

```yaml
agent:
  name: my-agent
my_agent_handles:
  - ai_training_data
```

Ancilis maps controls to EU AI Act articles and adds regulation-specific evidence fields:

| Control | EU AI Act Articles |
|---|---|
| PR-01 Identity | Art. 16 — Provider obligations |
| PR-02 Scope | Art. 9 — Risk management |
| PR-03 Provenance | Art. 15 — Accuracy and robustness |
| PR-04 Exposure | Art. 10 — Data governance |
| PR-05 Audit Trail | Art. 12, Art. 19 — Record-keeping |
| DE-01 Detection | Art. 9(2), Art. 72 — Ongoing monitoring |

Evidence records are automatically extended with `ai_decision_rationale`, `human_oversight_status`, `risk_level`, `drift_indicators`, and `bias_indicators`.

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 6 active, all passing (strict thresholds)
  EU AI Act: active (ai_training_data)
  Human oversight: required
  Evidence retention: 10 years
  Tool calls: 1,247 evaluated, 0 blocked
```

---

#### HIPAA / GDPR

Activated by health or personal data declarations. Tightens control thresholds and adds PHI/PII-specific evidence fields.

---

#### All Supported Data Types

| You Declare | Frameworks Activated |
|---|---|
| `personal_info` | SOC 2, GDPR |
| `health_records` | SOC 2, HIPAA, GDPR |
| `patient_data` | SOC 2, HIPAA, GDPR |
| `ai_training_data` | SOC 2, EU AI Act |
| `biometric_data` | SOC 2, EU AI Act |
| `credit_cards` | SOC 2 |
| `financial_records` | SOC 2 |
| Any other data type | SOC 2 |

**On the roadmap:**

PCI-DSS, GLBA, FedRAMP, CMMC, COPPA, FERPA, and additional frameworks. The overlay architecture is extensible — adding a new framework means adding a JSON profile, not changing the engine.

When a data type maps to a roadmap overlay, Ancilis tells you clearly:

```
? pci-dss would be activated by DC-FIN-01 via credit_cards but is not yet available
```

Baseline security controls are always active for every data type, regardless of overlay availability.

### 5. Export Posture Report

```bash
ancilis report --format pdf --period 90d
```

Hand this to your customer's procurement team. The report includes framework-by-framework compliance coverage, evidence counts, and hash chain verification — professional enough to attach to a procurement response.

## CLI

```bash
ancilis status                               # Current security posture (plain language)
ancilis status --verbose                     # Per-control detail with activation sources
ancilis config validate                      # Validate configuration
ancilis approve-tool <name>                  # Add tool to approved list
ancilis report --format terminal             # Quick review in terminal
ancilis report --format markdown             # Markdown for review
ancilis report --format pdf --period 30d     # PDF for procurement/audit
ancilis report --format aiuc1-readiness      # AIUC-1 certification readiness report
```

## Why Ancilis?

**The status quo is broken.** AI agents are making tool calls — reading databases, sending emails, modifying records — with no runtime security layer. Teams bolt on compliance after the fact: manual audits, spreadsheet evidence collection, and retroactive policy checks that can't keep pace with autonomous systems.

**Security should be inline, not after-the-fact.** Ancilis evaluates every tool call at execution time against a structured control set. There's no gap between what your agent does and what your security policy allows.

**Compliance should be a byproduct, not a project.** When every tool call is evaluated and every enforcement decision is recorded with full context, you already have the evidence. You don't need a separate compliance workstream — you need a report export.

**Certification in one config line.** Add `certification_targets: [aiuc-1]` and your agent is being evaluated against the first certifiable standard for AI agents. The readiness report tells you exactly where you stand — what's automated, what your team needs to document.

**Zero-friction entry, progressive disclosure.** Start with one line of config and audit mode. See your agent's security posture. Add certification targets when your customer asks. Declare data types for deeper regulatory coverage. Every step adds value without requiring the previous step to be exhaustive.

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
