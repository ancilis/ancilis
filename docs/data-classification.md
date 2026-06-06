# Data Classification Guide

Ancilis uses data classification to automatically activate the right regulatory overlays for your agent. Declare what data your agent handles, and the controls, thresholds, evidence retention, and compliance reporting adjust without code changes.

## How it works

```
ancilis.yaml                  Taxonomy                    Overlays
┌──────────────────┐    ┌─────────────────┐    ┌───────────────────────┐
│ my_agent_handles:│    │ health_records  │    │ HIPAA: strict PR-01,  │
│   - health_records├───►│   → DC-PHI     ├───►│   PR-02, PR-04, PR-05 │
│   - personal_info │    │ personal_info   │    │ GDPR: strict PR-02,   │
│                  │    │   → DC-PII     ├───►│   PR-04, PR-05, DE-01 │
└──────────────────┘    └─────────────────┘    │ SOC 2: standard       │
                                               └───────────────────────┘
```

1. You declare data types in `my_agent_handles`
2. Each type maps to one or more **DC codes** (data classification codes)
3. DC codes trigger **overlays** (regulatory profiles)
4. Overlays adjust control thresholds, evidence retention, and reporting

## Declaring data types

Add `my_agent_handles` to your `ancilis.yaml`:

```yaml
agent:
  name: my-agent

my_agent_handles:
  - health_records
  - personal_info
```

Validate your declarations:

```bash
ancilis config validate
```

```
Ancilis config — my-agent
  Mode: audit
  Handles: health_records → DC-PHI, personal_info → DC-PII
  Overlays: hipaa, gdpr, soc2
  Controls: 39 active (PR-01, PR-02, PR-04, PR-05 at strict threshold)
  Evidence retention: 2190 days (HIPAA requirement)
```

## Data types reference

### Types that activate overlays

These data types trigger specific regulatory overlays with adjusted thresholds and evidence requirements.

| Data type | DC code | Overlays activated | Key requirements |
|-----------|---------|-------------------|------------------|
| `health_records` | DC-PHI | HIPAA, GDPR, SOC 2 | 6-year retention, strict identity/scope/exposure/audit |
| `patient_data` | DC-PHI | HIPAA, GDPR, SOC 2 | Same as health_records |
| `personal_info` | DC-PII | GDPR, SOC 2 | Strict scope/exposure/audit/anomaly detection |
| `credit_cards` | DC-CHD | PCI-DSS v4.0 | Strict on 6 controls, daily monitoring, Luhn detection |
| `financial_data` | DC-FIN | SOC 2 | Standard thresholds, 365-day retention |
| `financial_records` | DC-FIN | SOC 2 | Same as financial_data |
| `general` | DC-GEN | SOC 2 | Universal enterprise baseline |
| `public_data` | DC-GEN | SOC 2 | Baseline controls apply |
| `ai_training_data` | DC-AI | EU AI Act, ISO 42001 | 10-year retention (EU AI Act), human oversight required |
| `biometric_data` | DC-BIO | EU AI Act | 10-year retention, human oversight required |

### Government overlay types

These types activate CMMC Level 2, FedRAMP Rev 5 Moderate, or both overlays for government data handling. Government system data (`DC-GOV`) activates both overlays simultaneously.

| Data type | DC code | Active overlay |
|-----------|---------|----------------|
| `controlled_unclassified` | DC-CUI | CMMC Level 2 |
| `government_cui` | DC-GOV, DC-CUI | CMMC Level 2 |
| `government_documents` | DC-GOV, DC-CUI | CMMC Level 2, FedRAMP Rev 5 Moderate |
| `government_system` | DC-GOV | CMMC Level 2, FedRAMP Rev 5 Moderate |
| `federal_contract` | DC-FCI | FedRAMP Rev 5 Moderate |
| `federal_contract_info` | DC-FCI | FedRAMP Rev 5 Moderate |
| `federal_cloud` | DC-FCI, DC-GOV | FedRAMP Rev 5 Moderate |
| `fedramp_system` | DC-FCI, DC-GOV | FedRAMP Rev 5 Moderate |

### Securities overlay types

These types now activate the securities-market overlay for MNPI handling, disclosure controls, and seven-year evidence retention.

| Data type | DC code | Active overlay |
|-----------|---------|----------------|
| `material_nonpublic` | DC-MNPI | Securities Markets (SEC Reg FD, SOX) |
| `mnpi` | DC-MNPI | Securities Markets (SEC Reg FD, SOX) |

### Baseline-only types

These types are recognized and classified but don't currently trigger additional overlays beyond the 39 common baseline controls. Overlays for these types are on the roadmap.

| Data type | DC code | Future overlay |
|-----------|---------|----------------|
| `childrens_data` | DC-MINOR | COPPA, GDPR Art. 8, FERPA |
| `critical_infrastructure` | DC-CRIT | NERC CIP, NIS2 |
| `export_controlled` | DC-ITAR | ITAR, EAR |
| `legal_data` | DC-LEGAL | Attorney-client privilege |
| `legal_privileged` | DC-LEGAL | Attorney-client privilege |
| `trade_secrets` | DC-IP | Trade secret protection |

## DC codes explained

DC codes are the internal classification identifiers that bridge plain-language data types to regulatory requirements. You don't need to use DC codes directly — declare data types in plain language and Ancilis handles the mapping.

| DC Code | Name | Pattern detection |
|---------|------|-------------------|
| DC-PHI | Protected Health Information | ICD-10 codes, NPI numbers, MRN identifiers, clinical terms |
| DC-PII | Personally Identifiable Information | SSN, email, phone, passport, name-address co-occurrence |
| DC-CHD | Cardholder Data | Card numbers (Luhn), CVV, expiration dates |
| DC-FIN | Financial Services Data | Account numbers, routing numbers, SWIFT/BIC, IBAN |
| DC-GEN | General Business Data | No pattern detection (baseline only) |
| DC-AI | AI Training / Model Data | Declared classification only |
| DC-BIO | Biometric Data | Declared classification only |
| DC-CUI | Controlled Unclassified Information | Declared classification only |
| DC-MNPI | Material Non-Public Information | Declared classification (contextual) |
| DC-FCI | Federal Contract Information | Declared classification only |
| DC-GOV | Government System Data | Declared classification only |
| DC-ITAR | Export-Controlled Data | Declared classification only |
| DC-CRIT | Critical Infrastructure OT Data | Declared classification only |
| DC-MINOR | Children's Data | Declared classification (contextual) |
| DC-LEGAL | Legal Privileged Data | Declared classification (contextual) |
| DC-IP | Trade Secrets & Proprietary Data | Declared classification (organizational) |

## Overlays in detail

### SOC 2 Type II

The universal enterprise compliance baseline. Activated by: `general`, `public_data`, `personal_info`, `financial_data`, `financial_records`, `health_records`, `patient_data`.

- **Jurisdiction:** Global
- **Controls:** All 39 common controls at standard threshold
- **Evidence retention:** 365 days minimum
- **Key focus:** Trust Services Criteria — logical access, change management, monitoring, incident response

### PCI-DSS v4.0

The most concrete regulatory framework for agents handling payment data. Activated by: `credit_cards`.

- **Jurisdiction:** Global
- **Strict controls:** PR-01, PR-02, PR-04, PR-05, PR-07, DE-01
- **Evidence retention:** 365 days (3 months immediately available per Req 10.5.1)
- **Key focus:** Cardholder data protection — unique identity, least privilege, encryption in transit/at rest, daily log review, file integrity monitoring

### GDPR

EU data protection regulation. Activated by: `personal_info`, `health_records`, `patient_data`.

- **Jurisdiction:** EU (applies globally to data of EU residents)
- **Strict controls:** PR-02, PR-04, PR-05, DE-01
- **Evidence retention:** 365 days minimum
- **Key focus:** Lawful basis, purpose limitation, security of processing, data subject rights, 72-hour breach notification

### HIPAA Security Rule

US healthcare data protection. Activated by: `health_records`, `patient_data`.

- **Jurisdiction:** US (federal)
- **Strict controls:** PR-01, PR-02, PR-04, PR-05
- **Evidence retention:** 2190 days (6 years)
- **Key focus:** Person/entity authentication, minimum necessary standard, transmission security, audit controls

### EU AI Act

First regulation directly governing AI agent behavior. Activated by: `ai_training_data`, `biometric_data`.

- **Jurisdiction:** EU (applies globally to AI systems serving EU market)
- **Strict controls:** PR-01, PR-05, DE-01, GOV-04
- **Evidence retention:** 3650 days (10 years)
- **Human oversight required:** Yes (Art. 14)
- **Key focus:** Risk management, data governance, automatic logging, human oversight, post-market monitoring, serious incident reporting

### Securities Markets (MNPI, SEC Reg FD, SOX)

Activated by: `material_nonpublic`, `mnpi`.

- **Jurisdiction:** US
- **Strict controls:** PR-01, PR-02, PR-03, PR-04, PR-05, DE-01
- **Evidence retention:** 2555 days (7 years)
- **Key focus:** MNPI access control, information barriers, disclosure approvals, simultaneous-public-disclosure paths, and audit-ready evidence for market-sensitive workflows

### ISO/IEC 42001:2023

AI management system standard. Activated by: `ai_training_data`.

- **Jurisdiction:** Global
- **Controls:** All 39 common controls at standard threshold
- **Evidence retention:** 1095 days (3 years)
- **Key focus:** Management system scope, risk assessment, operational planning, internal audit, continual improvement

### NIST CSF 2.0

Always active as the baseline overlay. All AKSI controls are organized by CSF functions (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER).

- **Jurisdiction:** Global
- **Controls:** All 39 common controls at standard threshold
- **Evidence retention:** 365 days minimum
- **Key focus:** Framework alignment — familiar language for US federal contractors, self-assessment via CSF Profiles

## Common scenarios

### Healthcare agent

```yaml
agent:
  name: patient-assistant
  owner: clinical-ops@hospital.com
my_agent_handles:
  - health_records
  - personal_info
security:
  mode: enforce
  tools:
    allowed:
      - lookup_patient
      - get_diagnosis
      - schedule_appointment
```

Activates: HIPAA + GDPR + SOC 2. Evidence retained 6 years. Strict thresholds on identity, scope, exposure, and audit controls. Only listed tools execute.

### Payment processing agent

```yaml
agent:
  name: payment-agent
  owner: payments-team@company.com
my_agent_handles:
  - credit_cards
  - personal_info
security:
  mode: enforce
  tools:
    allowed:
      - process_payment
      - lookup_order
      - send_receipt
  scope:
    blocked_destinations:
      - "*.external.io"
```

Activates: PCI-DSS v4.0 + GDPR + SOC 2. Strict thresholds on 6 controls. Credit card patterns detected via Luhn validation. External destinations blocked.

### AI/ML pipeline agent

```yaml
agent:
  name: training-pipeline
  owner: ml-team@company.com
my_agent_handles:
  - ai_training_data
  - personal_info
security:
  mode: audit
```

Activates: EU AI Act + ISO 42001 + GDPR + SOC 2. 10-year evidence retention. Human oversight required (EU AI Act Art. 14). Start in audit mode to observe before enforcing.

### General enterprise agent

```yaml
agent:
  name: support-bot
  owner: support-team@company.com
my_agent_handles:
  - general
```

Activates: SOC 2. Standard thresholds. 365-day retention. The most common starting point for enterprise agents.

## Combining with certification targets

Data classification and certification targets compose. Use both when you want overlay-driven compliance plus certification readiness:

```yaml
agent:
  name: certified-agent
my_agent_handles:
  - health_records
  - personal_info
certification_targets:
  - aiuc-1
```

This activates HIPAA, GDPR, SOC 2 overlays (from data classification) plus AIUC-1 certification requirements (from certification target). The strictest threshold and longest retention always win.

## Runtime pattern detection

For data types with pattern detection (DC-PHI, DC-PII, DC-CHD, DC-FIN), PR-04 scans outbound tool call parameters in real time. If your agent sends data matching these patterns to an unauthorized destination, the evaluation fails.

The response scanner also monitors MCP tool responses for sensitive patterns and encryption findings. Recommendations are surfaced via `middleware.get_recommendations()`.

If Ancilis detects patterns that don't match your declarations, it recommends adding the appropriate data type:

```
Recommendation: Detected email patterns in tool responses.
Consider adding 'personal_info' to my_agent_handles in ancilis.yaml.
```

## Validation

Invalid data types produce clear error messages:

```bash
$ ancilis config validate
# With: my_agent_handles: [medical]
# Error: Unknown data type in my_agent_handles: 'medical'. Valid types: ai_training_data, biometric_data, ...
```

The validator checks data types against the taxonomy at `shared/classifications/taxonomy.json`.
