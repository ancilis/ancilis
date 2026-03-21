# Data Classification Example

Declare what data your agent handles. Get the right compliance controls automatically.

## What this demonstrates

Your agent handles health records and personal information. You shouldn't need to know which regulations apply — that's Ancilis's job.

The flow:

1. Config declares `my_agent_handles: [health_records, personal_info]`
2. HIPAA, GDPR, and SOC 2 overlays activate automatically
3. Approved tool calls pass through with compliance evidence
4. Unauthorized tools are blocked in enforce mode
5. `ancilis report` shows per-framework compliance posture with regulatory citations

## Prerequisites

```bash
pip install ancilis
```

## Run

```bash
cd examples/data-classification
python run.py
```

## Config

```yaml
agent:
  name: health-agent
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

Two lines in `my_agent_handles`. Three overlays activated. No framework crosswalking.

## Expected output

```
=== Data Classification Example ===
Agent: health-agent
Mode: enforce
Data handled: health_records, personal_info

Overlays activated automatically:
  GDPR — triggered by health_records, personal_info declaration
  HIPAA Security Rule — triggered by health_records declaration
  SOC 2 Type II — triggered by health_records, personal_info declaration

Running approved tool calls...
  lookup_patient('P-1234') -> {'id': 'P-1234', 'name': 'Jane Smith', ...}
  get_diagnosis('P-1234') -> Type 2 diabetes, managed with metformin 500mg BID
  schedule_appointment('P-1234', '2026-04-01') -> Appointment scheduled for P-1234 on 2026-04-01

Attempting unauthorized tool call (enforce mode)...
  Ancilis [blocked]: Action 'export_all_records' blocked — scope enforcement, tool provenance check.
  To approve: ancilis approve-tool export_all_records
  To review: ancilis status

=== Evidence Summary ===
  Records: 4
  Decisions: {'BLOCK': 1, 'ALLOW': 3}
  Hash chain: intact
```

## What happened

- `health_records` maps to HIPAA and GDPR regulatory overlays
- `personal_info` maps to GDPR and SOC 2 overlays
- Approved tools pass scope and provenance checks — evidence recorded
- `export_all_records` is not in the allowed list — blocked with an actionable message
- The HIPAA compliance posture shows regulatory citations (HIPAA Security Rule §164.312)
- Evidence retention automatically set to 2190 days (6 years) per HIPAA requirements

## Data types you can declare

| Type | Overlays activated |
|------|-------------------|
| `credit_cards` | PCI-DSS v4 |
| `personal_info` | SOC 2 Type II, GDPR |
| `health_records` | SOC 2 Type II, HIPAA, GDPR |
| `patient_data` | SOC 2 Type II, HIPAA, GDPR |
| `ai_training_data` | ISO 42001, EU AI Act |
| `biometric_data` | EU AI Act |
| `financial_records` | SOC 2 Type II |

23 data types are supported. See `shared/classifications/taxonomy.json` for the complete list.
