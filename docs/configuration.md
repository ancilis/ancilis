# Configuration Reference

Ancilis is configured through `ancilis.yaml` in your project root. The config is validated with Pydantic and resolved into a runtime configuration that determines which controls, overlays, and certifications are active.

## Minimal config

```yaml
config_version: 2

agent:
  name: my-agent
```

This activates the 39 common AKSI v0.6 controls in audit mode. Every tool call is evaluated and evidence-recorded.

## Full config structure

```yaml
config_version: 2              # Schema version. Unversioned files are treated as v1.

agent:
  name: my-agent              # Required. Identifies your agent in evidence records.
  description: ""              # Optional. Human-readable description.
  owner: ""                    # Optional. Team or individual responsible.

security:
  mode: audit                  # "audit" (default) or "enforce"
  tools:
    allowed: []                # Tools permitted to execute
    blocked: []                # Tools explicitly forbidden (takes precedence over allowed)
  scope:
    max_actions_per_minute: null  # Rate limit (null = no limit)
    allowed_destinations: []      # Allowed URL/host destinations
    blocked_destinations: []      # Blocked URL/host destinations
  controls:                    # Per-control overrides
    PR-01:
      enabled: true            # Disable individual controls if needed

my_agent_handles: []           # Data types your agent processes
certification_targets: []      # Certification standards to target

compliance:
  overlays: null               # Explicit overlay selection (null = auto from data types)
  evidence:
    storage: local             # Evidence storage backend
    retention_days: 365        # Minimum retention (overlays may increase this)
```

## Config fields

### `config_version`

`config_version: 2` is the current schema version. Older unversioned configs are treated as v1 and are migrated in memory by the SDK. To preview or write the migration with a backup:

```bash
ancilis config migrate --config ancilis.yaml
ancilis config migrate --config ancilis.yaml --apply
```

`--apply` writes `ancilis.yaml.bak` before replacing the file.

### `agent` (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Agent identifier. Used in evidence records and CLI output. |
| `description` | string | no | Human-readable description. |
| `owner` | string | no | Team or individual responsible for this agent. |

### `security`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"audit"` | `"audit"` logs everything, blocks nothing. `"enforce"` blocks policy violations. |
| `tools.allowed` | list | `[]` | Tools permitted to execute. Empty = all tools allowed (scope check passes). |
| `tools.blocked` | list | `[]` | Tools explicitly forbidden. Takes precedence over `allowed`. |
| `scope.max_actions_per_minute` | int or null | `null` | Rate limit per agent. `null` = no limit. |
| `scope.allowed_destinations` | list | `[]` | URL/host allowlist for HTTP producer. |
| `scope.blocked_destinations` | list | `[]` | URL/host blocklist for HTTP producer. |

### `my_agent_handles`

A list of plain-language data type names. Each type maps to one or more regulatory overlays that activate automatically.

```yaml
my_agent_handles:
  - health_records      # HIPAA, GDPR, SOC 2
  - personal_info       # GDPR, SOC 2
  - credit_cards        # PCI-DSS v4
```

#### Available data types

| Type | Overlays activated |
|------|-------------------|
| `ai_training_data` | EU AI Act, ISO 42001 |
| `biometric_data` | EU AI Act |
| `credit_cards` | PCI-DSS v4 |
| `financial_data` | SOC 2 Type II |
| `financial_records` | SOC 2 Type II |
| `general` | SOC 2 Type II |
| `government_cui` | CMMC Level 2 |
| `government_documents` | CMMC Level 2 |
| `government_system` | CMMC Level 2 |
| `health_records` | HIPAA, GDPR, SOC 2 Type II |
| `patient_data` | HIPAA, GDPR, SOC 2 Type II |
| `personal_info` | GDPR, SOC 2 Type II |
| `public_data` | SOC 2 Type II |
| `childrens_data` | baseline only |
| `controlled_unclassified` | CMMC Level 2 |
| `critical_infrastructure` | baseline only |
| `export_controlled` | baseline only |
| `federal_contract` | baseline only |
| `federal_contract_info` | baseline only |
| `legal_data` | baseline only |
| `legal_privileged` | baseline only |
| `material_nonpublic` | Securities Markets (SEC Reg FD, SOX) |
| `mnpi` | Securities Markets (SEC Reg FD, SOX) |
| `trade_secrets` | baseline only |

Types marked "baseline only" are recognized and classified but don't currently trigger an overlay beyond the 26 baseline controls. They will activate overlays as those profiles are implemented. Government and CUI-oriented types now activate the `cmmc-l2` overlay, and MNPI-oriented types now activate the `securities-mnpi` overlay.

### `certification_targets`

```yaml
certification_targets:
  - aiuc-1
```

Currently available targets:

| Target | Standard | Controls activated |
|--------|----------|-------------------|
| `aiuc-1` | AIUC-1 AI Agent Certification Standard | PR-01, PR-02, PR-03, PR-04, PR-05, DE-01 |

Certification targets compose with data classification — you can use both.

### `compliance`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `overlays` | list or null | `null` | Explicit overlay selection. `null` = auto-detect from `my_agent_handles`. |
| `evidence.storage` | string | `"local"` | Evidence storage backend. Only `"local"` is supported. |
| `evidence.retention_days` | int | `365` | Minimum evidence retention. Overlays may increase this (e.g., HIPAA requires 2190 days). |

## Two activation paths

### Path A: Certification intent

```yaml
certification_targets:
  - aiuc-1
```

Controls required by the certification standard activate. Evidence mapping and readiness reporting are automatic. You don't need to know which controls map to which requirements.

### Path B: Data classification

```yaml
my_agent_handles:
  - health_records
```

Overlays (HIPAA, GDPR, SOC 2) activate based on data type declarations. Threshold adjustments, regulatory citations, and evidence retention requirements are applied from the overlay profiles.

### Path A + B combined

```yaml
certification_targets:
  - aiuc-1
my_agent_handles:
  - health_records
  - personal_info
```

Both paths compose. Certification controls activate alongside data-driven overlays. The strictest threshold and longest retention always win.

## Validation

```bash
ancilis config validate
ancilis config validate --verbose
```

Produces actionable error messages for common mistakes:

- Missing `agent.name`: `"Fix: add 'agent: { name: my-agent }' to ancilis.yaml"`
- Unknown data type: `"Unknown data type in my_agent_handles: 'medical'. Valid types: ai_training_data, biometric_data, ..."`
- Invalid mode: `"security.mode must be 'audit' or 'enforce'"`
- Unrecognized certification target: `"certification_targets contains unrecognized value 'aiuc-2'. Available targets: aiuc-1"`
- Unknown key typo: `"Unknown key 'agent.nme'. Did you mean 'agent.name'?"`
- Unknown overlay: `"Unknown overlay profile 'fedram'. Did you mean 'fedramp'?"`

## Global SDK telemetry

Anonymous SDK telemetry is controlled outside project `ancilis.yaml` files so it
does not change repository state. It defaults to off and stores consent in
`~/.ancilis/config.toml`.

```bash
ancilis telemetry status
ancilis telemetry on
ancilis telemetry off
```

When enabled, the SDK queues coarse events such as `scan_executed`,
`report_generated`, `overlay_activated`, and `cli_command` under
`~/.ancilis/telemetry/`. Events never include file paths, file contents, evidence
records, API keys, email addresses, or platform account identifiers. Setting
`DO_NOT_TRACK` or `DNT` disables collection even when local consent is on.
