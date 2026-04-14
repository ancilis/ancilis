# Evidence and Reporting

Every tool call evaluation produces a hash-chained evidence record stored in a local DuckDB database. The CLI reads that store to generate status output and compliance reports.

## Evidence records

Each evaluation produces an `EvidenceRecord` with:

| Field | Description |
|-------|-------------|
| `record_id` | Unique identifier for this record |
| `evaluation_id` | Links to the evaluation that produced it |
| `timestamp` | ISO 8601 timestamp |
| `agent_id` | Agent that made the tool call |
| `source_type` | Producer type (framework, mcp, cli, http) |
| `tool_name` | Name of the tool called |
| `decision` | ALLOW or BLOCK |
| `mode` | audit or enforce |
| `control_results` | Per-control evaluation results (JSON) |
| `active_overlays` | Overlays active at evaluation time |
| `data_classifications` | Data classifications active |
| `active_certifications` | Certification targets active |
| `record_hash` | SHA-256 hash of this record |
| `previous_hash` | Hash of the previous record (chain link) |
| `total_duration_ms` | Evaluation duration |

## Hash chain

Evidence records form a cryptographic hash chain. Each record's hash includes the previous record's hash, creating a tamper-evident sequence. The genesis record chains from a fixed seed value.

Verification:

```bash
ancilis status --verbose
```

Shows `hash chain intact` or `hash chain BROKEN` if tampering is detected.

The chain integrity is also verified during report generation.

**Trust boundary**: The hash chain detects modification after the fact. It does not prevent replacement of the entire database by an attacker with host access.

## Evidence storage

Default path: `~/.ancilis/{agent_name}-{cwd_hash}/evidence.duckdb`

The `cwd_hash` disambiguates agents with the same name in different projects.

You can query evidence directly with DuckDB:

```python
import duckdb

conn = duckdb.connect("~/.ancilis/my-agent-a1b2c3d4/evidence.duckdb")
result = conn.execute("SELECT tool_name, decision, COUNT(*) FROM evidence_records GROUP BY tool_name, decision").fetchall()
for row in result:
    print(row)
```

## CLI reporting

### `ancilis status`

Shows current agent security posture in plain language.

```bash
ancilis status
```

```
Ancilis — my-agent
  Mode: audit
  Controls: 26 active, all passing
  Tool calls: 42 evaluated, 0 blocked
```

With `--verbose`, shows per-control breakdown and activation details.

On empty store: `"No evaluations recorded yet. Run your agent with Ancilis to start collecting evidence."`

### `ancilis report`

Generates posture reports with framework-by-framework compliance coverage.

```bash
# Terminal format (default)
ancilis report

# Markdown for review
ancilis report --format markdown -o report.md

# AIUC-1 certification readiness
ancilis report --format aiuc1-readiness

# OSCAL Assessment Results JSON
ancilis report generate --format oscal -o report.oscal.json

# PDF for procurement (requires pandoc)
ancilis report --format pdf -o report.pdf

# Custom period
ancilis report --period 90d
```

Report sections:

1. **Baseline security** — all controls, pass rates, tools evaluated
2. **Compliance posture** — per-overlay sections with regulatory citations (when overlays are active)
3. **Certification readiness** — requirement-by-requirement coverage (when certification targets are active)
4. **Evidence integrity** — record count and hash chain status

### `ancilis report` output structure

Terminal reports show control IDs and regulatory citations. This is the auditor-facing view — control IDs are appropriate here.

```
HIPAA Security Rule Compliance Posture
Activated by: health_records declaration
Controls at strict threshold: PR-01, PR-02, PR-04, PR-05

  164.312(d)  ✓ PR-01: 42 evaluations, 100.0% pass
  164.312(a)(1), 164.308(a)(3)  ✓ PR-02: 42 evaluations, 100.0% pass
  ...
  Evidence retention: 2190 days ✓
```

### Report periods

Reports are filtered by time period. Default is 30 days.

```bash
ancilis report --period 7d    # Last 7 days
ancilis report --period 90d   # Last 90 days
ancilis report --period 365d  # Last year
```

Evidence chain verification always runs against the full store regardless of the period filter.

## Platform exports

Use `ancilis report export` to download server-rendered evidence exports from the Ancilis platform.

```bash
ancilis report export --format oscal --period 30d \
  --api-url https://app.ancilis.ai \
  --auth-token "$ANCILIS_JWT" \
  --output report.oscal.json
```

Supported export formats are `csv`, `ndjson`, and `oscal`.
