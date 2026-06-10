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
| `source_type` | Producer type (`agent` by default; e.g. `mcp`, `dependency_scan`, or an importer type) |
| `tool_name` | Name of the tool called |
| `decision` | ALLOW, BLOCK, or FLAG |
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

Shows the hash-chain status: `verified (HMAC)` for keyed records, `legacy-unverified`
for legacy (unkeyed v1) records, `reset/purged` when the store was wiped via a
signed checkpoint, or `BROKEN` if tampering is detected.

The chain integrity is also verified during report generation.

**Trust boundary**: New records use an HMAC-SHA256 keyed hash chain. With the chain key (held outside the DB), per-record tampering and forgery are detected. Without a key, records fall back to legacy unkeyed SHA-256 and `verify_chain` reports them as *legacy-unverified* — a writer-capable attacker can forge a record and re-chain it, not just replace the whole database. See [limitations](limitations.md) for the full boundary.

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
  Controls: 39 active, 11 runtime-verified, 27 pending, 1 flagged
  Tool calls: 42 evaluated, 0 blocked
  Sync: 42 pending, 0 failed
```

With `--verbose`, shows per-control breakdown and activation details.

On empty store: `"No evaluations recorded yet. Run your agent with Ancilis to start collecting evidence."`

### `ancilis evidence list`

Lists recent evidence records directly from the local DuckDB store.

```bash
ancilis evidence list --limit 10
ancilis evidence list --classification DC-PII --control-id PR-05
ancilis evidence list --format json
```

The table view includes timestamp, short evidence ID, agent ID, source type,
classification, control ID, and status. JSON output returns full evidence
records.

### `ancilis evidence show`

Shows the full evidence record by exact ID or a short prefix of at least seven
characters.

```bash
ancilis evidence show 9f2a4c1
ancilis evidence show 9f2a4c1 --format json
```

Pretty output includes classification metadata, control results, source
provenance when present, and framework mappings derived from active overlays and
certification targets.

### `ancilis certify`

Computes dry-run framework coverage from local evidence.

```bash
ancilis certify --target soc2
ancilis certify --target pci --format json --dry-run
```

The command reports each in-scope AKSI control's coverage status — `covered`,
`policy_gated`, `attestation_required`, `attestation_stale`,
`attestation_incomplete`, or `gap` — along with the action required, evidence
count, and the latest evidence timestamp. If no evidence exists, all in-scope
controls are listed as gaps.

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

The terminal and markdown formats render compliance posture differently. The terminal format is a compact at-a-glance view; the markdown format is the detailed auditor-facing view with regulatory citations.

**Terminal format** (`--format terminal`) leads with "Ancilis Posture Report" and renders a "Compliance Matrix:" grid — one row per control, one column per active overlay, with `✓`/`-` cells showing whether each control passes for that overlay:

```
Ancilis Posture Report — my-agent
Period: 2026-05-08 to 2026-06-07
Mode: audit
Posture: HEALTHY (1/39 controls passing)
Evaluations: 15 total | 0 blocked | 15 allowed
Active overlays: Financial Services (GLBA, SOX, DORA), SOC 2 Type II
Active certifications: none
Evidence chain: ✓ legacy-unverified (set ANCILIS_CHAIN_KEY) (15 records)

Baseline Controls:
  ✓ 1 controls passing (full detail preserved in markdown)
Tools evaluated: dependency-scanner

Compliance Matrix:
  Control | Financial Services (GLBA, SOX, DORA) | SOC 2 Type II
  DE-01   | ✓                                    | ✓            
  DE-02   | -                                    | -            
  DE-03   | -                                    | -            
  ...  # truncated: one row per control through RS-06
```

**Markdown format** (`--format markdown`) emits a per-overlay "_X_ Compliance Posture" section with `Activated by:`, `Controls at strict threshold:`, an `Evidence retention:` line, and a citation table keyed `| Citation | Control | Type | Evaluations | Pass Rate |`:

```markdown
## Financial Services (GLBA, SOX, DORA) Compliance Posture

**Activated by:** financial_records declaration  
**Controls at strict threshold:** DE-01, PR-01, PR-02, PR-04, PR-05  

Ancilis provides runtime evidence for 18 of 39 mapped criteria; the remaining 21 are organizational controls it does not assess (evidenced by attestation).

| Citation | Control | Type | Evaluations | Pass Rate |
|----------|---------|------|-------------|-----------|
| GLBA 16 CFR 314.4(c)(8), 314.4(h), SOX §404, DORA Art.10, Art.17, Art.19 | DE-01 | runtime | 15 | 0.0% |
| GLBA 16 CFR 314.4(d), SOX §404, DORA Art.9, Art.15 | DE-02 | runtime | 0 | - |
| ...  # truncated: one row per mapped control through RS-06 |

Evidence retention: 2555 days configured, 2555 required ✓
Enforce the window with: ancilis evidence prune
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
