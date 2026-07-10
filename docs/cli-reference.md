# CLI Reference

Install the CLI with `pip install ancilis`. All commands accept `--help`.

```bash
ancilis --version
ancilis --help
```

---

## `ancilis-cover`

`ancilis-cover` starts the official unified local MCP server for Cover onboarding, gap assessment, and runtime posture tools.

```bash
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

Cover exposes project inspection, classification, setup recommendation, explicit code review, onboarding report, gap assessment, and runtime posture tools. It is read-only: no network calls, no LLM calls, no MCP sampling, and no file writes.

---

## `ancilis serve`

`ancilis serve` remains available as a compatibility MCP entry point for one release. New MCP host configs should prefer `ancilis-cover`.

```bash
ancilis serve
```

---

## `ancilis shell`

Start a read-only interactive shell for inspecting local SDK state.

```bash
ancilis shell [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `--session TEXT` | Scope to a specific session ID |
| `--latest / --all` | Use the latest session (default) or all sessions |

First-slice commands:

```text
help
posture
config show
overlay list
evidence list [--limit N] [--tool NAME] [--decision ALLOW|BLOCK|FLAG] [--session ID]
evidence show <record_id>
evaluate <control_id>
exit
quit
```

The shell is read-only. It does not activate overlays, change config, rerun evaluations, or write evidence records.

---

## `ancilis status`

Show current agent security posture.

```bash
ancilis status [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Show detailed status with per-control breakdown |
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `--session TEXT` | Scope to a specific session ID |
| `--latest / --all` | Show latest session (default) or all sessions |

**Examples:**

```bash
# Basic posture summary
ancilis status

# Verbose with per-control breakdown
ancilis status --verbose

# Scope to a specific config and database
ancilis status --config path/to/ancilis.yaml --db path/to/evidence.duckdb

# Show all sessions, not just the latest
ancilis status --all
```

**Example output:**

```
Ancilis — my-agent
  Mode: audit
  Controls: 39 active, 39 pending
  Financial Services (GLBA, SOX, DORA): active — triggered by financial_records declaration
  SOC 2 Type II: active — triggered by financial_records declaration
  Tool calls: 5 evaluated, 0 blocked
  Sync: 10 pending, 0 failed
```

---

## `ancilis scan`

Evaluate evidence posture and return pass/fail for CI/CD pipelines.

```bash
ancilis scan [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--ci` | Machine-readable JSON output; exit code reflects compliance |
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `--session TEXT` | Scope to a specific session ID |
| `--latest / --all` | Show latest session (default) or all sessions |
| `--period TEXT` | Evidence window: `1h`, `24h`, `7d`, `30d` |

**Exit codes (with `--ci`):**

| Code | Meaning |
|------|---------|
| `0` | Compliant — all enabled controls pass |
| `1` | Non-compliant — one or more controls have violations |

**Examples:**

```bash
# Human-readable scan
ancilis scan --period 24h

# CI mode: JSON output + structured exit code
ancilis scan --ci --period 24h

# Scope to a specific session
ancilis scan --ci --session "$AGENT_SESSION_ID"

# Use in a pipeline (GitHub Actions)
ancilis scan --ci --period 24h > ancilis-scan.json
```

**JSON output schema (`--ci`):**

```json
{
  "version": "0.1.0",
  "agent": "my-agent",
  "mode": "audit",
  "timestamp": "2026-06-07T11:47:57.717831+00:00",
  "controls": [
    {
      "id": "PR-01",
      "name": "Action Authorization",
      "status": "pass",
      "evaluations": 5,
      "failures": 0,
      "flags": 0
    }
  ],
  "dependencies": {
    "posture": "skip",
    "findings": [
      {
        "result": "SKIP",
        "detail": "No dependency manifests found"
      }
    ]
  },
  "summary": {
    "total_controls": 39,
    "passing": 1,
    "failing": 0,
    "skipped": 38,
    "total_evaluations": 5
  },
  "posture": "compliant",
  "exit_code": 0
}
```

---

## `ancilis remediate`

Show remediation guidance for controls that are currently `GAP` or `PARTIAL` in
the selected evidence window.

```bash
ancilis remediate [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--latest / --all` | Show latest session (default) or all sessions |
| `--session TEXT` | Scope to a specific session ID |
| `--period TEXT` | Evidence window: `24h`, `7d`, `30d` |
| `--control TEXT` | Show guidance for one control ID, even with no current gap |
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |

Example output:

```text
PR-01 (Identity verification) — GAP
  Time: 5 minutes | Difficulty: Easy | Evidence: 1 evals, 1 failures, 0 flags
  How to fix:
    - Add or correct agent.name in ancilis.yaml.
    - Ensure your middleware or producer uses the same agent name when recording actions.
    - Re-run your agent and then run ancilis scan again.
```

The command uses local shared remediation content and current evidence summary
data. It does not change evidence records or create platform remediation tasks.

---

## `ancilis telemetry`

Inspect or change anonymous SDK telemetry settings. Telemetry is opt-in and
defaults to off. Consent is stored in `~/.ancilis/config.toml`; queued events are
kept locally under `~/.ancilis/telemetry/` and are sent silently at most once per
hour. `DO_NOT_TRACK` or `DNT` disables collection regardless of local consent.

```bash
ancilis telemetry status
ancilis telemetry on
ancilis telemetry off
ancilis telemetry flush
```

Telemetry events are coarse product-usage events such as `scan_executed`,
`report_generated`, `overlay_activated`, `adapter_used`, and `cli_command`.
They do not include file paths, file contents, evidence records, email
addresses, API keys, or platform account identifiers.

---

## `ancilis report`

Generate a posture report.

```bash
ancilis report [OPTIONS] [COMMAND]
```

| Option | Description |
|--------|-------------|
| `--latest / --all` | Show latest session (default) or all sessions |
| `--session TEXT` | Scope to a specific session ID |
| `--period TEXT` | Reporting period: `7d`, `30d`, `90d`, `365d` |
| `--format` | Output format: `terminal`, `markdown`, `pdf`, `aiuc1-readiness`, `ndjson`, `csv`, `oscal` |
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `-o, --output TEXT` | Output file path |

### `ancilis report generate`

Generate a posture report in the specified format.

```bash
# Terminal output (default)
ancilis report generate

# Markdown file
ancilis report generate --format markdown --output report.md

# PDF (requires pandoc + xelatex)
ancilis report generate --format pdf --output report.pdf

# AIUC-1 readiness report
ancilis report generate --format aiuc1-readiness

# Last 7 days
ancilis report generate --period 7d

# JSON lines (for machine processing)
ancilis report generate --format ndjson --output records.ndjson
```

!!! note "PDF prerequisites"
    PDF export requires `pandoc` and `xelatex`. Install with:
    ```bash
    brew install pandoc mactex  # macOS
    apt install pandoc texlive-xetex  # Debian/Ubuntu
    ```

---

## `ancilis approve-tool`

Approve a tool so it passes scope and provenance checks.

Adds the tool to `security.tools.allowed` in your config file. On the next middleware session, the tool will be recognized as operator-approved.

```bash
ancilis approve-tool [OPTIONS] TOOL_NAME
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |

**Examples:**

```bash
# Approve a tool that was blocked
ancilis approve-tool send-email

# Approve with a specific config
ancilis approve-tool send-email --config path/to/ancilis.yaml
```

After approval, the tool's description is hashed and stored. If the description changes later, PR-03 (Tool/Model Integrity and Provenance) will detect the mismatch.

---

## `ancilis doctor`

Run a practical local setup check for the Ancilis CLI and runtime assets.

```bash
ancilis doctor [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |

**Example:**

```bash
ancilis doctor
```

Checks: Python version, config validity, evidence store path, CLI dependencies (pandoc for PDF export), and control catalog integrity.

---

## `ancilis evidence`

Evidence store management commands.

### `ancilis evidence list`

List evidence records from the configured evidence store, newest first.

```bash
ancilis evidence list [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `--limit INTEGER` | Maximum records to return (default: `20`) |
| `--since TEXT` | Only include records at or after this ISO-8601 timestamp |
| `--agent-id TEXT` | Filter to a single agent ID |
| `--classification TEXT` | Filter by data classification code, such as `DC-PII` |
| `--control-id TEXT` | Filter by AKSI control ID, such as `PR-05` |
| `--format json\|table` | Output format (default: `table`) |

**Examples:**

```bash
ancilis evidence list --limit 10
ancilis evidence list --classification DC-PII --control-id PR-05
ancilis evidence list --since 2026-05-19T00:00:00+00:00 --format json
```

If no records match, the command prints `No evidence records found.` and exits successfully.

### `ancilis evidence show`

Show a full evidence record by exact ID or by a short prefix of at least seven
characters.

```bash
ancilis evidence show [OPTIONS] EVIDENCE_ID
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `--format json\|pretty` | Output format (default: `pretty`) |

**Examples:**

```bash
ancilis evidence show 9f2a4c1
ancilis evidence show 9f2a4c1 --format json
```

If a short prefix matches multiple records, the command exits non-zero and lists
the matching evidence IDs.

### `ancilis evidence sessions`

List known evidence sessions with record counts and time ranges.

```bash
ancilis evidence sessions [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |

**Example output:**

```
SESSION ID                                RECORDS  FIRST SEEN                LAST SEEN
----------------------------------------------------------------------------------------------------
68a36bf9-fc42-4598-9b15-4a0b399233d3            5  2026-06-07T11:45:07.257386+00:00  2026-06-07T11:46:41.237236+00:00
```

### `ancilis evidence reset`

Clear ALL evidence records and restart the hash chain from genesis.

```bash
ancilis evidence reset [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |
| `-y, --yes` | Skip confirmation prompt |

!!! warning
    This operation is irreversible. All evidence records are permanently deleted.

---

## `ancilis certify`

Report dry-run framework coverage from local evidence. In v0.1 this command
does not generate certification artifacts; it computes a per-control
`coverage_status` for the selected target. The possible values are `covered`,
`gap`, `pending`, `policy_gated`, `attestation_required`, `attestation_stale`, and
`attestation_incomplete`.

```bash
ancilis certify --target TARGET [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--target soc2\|hipaa\|pci\|aiuc1\|eu_ai_act` | Framework or certification target to evaluate |
| `--dry-run` | Accepted as a no-op; dry-run coverage is the v0.1 behavior |
| `--format json\|table` | Output format (default: `table`) |
| `--config TEXT` | Path to `ancilis.yaml` |
| `--db TEXT` | Path to evidence database |

**Examples:**

```bash
ancilis certify --target soc2
ancilis certify --target pci --format json --dry-run
```

**Example output (`--target soc2`):**

```text
control_id  framework_ref                         coverage_status           action_required           evidence_count  last_evidence_at
--------------------------------------------------------------------------------------------------------------------------------------------------
DE-01       CC7.2, CC7.3                          covered                   —                         20              2026-06-07T11:56:36.496535+00:00
DE-04       CC7.3                                 policy_gated              enable in policy          5               2026-06-06T10:04:00Z
GOV-04      CC1.4, CC4.1, CC4.2                   attestation_required      ancilis attest GOV-04     5               2026-06-06T10:04:00Z
PR-03       CC8.1                                 gap                       remediate                 5               2026-06-06T10:04:00Z
# ... rows truncated ...
```

Even with no evidence, `certify` does not list every control as a gap. An empty
store evaluates synthetic dry-run results, so in-scope controls resolve to a mix
of `covered`, `policy_gated`, and `attestation_required` (and zero `gap`
controls). Gaps appear only once evidence produces a failing or flagged result
for a control. The command exits successfully regardless.

---

## `ancilis config`

Configuration management commands.

### `ancilis config validate`

Validate `ancilis.yaml` configuration.

```bash
ancilis config validate [OPTIONS] [CONFIG_PATH_ARG]
```

| Option | Description |
|--------|-------------|
| `--config TEXT` | Path to `ancilis.yaml` |

**Examples:**

```bash
# Validate the default config
ancilis config validate

# Validate a specific file
ancilis config validate path/to/ancilis.yaml

# Validate with the --config flag
ancilis config validate --config examples/demo/ancilis.yaml
```

---

## `ancilis connect`

Connect this SDK to the optional Ancilis platform dashboard. The platform is
strictly optional — Ancilis evaluates actions and stores evidence fully locally
with nothing connected.

```bash
ancilis connect [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--api-key TEXT` | Platform API key (create one in the Ancilis dashboard Settings). When supplied, writes `~/.ancilis/platform.json`. |
| `--api-url TEXT` | Ancilis platform API base URL (default: `https://api.ancilis.ai`) |

With `--api-key`, the command writes `~/.ancilis/platform.json` (mode `0600`,
since it holds a secret) containing `api_url` and `api_key` so that `ancilis
doctor` and `ancilis sync` can reach the hosted platform. Without it, the command
reports the current connection status. It does not open a browser.

**Examples:**

```bash
# Report current connection status
ancilis connect

# Store platform credentials
ancilis connect --api-key sk-ancilis-...

# Point at a self-hosted platform
ancilis connect --api-key sk-ancilis-... --api-url https://ancilis.internal.example.com
```

---

## Global Options

All commands support:

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help for any command |

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANCILIS_CHAIN_KEY` | HMAC key for the evidence hash chain (v2). When unset, evidence is written with the legacy-unverified chain. | unset |
| `ANCILIS_NO_UPDATE_CHECK` | Disable the background CLI update check | unset |
