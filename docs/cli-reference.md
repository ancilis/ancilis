# CLI Reference

Install the CLI with `pip install ancilis`. All commands accept `--help`.

```bash
ancilis --version
ancilis --help
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
| `--config TEXT` | Path to `ancilis.yaml` (default: `./ancilis.yaml`) |
| `--db TEXT` | Path to evidence database (default: `./ancilis-evidence.duckdb`) |
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
Ancilis status for my-agent
Evidence store: 847 records (DuckDB, hash-chained)
Chain integrity: valid

Active controls: PR-01, PR-02, PR-03, PR-04, PR-05, DE-01
Active overlays: SOC 2, PCI-DSS

Sessions: 1
  session-abc123   847 records   2026-04-07 10:00 → 2026-04-07 11:30

Posture: COMPLIANT (4 ALLOW, 2 BLOCK in last session)
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
| `2` | Configuration error — `ancilis.yaml` missing or invalid |

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
  "mode": "enforce",
  "posture": "compliant",
  "summary": {
    "total_controls": 6,
    "passing": 6,
    "failing": 0,
    "skipped": 0,
    "total_evaluations": 847
  },
  "controls": [
    {
      "id": "PR-01",
      "name": "Tool Call Approval",
      "status": "pass",
      "evaluations": 847,
      "failures": 0,
      "flags": 0
    }
  ],
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
| `--format` | Output format: `terminal`, `markdown`, `pdf`, `aiuc1-readiness`, `ndjson`, `csv` |
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

After approval, the tool's description is hashed and stored. If the description changes later, PR-03 (Tool Provenance Verification) will detect the mismatch.

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
Sessions in ancilis-evidence.duckdb:

  session-abc123   847 records   2026-04-07 10:00 → 2026-04-07 11:30
  session-def456   312 records   2026-04-06 09:15 → 2026-04-06 10:00
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

Connect to the Ancilis platform dashboard.

```bash
ancilis connect
```

Opens the browser to the Ancilis platform and authenticates with your local evidence store. Requires an active platform account.

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
| `ANCILIS_CONFIG` | Path to `ancilis.yaml` | `./ancilis.yaml` |
| `ANCILIS_DB` | Path to evidence database | `./ancilis-evidence.duckdb` |
