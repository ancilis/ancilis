# CI/CD Integration Guide

Run Ancilis compliance checks automatically on every pull request — compliance-as-code that catches policy violations before they reach production.

---

## Overview

`ancilis scan` evaluates the evidence your agent accumulated during its last run and returns a structured pass/fail result. In CI/CD mode (`--ci`), it outputs machine-readable JSON and exits with a code your pipeline can act on:

| Exit code | Meaning |
|-----------|---------|
| `0` | Compliant — all enabled controls pass |
| `1` | Non-compliant — one or more controls have violations |
| `2` | Configuration error — `ancilis.yaml` missing or invalid |

This makes it trivial to gate merges on compliance posture.

---

## Prerequisites

- Python 3.10 or later
- `ancilis.yaml` committed to your repository root (or accessible at a known path)
- An evidence database (`.duckdb`) populated by your agent during its run

---

## Quick Start

Minimal GitHub Actions example — add this to `.github/workflows/compliance.yml`:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
- run: pip install ancilis
- run: ancilis scan --ci --period 24h
```

That's it. The job fails on violations, passes when compliant.

---

## Setup

### Install

```sh
pip install ancilis
```

### Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANCILIS_CONFIG` | Path to `ancilis.yaml` | `./ancilis.yaml` |
| `ANCILIS_DB` | Path to evidence database | `./ancilis-evidence.duckdb` |

Pass these as CI/CD secrets or job-level environment variables.

### Minimal `ancilis.yaml`

```yaml
agent_name: my-agent
mode: audit          # or enforce
controls:
  PR-01:
    enabled: true
  DE-01:
    enabled: true
```

---

## Configuration

### Selecting a time window

Use `--period` to scope the evidence evaluated:

```sh
ancilis scan --ci --period 1h    # last hour
ancilis scan --ci --period 24h   # last 24 hours (recommended for PRs)
ancilis scan --ci --period 7d    # last week
```

### Scoping to a session

If your agent writes evidence under a session ID, scope the scan to that session to avoid stale evidence from earlier runs:

```sh
ancilis scan --ci --session "$AGENT_SESSION_ID"
```

### Choosing a mode

- **`audit`** — records violations but does not block agent tool calls. Use this when introducing Ancilis for the first time.
- **`enforce`** — blocks tool calls that violate controls. Violations in enforce mode always fail `ancilis scan`.

Set `mode` in `ancilis.yaml`. You can run the scan in either mode; the scan result reflects what the agent actually did.

---

## Interpreting Results

### JSON output schema

`ancilis scan --ci` writes to stdout:

```json
{
  "version": "0.1.0",
  "agent": "my-agent",
  "mode": "audit",
  "timestamp": "2026-04-07T03:00:00+00:00",
  "controls": [
    {
      "id": "PR-01",
      "name": "Tool Call Approval",
      "status": "pass",
      "evaluations": 12,
      "failures": 0,
      "flags": 0
    }
  ],
  "summary": {
    "total_controls": 3,
    "passing": 2,
    "failing": 0,
    "skipped": 1,
    "total_evaluations": 24
  },
  "posture": "compliant",
  "exit_code": 0
}
```

### Control statuses

| Status | Meaning |
|--------|---------|
| `pass` | No failures in the evidence window |
| `fail` | One or more FAIL or ERROR evaluations |
| `skip` | No evidence recorded for this control |

A `skip` does **not** fail the scan — it means the control had no activity to evaluate. If you expect evidence and see `skip`, check that your agent is writing to the configured database path.

### Controls reference

| ID | Name | What it checks |
|----|------|----------------|
| `PR-01` | Tool Call Approval | Tool calls were approved before execution |
| `PR-02` | Input Validation | Inputs were validated against policy |
| `PR-03` | Output Inspection | Outputs were inspected before use |
| `PR-04` | Scope Enforcement | Tool calls stayed within declared scope |
| `PR-05` | Rate Limiting | Call rates stayed within configured limits |
| `DE-01` | Data Exfiltration | No prohibited data left the agent boundary |

---

## Platform Examples

Ready-to-use files in `examples/ci/`:

| File | Platform |
|------|----------|
| [`examples/ci/github-actions.yml`](../examples/ci/github-actions.yml) | GitHub Actions — full workflow with PR comment |
| [`examples/ci/gitlab-ci.yml`](../examples/ci/gitlab-ci.yml) | GitLab CI — job with artifacts and dotenv report |
| [`examples/ci/compliance-check.sh`](../examples/ci/compliance-check.sh) | Generic shell script — any CI platform |

---

## Advanced

### Custom overlay profiles

Activate a compliance overlay (e.g. financial regulations) in `ancilis.yaml`:

```yaml
overlays:
  financial:
    enabled: true
    regulations: [GLBA, SOX, DORA]
```

The scan evaluates the active overlay's additional controls alongside the base set.

### Multi-agent pipelines

Each agent writes evidence to its own session. Scan them independently:

```sh
ancilis scan --ci --session "$AGENT_A_SESSION" --db agent-a.duckdb
ancilis scan --ci --session "$AGENT_B_SESSION" --db agent-b.duckdb
```

Or aggregate evidence from all sessions by omitting `--session`.

### Evidence export for audit

Export the evidence database for long-term retention:

```sh
# Save the DuckDB file as a pipeline artifact
cp ancilis-evidence.duckdb "$ARTIFACT_DIR/evidence-$(date +%Y%m%d).duckdb"
```

The file contains an SHA-256 hash chain. Each row's `evidence_hash` covers all previous rows, so tampering is detectable.

### Introducing Ancilis without blocking PRs

Start in audit mode and use `allow_failure: true` (GitLab) or `continue-on-error: true` (GitHub Actions) while you tune thresholds. Once you trust the signal, flip `allow_failure: false` and set `mode: enforce` in `ancilis.yaml`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Exit code 2, no JSON output | `ancilis.yaml` not found | Set `ANCILIS_CONFIG` to the correct path |
| All controls show `skip` | Evidence DB is empty or wrong path | Confirm `ANCILIS_DB` points to the file your agent wrote |
| Scan passes but agent blocked calls | Mode is `audit` — scan only sees evidence, not blocked calls | Check `mode: enforce` if you want blocks to fail the scan |
| `ancilis: command not found` | Pip install not in `PATH` | Add `$(python -m site --user-base)/bin` to `PATH`, or use `python -m ancilis` |
| Evidence from previous run is included | No session scoping | Use `--session` to pin to the current agent run |
