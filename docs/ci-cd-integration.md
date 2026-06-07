# CI/CD Integration Guide

Run Ancilis compliance checks automatically on every pull request — compliance-as-code that catches policy violations before they reach production.

---

## Overview

`ancilis scan` evaluates the evidence your agent accumulated during its last run and returns a structured pass/fail result. In CI/CD mode (`--ci`), it outputs machine-readable JSON and exits with a code your pipeline can act on:

| Exit code | Meaning |
|-----------|---------|
| `0` | Compliant — no enabled control has violations |
| `1` | Non-compliant — one or more controls have violations (or a tool call was blocked) |

If `ancilis.yaml` is missing or cannot be loaded, the scan falls back to a default configuration rather than erroring out.

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
| `ANCILIS_CHAIN_KEY` | HMAC key for keyed (v2) tamper-evident evidence chains | unset (legacy unkeyed SHA-256) |
| `ANCILIS_NO_UPDATE_CHECK` | Set to disable the background update check | unset |
| `ANCILIS_TELEMETRY_DISABLE_PROMPT` | Suppress the first-run anonymous-telemetry prompt | unset |

Pass these as CI/CD secrets or job-level environment variables.

The config and evidence-database paths are **not** environment variables — pass them with the `--config` and `--db` CLI options. If `--db` is omitted, the store defaults to `~/.ancilis/<agent-name>-<cwd-hash>/evidence.duckdb`.

### Minimal `ancilis.yaml`

```yaml
agent:
  name: my-agent
security:
  mode: audit        # or enforce
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

Set `security.mode` in `ancilis.yaml`. You can run the scan in either mode; the scan result reflects what the agent actually did.

---

## Interpreting Results

### JSON output schema

`ancilis scan --ci` writes to stdout:

All common controls are enabled by default (opt-out) — a typical scan reports every control in the active framework (~39 for the base set), most of them `skip` until evidence accumulates:

```json
{
  "version": "0.1.0",
  "agent": "my-agent",
  "mode": "audit",
  "timestamp": "2026-06-07T12:07:00.743334+00:00",
  "controls": [
    {
      "id": "DE-01",
      "name": "Behavioral Anomaly Detection",
      "status": "pass",
      "evaluations": 15,
      "failures": 0,
      "flags": 0
    },
    {
      "id": "DE-02",
      "name": "Classification Drift and Boundary Validation",
      "status": "skip",
      "evaluations": 0,
      "failures": 0,
      "flags": 0
    }
    // ... 37 more controls, mostly "skip" until evidence is recorded ...
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
    "total_evaluations": 15
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
| `PR-01` | Action Authorization | Sensitive actions were authorized against policy before execution |
| `PR-02` | Permission Scope Enforcement | The agent operated inside its declared least-privilege scopes |
| `PR-03` | Tool/Model Integrity and Provenance | Tools, model artifacts, and integrations matched trusted baselines |
| `PR-04` | Data Exposure Prevention | Sensitive or regulated data was constrained before leaving the system |
| `PR-05` | Context and Tenant Isolation | Execution context did not leak across tenant or task boundaries |
| `DE-01` | Behavioral Anomaly Detection | Agent behavior stayed within expected baselines |

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

Activate one or more compliance overlays (e.g. financial regulations) in `ancilis.yaml`:

```yaml
compliance:
  overlays: [glba, dora]
```

The scan evaluates each active overlay's additional controls alongside the base set.

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
# Run the scan against an explicit evidence DB path, then save that file as an artifact
ancilis scan --ci --db ./evidence.duckdb
cp ./evidence.duckdb "$ARTIFACT_DIR/evidence-$(date +%Y%m%d).duckdb"
```

Pin the database location with `--db` (rather than relying on the per-agent default under `~/.ancilis/`) so the path your scan reads is the same one you archive.

The file contains a hash chain: each row's `record_hash` chains from the `previous_hash`. Set `ANCILIS_CHAIN_KEY` to write keyed (HMAC-SHA256, v2) records so the chain is tamper-evident; without a key, records use the legacy unkeyed SHA-256 format, which is not cryptographically attestable against a writer-capable adversary.

### Introducing Ancilis without blocking PRs

Start in audit mode and use `allow_failure: true` (GitLab) or `continue-on-error: true` (GitHub Actions) while you tune thresholds. Once you trust the signal, flip `allow_failure: false` and set `mode: enforce` in `ancilis.yaml`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Wrong agent name in output | `ancilis.yaml` not found — scan fell back to a default config | Point `--config` at the correct path |
| Unexpectedly few controls | Controls are opt-out (enabled by default); some were explicitly turned off with `enabled: false` in `ancilis.yaml` | Remove the `enabled: false` overrides for any control you expect to run |
| All controls show `skip` | Evidence DB is empty or wrong path | Confirm `--db` points to the file your agent wrote |
| Scan passes despite a risky run | Mode is `audit` — the agent recorded violations but never issued a `BLOCK` decision (a `BLOCK` decision in the evidence window fails the scan) | Set `security.mode: enforce` so violating calls are blocked and recorded as `BLOCK` |
| `ancilis: command not found` | Pip install not in `PATH` | Add `$(python -m site --user-base)/bin` to `PATH`, or use `python -m ancilis` |
| Evidence from previous run is included | No session scoping | Use `--session` to pin to the current agent run |
