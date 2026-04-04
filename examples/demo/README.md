# Ancilis Demo - Financial AI Agent

A self-contained demo that shows Ancilis intercepting AI agent tool calls, evaluating them against security controls, and generating hash-chained evidence.

- **Runtime enforcement**: 4 tool calls are ALLOWED, 2 are BLOCKED based on security policy
- **Data classification-driven overlays**: Financial data handling activates SOC 2, PCI-DSS, and GLBA overlays automatically
- **Cryptographic evidence chain**: Every evaluation is persisted to DuckDB with SHA-256 hash chaining

## Prerequisites

- Python 3.10+
- Docker Desktop (or another reachable local Docker daemon) for the full SDK -> Platform walkthrough
- `curl` for the Platform login, integration registration, and sync steps in `run-all.sh`
- A Platform checkout at either `./platform`, `../ancilis-one-shot/platform`, or a custom path passed via `ANCILIS_PLATFORM_DIR`

## Quick Start

```bash
# One-command setup and run (from repo root)
bash examples/demo/setup.sh

# Or run manually
pip install -e ".[dev]"
python examples/demo/run.py

# Full SDK -> Platform walkthrough
bash examples/demo/run-all.sh
```

`run-all.sh` auto-detects the Platform checkout from either:
- `./platform`
- `../ancilis-one-shot/platform`

If your Platform repo lives somewhere else, point the walkthrough at it explicitly:

```bash
ANCILIS_PLATFORM_DIR=/path/to/platform-or-repo-root bash examples/demo/run-all.sh
```

`run-all.sh` also honors a few environment overrides when your local stack differs from the defaults:

```bash
ANCILIS_DEMO_BACKEND_URL=http://localhost:8000
ANCILIS_DEMO_DASHBOARD_URL=http://localhost:3000
ANCILIS_DEMO_OPEN_BROWSER=0
```

When the walkthrough finishes, sign in to the dashboard with:
- `admin@ancilis.demo`
- `AncilisDemo123!`

## What to Look For

The demo simulates a financial AI agent making 6 MCP tool calls:

| Tool | Decision | Why |
|------|----------|-----|
| `check_balance` | ALLOW | In allowed list, returns PII (name, account number) |
| `get_transactions` | ALLOW | In allowed list, returns financial transaction data |
| `transfer_funds` | ALLOW | In allowed list, triggers exposure control for outbound movement |
| `export_customer_list` | BLOCK | Not in allowed list (enforce mode) |
| `drop_audit_log` | BLOCK | Explicitly blocked in security policy |
| `lookup_credit_score` | ALLOW | In allowed list, triggers GLBA overlay (SSN in response) |

After the tool calls, the demo prints:
- A middleware summary line showing the evaluated tool-call total and detected issues
- Full `ancilis status --verbose` output showing active overlays and certifications
- The DuckDB evidence file path

## Configuration

See `ancilis.yaml` for the agent security policy:
- `security.mode: enforce` blocks disallowed tools (vs `audit` which logs but allows)
- `my_agent_handles` declares data types, which activates compliance overlays
- `certification_targets: [aiuc-1]` activates AIUC-1 certification controls

## Next Step

Run `bash examples/demo/run-all.sh` to push the generated evidence into the Platform and open the dashboard flow end to end.
