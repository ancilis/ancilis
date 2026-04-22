# Ancilis Demo - Financial AI Agent

A self-contained demo that shows Ancilis intercepting AI agent tool calls, evaluating them against security controls, and generating hash-chained evidence.

- **Runtime enforcement**: 4 tool calls are ALLOWED, 2 are BLOCKED based on security policy
- **Data classification-driven overlays**: Financial data handling activates SOC 2, PCI-DSS, and GLBA overlays automatically
- **Cryptographic evidence chain**: Every evaluation is persisted to DuckDB with SHA-256 hash chaining

## Prerequisites

- Python 3.10+
- Node.js 18+ for the dashboard portion of the full SDK -> Platform walkthrough
- `curl` for the Platform login, integration registration, and sync steps in `run-all.sh`
- Docker Desktop (or another reachable local Docker daemon) when you want `run-all.sh` to start the Platform stack locally
- A Platform checkout at either `./platform`, `../ancilis-one-shot/platform`, or a custom path passed via `ANCILIS_PLATFORM_DIR` when you want `run-all.sh` to start the Platform stack locally

## 30-Second Demo Path

Use this when you only need to show the SDK intercepting tool calls, enforcing policy, and writing DuckDB evidence locally:

```bash
# One-command setup and local demo run (from repo root)
bash examples/demo/setup.sh

# Or run manually
pip install -e ".[dev]"
python examples/demo/run.py
```

`setup.sh` now performs the shared demo preflight checks first, so it fails fast if Python 3.10+ is missing.

## 5-Minute Demo Path

Use this when you want the fuller SDK -> Platform walkthrough, including local Platform startup, evidence registration, and dashboard sync:

```bash
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
ANCILIS_DEMO_SKIP_STACK_START=1
```

Set `ANCILIS_DEMO_SKIP_STACK_START=1` when the Platform API and dashboard are already running. In that mode, `run-all.sh` skips the local `docker compose up` step and reuses the stack exposed at `ANCILIS_DEMO_BACKEND_URL` and `ANCILIS_DEMO_DASHBOARD_URL`.

## Screen-Recording Discovery Path

Use this for the acquirer-facing flow where the platform discovers a realistic agent fleet, surfaces data classifications, and syncs SDK evidence through the SDK Direct adapter:

```bash
bash examples/demo/run-discovery.sh
```

The discovery demo seeds five agents across MCP, Bedrock, CLI, Framework, and HTTP architectures. Each agent emits hash-chained evidence over a simulated multi-day timeline, includes real pattern detections for PHI, PII, or cardholder data, and writes a manifest that contains the local DuckDB paths for SDK Direct ingestion.

When the full walkthrough is up, the default local endpoints are:
- Dashboard: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- Backend docs: `http://localhost:8000/docs`

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
- A framed tool registry showing which demo tools are approved, unapproved, or explicitly blocked
- A tool-call transcript with the 4 `ALLOW` and 2 `BLOCK` decisions plus short explanatory notes
- A summary block with evaluated counts, active overlays, AIUC-1 readiness tracking, and evidence totals
- The DuckDB evidence file path plus the command to continue into the full SDK -> Platform walkthrough

If you want the verbose CLI views after the local demo run, point them at the emitted DuckDB path:

```bash
ancilis status --verbose --config examples/demo/ancilis.yaml --db /path/to/evidence.duckdb
ancilis report generate --format markdown --config examples/demo/ancilis.yaml --db /path/to/evidence.duckdb
```

## Configuration

See `ancilis.yaml` for the agent security policy:
- `security.mode: enforce` blocks disallowed tools (vs `audit` which logs but allows)
- `my_agent_handles` declares data types, which activates compliance overlays
- `certification_targets: [aiuc-1]` activates AIUC-1 certification controls

## Next Step

Run `bash examples/demo/run-all.sh` to push the generated evidence into the Platform and open the dashboard flow end to end.
