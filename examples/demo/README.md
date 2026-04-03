# Ancilis Demo - Financial AI Agent

A self-contained demo that shows Ancilis intercepting AI agent tool calls, evaluating them against security controls, and generating hash-chained evidence.

- **Runtime enforcement**: 4 tool calls are ALLOWED, 2 are BLOCKED based on security policy
- **Data classification-driven overlays**: Financial data handling activates SOC 2, PCI-DSS, and GLBA overlays automatically
- **Cryptographic evidence chain**: Every evaluation is persisted to DuckDB with SHA-256 hash chaining

## Prerequisites

- Python 3.10+

## Quick Start

```bash
# One-command setup and run (from repo root)
bash examples/demo/setup.sh

# Or run manually
pip install -e ".[dev]"
python examples/demo/run.py
```

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
- A summary line with ALLOW/BLOCK counts
- Full `ancilis status --verbose` output showing active overlays and certifications
- The DuckDB evidence file path

## Configuration

See `ancilis.yaml` for the agent security policy:
- `security.mode: enforce` blocks disallowed tools (vs `audit` which logs but allows)
- `my_agent_handles` declares data types, which activates compliance overlays
- `certification_targets: [aiuc-1]` activates AIUC-1 certification controls

## Next Step

Start the Platform dashboard to visualize the evidence this demo produces.
