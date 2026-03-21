# MCP Middleware Example

Wrap your MCP client session. Every tool call gets evaluated before it reaches the server.

## What this demonstrates

1. AncilisMiddleware wrapping an MCP client session
2. Tool discovery and automatic registry (OBSERVED/APPROVED states)
3. Allowed tools passing through with evidence recorded
4. Unauthorized tools blocked in enforce mode
5. Same scenario in audit mode — failures logged, nothing blocked
6. The `get_summary_line()` output your agent framework can surface

## Prerequisites

```bash
pip install "ancilis[mcp]"
```

This example uses a mock MCP session — no real MCP server needed.

## Run

```bash
cd examples/mcp-middleware
python run.py
```

## Config

```yaml
agent:
  name: mcp-demo-agent
security:
  mode: enforce
  tools:
    allowed:
      - get-status
      - get-transactions
    blocked:
      - delete-database
```

## Expected output

```
=== Enforce Mode ===
Config: get-status and get-transactions allowed, delete-database blocked

Discovered 4 tools from MCP server

Tool registry:
  get-status: approved
  get-transactions: approved
  send-email: observed
  delete-database: observed

1. Calling 'get-status' (allowed)...
   Result: All systems operational.
   Decision: ALLOW

2. Calling 'get-transactions' (allowed)...
   Result: Transaction #1: $42.00 at Merchant A
   Decision: ALLOW

3. Calling 'send-email' (not in allowed list, enforce mode)...
   BLOCKED: Ancilis [blocked]: Tool 'send-email' blocked — scope enforcement, tool provenance check.
  To approve: ancilis approve-tool send-email
  To review: ancilis status

4. Calling 'delete-database' (explicitly blocked)...
   BLOCKED: Ancilis [blocked]: Tool 'delete-database' blocked — scope enforcement, tool provenance check.
  To approve: ancilis approve-tool delete-database
  To review: ancilis status

Ancilis: 4 tool calls evaluated. 2 issues. Run `ancilis status` for details.

=== Audit Mode ===
Same tools, same calls — but mode is audit (log everything, block nothing)

Calling 'send-email' (not in allowed list, audit mode)...
  Result: Email sent to user@example.com
  Decision: ALLOW
  Mode: audit
  Failures logged: ['PR-02', 'PR-03']

Calling 'delete-database' (explicitly blocked, audit mode)...
  Result: Database dropped.
  Decision: ALLOW
  Failures logged: ['PR-02', 'PR-03']

Ancilis: 2 tool calls evaluated. 2 issues. Run `ancilis status` for details.

Done. Same policy, two modes. Enforce blocks. Audit logs.
```

## What happened

- Middleware auto-discovers tools from the MCP server via `list_tools()`
- Tools in `security.tools.allowed` are registered as APPROVED
- Other tools are registered as OBSERVED (discovered but not yet approved)
- In **enforce mode**: unapproved tools are blocked before reaching the server
- In **audit mode**: same evaluation happens, failures are logged, but the call goes through
- Every evaluation produces a hash-chained evidence record
- The `get_summary_line()` gives your agent framework a one-liner to surface

## Audit vs. enforce

The only difference is one config field: `security.mode`.

- **audit** (default): Evaluate everything, log everything, block nothing. Use this when onboarding.
- **enforce**: Evaluate everything, log everything, block violations. Use this in production.

Both modes produce identical evidence records. The `mode` field in each record shows which was active.
