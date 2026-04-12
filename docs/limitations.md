# Limitations

What Ancilis does and doesn't do. Honesty builds credibility.

## Evaluation scope

Ancilis evaluates actions that flow through its explicit producers and middleware. It does not claim universal interception.

- **MCP middleware** intercepts `call_tool` on a wrapped `ClientSession`. Tool calls not routed through the middleware are not evaluated.
- **CLI producer** wraps explicit `subprocess.run` calls. Shell commands your agent runs outside the producer are not captured.
- **HTTP producer** wraps explicit HTTP calls you pass to it. Ancilis does **not** monkey-patch `requests`, `httpx`, `aiohttp`, or any other HTTP library. If you don't pass the call through the producer, it's not evaluated.
- **Tool producer** wraps Python functions you explicitly wrap. Functions called normally are not evaluated.

## Control evaluator coverage

26 controls are defined in the AKSI taxonomy. 9 have runtime evaluators today:

| Control | Evaluator | What it checks |
|---------|-----------|---------------|
| PR-01 | Identity verification | Agent identity present and valid |
| PR-02 | Scope enforcement | Tool in allowed list, not in blocked list, rate limits |
| PR-03 | Tool provenance | Tool registered and hash-verified |
| PR-04 | Data exposure scan | Sensitive data patterns in parameters |
| PR-05 | Audit trail | Evidence record written for this evaluation |
| PR-06 | Config integrity baseline | Hashes tool config on first call, detects drift on subsequent calls |
| PR-07 | Transport security | Verifies tool endpoint URLs use HTTPS (localhost exempt) |
| PR-08 | Input validation | Detects SQL injection, command injection, path traversal in parameters |
| DE-01 | Baseline detection | Behavioral anomaly detection against established baseline |

The remaining 17 controls (GOV-01 through RC-02) are defined in the control taxonomy, appear in reports with regulatory citations, and produce `SKIP` results. Their evaluators are not yet implemented.

This means:
- Reports show all 26 controls with regulatory mapping
- Only 9 controls produce PASS/FAIL/FLAG results
- Compliance posture for controls without evaluators shows "no evaluations" rather than false positives

## TypeScript SDK

The TypeScript package is **preview**. Python remains the production-supported path, but the current preview is materially further along than the original launch posture:

- The TypeScript SDK now includes the core engine, hash-chained DuckDB evidence store, MCP middleware, CLI/HTTP/tool producers, `doctor`, and report generation/rendering.
- Preview status remains because parity auditing and release hardening are still in progress, so edge-case behavior can still differ from Python.
- TypeScript publication must remain artifact-bound: verify the exact packed tarball, then publish that same tarball rather than rebuilding during publish.

## Overlay depth

Overlay profiles vary in how many controls they map:

| Overlay | Controls mapped | Controls with adjustments |
|---------|----------------|--------------------------|
| SOC 2 Type II | 26 | 6 |
| PCI-DSS v4 | 26 | 6 |
| HIPAA | 26 | 4 |
| GDPR | 26 | 4 |
| EU AI Act | 26 | 4 |
| ISO 42001 | 26 | 0 (alignment-based) |
| NIST CSF 2.0 | 26 | 0 (alignment-based) |

All overlays map all 26 controls and produce compliance posture reports. Controls with adjustments have framework-specific thresholds or evidence requirements. Controls without adjustments use the base AKSI definitions.

## Evidence trust boundary

The SHA-256 hash chain provides tamper detection — if someone modifies a record in the DuckDB database, verification will fail. However:

- An attacker with host access could replace the **entire** database with a new one that has a valid chain
- The hash chain does not prevent deletion, only detects modification
- Evidence integrity ultimately depends on protecting the underlying host and database file

For stronger guarantees, export evidence to an append-only external store.

## No GUI, no SaaS

Ancilis is an SDK and CLI. There is no web dashboard, no hosted service, no cloud sync. Evidence is local. Reports are generated locally.

## PDF export

PDF report generation requires `pandoc` and `xelatex` installed on the system. Without them, the `--format pdf` flag writes a Markdown fallback alongside the requested PDF path and reports the fallback path explicitly.

## What Ancilis is NOT

- **Not a WAF or network proxy.** It doesn't sit in front of your APIs.
- **Not an anomaly detection service.** DE-01 does baseline behavioral detection, but Ancilis is primarily policy-driven (deterministic evaluation against declared rules).
- **Not a replacement for Vanta/Drata.** It's the agent module they don't have.
- **Not a replacement for agent security tools.** It makes those tools auditable with compliance-grade evidence.
