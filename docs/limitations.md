# Limitations

What Ancilis does and doesn't do. Honesty builds credibility.

## Evaluation scope

Ancilis evaluates actions that flow through its explicit producers and middleware. It does not claim universal interception.

- **MCP middleware** intercepts `call_tool` on a wrapped `ClientSession`. Tool calls not routed through the middleware are not evaluated.
- **CLI producer** wraps explicit `subprocess.run` calls. Shell commands your agent runs outside the producer are not captured.
- **HTTP producer** wraps explicit HTTP calls you pass to it. Ancilis does **not** monkey-patch `requests`, `httpx`, `aiohttp`, or any other HTTP library. If you don't pass the call through the producer, it's not evaluated.
- **Tool producer** wraps Python functions you explicitly wrap. Functions called normally are not evaluated.

## Control evaluator coverage

41 controls are defined in the AKSI v0.6 taxonomy. 39 common controls are active for every governed agent; `PAY-01` and `PAY-02` activate only for `DC-PAY`, `AGENT_PAYMENTS`, or `X402`. 12 controls have runtime evaluators today:

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
| DE-02 | Classification drift | Declared-vs-observed classification and boundary drift |
| DE-04 | Evidence integrity | Evidence chain and missing telemetry checks |
| GOV-02 | Ownership accountability | Named owner and accountability metadata |

The remaining controls are defined in the control taxonomy and produce `SKIP` results unless evidence is imported or a runtime evaluator is implemented.

This means:
- Reports show all 41 catalog controls, with 39 common controls active by default
- 12 controls produce runtime PASS/FAIL/FLAG/SKIP results
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
| SOC 2 Type II | legacy baseline mapping | 6 |
| PCI-DSS v4 | legacy baseline mapping | 6 |
| HIPAA | legacy baseline mapping | 4 |
| GDPR | legacy baseline mapping | 4 |
| EU AI Act | legacy baseline mapping | 4 |
| ISO 42001 | legacy baseline mapping | 0 (alignment-based) |
| NIST CSF 2.0 | legacy baseline mapping | 0 (alignment-based) |

Overlays produce compliance posture reports and only reference known AKSI v0.6 controls. Some overlay profiles still reflect the pre-v0.6 baseline depth; controls without adjustments use the base AKSI definitions.

## Evidence trust boundary

The SHA-256 hash chain provides tamper detection — if someone modifies a record in the DuckDB database, verification will fail. However:

- An attacker with host access could replace the **entire** database with a new one that has a valid chain
- The hash chain does not prevent deletion, only detects modification
- Evidence integrity ultimately depends on protecting the underlying host and database file

For stronger guarantees, export evidence to an append-only external store.

### Hash chain field coverage

All evidence record fields relevant to a control decision are included in the SHA-256 hash:
`evaluation_id`, `timestamp`, `agent_id`, `source_type`, `tool_name`, `decision`, `mode`,
`control_results`, `active_overlays`, `data_classifications`, `active_certifications`,
`total_duration_ms`, `previous_hash`, and `output_summary` (when present).

Fields excluded from the hash by design: `record_id`, `sdk_version`, `detected_data_types`,
`classification_context`. These are supplemental metadata and their modification does not alter
the tamper-evidence of the control decision record.

**Backward compatibility:** Records created before `output_summary` was added to the hash scheme
store `NULL` for that field. `verify_chain` uses conditional-inclusion logic — `output_summary`
is added to the canonical payload only when non-null. This means:
- Legacy records with `output_summary=NULL` verify correctly against their stored hash.
- Post-hoc injection of a non-null value into a legacy record is still detected as a hash
  mismatch, because the recomputed canonical includes the injected value while the stored hash
  does not.

## No GUI, no SaaS

Ancilis is an SDK and CLI. There is no web dashboard, no hosted service, no cloud sync. Evidence is local. Reports are generated locally.

## PDF export

PDF report generation requires `pandoc` and `xelatex` installed on the system. Without them, the `--format pdf` flag writes a Markdown fallback alongside the requested PDF path and reports the fallback path explicitly.

## What Ancilis is NOT

- **Not a WAF or network proxy.** It doesn't sit in front of your APIs.
- **Not an anomaly detection service.** DE-01 does baseline behavioral detection, but Ancilis is primarily policy-driven (deterministic evaluation against declared rules).
- **Not a replacement for Vanta/Drata.** It's the agent module they don't have.
- **Not a replacement for agent security tools.** It makes those tools auditable with compliance-grade evidence.
