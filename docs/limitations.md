# Limitations

What Ancilis does and doesn't do. Honesty builds credibility.

## Evaluation scope

Ancilis evaluates actions that flow through its explicit producers and middleware. It does not claim universal interception.

- **MCP middleware** intercepts `call_tool` on a wrapped `ClientSession`. Tool calls not routed through the middleware are not evaluated.
- **CLI producer** wraps explicit `subprocess.run` calls. Shell commands your agent runs outside the producer are not captured.
- **HTTP producer** wraps explicit HTTP calls you pass to it. Ancilis does **not** monkey-patch `requests`, `httpx`, `aiohttp`, or any other HTTP library. If you don't pass the call through the producer, it's not evaluated.
- **Tool producer** wraps Python functions you explicitly wrap. Functions called normally are not evaluated.

## Control evaluator coverage

41 controls are defined in the AKSI v0.6 taxonomy. 39 common controls are active for every governed agent; `PAY-01` and `PAY-02` activate only for `DC-PAY`, `AGENT_PAYMENTS`, or `X402`.

Python has 18 direct runtime evaluators and 23 attestation-backed evaluators. TypeScript has direct evaluators for its core runtime controls and catalog-backed evaluators for the remaining AKSI controls. Catalog-backed TypeScript controls return `FLAG` until explicit manual attestation is supplied; keyword matches are hints, not proof.

Direct runtime evaluator controls:

| Control | Evaluator | What it checks |
|---------|-----------|---------------|
| DE-01 | Behavioral anomaly detection | Activity against established behavioral baselines |
| DE-02 | Classification drift | Declared-vs-observed data classification and boundary drift |
| DE-03 | Configuration/dependency drift | Tool, dependency, and policy baseline drift |
| DE-04 | Evidence integrity | Evidence chain and missing telemetry checks |
| GOV-01 | Agent identity declaration and match | Declared agent identity matched at runtime (consistency check, not credential authentication) |
| GOV-02 | Ownership accountability | Named owner and accountability metadata |
| GOV-03 | Risk tolerance baseline | Policy thresholds, autonomy limits, and escalation requirements |
| ID-01 | Agent inventory | Registry metadata for governed agents and tool surfaces |
| PR-01 | Action authorization | Agent identity authorized, target not blocked, policy gate satisfied |
| PR-02 | Permission scope enforcement | Tool in allowed list, not in blocked list, rate limits |
| PR-03 | Tool provenance | Tool registered and hash-verified |
| PR-04 | Data exposure scan | Sensitive data patterns in parameters |
| PR-05 | Context isolation | Tenant and context-boundary isolation signals |
| PR-06 | Audit trail | Evidence record written for this evaluation |
| PR-07 | Transport security | Verifies tool endpoint URLs use HTTPS (localhost exempt) |
| PR-08 | Input validation | Detects SQL injection, command injection, path traversal in parameters |
| PR-09 | Sandbox enforcement | Controlled code execution and approved sandbox signals |
| RS-02 | Containment | Quarantine, block, or kill-switch signals |

The remaining 23 controls are evidence-backed and require attached, imported, or attested evidence when they cannot be proven from a single action alone.

This means:
- Reports show all 41 catalog controls, with 39 common controls active by default
- Every control has an honest evaluation path: direct runtime evaluation or attestation-backed review
- Compliance posture for attestation-backed controls shows required evidence rather than false positives

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

The hash chain over evidence records protects integrity. New records use
**HMAC-SHA256 (chain format v2)**, keyed with a secret held OUTSIDE the database
— the `ANCILIS_CHAIN_KEY` environment variable or an OS keyring entry.
`verify_chain` requires that key to verify v2 records.

- **With the key (v2):** modification or per-record forgery is detected — an
  attacker who can write the database cannot recompute a valid HMAC, or re-chain
  the following records, without the key. This holds only while the key is kept
  off the database host's persistent storage.
- **Without a key (legacy v1, unkeyed SHA-256):** the chain detects accidental
  corruption but is NOT cryptographically attestable against a writer-capable
  adversary. Anyone who can write the database can alter a record, recompute its
  SHA-256 hash, and re-chain every following record into a fully valid chain —
  **this is per-record forgery, not merely whole-database replacement.**
  `verify_chain` reports such records as **legacy-unverified**, never as verified.
- The chain does not by itself prevent deletion. `ancilis evidence reset` and
  `ancilis evidence prune` first record a signed high-water-mark checkpoint, so a
  wipe is reported by `verify_chain` rather than passing as a pristine empty chain.
- **Downgrade resistance and its limit.** A signed keyed migration checkpoint
  marks where keyed (v2) chaining began; `verify_chain` rejects a v1 record after
  that boundary, and trusts only *keyed* checkpoints to authorize a purge gap, so
  an attacker cannot bypass HMAC by editing the version column or forging an
  unkeyed checkpoint. The residual limit is inherent to in-database integrity: an
  attacker who can write the DB *and* deletes every keyed record and checkpoint
  reduces the store to an all-legacy chain — which `verify_chain` then reports as
  `legacy-unverified` (not `verified`), so an operator who has been writing keyed
  evidence will see the downgrade. Exporting to an append-only external store
  removes this residual entirely.

Migration: records created before keyed chaining stay v1 (reported as
legacy-unverified). Set `ANCILIS_CHAIN_KEY` to write v2 records going forward;
the chain continues from the last record. For the strongest guarantee, also
export evidence to an append-only external store.

### Hash chain field coverage

The canonical payload that is hashed covers every field relevant to a control
decision: `evaluation_id`, `timestamp`, `agent_id`, `source_type`, `tool_name`,
`decision`, `mode`, `control_results`, `active_overlays`, `data_classifications`,
`active_certifications`, `total_duration_ms`, `previous_hash`, and (when present)
`output_summary`, `session_id`, `tenant_id`, `detected_data_types`, `sdk_version`,
`framework_version`, and `classification_context`. Only storage addresses
(`record_id`, `seq_id`) and the `record_hash` output itself are excluded.

**Backward compatibility (ANC-922):** older v1 records were hashed over a narrower
payload (before the expanded metadata fields were added). `verify_chain` accepts
those narrower payloads ONLY for v1 (legacy) records and reports them as
legacy-unverified. v2 (keyed) records must match the full payload exactly, so the
narrower-payload path can never be used to forge a keyed record by stripping fields.

## Local-first; optional hosted platform

Ancilis is an SDK and CLI that runs fully local by default: every action is
evaluated locally, evidence is written to a local DuckDB store, and reports are
generated locally. Core evaluation requires no network and no hosted service.

There is an **optional** hosted platform (dashboard), and it is strictly opt-in:

- Sync is enabled by setting `platform.url` in `ancilis.yaml` together with an
  API key in the environment variable named by `platform.api_key_env` (default
  `ANCILIS_API_KEY`). With no `platform.url` configured, `ancilis sync` does
  nothing and there is no background sync.
- `ancilis connect --api-key <key>` writes `~/.ancilis/platform.json`; that file
  is what `ancilis doctor`'s connectivity/API-key checks read. (Evidence sync
  itself reads `platform.url` + the env-var key, not `platform.json`.)
- `ancilis sync` then POSTs evidence batches to `<platform.url>/api/evidence/batches`
  (use an `https://` platform URL for transport security — the client posts to
  whatever URL you configure) so the dashboard can show posture across environments.

What leaves your machine: only when `platform.url` is configured and you run
`ancilis sync`, the serialized evidence records are uploaded — that includes the
record/previous hashes, agent and tool identifiers, decision and mode, per-control
results, active overlays, data classifications, certifications, session and tenant
IDs, SDK/framework versions, detected data types, classification context, and any
`output_summary` you recorded. With no `platform.url` set, nothing is uploaded. To
guarantee fully offline operation even if a URL is present, set
`sync.offline_mode: always_offline` in `ancilis.yaml`.

## PDF export

PDF report generation requires `pandoc` and `xelatex` installed on the system. Without them, the `--format pdf` flag writes a Markdown fallback alongside the requested PDF path and reports the fallback path explicitly.

## What Ancilis is NOT

- **Not a WAF or network proxy.** It doesn't sit in front of your APIs.
- **Not an anomaly detection service.** DE-01 does baseline behavioral detection, but Ancilis is primarily policy-driven (deterministic evaluation against declared rules).
- **Not a replacement for Vanta/Drata.** It's the agent module they don't have.
- **Not a replacement for agent security tools.** It makes those tools auditable with compliance-grade evidence.
