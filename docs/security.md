---
title: "Security Model & Threat Model"
description: "What Ancilis protects, the trust boundaries it assumes, and what it explicitly does not defend against."
---

## Overview

Ancilis is a runtime governance layer for AI agents: it evaluates agent tool calls
against the AKSI control catalog, can block disallowed actions (in `enforce`
mode), and records an audit-ready evidence trail. This page states the security
properties it provides, the boundaries it assumes, and — just as importantly —
what it does **not** defend against. Nothing here over-promises legal or
regulatory standing; for the per-control runtime-vs-organizational split see
[Controls Reference](/controls-reference), and for the hard edges see
[Limitations](/limitations).

## Architecture & trust boundaries

Ancilis runs **in-process** with your agent (Python or TypeScript). It is a
library, not a network proxy or a sandbox.

- **The agent process is trusted.** Ancilis evaluates the actions an agent
  *declares* (via a producer or middleware). Code running in the same process can
  bypass the SDK entirely — Ancilis is a governance and evidence layer, not an
  OS- or container-level isolation boundary.
- **Evidence is stored locally** in a DuckDB file (default
  `~/.ancilis/<agent-name>-<cwd-hash>/evidence.duckdb`). Anyone who can read that
  file can read the evidence; anyone who can write it can attempt tampering (see
  Evidence integrity below).
- **The hosted platform is optional and opt-in.** With nothing connected, Ancilis
  runs fully locally and makes no network calls for evaluation. `ancilis connect`
  writes an API key to `~/.ancilis/platform.json` (mode `0600`); `ancilis sync`
  pushes evidence to it. The local evaluation result never depends on the
  platform.

## Asset 1 — Evidence integrity

The evidence chain is a hash chain. Its strength depends on whether a key is set:

- **Keyed (v2):** when `ANCILIS_CHAIN_KEY` is set (or an OS keyring entry exists),
  each record is chained with **HMAC-SHA256**. `verify_chain` requires the key;
  a record altered or re-signed with a different key fails verification.
- **Legacy (v1):** without a key, records use an unkeyed SHA-256 chain. This
  detects accidental corruption but is **not** cryptographically attestable: an
  attacker with database write access can alter a record, recompute its SHA-256
  hash, and re-chain every following record into a valid chain (per-record
  forgery, not merely whole-DB replacement). `verify_chain` reports such records
  as **`legacy-unverified`**, never as `verified`.

**Key custody.** The chain key is held *outside* the database — environment
variable or OS keyring — so that DB read/write access alone does not yield the
key. Protect it like any signing secret; losing it makes future records
unverifiable, leaking it lets a holder forge.

**Deletion is recorded, not silent.** `ancilis evidence reset` and `prune` write
a signed high-water-mark checkpoint before deleting, so a wipe surfaces as
`reset-or-purged` rather than passing as a pristine empty chain. A signed
migration boundary defeats version-column downgrade, and only keyed checkpoints
are trusted to authorize a pruned gap when a key is present.

**Residual (documented).** Against an attacker who can write the DB *and* delete
every keyed record and checkpoint, the store degrades to an all-legacy chain that
`verify_chain` reports as `legacy-unverified` (not `verified`) — detectable by a
key-holding operator, and removed entirely by exporting evidence to an
append-only external store. This is the inherent limit of in-database integrity
without an external anchor.

## Asset 2 — Action enforcement

In `enforce` mode the engine **BLOCKs** an action if any control result is `FAIL`
or `ERROR`; otherwise it `ALLOW`s. In `audit` mode nothing is blocked — actions
are evaluated and recorded only.

Enforcement only binds for **enforce-capable** producers that gate the call on the
decision (tool, MCP, CLI, and the Semantic Kernel filter). Provider **adapters**
(Anthropic, OpenAI, Bedrock, …) and the LangChain/CrewAI/AutoGen integrations are
**observe-only**: they record evidence but do not block, and they emit a warning
if used in `enforce` mode. Do not rely on an observe-only producer to prevent an
action — see [Producers](/producers) for the per-producer enforcement column.

A detected-but-unblocked exposure (e.g. sensitive data with no destination
policy) is surfaced as a **FLAG**, and the posture headline never reports
"all passing" while any control is flagged, pending, or failing.

## Asset 3 — Secrets & configuration

- `ANCILIS_CHAIN_KEY` — the evidence-chain HMAC key (see above). Never commit it.
- `~/.ancilis/platform.json` — the platform API key, written `0600` in a `0700`
  directory. `ancilis init` appends `.ancilis/` to an existing `.gitignore`.
- `ANCILIS_API_KEY` — platform key via environment, for CI.

Ancilis redacts/normalizes evidence it stores, and PR-04 (Data Exposure
Prevention) scans outbound parameters for sensitive patterns, but **you remain
responsible** for not passing secrets into tool parameters that get recorded.

## What Ancilis does NOT protect against

Being explicit here is part of the design:

- **In-process bypass.** Code in the agent process can call tools without going
  through a producer; Ancilis governs declared actions, not arbitrary code.
- **A compromised host or DB with the key.** If the chain key and the database are
  both in the attacker's hands, evidence can be forged. Key custody is the
  boundary.
- **Organizational controls.** Many AKSI controls (the `attestation` ones) are not
  runtime-evaluated; Ancilis tracks them via attestation, it does not enforce
  them. The report distinguishes runtime-evaluated from organizational criteria.
- **Network/transport security, sandboxing, or DoS.** Ancilis is not a WAF, a
  sandbox, or a rate-limit/DoS defense. PR-07 checks for plainly insecure URLs in
  parameters; it is not a TLS-terminating proxy.
- **Correctness of the agent's own logic.** Ancilis evaluates policy compliance of
  tool calls, not whether the agent's task output is correct.

## Reporting a vulnerability

If you believe you have found a security issue in the SDK, please report it
privately to the maintainers rather than opening a public issue, and include a
reproduction. (See the repository's `SECURITY.md`/contact for the current
channel.)
