# Session Brief — March 12, 2026: Independent Review & Trust Model Corrections

**Commit:** `7c9fc2b` on `main`
**Reviewed by:** Codex (GPT-5, independent MCP reviewer) + Kevin (manual review using Codex)
**Tests:** 178/178 Python passing post-commit

---

## What Happened

Kevin ran the first independent code review of the Ancilis SDK using Codex MCP. Three rounds of review-fix cycles followed — two Codex-initiated, one Kevin-initiated — producing a single commit that corrects the trust model, fixes persistence, wires certification activation end-to-end, and brings the SDK to a credible v0 posture.

A `CLAUDE.md` was also added to the repo root establishing a repeatable Codex integration protocol for future development sessions.

## Review Rounds

### Round 1: Codex (6 findings — 3 P1, 3 P2)

| ID | Sev | Finding | Resolution |
|----|-----|---------|------------|
| 1 | P1 | Readiness % reflects mapping coverage, not actual posture | `certification.py` now requires PASS>0 and FAIL==0 per requirement; outputs both `readiness_percentage` (posture) and `coverage_percentage` (mapping) |
| 2 | P1 | Period-filtered reports not implemented | `get_summary(since=)` added to evidence store; `WHERE timestamp >= ?` threaded through all queries |
| 3 | P1 | Evidence store defaults to `:memory:`, no persistence | Per-agent, per-project DuckDB at `~/.ancilis/{name}-{cwd_hash}/evidence.duckdb` |
| 4 | P2 | PR-03 provenance evaluator checks hash drift but never checks approval status | PR-03 now FAILs unapproved (OBSERVED) tools; FLAGs approved tools without hash baseline |
| 5 | P2 | `certification_targets` parsed but never activates controls | Config now flows through `ActivationResolver` to enable controls and set retention |
| 6 | P2 | Python quick-start (`pip install ancilis`) broken — `mcp` not bundled | `mcp` as optional extra (`pip install ancilis[mcp]`); lazy `__getattr__` for `AncilisMiddleware` import |

### Round 2: Codex (3 P1, 2 P2 — on our changes)

| ID | Sev | Finding | Resolution |
|----|-----|---------|------------|
| 1 | P1 | Cross-agent contamination — global DB path shared across agents | Scoped DB path to `{agent_name}-{cwd_hash}` |
| 2 | P1 | `approve-tool` fails before `list_tools()` discovery | Middleware pre-seeds registry from config `tools_allowed` on init |
| 3 | P1 | TypeScript SDK still has old behavior (`:memory:`, auto-approve, static readiness) | **Deferred** — intentionally waiting on Python port completion |
| 4 | P2 | `FLAG` result not counted in summary aggregation | Added FLAG to all summary counters |
| 5 | P2 | README install command and AIUC-1 numbers stale | Updated to `pip install ancilis[mcp]` and accurate 17/20 (85%) |

### Round 3: Kevin's Review via Codex (1 P1, 2 P2, 1 P3)

| ID | Sev | Finding | Resolution |
|----|-----|---------|------------|
| 1 | P1 | PR-03 gives PASS to approved tools with no description hash baseline | Changed to FLAG with explanatory detail |
| 2 | P2 | Agent name collisions across projects with same agent name | CWD hash added to DB path |
| 3 | P2 | Fresh install `ancilis status` says "all passing" with zero evidence | Now shows "not yet evaluated" when no evidence exists |
| 4 | P3 | README AIUC-1 numbers don't match actual profile | Corrected to 17 of 20 requirements (85%) |

## Key Architectural Changes

### ToolStatus Enum (registry.py)

The boolean `approved: bool` field on `ToolEntry` was replaced with a three-state enum: `OBSERVED` (discovered at runtime, not approved), `APPROVED` (operator-approved), `BLOCKED`. This is the foundation of the trust model — discovery and approval are now distinct lifecycle events.

### Evidence Scoping (store.py)

Evidence storage moved from a global `:memory:` default to persistent, scoped DuckDB instances at `~/.ancilis/{agent_name}-{cwd_hash}/evidence.duckdb`. The CWD hash prevents collisions when the same agent name is used across different projects. An `in_memory=True` flag preserves test isolation.

### Certification Activation Wiring (config.py)

`certification_targets` in config now actually does something — it flows through `ActivationResolver` to activate the controls required by the target certification profile (e.g., AIUC-1), set evidence retention thresholds, and apply audit requirements. Previously it was parsed and ignored.

### Provenance Trust Model (pr03_provenance.py)

PR-03 now implements a three-outcome evaluation: **FAIL** if the tool is OBSERVED (not approved), **FLAG** if the tool is approved but has no description hash baseline yet, **PASS** if the tool is approved and its hash matches the stored baseline. This prevents false confidence on fresh installs.

## Codex MCP Integration

Codex was added as an MCP server for independent code review:

```
claude mcp add codex -s user -- codex -m gpt-5 -c model_reasoning_effort="high" mcp
```

The `CLAUDE.md` at repo root establishes the review protocol: Codex reads the repo fresh, infers the use case from implementation (not project intent), compares claims against code, and returns findings ordered by severity with file/line references. This creates a repeatable adversarial review loop that caught real issues across all three rounds.

## Bugs Hit During Implementation

| Bug | Cause | Fix |
|-----|-------|-----|
| `datetime.UTC` ImportError | Python 3.11+ only; system is 3.10 | `timezone.utc` throughout |
| Eager `AncilisMiddleware` import breaks all tests | `mcp` not installed outside middleware context | Lazy `__getattr__` in `__init__.py` |
| Duplicate `[project.optional-dependencies]` in pyproject.toml | Adding `mcp` extra created second section | Merged into single section |
| `ToolEntry(approved=True)` in tests | Dataclass field renamed to `status` enum | Updated all test helpers |
| `KeyError: 'automated_percentage'` in renderer | Key renamed in certification.py, not renderer | Synced all three renderers |
| `EvidenceStore(config)` creates real files in tests | Persistent default replaced `:memory:` | Added `in_memory=True` parameter |

## Files Changed (22)

**Core SDK (10):** `__init__.py`, `config.py`, `engine/registry.py`, `engine/evaluators/pr03_provenance.py`, `evidence/store.py`, `middleware/middleware.py`, `middleware/discovery.py`, `middleware/action_builder.py`, `report/certification.py`, `report/generator.py`, `report/renderer.py`

**CLI (2):** `cli/status.py`, `cli/approve.py`

**Shared (2):** `controls/pr-03.json`, `schemas/config.schema.json`

**Tests (4):** `test_engine.py`, `test_cli.py`, `test_activation.py`, `test_evidence.py`

**Project (4):** `CLAUDE.md`, `README.md`, `pyproject.toml`

## Updated Build Unit Status

| Unit | Name | Status |
|------|------|--------|
| Unit 0 | README & Repository Setup | Complete |
| Unit 1 | Policy Schema & Configuration | Complete |
| Unit 2 | Control Engine Core | Complete |
| Unit 3 | MCP Middleware & Pattern Detection | Complete |
| Unit 4 | Evidence Generation | Complete |
| Unit 5 | Overlay Activation & Remaining Controls | Complete |
| Unit 6 | Posture Report & CLI | Complete |
| Retrofit | Cert declaration + output disclosure | Complete |
| **Independent Review** | **Codex review + trust model corrections** | **Complete** |

## Open Items Carried Forward

- **TypeScript parity** — Python is ahead on: persistent evidence, period filtering, ToolStatus enum, posture-based readiness, FLAG results. TS port is the next logical workstream.
- **`git push`** — Commit `7c9fc2b` is local only. Needs push to remote (SSH alias `github-ancilis` requires Kevin's local terminal).
- **Product decisions still unresolved** — Form factor (SDK confirmed), business model (BSL strong candidate), license (not final).

## Strategic Takeaway

The Codex review loop proved its value — each round found real issues in the previous round's fixes. The trust model is now honest: fresh installs say "not yet evaluated," unapproved tools fail provenance, and readiness percentages reflect actual posture rather than mapping coverage. The SDK is now at a credible v0 state for initial adoption.

---

*Session brief — March 12, 2026 — Project Ancilis Internal*
