# Ancilis Build Pipeline v2 — Design Specification

**Status:** PROPOSED
**Date:** 2026-03-30
**Author:** Kevin + Claude
**Supersedes:** v1 (13-state single-lane pipeline)

---

## Problem with v1

The v1 pipeline applies maximum governance to every item. A typo fix goes through the same PRD → adversarial review → build prompt drafting → build prompt review → build → code review → human gate path as a schema migration. The 13-state machine encodes phase, owner, and decision into a single enum, making routing rigid and automation brittle. The build-prompt-as-artifact stage adds a review gate that doesn't earn its keep for most work.

## Design Principles

1. **Governance proportional to risk.** Fast-lane items should take minutes, not days.
2. **Fewer states, more fields.** Phase is one axis. Owner, decision, lane, and round are separate.
3. **Notion is the control plane, not the execution plane.** Queue, visibility, links, next action. Artifacts live in the repo or PRs.
4. **Idempotent stages.** If a worker dies mid-task, rerunning produces the same outcome, not duplicates.
5. **Structured handoffs.** Reviews return machine-readable decisions, not conversational prose.

---

## Lanes

Every item is assigned a lane at triage. The lane determines which stages it passes through.

### Fast Lane
**Use for:** typo fixes, doc updates, copy changes, test additions, small refactors confined to one module, dependency bumps.

**Flow:** `NEW → BUILD → VERIFY → MERGED`

No spec stage. No cross-model review. Claude or Codex builds directly from the task brief. Verification is CI only (tests pass, lint clean). When CI passes, Kevin gets a notification. Auto-merges after 1 hour if no objection. If Kevin holds or requests changes within the window, the item moves to REVIEW.

**Routing signal:** Type is one of `Bug Fix`, `Documentation`, `Refactor` AND estimated touch surface ≤ 3 files AND no schema/API/auth changes.

### Standard Lane
**Use for:** normal features, non-trivial bugs, integrations, multi-file refactors.

**Flow:** `NEW → SPEC → BUILD → VERIFY → REVIEW → MERGED`

PRD required. ADR only if there's an architecture decision. No separate build-prompt stage — the spec IS the build instruction. One cross-model review after build. Human gate before merge.

**Routing signal:** Default lane for anything that doesn't qualify as fast or high-risk.

### High-Risk Lane
**Use for:** auth changes, schema migrations, public API changes, infrastructure, anything touching evidence chain integrity, payment/billing, data classification logic.

**Flow:** `NEW → SPEC → SPEC_REVIEW → BUILD → VERIFY → REVIEW → HUMAN_CHECKPOINT → MERGED`

Full PRD + ADR. Adversarial spec review (Claude ↔ Codex). Build with explicit guardrails. Cross-model code review. Explicit human checkpoint before merge where you review the PR yourself.

**Routing signal:** Type is `Infrastructure` OR Phase is `Phase 0 - SDK Ship` OR item touches auth, schema, public API, evidence store, data classification, or AKSI controls.

---

## State Machine

### Phases (the `phase` field)

```
NEW → SPEC → BUILD → VERIFY → REVIEW → MERGED
                                  ↓
                               BLOCKED
```

Six phases plus BLOCKED. That's it.

| Phase | Description |
|-------|-------------|
| `NEW` | Item submitted. Needs triage (lane assignment, priority, owner). |
| `SPEC` | Design work. PRD and/or ADR being drafted or reviewed. |
| `BUILD` | Code being written. Feature branch active. |
| `VERIFY` | CI running. Tests, lint, type checks. |
| `REVIEW` | Cross-model or human code review in progress. |
| `MERGED` | PR merged to main. Done. |
| `BLOCKED` | Stuck. Needs human decision. |

### Supporting Fields

These fields are orthogonal to phase and tracked separately:

| Field | Type | Values | Purpose |
|-------|------|--------|---------|
| `Lane` | Select | `fast`, `standard`, `high-risk` | Determines which stages apply |
| `Owner` | Select | `Kevin`, `Claude`, `Codex`, `System` | Who is responsible for the current action |
| `Decision` | Select | `pending`, `approved`, `approved_with_nits`, `changes_requested`, `escalated` | Outcome of the last review |
| `Round` | Number | 0–3 | Review iteration count (circuit breaker at 3) |
| `Run ID` | Text | UUID | Current orchestrator run claiming this item |
| `Claimed At` | Date | ISO timestamp | When the current run claimed ownership |
| `Last Error` | Text | Error message | Last failure, if any |

### Transition Rules

**Universal rules:**
- Only `changes_requested` triggers a loop back. `approved_with_nits` moves forward (optionally spawns a follow-up item for nits).
- If `Round >= 3` at any review point → `phase = BLOCKED`, `Owner = Kevin`, `Decision = escalated`.
- If `Last Error` is set and `Claimed At` is > 10 minutes old, the item is considered abandoned and can be reclaimed.

**Fast lane transitions:**

```
NEW (Kevin sets lane=fast, owner=Codex)
  → BUILD (Codex builds from task brief on feature branch)
  → VERIFY (System runs CI)
  → REVIEW (owner=Kevin, notification sent, 1-hour auto-merge timer starts)
    → if no objection within 1 hour: auto-merge → MERGED
    → if Kevin holds: owner=Kevin, timer paused, manual review
  → MERGED
```

**Standard lane transitions:**

```
NEW (Kevin sets lane=standard, owner=Claude)
  → SPEC (Claude drafts PRD, optionally ADR)
    → owner=Codex, decision=pending (Codex reviews spec)
    → if approved: phase=BUILD, owner=Codex
    → if changes_requested: owner=Claude, round++
    → if escalated: phase=BLOCKED, owner=Kevin
  → BUILD (Codex builds on feature branch)
  → VERIFY (System runs CI)
  → REVIEW (Claude reviews code)
    → if approved: phase=MERGED (or owner=Kevin for final look)
    → if changes_requested: phase=BUILD, owner=Codex, round++
  → MERGED
```

**High-risk lane transitions:**

```
NEW (Kevin sets lane=high-risk, owner=Claude)
  → SPEC (Claude drafts PRD + ADR)
    → owner=Codex, decision=pending (adversarial review)
    → review loop with circuit breaker
    → if approved: owner=Codex
  → BUILD (Codex builds with explicit guardrails from spec)
  → VERIFY (System runs CI + extended checks)
  → REVIEW (Claude reviews code, then owner=Kevin for human checkpoint)
    → Kevin approves or requests changes
  → MERGED
```

---

## Review Response Schema

Every review (spec or code) returns a structured response. This is what gets written to the Feedback Log.

```json
{
  "decision": "approved | approved_with_nits | changes_requested | escalated",
  "summary": "One-line summary of the review outcome",
  "issues": [
    {
      "severity": "blocking | suggestion | nit",
      "file": "path/to/file.py",
      "line": 42,
      "description": "What's wrong and what to do about it"
    }
  ],
  "nits_follow_up": true,
  "reviewer": "Claude | Codex",
  "timestamp": "2026-03-30T14:30:00Z"
}
```

Only `blocking` issues trigger `changes_requested`. Suggestions and nits are advisory. If `nits_follow_up` is true, the orchestrator creates a separate fast-lane item to clean them up later.

---

## Artifact Locations

| Artifact | v1 Location | v2 Location | Rationale |
|----------|-------------|-------------|-----------|
| PRD | Notion subpage | `docs/prd/ITEM-SLUG.md` in repo | Version-controlled, reviewable in PRs |
| ADR | Notion subpage | `docs/adr/ADR-NNN.md` in repo | Already have ADR convention in repo |
| Build prompt | Notion subpage | Eliminated for standard/fast. For high-risk: section in PRD | Not a first-class artifact |
| Review feedback | Notion Feedback Log | PR comments (code review) + Notion summary field | Reviews belong where the code is |
| Pipeline instructions | Notion page | `docs/pipeline-v2-design.md` (this file) + `tools/pipeline/` | Behavior-changing prompts go through code review |
| Status/queue | Notion database | Notion database (unchanged) | Notion is good at this |

---

## Notion Database Schema (v2)

Update the existing Build Pipeline database. Changes from v1 marked with *.

| Property | Type | Notes |
|----------|------|-------|
| Name | Title | Unchanged |
| *Phase | Select | `NEW`, `SPEC`, `BUILD`, `VERIFY`, `REVIEW`, `MERGED`, `BLOCKED` |
| *Lane | Select | `fast`, `standard`, `high-risk` |
| Owner | Select | `Kevin`, `Claude`, `Codex`, `System` (renamed from "Assigned To") |
| Priority | Select | Unchanged |
| Type | Select | Unchanged |
| *Milestone | Select | Replaces "Phase" (the roadmap phase). `SDK Ship`, `Platform Core`, `Integrations`, `Discovery`, `Dashboard`, `Polish` |
| *Decision | Select | `pending`, `approved`, `approved_with_nits`, `changes_requested`, `escalated` |
| *Round | Number | Renamed from "Review Round" |
| PRD Link | URL | Now points to repo file, not Notion subpage |
| ADR Link | URL | Same |
| PR Link | URL | Unchanged |
| Branch | Text | Unchanged |
| *Summary | Text | Short summary of latest outcome (replaces verbose Feedback Log) |
| *Run ID | Text | Orchestrator lease tracking |
| *Claimed At | Date | Orchestrator lease tracking |
| *Last Error | Text | Last failure message |
| Created | Created Time | Unchanged |
| Last Updated | Last Edited Time | Unchanged |
| Blocked By | Relation (self) | Unchanged |

**Removed:** Status (replaced by Phase), Feedback Log (replaced by Summary + PR comments), Build Prompt Link (eliminated), Related ADR (folded into ADR Link).

---

## Orchestrator Architecture

### Server-side Python orchestrator

The orchestrator (`tools/pipeline/pipeline_orchestrator.py`) runs as a single loop, either via cron or a persistent process. It handles both Claude and Codex dispatch.

```
┌─────────────────────────────────────┐
│         Orchestrator (Python)        │
│                                      │
│  1. Query Notion for claimable items │
│  2. Claim item (set Run ID + time)   │
│  3. Route by lane + phase            │
│  4. Dispatch to Claude API or        │
│     Codex CLI (codex exec)           │
│  5. Parse structured response        │
│  6. Update Notion + create artifacts │
│  7. Release claim                    │
│                                      │
│  Runs every 30 min via cron          │
│  One item per provider per run       │
└─────────────────────────────────────┘
```

### Claim/lease model

Before processing an item, the orchestrator:
1. Checks that `Run ID` is empty OR `Claimed At` is > 10 minutes ago (abandoned lease)
2. Sets `Run ID` to a new UUID and `Claimed At` to now
3. Processes the item
4. On success: clears `Run ID`, updates Phase/Owner/Decision
5. On failure: writes error to `Last Error`, clears `Run ID`

This prevents duplicate work if two orchestrator instances overlap.

### Codex dispatch

For build and spec-review stages assigned to Codex:

```bash
codex exec \
  --writable \
  --json \
  -p "$(cat /tmp/codex-prompt-ITEM_ID.txt)" \
  2>/dev/null
```

The orchestrator constructs the prompt from the item's context, writes it to a temp file, runs `codex exec`, parses the JSON output, and updates Notion.

### Claude dispatch

For spec-drafting and code-review stages assigned to Claude:

```python
response = anthropic_client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=8000,
    messages=[{"role": "user", "content": prompt}],
)
```

Same pattern: construct prompt, call API, parse structured response, update Notion.

---

## GitHub Integration

### Auto-SHIPPED on merge

A GitHub Action triggers on PR merge to main:

```yaml
name: Pipeline - Auto Complete
on:
  pull_request:
    types: [closed]
    branches: [main]

jobs:
  update-notion:
    if: github.event.pull_request.merged == true
    runs-on: ubuntu-latest
    steps:
      - name: Update Notion
        run: |
          # Extract item slug from branch name (feature/item-slug)
          # Find matching Notion item
          # Set Phase = MERGED
```

### CI as VERIFY stage

The existing CI pipeline (tests, lint, type checks) serves as the VERIFY stage. The orchestrator checks CI status via GitHub API before advancing past VERIFY.

---

## Migration from v1

1. **Update Notion schema** — add new fields, rename existing ones, update select options
2. **Create new views** — lane-based views replace the current queue views
3. **Rewrite orchestrator** — update `pipeline_orchestrator.py` for v2 state machine
4. **Move existing items** — map v1 statuses to v2 phases (most will be NEW or SPEC)
5. **Archive v1 instruction pages** — keep for reference, mark as superseded
6. **Test with one item per lane** — verify fast, standard, and high-risk flows end-to-end

---

## Lane Routing Quick Reference

| Signal | Lane |
|--------|------|
| Type = Documentation | fast |
| Type = Bug Fix AND ≤ 3 files | fast |
| Type = Refactor AND ≤ 3 files AND no API/schema | fast |
| Type = Infrastructure | high-risk |
| Touches auth, schema, public API, evidence store | high-risk |
| Touches AKSI controls or data classification | high-risk |
| Phase 0 items (SDK Ship) | high-risk |
| Everything else | standard |

The orchestrator can suggest a lane at triage. You confirm or override.

---

## Decisions (Resolved)

1. **Fast-lane auto-merge:** Yes — notify Kevin, auto-merge after 1 hour if no objection. Notification goes out when CI passes. If Kevin responds with a hold or change request within the window, the merge is paused and the item moves to REVIEW with Owner = Kevin.
2. **Nit follow-ups:** Auto-created. When a review returns `approved_with_nits`, the orchestrator creates a separate fast-lane item for the nits and links it via Blocked By. The parent item proceeds to merge.
3. **Codex model split:** Yes — use heavier model for adversarial spec/code review, faster model for builds. The orchestrator parameterizes model selection per stage.
4. **Artifact commit strategy:** PRDs and ADRs are committed to a `docs/` branch and PR'd for review. They are not committed directly to the feature branch. This keeps design artifacts reviewable independently of code changes.
