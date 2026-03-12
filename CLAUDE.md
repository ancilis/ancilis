# Ancilis SDK — Claude Code Project Guide

## Project Overview

Ancilis is a runtime control-and-evidence layer for tool-using AI agents. It intercepts MCP tool calls, evaluates them against security controls, generates cryptographically chained evidence, and produces posture/compliance reports.

**Architecture:** Data-classification-driven, runtime-native, inherently scalable. Evidence as byproduct. Security-first.

## Key Directories

- `python/src/ancilis/` — Python SDK (middleware, evidence store, CLI, engine, reports)
- `typescript/src/ancilis/` — TypeScript SDK (parallel implementation)
- `shared/` — Cross-language shared definitions (controls, overlays, certifications, schemas)
- `python/tests/` — Python test suite (pytest)

## Development Commands

```bash
# TypeScript tests
npx vitest run

# Python tests (use venv)
source .venv/bin/activate && pytest python/tests/ -v

# Install Python package in dev mode
source .venv/bin/activate && pip install -e ".[dev]"

# Validate config
ancilis config validate ancilis.yaml
```

## Codex Integration — Independent Review Protocol

When reviewing Ancilis, use Codex MCP as an independent, read-only reviewer by default unless the developer explicitly asks for edits. Have Codex inspect the repo and docs as if encountering the product fresh, infer the use case from what is actually implemented, compare implementation against claims, and challenge assumptions rather than echoing project intent.

Ask Codex for:
1. **Findings first**, ordered by severity, with file/line references
2. **Inferred product/use case** and how effectively the current build solves it
3. **What appears complete vs aspirational**
4. **Concrete strategy recommendations** for adoption, feature priority, and SDK/product design

Prefer grounded observations over speculation, and say explicitly when something could not be verified from the current codebase.

## Architecture Notes

- **Evidence store:** DuckDB-backed with SHA-256 hash chain integrity
- **Config flow:** ancilis.yaml → Pydantic validation → ResolvedConfig → Engine evaluation
- **Activation paths:** (1) data_handling → DC codes → overlay activation, (2) certification_targets → certification profiles → control activation
- **Controls:** PR-01 (Identity), PR-02 (Scope), PR-03 (Provenance), PR-04 (Exposure), PR-05 (Audit Trail), DE-01 (Baseline Detection)
- **Modes:** `audit` (evaluate + log, allow all) and `enforce` (evaluate + block violations)

## Non-Negotiable Principles

- Compliance is a byproduct of doing security right, not the goal itself
- Every output should reinforce: data-classification-driven, runtime-native, inherently scalable
- Respectful of existing compliance frameworks — the opportunity is different because AI agents are fundamentally different
- Never frame as criticism of existing standards; always frame as opportunity-forward
