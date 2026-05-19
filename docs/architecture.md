# Architecture

## Core flow

```
Producers (MCP, CLI, HTTP, Tool wrapper)
    ↓
Action Objects (protocol-agnostic)
    ↓
Engine (AKSI v0.6 controls, deterministic evaluation)
    ↓
Evidence Store (DuckDB, SHA-256 hash chain)
    ↓
Reports (terminal, markdown, PDF, AIUC-1 readiness)
```

## Key abstractions

### Action Object

Protocol-agnostic representation of a tool call. Contains:
- Agent identity (`agent_id`)
- Tool information (`tool.name`, `tool.description_hash`)
- Parameters (raw payload + SHA-256 hash)
- Context (active data classifications, overlays)
- Source type (which producer created it)

All producers translate their protocol-specific invocations into Actions. The engine evaluates Actions — it doesn't know or care about the source protocol.

### Engine

The engine evaluates an Action against all active controls and produces an `EvaluationResult`. Each control evaluator runs independently and produces a `ControlResult` (PASS, FAIL, FLAG, SKIP, ERROR).

Decision logic:
- In **audit** mode: ALLOW always, log everything
- In **enforce** mode: BLOCK if any control FAILs, ALLOW otherwise

### Evidence Store

DuckDB-backed with SHA-256 hash chain integrity. Each record links to the previous record's hash, creating a tamper-evident chain from a fixed genesis seed.

Default path: `~/.ancilis/{agent_name}-{cwd_hash}/evidence.duckdb`

### Config resolution

`ancilis.yaml` → Pydantic validation → `ResolvedConfig`

Two activation paths (from ADR-004):
1. **Data classification**: `my_agent_handles` → DC codes → overlay activation
2. **Certification intent**: `certification_targets` → certification profile → control activation

Both compose. The strictest threshold and longest retention always win.

## Directory structure

```
python/src/ancilis/
├── activation/      # Overlay and certification resolution
├── cli/             # Click CLI commands
├── controls/        # Shared evaluator implementations
├── engine/          # Core evaluation engine
│   └── evaluators/  # PR-01 through PR-04
├── evidence/        # DuckDB store, hash chain, record schema
├── middleware/       # MCP middleware
├── producers/       # MCP, CLI, HTTP, Tool producers
└── report/          # Report generation and rendering

shared/
├── classifications/ # Data classification taxonomy
├── controls/        # 41 AKSI v0.6 control definitions (JSON)
├── overlays/        # Regulatory overlay profiles + certifications
└── schemas/         # JSON schemas for Action, EvaluationResult, EvidenceRecord
```

## Design principles

- **Data-classification-driven.** Declare your data, get the right controls.
- **Runtime-native.** Evaluation happens in-process, at tool call time.
- **Evidence as byproduct.** Compliance evidence is a natural output of doing security right.
- **Protocol-agnostic.** The Action Object Abstraction decouples producers from evaluation.
- **Deterministic.** Policy evaluation is pass/fail against declared rules, not heuristic.
