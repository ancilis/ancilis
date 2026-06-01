# Ancilis Python SDK

## CLI

The Python package installs the `ancilis` command. The CLI is implemented with
Click and reads the same local DuckDB evidence store written by the runtime
engine, middleware, and producers.

### `ancilis evidence list`

List recent evidence records, newest first.

```bash
ancilis evidence list --limit 10
ancilis evidence list --classification DC-PII --control-id PR-05 --format json
ancilis evidence list --since 2026-05-19T00:00:00+00:00 --agent-id support-agent
```

### `ancilis evidence show`

Show one full evidence record by full ID or a short prefix of at least seven
characters.

```bash
ancilis evidence show 9f2a4c1
ancilis evidence show 9f2a4c1 --format json
```

### `ancilis certify`

Compute v0.1 dry-run certification coverage for an in-scope framework. The
command reports covered, partial, and gap controls; it does not generate full
certification artifacts yet.

```bash
ancilis certify --target soc2
ancilis certify --target pci --format json --dry-run
```
