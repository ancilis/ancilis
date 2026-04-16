# Demo Run Evidence Boundary

## Decision

Demo and report views must use an explicit evidence scope instead of treating a DuckDB file as the reporting boundary.

For SDK Direct demo integrations, the default scope is the latest SDK `session_id` for each configured DuckDB path. Historical records remain in the SDK DuckDB store and may remain in Platform PostgreSQL as audit history, but posture/report/dashboard queries for a scoped demo source count only the selected session unless the source is configured for all-history mode.

## Rationale

The DuckDB evidence store is intentionally append-only across agent runs. Reusing the same `~/.ancilis/{agent}-{cwd-hash}/evidence.duckdb` file is normal, so the file itself cannot mean "current demo run." Counting every record in that file inflates demo posture, findings, and report totals after repeated runs.

Resetting or purging evidence is the wrong boundary. It loses audit history, creates operator-dependent cleanup behavior, and weakens the evidence-as-byproduct model. The correct boundary is deterministic metadata already produced by the SDK and carried through Platform ingestion:

- Platform tenant: `EvidenceRecord.org_id`
- Platform source: `EvidenceRecord.source_id`
- SDK source path: `EvidenceRecord.context["sdk_db_path"]`
- SDK run: `EvidenceRecord.context["session_id"]`
- Optional SDK tenant signal: `EvidenceRecord.context["tenant_id"]`
- Import batch: `EvidenceRecord.batch_id`, for integrity and audit, not as the primary run boundary
- Report window: timestamp filters remain additive, not a substitute for run scoping

## Implementation Shape

`SDKDirectAdapter` should support an explicit sync scope in `EvidenceSource.config`:

```json
{
  "sync": {
    "mode": "incremental",
    "batch_size": 500,
    "scope": { "mode": "latest_session" }
  }
}
```

Modes:

- `all_history`: existing behavior; collect and report all records selected by high-water mark and report window.
- `latest_session`: determine the most recent non-null `session_id` in each configured DuckDB path and collect/report only that session.
- `session`: collect/report a named `session_id`; useful for reruns and debugging.

The adapter should persist the resolved scope in source health/config metadata such as:

```json
{
  "current_scope": {
    "mode": "latest_session",
    "paths": [
      {
        "sdk_db_path": "/abs/path/evidence.duckdb",
        "session_id": "demo-run-20260416",
        "tenant_id": null
      }
    ]
  }
}
```

Platform query code that builds posture dashboards, posture exports, and demo-facing data-flow/report summaries must apply that scope by matching `source_id`, `sdk_db_path`, and `session_id` from `EvidenceRecord.context`. Evidence list/export endpoints may continue to expose all history unless the caller requests a scope filter.

## Constraints

- Do not reset DuckDB or require users to run `ancilis evidence reset`.
- Do not delete historical Platform evidence merely because a newer SDK session exists.
- Keep deterministic evaluation. Scope selection is a database query over persisted metadata, not an LLM or heuristic cleanup pass.
- Preserve hash-chain verification. The SDK record hash remains tied to the original SDK payload; Platform scope metadata lives outside the SDK hash but is covered by Platform `evidence_hash` when copied into `EvidenceRecord.context`.
- Preserve backward compatibility. Existing sources without `sync.scope` keep all-history behavior.

## Tests Required

Regression coverage must prove that a DuckDB file containing an old blocked session and a newer clean session produces current demo/report totals from the newer session only when `sync.scope.mode == "latest_session"`.

Backend tests should also cover:

- default all-history behavior is unchanged;
- explicit `session` mode selects the requested session;
- source health records the resolved scope;
- Platform dashboard/report counts ignore stale SDK session records for scoped sources while raw evidence history remains available;
- tenant/source isolation is always part of the query boundary.
