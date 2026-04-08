# SARIF → AKSI Control Mapping

`sarif-aksi-controls.json` maps SARIF rule IDs to Ancilis AKSI control IDs.

## Format

```json
{
  "_version": "1.0.0",
  "mappings": {
    "<rule-id-or-pattern>": "<aksi-control-id>"
  }
}
```

### Pattern matching

Patterns are matched in order; **first match wins**.

| Pattern style | Example | Matches |
|---|---|---|
| Exact | `"js/sql-injection"` | That rule ID only |
| Glob prefix | `"js/sql-*"` | Any rule starting with `js/sql-` |

Glob matching uses `*` as a wildcard suffix only (no full glob syntax).

### AKSI control IDs

| Control | Meaning |
|---|---|
| `PR-01` | Access control / request validation |
| `PR-02` | Rate limiting |
| `PR-03` | Input validation / injection prevention |
| `PR-04` | Cryptographic controls |
| `PR-05` | Secrets management |

### Adding entries

Add new mappings to the `mappings` object. More specific patterns should appear before wildcards since matching is first-match.

### CycloneDX

CycloneDX vulnerability severities map directly to evidence results — no mapping table is needed:

| Severity | Evidence result |
|---|---|
| `critical`, `high` | `BLOCK` |
| `medium` | `FLAG` |
| `low`, `none`, `unknown` | `ALLOW` |
