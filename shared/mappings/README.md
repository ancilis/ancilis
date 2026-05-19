# SARIF → AKSI Control Mapping

`sarif-aksi-controls.json` maps SARIF rule IDs to Ancilis AKSI control IDs.

## Format

```json
{
  "version": 1,
  "mappings": [
    {
      "rule_id": "<rule-id-or-pattern>",
      "control_id": "<aksi-control-id>",
      "match": "exact",
      "description": "Why this scanner rule maps to the AKSI control."
    }
  ]
}
```

### Pattern matching

Exact rules are evaluated before glob rules. Glob rules are then evaluated in file order.

| Pattern style | Example | Matches |
|---|---|---|
| Exact | `"js/sql-injection"` | That rule ID only |
| Glob prefix | `"js/sql-*"` | Any rule starting with `js/sql-` |

Glob matching uses `*` as a wildcard suffix only (no full glob syntax).

### AKSI control IDs

| Control | Meaning |
|---|---|
| `PR-02` | Permission scope enforcement |
| `PR-03` | Tool/model integrity and provenance |
| `PR-04` | Data exposure prevention |
| `PR-08` | Input validation and injection resistance |
| `PR-09` | Controlled code execution and sandbox enforcement |

### Adding entries

Add new mappings to the `mappings` array. Set `match` to `exact` for one rule ID or `glob` for a wildcard pattern.

### CycloneDX

CycloneDX vulnerability severities map directly to evidence results — no mapping table is needed:

| Severity | Evidence result |
|---|---|
| `critical`, `high` | `BLOCK` |
| `medium` | `FLAG` |
| `low`, `none`, `unknown` | `ALLOW` |
