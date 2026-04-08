# Multi-Tenant Data Isolation Architecture

> Ancilis security isolation model: defense-in-depth tenant data separation across platform and SDK.

## 1. Isolation Model Overview

Ancilis enforces tenant data isolation through four independent layers. Each layer provides a distinct guarantee; all four must be breached simultaneously for cross-tenant data leakage to occur.

```
Layer 1: PostgreSQL Row-Level Security (RLS)  — database-enforced query filtering
Layer 2: FastAPI tenant middleware              — JWT extraction + session injection
Layer 3: Runtime guards                        — fail-closed before_execute listener
Layer 4: CI linter                             — static analysis of raw SQL paths
```

**Design principle:** No single layer trusts another. RLS is the primary isolation mechanism at the database level. Middleware injects tenant context. Runtime guards catch application bugs that bypass middleware. CI linting catches developer errors before they ship.

## 2. PostgreSQL Row-Level Security

### Policy Design

Every tenant-scoped table has RLS enabled via Alembic migration:

```sql
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON {table}
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
```

**Key decisions:**

- **`FORCE ROW LEVEL SECURITY`** ensures policies apply even to table owners. Without this, the database owner role would bypass all RLS policies — defeating the purpose in environments where the application connects as the table owner.
- **`current_setting('app.tenant_id')`** reads from the PostgreSQL session variable set by the middleware layer. This avoids passing tenant_id through application queries, removing an entire class of "forgot to add WHERE tenant_id = ?" bugs.
- **`tenant_id UUID NOT NULL`** on all tenant-scoped columns with a foreign key to the tenants table. No nullable tenant references — every row belongs to exactly one tenant.

### Admin Bypass

A dedicated `BYPASSRLS` role is created for migration and administrative operations:

```sql
CREATE ROLE ancilis_admin WITH BYPASSRLS;
```

This role is **only** used by:
- Alembic migrations (DDL operations)
- System-level admin endpoints via `get_admin_db()` dependency
- Never exposed to tenant-facing API routes

## 3. API Middleware — JWT Extraction and Session Injection

### Tenant Context Flow

```
HTTP Request → JWT Bearer Token → get_current_tenant() → tenant_id
    → get_tenant_db() → SET LOCAL app.tenant_id → SQLAlchemy session
        → All queries auto-filtered by RLS
```

### `get_current_tenant()` Dependency

FastAPI dependency that:
1. Extracts `tenant_id` claim from the Authorization Bearer JWT
2. Returns HTTP 401 if JWT is missing or `tenant_id` claim absent
3. Validates tenant exists in the tenants table (with short-TTL cache)

### `get_tenant_db()` Dependency

Chains `get_current_tenant()` into a SQLAlchemy session with tenant context injected:

```python
# In the SQLAlchemy after_begin event:
session.execute(text("SET LOCAL app.tenant_id = :tid"), {"tid": str(tenant_id)})
```

### Connection Pool Safety: `SET LOCAL` vs `SET`

This is the most critical implementation detail in the middleware layer.

| Behavior | `SET` | `SET LOCAL` |
|----------|-------|-------------|
| Scope | Session (connection) | Transaction only |
| After COMMIT/ROLLBACK | **Persists** | **Resets to default** |
| Connection pool risk | Previous tenant's ID **leaks** to next checkout | Clean slate on every checkout |

**Ancilis uses `SET LOCAL` exclusively.** When a connection is returned to the pool after a transaction completes, `app.tenant_id` automatically resets. This prevents tenant context from leaking between requests that share pooled connections.

If `SET` were used instead, a connection returned to the pool would retain the previous tenant's ID. The next request checking out that connection would inherit stale tenant context — a direct path to cross-tenant data leakage.

### `get_admin_db()` — System Sessions

Separate dependency for internal/system operations:
- Connects with the `BYPASSRLS` admin role
- Can read/write across all tenants (for migrations, system reports)
- **Never injected into tenant-facing API routes** — enforced by code review and the CI linter

## 4. Runtime Guards

### `before_execute` Event Listener

Registered on the tenant session factory's SQLAlchemy engine:

```python
@event.listens_for(tenant_engine, "before_execute")
def verify_tenant_context(conn, clauseelement, multiparams, params):
    # Check that app.tenant_id is set in the PostgreSQL session
    result = conn.execute(text("SELECT current_setting('app.tenant_id', true)"))
    tenant_id = result.scalar()
    if not tenant_id:
        raise TenantContextMissing(
            "Query attempted without tenant context — aborting"
        )
```

**Behavior:**
- Runs before every SQL statement on tenant-scoped connections
- Raises `TenantContextMissing(RuntimeError)` if `app.tenant_id` is not set — **fail closed**
- Skips check for:
  - Admin session factory (BYPASSRLS connections)
  - DDL operations (CREATE, ALTER, DROP)

**Why fail closed?** If tenant context is missing, the query would execute against all rows (RLS uses `current_setting` which returns NULL, and NULL comparisons fail). Rather than silently returning no results or all results depending on policy wording, the guard raises immediately. This converts a potential silent data leak into a loud, traceable error.

### `TenantContextMissing` Exception

```python
class TenantContextMissing(RuntimeError):
    """Raised when a tenant-scoped query is attempted without tenant context."""
    pass
```

This exception is:
- Caught by FastAPI error handlers → returns HTTP 500 with a generic error (no tenant details in response)
- Logged with full context for debugging
- Triggers alerts in monitoring

## 5. CI Linter

### Raw SQL Tenant Binding Verification

A CI step scans Python source files for raw SQL strings targeting tenant-scoped tables:

**What it checks:**
- Any raw SQL (outside of ORM) that references a tenant-scoped table must include `tenant_id` parameter binding
- Flags patterns like `f"SELECT * FROM evidence_records WHERE ..."` without tenant_id
- Runs as a pytest check or standalone script in the CI pipeline

**Design constraints:**
- Conservative: false positives are worse than false negatives. The linter complements RLS and runtime guards — it doesn't need to catch everything
- Focus on raw SQL only — ORM queries are covered by RLS automatically
- Does not block on DDL or migration files

## 6. DuckDB SDK Parity — Tenant Scoping

The SDK evidence store (DuckDB) mirrors the platform's tenant isolation model for local/demo environments and hybrid deployments.

### Schema

```sql
CREATE TABLE IF NOT EXISTS evidence_records (
    ...
    tenant_id VARCHAR    -- nullable for backward compatibility
);
```

The `tenant_id` column is nullable. When not set, the store operates in single-tenant mode (backward-compatible with pre-isolation deployments).

### Store Initialization

Both Python and TypeScript SDKs accept an optional tenant_id at construction:

**Python:**
```python
store = EvidenceStore(config, tenant_id="tenant-abc-123")
```

**TypeScript:**
```typescript
const store = new EvidenceStore(config, { tenantId: "tenant-abc-123" });
```

### Query Scoping

When `tenant_id` is set:
- All read operations (`getRecords`, `getSummary`, `count`, `listSessions`) add `WHERE tenant_id = ?`
- All write operations include `tenant_id` in INSERT statements
- When `tenant_id` is None/undefined: no tenant filter applied (single-tenant backward compatibility)

### Hash Chain Isolation

Each tenant maintains an **independent hash chain**:

- **Previous hash lookup** is scoped: `SELECT record_hash FROM evidence_records WHERE tenant_id = ? ORDER BY seq_id DESC LIMIT 1`
- **Genesis seed** (`sha256("ancilis-genesis-v1")`) is the starting point for each new tenant's chain
- **Canonical payload** includes `tenant_id` when set:

```python
payload = {
    "evaluation_id": ...,
    "agent_id": ...,
    # ... other fields sorted alphabetically
    "tenant_id": tenant_id,     # included only when set
    "previous_hash": previous_hash,  # scoped to this tenant's chain
}
hash = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")))
```

**Cross-language parity:** Python and TypeScript implementations produce identical hash outputs for identical inputs. Both use:
- JSON with `sort_keys=True` and compact separators `(",", ":")`
- SHA-256 hex digest
- Conditional inclusion of `tenant_id` (omitted when None/undefined, preserving backward compatibility)

### Evidence Path Isolation

Each agent+workspace combination gets its own DuckDB file at `~/.ancilis/{agent}-{cwd-hash}/evidence.duckdb`. Tenant scoping operates **within** this file — multiple tenants can coexist in one DuckDB when explicitly configured, but each tenant's data and hash chain are logically isolated.

## 7. Verification Strategy

### Automated Isolation Test Suite (ANC-211)

A comprehensive integration test suite verifies tenant isolation on every CI build:

**Test fixtures:**
- `tenant_a` and `tenant_b` factory fixtures — each creates a tenant with JWT credentials
- `seed_tenant_data(tenant)` populates all tenant-scoped tables with identifiable test data
- Full cleanup after each test session

**Read isolation tests** (per tenant-scoped endpoint):
- `test_{endpoint}_returns_only_own_data` — authenticate as Tenant A, verify zero Tenant B records
- `test_{endpoint}_cross_tenant_access_denied` — authenticate as Tenant A, request Tenant B resource by ID, expect 403 or 404
- `test_{endpoint}_bulk_no_leak` — list/search endpoints return only current tenant's data

**Write isolation tests:**
- `test_create_in_other_tenant_rejected` — POST with Tenant A auth targeting Tenant B namespace returns 403
- `test_update_other_tenant_resource_rejected` — PATCH/PUT cross-tenant returns 403
- `test_delete_other_tenant_resource_rejected` — DELETE cross-tenant returns 403

**Edge case tests:**
- `test_no_tenant_context_rejected` — request without JWT returns 401
- `test_invalid_tenant_id_rejected` — JWT with non-existent tenant_id returns 401/403
- `test_rls_bypassed_only_by_admin` — admin session sees all tenants, regular session does not

**Test requirements:**
- Real PostgreSQL (no database mocking)
- Full cleanup after each run
- No execution order dependencies
- Tagged with `@pytest.mark.tenant_isolation` for selective execution
- Runs on every CI build

### SDK-Level Verification

The Python and TypeScript SDKs each include tenant isolation unit tests:
- `test_tenant_scoped_store` — records from tenant A not visible to tenant B
- `test_tenant_hash_chain_independent` — hash chains don't cross tenants
- `test_no_tenant_backward_compatible` — existing single-tenant behavior preserved
- `test_tenant_id_in_record` — stored records include tenant_id field

---

## Summary: Isolation Guarantees

| Threat | Layer 1 (RLS) | Layer 2 (Middleware) | Layer 3 (Guard) | Layer 4 (Linter) |
|--------|:---:|:---:|:---:|:---:|
| Missing WHERE clause | Blocked | - | - | Flagged |
| Wrong tenant in session | Blocked | Prevented | - | - |
| No tenant context at all | Blocked | HTTP 401 | Exception | - |
| Raw SQL without binding | Blocked | - | Exception | Flagged |
| Connection pool leak | Blocked | SET LOCAL resets | - | - |
| Admin role misuse | - | Route restriction | Bypass check | - |

No single layer failure results in cross-tenant data exposure. The isolation model is designed so that any individual layer can fail and the remaining layers still prevent data leakage.
