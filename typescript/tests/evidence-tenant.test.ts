/**
 * Tests for ANC-213 — DuckDB tenant scoping in the TypeScript SDK evidence store.
 *
 * Acceptance criteria:
 *   - tenant_id column added to schema
 *   - Queries filtered by tenantId when set
 *   - Hash chain includes tenantId
 *   - Independent hash chains per tenant
 *   - Backward-compatible when tenantId undefined
 */

import { describe, it, expect, afterEach } from "vitest";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import type { EvaluationResult } from "../src/ancilis/engine/result.js";
import { GENESIS_SEED, canonicalPayload } from "../src/ancilis/evidence/chain.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";

function makeConfig(overrides: Record<string, unknown> = {}): ResolvedConfig {
  return loadConfig({ raw: { agent: { name: "test-agent" }, ...overrides } });
}

function makeEvaluation(overrides: Partial<EvaluationResult> = {}): EvaluationResult {
  return {
    evaluationId: "eval-001",
    actionId: "action-001",
    timestamp: "2025-01-15T10:30:00Z",
    agentId: "test-agent",
    sourceType: "mcp",
    mode: "audit",
    controlResults: [
      {
        controlId: "PR-01",
        controlName: "Agent Identity",
        result: "PASS",
        detail: "Agent identity verified",
        evidenceData: { agent_id: "test-agent" },
        durationMs: 1.5,
      },
    ],
    decision: "ALLOW",
    decisionReason: "All controls passed",
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 5.0,
    ...overrides,
  };
}

describe("Tenant Scoping — evidence store", () => {
  let storeA: EvidenceStore;
  let storeB: EvidenceStore;
  let storeNoTenant: EvidenceStore;

  afterEach(async () => {
    if (storeA) await storeA.close();
    if (storeB) await storeB.close();
    if (storeNoTenant) await storeNoTenant.close();
  });

  // AC: tenant_id stored in record and returned
  it("tenant_id in record", async () => {
    storeA = new EvidenceStore(makeConfig(), { inMemory: true, tenantId: "tenant-alpha" });
    const record = await storeA.store(makeEvaluation(), "tool-x");
    expect(record.tenantId).toBe("tenant-alpha");
  });

  // AC: records from tenant A not visible to tenant B store (isolation)
  it("tenant-scoped store — records not visible across tenants", async () => {
    // Both stores point at the same in-memory DB via a shared path approach is not
    // possible with DuckDB in-memory, so we test isolation by storing to a shared
    // file-path DB.  Use distinct stores sharing one DuckDB file via dbPath.
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const { randomUUID } = await import("node:crypto");

    const dbPath = join(tmpdir(), `ancilis-tenant-iso-${randomUUID()}.duckdb`);

    storeA = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-A" });
    storeB = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-B" });

    // Store a record under tenant A
    await storeA.store(makeEvaluation({ evaluationId: "e-A" }), "tool-a");
    // Store a record under tenant B
    await storeB.store(makeEvaluation({ evaluationId: "e-B" }), "tool-b");

    // Each tenant sees only its own record
    const recordsA = await storeA.getRecords();
    const recordsB = await storeB.getRecords();

    expect(recordsA.length).toBe(1);
    expect(recordsA[0]!.evaluationId).toBe("e-A");

    expect(recordsB.length).toBe(1);
    expect(recordsB[0]!.evaluationId).toBe("e-B");
  });

  // AC: count() is scoped per tenant
  it("count is scoped per tenant", async () => {
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const { randomUUID } = await import("node:crypto");

    const dbPath = join(tmpdir(), `ancilis-tenant-count-${randomUUID()}.duckdb`);

    storeA = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-A" });
    storeB = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-B" });

    await storeA.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await storeA.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    await storeB.store(makeEvaluation({ evaluationId: "e3" }), "t3");

    expect(await storeA.count()).toBe(2);
    expect(await storeB.count()).toBe(1);
  });

  // AC: independent hash chains per tenant — tenant A and B have separate hash chains
  it("tenant hash chain independent", async () => {
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const { randomUUID } = await import("node:crypto");

    const dbPath = join(tmpdir(), `ancilis-tenant-chain-${randomUUID()}.duckdb`);

    storeA = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-A" });
    storeB = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-B" });

    // Both tenants start from GENESIS_SEED
    const rA1 = await storeA.store(makeEvaluation({ evaluationId: "eA1" }), "tool-a");
    const rB1 = await storeB.store(makeEvaluation({ evaluationId: "eB1" }), "tool-b");

    expect(rA1.previousHash).toBe(GENESIS_SEED);
    expect(rB1.previousHash).toBe(GENESIS_SEED);

    // Second record for each tenant chains to its own first record, not the other's
    const rA2 = await storeA.store(makeEvaluation({ evaluationId: "eA2" }), "tool-a");
    const rB2 = await storeB.store(makeEvaluation({ evaluationId: "eB2" }), "tool-b");

    expect(rA2.previousHash).toBe(rA1.recordHash);
    expect(rB2.previousHash).toBe(rB1.recordHash);

    // Cross-check: tenant A's second record does NOT chain to tenant B's first record
    expect(rA2.previousHash).not.toBe(rB1.recordHash);
  });

  // AC: hash chains for both tenants are individually valid
  it("tenant hash chains verify independently", async () => {
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const { randomUUID } = await import("node:crypto");

    const dbPath = join(tmpdir(), `ancilis-tenant-verify-${randomUUID()}.duckdb`);

    storeA = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-A" });
    storeB = new EvidenceStore(makeConfig(), { dbPath, tenantId: "tenant-B" });

    await storeA.store(makeEvaluation({ evaluationId: "eA1" }), "tool-a");
    await storeA.store(makeEvaluation({ evaluationId: "eA2" }), "tool-a");
    await storeB.store(makeEvaluation({ evaluationId: "eB1" }), "tool-b");

    const { valid: validA, errors: errorsA } = await storeA.verifyChain();
    const { valid: validB, errors: errorsB } = await storeB.verifyChain();

    expect(validA).toBe(true);
    expect(errorsA).toEqual([]);
    expect(validB).toBe(true);
    expect(errorsB).toEqual([]);
  });

  // AC: backward-compatible when tenantId undefined
  it("no tenant backward compatible — existing behavior unchanged", async () => {
    storeNoTenant = new EvidenceStore(makeConfig(), { inMemory: true });

    const r1 = await storeNoTenant.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    const r2 = await storeNoTenant.store(makeEvaluation({ evaluationId: "e2" }), "t2");

    // tenantId is null/undefined in returned records
    expect(r1.tenantId == null).toBe(true);
    expect(r2.tenantId == null).toBe(true);

    // Chain links correctly
    expect(r1.previousHash).toBe(GENESIS_SEED);
    expect(r2.previousHash).toBe(r1.recordHash);

    // Counts work normally
    expect(await storeNoTenant.count()).toBe(2);

    // Chain valid
    const { valid } = await storeNoTenant.verifyChain();
    expect(valid).toBe(true);
  });

  // AC: tenantId is included in hash payload (different tenant → different hash for same input)
  it("tenantId affects hash output", async () => {
    const baseArgs = {
      evaluationId: "e1",
      timestamp: "2025-01-15T10:30:00Z",
      agentId: "test-agent",
      sourceType: "mcp" as const,
      toolName: "tool-x",
      decision: "ALLOW",
      mode: "audit" as const,
      controlResults: [],
      activeOverlays: [] as string[],
      dataClassifications: [] as string[],
      activeCertifications: [] as string[],
      totalDurationMs: 5.0,
      previousHash: GENESIS_SEED,
    };

    const payloadNoTenant = canonicalPayload({ ...baseArgs });
    const payloadWithTenant = canonicalPayload({ ...baseArgs, tenantId: "tenant-X" });
    const payloadOtherTenant = canonicalPayload({ ...baseArgs, tenantId: "tenant-Y" });

    // Different tenants produce different payloads
    expect(payloadNoTenant).not.toBe(payloadWithTenant);
    expect(payloadWithTenant).not.toBe(payloadOtherTenant);

    // Payload with tenant includes the tenant_id key
    const parsed = JSON.parse(payloadWithTenant);
    expect(parsed.tenant_id).toBe("tenant-X");

    // Payload without tenant does NOT include tenant_id key
    const parsedNoTenant = JSON.parse(payloadNoTenant);
    expect("tenant_id" in parsedNoTenant).toBe(false);
  });
});
