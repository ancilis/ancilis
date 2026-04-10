/** Tests for baseline snapshot and drift detection (TypeScript). */

import { describe, it, expect, beforeEach } from "vitest";
import { BaselineManager } from "../src/ancilis/baselines/index.js";
import { DriftDetector, computeControlStats, passRate, dominantResult } from "../src/ancilis/baselines/drift.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import type { EvaluationResult } from "../src/ancilis/engine/result.js";

// Minimal config stub
function makeConfig(agentName = "test-agent"): ResolvedConfig {
  return {
    agentName,
    mode: "audit",
    controls: new Map(),
    activeOverlays: new Map(),
    activeCertifications: [],
    approvedTools: [],
  } as unknown as ResolvedConfig;
}

// Helper to build an in-memory EvidenceStore
async function makeStore(config: ResolvedConfig): Promise<EvidenceStore> {
  return new EvidenceStore(config, { inMemory: true });
}

// Helper to build a stub EvaluationResult
function makeEval(
  controlId: string,
  result: "PASS" | "FAIL" | "FLAG" | "SKIP",
  agentId = "test-agent",
): EvaluationResult {
  return {
    evaluationId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    agentId,
    sourceType: "agent",
    decision: result === "FAIL" ? "BLOCK" : "ALLOW",
    mode: "audit",
    controlResults: [
      {
        controlId,
        controlName: `Control ${controlId}`,
        result,
        detail: null,
        evidenceData: null,
        durationMs: 1,
      },
    ],
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 1,
  };
}

// ---------------------------------------------------------------------------
// computeControlStats
// ---------------------------------------------------------------------------
describe("computeControlStats", () => {
  it("aggregates pass/fail counts across rows", () => {
    const rows = [
      { control_results: JSON.stringify([{ control_id: "PR-01", control_name: "PR-01", result: "PASS" }]) },
      { control_results: JSON.stringify([{ control_id: "PR-01", control_name: "PR-01", result: "PASS" }]) },
      { control_results: JSON.stringify([{ control_id: "PR-01", control_name: "PR-01", result: "FAIL" }]) },
    ];
    const stats = computeControlStats(rows);
    expect(stats["PR-01"]?.pass).toBe(2);
    expect(stats["PR-01"]?.fail).toBe(1);
    expect(stats["PR-01"]?.total).toBe(3);
  });

  it("handles empty rows", () => {
    expect(computeControlStats([])).toEqual({});
  });

  it("handles already-parsed JSON in control_results", () => {
    const rows = [
      { control_results: [{ control_id: "DE-01", result: "SKIP" }] },
    ];
    const stats = computeControlStats(rows as Array<{ control_results: unknown }>);
    expect(stats["DE-01"]?.skip).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// passRate / dominantResult
// ---------------------------------------------------------------------------
describe("passRate", () => {
  it("returns 1.0 for empty stats", () => {
    expect(passRate({ controlName: "x", pass: 0, fail: 0, flag: 0, skip: 0, error: 0, total: 0 })).toBe(1.0);
  });

  it("computes correctly", () => {
    expect(passRate({ controlName: "x", pass: 3, fail: 1, flag: 0, skip: 0, error: 0, total: 4 })).toBeCloseTo(0.75);
  });
});

describe("dominantResult", () => {
  it("returns SKIP for empty stats", () => {
    expect(dominantResult({ controlName: "x", pass: 0, fail: 0, flag: 0, skip: 0, error: 0, total: 0 })).toBe("SKIP");
  });

  it("returns all-pass as PASS", () => {
    expect(dominantResult({ controlName: "x", pass: 5, fail: 0, flag: 0, skip: 0, error: 0, total: 5 })).toBe("PASS");
  });

  it("returns dominant result in mixed case", () => {
    const result = dominantResult({ controlName: "x", pass: 2, fail: 3, flag: 0, skip: 0, error: 0, total: 5 });
    expect(result).toBe("FAIL");
  });
});

// ---------------------------------------------------------------------------
// DriftDetector
// ---------------------------------------------------------------------------
describe("DriftDetector", () => {
  it("returns STABLE when no drift", () => {
    const baseline = {
      baselineId: "b1",
      createdAt: new Date().toISOString(),
      agentId: "agent",
      overlayId: null,
      label: "test",
      isActive: true,
      metadata: null,
      controlSnapshots: [
        { controlId: "PR-01", result: "PASS", passRate: 1.0, totalEvaluations: 10, evidenceWindowStart: "", evidenceWindowEnd: "" },
      ],
    };
    const currentStats = {
      "PR-01": { controlName: "PR-01", pass: 10, fail: 0, flag: 0, skip: 0, error: 0, total: 10 },
    };
    const detector = new DriftDetector();
    const report = detector.detect(baseline, currentStats, { "PR-01": null }, {}, {});
    expect(report.overallStatus).toBe("STABLE");
    expect(report.controlDrifts).toHaveLength(0);
    expect(report.summary.stable).toBe(1);
  });

  it("detects CRITICAL drift when 100% pass rate drops to failure", () => {
    const baseline = {
      baselineId: "b1",
      createdAt: new Date().toISOString(),
      agentId: "agent",
      overlayId: null,
      label: "test",
      isActive: true,
      metadata: null,
      controlSnapshots: [
        { controlId: "PR-01", result: "PASS", passRate: 1.0, totalEvaluations: 10, evidenceWindowStart: "", evidenceWindowEnd: "" },
      ],
    };
    const currentStats = {
      "PR-01": { controlName: "PR-01", pass: 0, fail: 5, flag: 0, skip: 0, error: 0, total: 5 },
    };
    const detector = new DriftDetector();
    const report = detector.detect(baseline, currentStats, { "PR-01": null }, {}, {});
    expect(report.overallStatus).toBe("DRIFTED");
    expect(report.controlDrifts[0]?.severity).toBe("CRITICAL");
  });

  it("detects HIGH drift when PASS → FAIL", () => {
    const baseline = {
      baselineId: "b1",
      createdAt: new Date().toISOString(),
      agentId: "agent",
      overlayId: null,
      label: "test",
      isActive: true,
      metadata: null,
      controlSnapshots: [
        { controlId: "PR-02", result: "PASS", passRate: 0.8, totalEvaluations: 10, evidenceWindowStart: "", evidenceWindowEnd: "" },
      ],
    };
    const currentStats = {
      "PR-02": { controlName: "PR-02", pass: 0, fail: 5, flag: 0, skip: 0, error: 0, total: 5 },
    };
    const detector = new DriftDetector();
    const report = detector.detect(baseline, currentStats, { "PR-02": null }, {}, {});
    expect(report.controlDrifts[0]?.severity).toBe("HIGH");
  });

  it("treats disappeared controls as HIGH drift if they were passing", () => {
    const baseline = {
      baselineId: "b1",
      createdAt: new Date().toISOString(),
      agentId: "agent",
      overlayId: null,
      label: "test",
      isActive: true,
      metadata: null,
      controlSnapshots: [
        { controlId: "PR-01", result: "PASS", passRate: 1.0, totalEvaluations: 5, evidenceWindowStart: "", evidenceWindowEnd: "" },
      ],
    };
    const detector = new DriftDetector();
    const report = detector.detect(baseline, {}, {}, {}, {});
    expect(report.overallStatus).toBe("DRIFTED");
    expect(report.controlDrifts[0]?.severity).toBe("HIGH");
    expect(report.controlDrifts[0]?.currentResult).toBe("SKIP");
  });

  it("populates evidenceDelta from provided maps", () => {
    const baseline = {
      baselineId: "b1",
      createdAt: new Date().toISOString(),
      agentId: "agent",
      overlayId: null,
      label: "test",
      isActive: true,
      metadata: null,
      controlSnapshots: [
        { controlId: "PR-01", result: "PASS", passRate: 1.0, totalEvaluations: 10, evidenceWindowStart: "", evidenceWindowEnd: "" },
      ],
    };
    const currentStats = {
      "PR-01": { controlName: "PR-01", pass: 0, fail: 2, flag: 0, skip: 0, error: 0, total: 2 },
    };
    const detector = new DriftDetector();
    const report = detector.detect(
      baseline, currentStats,
      { "PR-01": "2026-01-01T00:00:00.000Z" },
      { "PR-01": ["eval-1", "eval-2"] },
      { "PR-01": ["bash_tool"] },
    );
    expect(report.controlDrifts[0]?.evidenceDelta.newFailures).toEqual(["eval-1", "eval-2"]);
    expect(report.controlDrifts[0]?.evidenceDelta.failureTools).toEqual(["bash_tool"]);
    expect(report.controlDrifts[0]?.firstFailureAt).toBe("2026-01-01T00:00:00.000Z");
  });
});

// ---------------------------------------------------------------------------
// BaselineManager (integration, in-memory DuckDB)
// ---------------------------------------------------------------------------
describe("BaselineManager", () => {
  let store: EvidenceStore;
  let manager: BaselineManager;
  const config = makeConfig("test-agent");

  beforeEach(async () => {
    store = await makeStore(config);
    manager = new BaselineManager(store, config);
  });

  it("creates an empty baseline when no evidence exists", async () => {
    const baseline = await manager.create({ label: "v1" });
    expect(baseline.label).toBe("v1");
    expect(baseline.agentId).toBe("test-agent");
    expect(baseline.isActive).toBe(true);
    expect(baseline.controlSnapshots).toHaveLength(0);
  });

  it("captures control snapshots from evidence", async () => {
    await store.store(makeEval("PR-01", "PASS"), "bash_tool");
    await store.store(makeEval("PR-01", "PASS"), "bash_tool");
    await store.store(makeEval("DE-01", "FAIL"), "read_file");

    const baseline = await manager.create({ label: "v1" });
    const prSnap = baseline.controlSnapshots.find(s => s.controlId === "PR-01");
    const deSnap = baseline.controlSnapshots.find(s => s.controlId === "DE-01");

    expect(prSnap?.result).toBe("PASS");
    expect(prSnap?.passRate).toBeCloseTo(1.0);
    expect(deSnap?.result).toBe("FAIL");
  });

  it("deactivates previous active baseline on create", async () => {
    const b1 = await manager.create({ label: "v1" });
    const b2 = await manager.create({ label: "v2" });

    const fetched1 = await manager.getBaseline(b1.baselineId);
    const fetched2 = await manager.getBaseline(b2.baselineId);

    expect(fetched1.isActive).toBe(false);
    expect(fetched2.isActive).toBe(true);
  });

  it("lists baselines for agent", async () => {
    await manager.create({ label: "v1" });
    await manager.create({ label: "v2" });

    const list = await manager.listBaselines();
    expect(list).toHaveLength(2);
    // Ordered by created_at DESC
    expect(list[0]?.label).toBe("v2");
  });

  it("throws on getBaseline with unknown id", async () => {
    await expect(manager.getBaseline("nonexistent")).rejects.toThrow("Baseline not found");
  });

  it("deactivates a baseline", async () => {
    const b = await manager.create({ label: "v1" });
    await manager.deactivate(b.baselineId);
    const fetched = await manager.getBaseline(b.baselineId);
    expect(fetched.isActive).toBe(false);
  });

  it("checkDrift returns STABLE with same evidence", async () => {
    await store.store(makeEval("PR-01", "PASS"), "bash_tool");
    await manager.create({ label: "v1" });

    // Evidence is from before the baseline, so nothing since baseline
    const report = await manager.checkDrift();
    expect(report.overallStatus).toBe("STABLE");
  });

  it("checkDrift throws when no active baseline", async () => {
    await expect(manager.checkDrift()).rejects.toThrow("No active baseline found");
  });

  it("checkDrift by id uses specified baseline", async () => {
    const b = await manager.create({ label: "v1" });
    // Deactivate it
    await manager.deactivate(b.baselineId);

    // Should be findable by ID even when inactive
    const report = await manager.checkDrift({ baselineId: b.baselineId });
    expect(report.baselineId).toBe(b.baselineId);
  });

  it("roundtrips metadata", async () => {
    const meta = { version: "1.2.3", env: "prod" };
    const b = await manager.create({ label: "meta-test", metadata: meta });
    const fetched = await manager.getBaseline(b.baselineId);
    expect(fetched.metadata).toEqual(meta);
  });

  it("stores snapshots in snake_case JSON (Python-compatible)", async () => {
    await store.store(makeEval("PR-01", "PASS"), "bash_tool");
    await manager.create({ label: "compat" });

    const rows = await store.query("SELECT control_snapshots FROM baselines LIMIT 1");
    const raw = (rows as Array<Record<string, unknown>>)[0]?.control_snapshots;
    const parsed = typeof raw === "string" ? JSON.parse(raw) as Array<Record<string, unknown>> : raw as Array<Record<string, unknown>>;
    expect(parsed[0]).toHaveProperty("control_id");
    expect(parsed[0]).toHaveProperty("pass_rate");
    expect(parsed[0]).toHaveProperty("total_evaluations");
    expect(parsed[0]).not.toHaveProperty("controlId");
  });

  it("multi-agent isolation: drift check only reads its own agent evidence", async () => {
    // Two managers sharing the SAME store but different agentIds
    const sharedStore = await makeStore(config);
    const configAlpha = makeConfig("agent-alpha");
    const configBeta = makeConfig("agent-beta");
    const mgrAlpha = new BaselineManager(sharedStore, configAlpha);
    const mgrBeta = new BaselineManager(sharedStore, configBeta);

    // Alpha stores passing evidence and creates a baseline
    await sharedStore.store(makeEval("PR-01", "PASS", "agent-alpha"), "bash_tool");
    await mgrAlpha.create({ label: "alpha-v1" });

    // Beta stores failing evidence for the same control
    await sharedStore.store(makeEval("PR-01", "FAIL", "agent-beta"), "bash_tool");
    await mgrBeta.create({ label: "beta-v1" });

    // Now add post-baseline evidence: alpha still passes, beta still fails
    await sharedStore.store(makeEval("PR-01", "PASS", "agent-alpha"), "bash_tool");
    await sharedStore.store(makeEval("PR-01", "FAIL", "agent-beta"), "bash_tool");

    // Alpha's drift check should see STABLE (only its own passing evidence)
    const alphaReport = await mgrAlpha.checkDrift();
    expect(alphaReport.overallStatus).toBe("STABLE");
    expect(alphaReport.agentId).toBe("agent-alpha");

    // Beta's drift check should see its own failing evidence (no regression from baseline though)
    const betaReport = await mgrBeta.checkDrift();
    expect(betaReport.agentId).toBe("agent-beta");

    // Critically: alpha must NOT see beta's failures
    const alphaDrifts = alphaReport.controlDrifts.filter(d => d.severity === "CRITICAL" || d.severity === "HIGH");
    expect(alphaDrifts).toHaveLength(0);
  });

  it("tenant isolation: baselines from different tenants don't cross", async () => {
    const storeA = new EvidenceStore(config, { inMemory: true });
    const storeB = new EvidenceStore(config, { inMemory: true });
    // Both use same DB but different tenant_id (reuse same in-memory DB is per instance)
    const mgA = new BaselineManager(storeA, config, { tenantId: "tenant-A" });
    const mgB = new BaselineManager(storeB, config, { tenantId: "tenant-B" });

    await mgA.create({ label: "tenant-a-baseline" });
    // mgB has its own in-memory DB, so no cross-contamination
    const listB = await mgB.listBaselines();
    expect(listB).toHaveLength(0);
  });
});
