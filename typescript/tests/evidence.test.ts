/**
 * Tests for ancilis evidence — Unit 4: Evidence Generation & Storage.
 */

import { describe, it, expect, afterEach } from "vitest";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import type { EvaluationResult } from "../src/ancilis/engine/result.js";
import { GENESIS_SEED, canonicalPayload, computeHash } from "../src/ancilis/evidence/chain.js";
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

// --- Hash Chain ---

describe("Hash Chain", () => {
  it("genesis seed is deterministic", () => {
    expect(GENESIS_SEED).toBe(GENESIS_SEED);
    expect(GENESIS_SEED.length).toBe(64);
  });

  it("canonical payload is deterministic", () => {
    const args = {
      evaluationId: "e1",
      timestamp: "2025-01-01T00:00:00Z",
      agentId: "agent",
      toolName: "tool",
      decision: "ALLOW",
      mode: "audit",
      controlResults: [] as Array<Record<string, unknown>>,
      activeOverlays: [] as string[],
      dataClassifications: [] as string[],
      activeCertifications: [] as string[],
      totalDurationMs: 1.0,
      previousHash: GENESIS_SEED,
    };
    expect(canonicalPayload(args)).toBe(canonicalPayload(args));
  });

  it("canonical payload has sorted keys", () => {
    const payload = canonicalPayload({
      evaluationId: "e1",
      timestamp: "t1",
      agentId: "a1",
      toolName: "tool",
      decision: "ALLOW",
      mode: "audit",
      controlResults: [],
      activeOverlays: [],
      dataClassifications: [],
      activeCertifications: [],
      totalDurationMs: 0.0,
      previousHash: "prev",
    });
    const parsed = JSON.parse(payload);
    const keys = Object.keys(parsed);
    expect(keys).toEqual([...keys].sort());
  });

  it("compute hash produces SHA-256", () => {
    const h = computeHash("test data");
    expect(h.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(h)).toBe(true);
  });

  it("different input different hash", () => {
    expect(computeHash("input1")).not.toBe(computeHash("input2"));
  });
});

// --- Evidence Store ---

describe("Evidence Store", () => {
  let store: EvidenceStore;

  afterEach(async () => {
    if (store) await store.close();
  });

  it("store creates record", async () => {
    const config = makeConfig();
    store = new EvidenceStore(config);
    const ev = makeEvaluation();

    const record = await store.store(ev, "my-tool");
    expect(record.evaluationId).toBe("eval-001");
    expect(record.toolName).toBe("my-tool");
    expect(record.decision).toBe("ALLOW");
    expect(record.recordHash.length).toBe(64);
  });

  it("first record uses genesis seed", async () => {
    store = new EvidenceStore(makeConfig());
    const record = await store.store(makeEvaluation(), "tool-a");
    expect(record.previousHash).toBe(GENESIS_SEED);
  });

  it("hash chain links", async () => {
    store = new EvidenceStore(makeConfig());

    const r1 = await store.store(makeEvaluation({ evaluationId: "e1" }), "tool-a");
    const r2 = await store.store(makeEvaluation({ evaluationId: "e2" }), "tool-b");

    expect(r1.previousHash).toBe(GENESIS_SEED);
    expect(r2.previousHash).toBe(r1.recordHash);
    expect(r2.recordHash).not.toBe(r1.recordHash);
  });

  it("count", async () => {
    store = new EvidenceStore(makeConfig());

    expect(await store.count()).toBe(0);
    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    expect(await store.count()).toBe(1);
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    expect(await store.count()).toBe(2);
  });

  it("get records all", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");

    const records = await store.getRecords();
    expect(records.length).toBe(2);
  });

  it("get records filter tool", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1" }), "tool-a");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "tool-b");

    const records = await store.getRecords({ toolName: "tool-a" });
    expect(records.length).toBe(1);
    expect(records[0]!.toolName).toBe("tool-a");
  });

  it("get records filter decision", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1", decision: "ALLOW" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2", decision: "BLOCK" }), "t2");

    const records = await store.getRecords({ decision: "BLOCK" });
    expect(records.length).toBe(1);
    expect(records[0]!.decision).toBe("BLOCK");
  });

  it("verify chain valid", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2" }), "t2");
    await store.store(makeEvaluation({ evaluationId: "e3" }), "t3");

    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(true);
    expect(errors).toEqual([]);
  });

  it("verify chain empty", async () => {
    store = new EvidenceStore(makeConfig());
    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(true);
    expect(errors).toEqual([]);
  });

  it("active certifications stored", async () => {
    const config = makeConfig();
    config.activeCertifications = ["SOC2", "HIPAA"];
    store = new EvidenceStore(config);

    const record = await store.store(makeEvaluation(), "t1");
    expect(record.activeCertifications).toEqual(["SOC2", "HIPAA"]);
  });

  it("active certifications default empty", async () => {
    store = new EvidenceStore(makeConfig());
    const record = await store.store(makeEvaluation(), "t1");
    expect(record.activeCertifications).toEqual([]);
  });

  it("blocked evaluation stored", async () => {
    store = new EvidenceStore(makeConfig());
    const record = await store.store(makeEvaluation({ decision: "BLOCK" }), "blocked-tool");
    expect(record.decision).toBe("BLOCK");
    expect(await store.count()).toBe(1);
  });
});

// --- Summary ---

describe("Summary", () => {
  let store: EvidenceStore;

  afterEach(async () => {
    if (store) await store.close();
  });

  it("get summary empty", async () => {
    store = new EvidenceStore(makeConfig());
    const summary = await store.getSummary();
    expect(summary.totalEvaluations).toBe(0);
    expect(summary.chainValid).toBe(true);
  });

  it("get summary with records", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1", decision: "ALLOW" }), "tool-a");
    await store.store(makeEvaluation({ evaluationId: "e2", decision: "ALLOW" }), "tool-b");
    await store.store(makeEvaluation({ evaluationId: "e3", decision: "BLOCK" }), "tool-a");

    const summary = await store.getSummary();
    expect(summary.totalEvaluations).toBe(3);
    expect((summary.decisions as Record<string, number>).ALLOW).toBe(2);
    expect((summary.decisions as Record<string, number>).BLOCK).toBe(1);
    expect(new Set(summary.toolsEvaluated as string[])).toEqual(new Set(["tool-a", "tool-b"]));
    expect(summary.chainValid).toBe(true);
  });

  it("get summary control pass rates", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1" }), "t1");
    await store.store(
      makeEvaluation({
        evaluationId: "e2",
        controlResults: [
          { controlId: "PR-01", controlName: "Agent Identity", result: "FAIL", detail: "Failed", evidenceData: {}, durationMs: 1.0 },
        ],
      }),
      "t2",
    );

    const summary = await store.getSummary();
    const rates = summary.controlPassRates as Record<string, Record<string, number>>;
    expect(rates["PR-01"]!.PASS).toBe(1);
    expect(rates["PR-01"]!.FAIL).toBe(1);
  });
});

// --- Purge ---

describe("Purge", () => {
  let store: EvidenceStore;

  afterEach(async () => {
    if (store) await store.close();
  });

  it("purge before", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1", timestamp: "2024-01-01T00:00:00Z" }), "t1");
    await store.store(makeEvaluation({ evaluationId: "e2", timestamp: "2025-06-01T00:00:00Z" }), "t2");
    expect(await store.count()).toBe(2);

    const removed = await store.purgeBefore("2025-01-01T00:00:00Z");
    expect(removed).toBe(1);
    expect(await store.count()).toBe(1);
  });

  it("purge none removed", async () => {
    store = new EvidenceStore(makeConfig());

    await store.store(makeEvaluation({ evaluationId: "e1", timestamp: "2025-06-01T00:00:00Z" }), "t1");

    const removed = await store.purgeBefore("2024-01-01T00:00:00Z");
    expect(removed).toBe(0);
    expect(await store.count()).toBe(1);
  });
});
