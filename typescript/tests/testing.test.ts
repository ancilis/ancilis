/**
 * Tests for @ancilis/testing — MockEvidenceStore, FakeProducer, matchers, and scenarios.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MockEvidenceStore } from "../src/ancilis/testing/mock-evidence-store.js";
import { FakeProducer } from "../src/ancilis/testing/fake-producer.js";
import { ComplianceScenarios } from "../src/ancilis/testing/scenarios.js";
import {
  AssertionError,
  expectControlToPass,
  expectControlToFail,
  expectControlToSkip,
  expectDecisionToBe,
  expectAllowed,
  expectBlocked,
  expectPostureAbove,
  expectAllPassed,
  setupAncilisMatchers,
} from "../src/ancilis/testing/matchers.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import { GENESIS_SEED } from "../src/ancilis/evidence/chain.js";

// Register custom matchers for expect().toPassControl() etc.
setupAncilisMatchers(expect);

// ---------------------------------------------------------------------------
// MockEvidenceStore
// ---------------------------------------------------------------------------

describe("MockEvidenceStore", () => {
  let store: MockEvidenceStore;

  beforeEach(() => {
    store = new MockEvidenceStore();
  });

  it("starts empty", async () => {
    expect(await store.count()).toBe(0);
    expect(store.getAll()).toHaveLength(0);
  });

  it("dbPath is :memory:", () => {
    expect(store.dbPath).toBe(":memory:");
  });

  it("addFakeRecord inserts a record", async () => {
    store.addFakeRecord({ toolName: "read_file", decision: "ALLOW" });
    expect(await store.count()).toBe(1);
    expect(store.getLastRecord()?.toolName).toBe("read_file");
  });

  it("addFakeRecord builds hash chain from GENESIS_SEED", async () => {
    const r1 = store.addFakeRecord({ toolName: "t1" });
    const r2 = store.addFakeRecord({ toolName: "t2" });
    expect(r1.previousHash).toBe(GENESIS_SEED);
    expect(r2.previousHash).toBe(r1.recordHash);
  });

  it("verifyChain is valid after addFakeRecord calls", async () => {
    store.addFakeRecord({ toolName: "t1" });
    store.addFakeRecord({ toolName: "t2" });
    const { valid, errors } = await store.verifyChain();
    expect(valid).toBe(true);
    expect(errors).toHaveLength(0);
  });

  it("getRecordsForTool filters correctly", () => {
    store.addFakeRecord({ toolName: "read_file" });
    store.addFakeRecord({ toolName: "write_file" });
    store.addFakeRecord({ toolName: "read_file" });
    expect(store.getRecordsForTool("read_file")).toHaveLength(2);
    expect(store.getRecordsForTool("write_file")).toHaveLength(1);
    expect(store.getRecordsForTool("delete_file")).toHaveLength(0);
  });

  it("getRecordsForDecision filters correctly", () => {
    store.addFakeRecord({ toolName: "t1", decision: "ALLOW" });
    store.addFakeRecord({ toolName: "t2", decision: "BLOCK" });
    store.addFakeRecord({ toolName: "t3", decision: "ALLOW" });
    expect(store.getRecordsForDecision("ALLOW")).toHaveLength(2);
    expect(store.getRecordsForDecision("BLOCK")).toHaveLength(1);
    expect(store.getRecordsForDecision("FLAG")).toHaveLength(0);
  });

  it("getRecords with filters", async () => {
    store.addFakeRecord({ toolName: "read_file", decision: "ALLOW", agentId: "a1" });
    store.addFakeRecord({ toolName: "write_file", decision: "BLOCK", agentId: "a2" });
    const allowed = await store.getRecords({ decision: "ALLOW" });
    expect(allowed).toHaveLength(1);
    expect(allowed[0]?.toolName).toBe("read_file");
    const byAgent = await store.getRecords({ agentId: "a2" });
    expect(byAgent).toHaveLength(1);
  });

  it("clear wipes all records", () => {
    store.addFakeRecord({ toolName: "t1" });
    store.addFakeRecord({ toolName: "t2" });
    store.clear();
    expect(store.getAll()).toHaveLength(0);
  });

  it("close is a no-op and does not throw", async () => {
    await expect(store.close()).resolves.toBeUndefined();
  });

  it("getSummary returns correct totals", async () => {
    store.addFakeRecord({ toolName: "t1", decision: "ALLOW" });
    store.addFakeRecord({ toolName: "t2", decision: "BLOCK" });
    const summary = await store.getSummary();
    expect(summary.totalEvaluations).toBe(2);
    expect((summary.decisions as Record<string, number>).ALLOW).toBe(1);
    expect((summary.decisions as Record<string, number>).BLOCK).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// FakeProducer
// ---------------------------------------------------------------------------

describe("FakeProducer", () => {
  it("creates with default test-agent config", () => {
    const producer = new FakeProducer();
    expect(producer.config.agentName).toBe("test-agent");
  });

  it("evaluate returns action, evaluation, and record", async () => {
    const producer = new FakeProducer();
    const { action, evaluation, record } = await producer.evaluate("read_file", { path: "/tmp/x" });
    expect(action.tool.name).toBe("read_file");
    expect(evaluation.decision).toMatch(/ALLOW|BLOCK|FLAG/);
    expect(record.toolName).toBe("read_file");
  });

  it("evaluation is stored in MockEvidenceStore", async () => {
    const producer = new FakeProducer();
    await producer.evaluate("read_file");
    expect(await producer.store.count()).toBe(1);
  });

  it("evaluateAll processes multiple calls", async () => {
    const producer = new FakeProducer();
    const results = await producer.evaluateAll([
      { toolName: "read_file" },
      { toolName: "write_file" },
      { toolName: "delete_file" },
    ]);
    expect(results).toHaveLength(3);
    expect(await producer.store.count()).toBe(3);
  });

  it("reset clears the store", async () => {
    const producer = new FakeProducer();
    await producer.evaluate("read_file");
    expect(await producer.store.count()).toBe(1);
    producer.reset();
    expect(await producer.store.count()).toBe(0);
  });

  it("accepts a custom config", async () => {
    const config = loadConfig({ raw: { agent: { name: "custom-agent" } } });
    const producer = new FakeProducer({ config, defaultAgentId: "custom-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(evaluation.agentId).toBe("custom-agent");
  });

  it("agentId override parameter overrides defaultAgentId", async () => {
    const producer = new FakeProducer();
    const { action } = await producer.evaluate("read_file", {}, "override-agent");
    expect(action.agentId).toBe("override-agent");
  });
});

// ---------------------------------------------------------------------------
// Assertion helpers (matchers)
// ---------------------------------------------------------------------------

describe("expectControlToPass / expectControlToFail", () => {
  it("passes when control is PASS", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectControlToPass(evaluation, "PR-01")).not.toThrow();
  });

  it("throws AssertionError when control is not PASS", async () => {
    // mismatched agentId → PR-01 fails
    const producer = new FakeProducer({ defaultAgentId: "wrong-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectControlToPass(evaluation, "PR-01")).toThrow(AssertionError);
  });

  it("passes when control is FAIL", async () => {
    const producer = new FakeProducer({ defaultAgentId: "wrong-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectControlToFail(evaluation, "PR-01")).not.toThrow();
  });

  it("throws AssertionError when control is not FAIL", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectControlToFail(evaluation, "PR-01")).toThrow(AssertionError);
  });

  it("throws AssertionError for unknown control ID", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectControlToPass(evaluation, "ZZ-99")).toThrow(AssertionError);
  });
});

describe("expectControlToSkip", () => {
  it("passes for a disabled control", async () => {
    const config = loadConfig({
      raw: {
        agent: { name: "minimal-agent" },
        security: { controls: { "PR-02": { enabled: false } } },
      },
    });
    const producer = new FakeProducer({ config, defaultAgentId: "minimal-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectControlToSkip(evaluation, "PR-02")).not.toThrow();
  });
});

describe("expectDecisionToBe / expectAllowed / expectBlocked", () => {
  it("expectDecisionToBe ALLOW passes for ALLOW decision", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectDecisionToBe(evaluation, "ALLOW")).not.toThrow();
  });

  it("expectAllowed passes for audit mode with passing controls", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectAllowed(evaluation)).not.toThrow();
  });

  it("expectBlocked passes for enforce mode with failing controls", async () => {
    const config = loadConfig({
      raw: {
        agent: { name: "strict-agent" },
        security: { mode: "enforce" },
      },
    });
    const producer = new FakeProducer({ config, defaultAgentId: "wrong-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectBlocked(evaluation)).not.toThrow();
  });

  it("expectDecisionToBe throws AssertionError on mismatch", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expect(() => expectDecisionToBe(evaluation, "BLOCK")).toThrow(AssertionError);
  });
});

describe("expectPostureAbove / expectAllPassed", () => {
  it("expectPostureAbove passes when all evaluations are ALLOW", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const results = await producer.evaluateAll([
      { toolName: "t1" },
      { toolName: "t2" },
      { toolName: "t3" },
    ]);
    const evals = results.map((r) => r.evaluation);
    expect(() => expectPostureAbove(evals, 0.8)).not.toThrow();
  });

  it("expectAllPassed passes when all evaluations are ALLOW", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const results = await producer.evaluateAll([{ toolName: "t1" }, { toolName: "t2" }]);
    const evals = results.map((r) => r.evaluation);
    expect(() => expectAllPassed(evals)).not.toThrow();
  });

  it("expectPostureAbove throws when posture is too low", async () => {
    // All calls fail PR-01 → ALLOW in audit mode (engine still allows), so posture should be 100%
    // Use enforce mode to get BLOCKs
    const config = loadConfig({
      raw: { agent: { name: "strict" }, security: { mode: "enforce" } },
    });
    const producer = new FakeProducer({ config, defaultAgentId: "wrong-agent" });
    const results = await producer.evaluateAll([
      { toolName: "t1" },
      { toolName: "t2" },
    ]);
    const evals = results.map((r) => r.evaluation);
    expect(() => expectPostureAbove(evals, 0.5)).toThrow(AssertionError);
  });
});

// ---------------------------------------------------------------------------
// Vitest custom matchers (expect().toPassControl() etc.)
// ---------------------------------------------------------------------------

describe("custom Vitest matchers", () => {
  it("expect(evaluation).toPassControl(id) passes for PASS", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    // @ts-expect-error — type augmentation takes effect only after setupAncilisMatchers
    expect(evaluation).toPassControl("PR-01");
  });

  it("expect(evaluation).toBeAllowed() passes for ALLOW", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    // @ts-expect-error
    expect(evaluation).toBeAllowed();
  });

  it("expect(evaluation).toFailControl(id) passes when control fails", async () => {
    const producer = new FakeProducer({ defaultAgentId: "wrong-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    // @ts-expect-error
    expect(evaluation).toFailControl("PR-01");
  });

  it("expect(evaluation).toHaveDecision('ALLOW') passes", async () => {
    const producer = new FakeProducer({ defaultAgentId: "test-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    // @ts-expect-error
    expect(evaluation).toHaveDecision("ALLOW");
  });
});

// ---------------------------------------------------------------------------
// ComplianceScenarios
// ---------------------------------------------------------------------------

describe("ComplianceScenarios", () => {
  it("fullyCompliant() — PR-01 passes and decision is ALLOW (audit mode)", async () => {
    const producer = ComplianceScenarios.fullyCompliant();
    const { evaluation } = await producer.evaluate("read_file");
    expectControlToPass(evaluation, "PR-01");
    // audit mode → ALLOW regardless of other control findings
    expectDecisionToBe(evaluation, "ALLOW");
  });

  it("missingIdentity() — PR-01 fails due to empty agentId", async () => {
    const producer = ComplianceScenarios.missingIdentity();
    const { evaluation } = await producer.evaluate("read_file");
    expectControlToFail(evaluation, "PR-01");
  });

  it("minimalViable() — only PR-01 is evaluated, others skip", async () => {
    const producer = ComplianceScenarios.minimalViable();
    const { evaluation } = await producer.evaluate("read_file");
    expectControlToPass(evaluation, "PR-01");
    expectControlToSkip(evaluation, "PR-02");
    expectControlToSkip(evaluation, "PR-03");
    expectControlToSkip(evaluation, "PR-04");
    expectControlToSkip(evaluation, "PR-05");
    expectControlToSkip(evaluation, "DE-01");
  });

  it("enforceMode() — decision is BLOCK when identity fails", async () => {
    const config = ComplianceScenarios.enforceMode().config;
    const producer = new FakeProducer({ config, defaultAgentId: "wrong-agent" });
    const { evaluation } = await producer.evaluate("read_file");
    expectControlToFail(evaluation, "PR-01");
    expectBlocked(evaluation);
  });

  it("fullyCompliantConfig() returns a ResolvedConfig", () => {
    const config = ComplianceScenarios.fullyCompliantConfig();
    expect(config.agentName).toBe("compliant-agent");
    expect(config.mode).toBe("enforce");
  });

  it("minimalViableConfig() returns a ResolvedConfig with disabled controls", () => {
    const config = ComplianceScenarios.minimalViableConfig();
    expect(config.controls.get("PR-02")?.enabled).toBe(false);
  });
});
