import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  MockEvidenceStore,
  FakeProducer,
  ScanResult,
  ComplianceScenarios,
  assertControlPasses,
  assertControlFails,
  assertControlFlags,
  assertPostureAbove,
  assertDecisionAllows,
  assertDecisionBlocks,
  makeTestConfig,
  makeAction,
} from "../src/ancilis/testing/index.js";
import type { EvaluationResult, ControlResult } from "../src/ancilis/engine/result.js";
import { Engine } from "../src/ancilis/engine/index.js";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function makePassResult(controlId: string): ControlResult {
  return {
    controlId,
    controlName: controlId,
    result: "PASS",
    detail: "ok",
    evidenceData: {},
    durationMs: 0,
  };
}

function makeFailResult(controlId: string): ControlResult {
  return {
    controlId,
    controlName: controlId,
    result: "FAIL",
    detail: "failed",
    evidenceData: {},
    durationMs: 0,
  };
}

function makeFlagResult(controlId: string): ControlResult {
  return {
    controlId,
    controlName: controlId,
    result: "FLAG",
    detail: "flagged",
    evidenceData: {},
    durationMs: 0,
  };
}

function makeSkipResult(controlId: string): ControlResult {
  return {
    controlId,
    controlName: controlId,
    result: "SKIP",
    detail: "skipped",
    evidenceData: {},
    durationMs: 0,
  };
}

function makeEvalResult(controlResults: ControlResult[], decision: "ALLOW" | "BLOCK" = "ALLOW"): EvaluationResult {
  return {
    evaluationId: "test-eval-id",
    actionId: "test-action-id",
    timestamp: new Date().toISOString(),
    agentId: "test-agent",
    sourceType: "agent",
    mode: "audit",
    controlResults,
    decision,
    decisionReason: "test",
    activeOverlays: [],
    dataClassifications: [],
    totalDurationMs: 0,
  };
}

// ---------------------------------------------------------------------------
// makeTestConfig
// ---------------------------------------------------------------------------

describe("makeTestConfig", () => {
  it("creates config with default agent name", () => {
    const config = makeTestConfig();
    expect(config.agentName).toBe("test-agent");
    expect(config.mode).toBe("audit");
  });

  it("creates config with custom agent name and mode", () => {
    const config = makeTestConfig({ agentName: "my-agent", mode: "enforce" });
    expect(config.agentName).toBe("my-agent");
    expect(config.mode).toBe("enforce");
  });

  it("accepts overlay option without throwing", () => {
    // Overlay may require data classifications to activate; test config creation succeeds
    expect(() => makeTestConfig({ overlay: "soc2" })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// makeAction
// ---------------------------------------------------------------------------

describe("makeAction", () => {
  it("creates action with default values", () => {
    const action = makeAction();
    expect(action.tool.name).toBe("test_tool");
    expect(action.agentId).toBe("test-agent");
    expect(action.actionType).toBe("tool_call");
    expect(action.actionId).toBeTruthy();
    expect(action.parameters.parameterHash).toBeTruthy();
  });

  it("creates action with custom tool and agent", () => {
    const action = makeAction({ toolName: "my_tool", agentId: "agent-42" });
    expect(action.tool.name).toBe("my_tool");
    expect(action.agentId).toBe("agent-42");
  });

  it("includes parameters in action", () => {
    const action = makeAction({ parameters: { key: "value" } });
    expect(action.parameters.raw).toEqual({ key: "value" });
  });

  it("includes session and classifications in context", () => {
    const action = makeAction({ sessionId: "s-1", dataClassifications: ["DC-01"] });
    expect(action.context?.sessionId).toBe("s-1");
    expect(action.context?.dataClassifications).toContain("DC-01");
  });

  it("each call generates a unique actionId", () => {
    const a1 = makeAction();
    const a2 = makeAction();
    expect(a1.actionId).not.toBe(a2.actionId);
  });
});

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

describe("ScanResult", () => {
  it("computes score correctly with all PASS", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01"), makePassResult("PR-02")]);
    const scan = new ScanResult([eval1]);
    expect(scan.score).toBe(1.0);
  });

  it("computes score correctly with mixed results", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01"), makeFailResult("PR-02")]);
    const scan = new ScanResult([eval1]);
    expect(scan.score).toBeCloseTo(0.5);
  });

  it("excludes SKIP from score denominator", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01"), makeSkipResult("PR-02")]);
    const scan = new ScanResult([eval1]);
    expect(scan.score).toBe(1.0);
  });

  it("returns 1.0 score when all results are SKIP", () => {
    const eval1 = makeEvalResult([makeSkipResult("PR-01"), makeSkipResult("PR-02")]);
    const scan = new ScanResult([eval1]);
    expect(scan.score).toBe(1.0);
  });

  it("getControlResult returns the result for a control", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01")]);
    const scan = new ScanResult([eval1]);
    const cr = scan.getControlResult("PR-01");
    expect(cr?.result).toBe("PASS");
  });

  it("getControlResult returns undefined for unknown control", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01")]);
    const scan = new ScanResult([eval1]);
    expect(scan.getControlResult("PR-99")).toBeUndefined();
  });

  it("decision returns the decision from the last evaluation", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01")], "ALLOW");
    const eval2 = makeEvalResult([makePassResult("PR-01")], "BLOCK");
    const scan = new ScanResult([eval1, eval2]);
    expect(scan.decision()).toBe("BLOCK");
  });

  it("throws when constructed with empty array", () => {
    expect(() => new ScanResult([])).toThrow();
  });

  it("fromSingle wraps a single evaluation", () => {
    const ev = makeEvalResult([makePassResult("PR-01")]);
    const scan = ScanResult.fromSingle(ev);
    expect(scan.evaluations.length).toBe(1);
  });

  it("FLAGS count against score", () => {
    const eval1 = makeEvalResult([makePassResult("PR-01"), makeFlagResult("DE-01")]);
    const scan = new ScanResult([eval1]);
    expect(scan.score).toBeCloseTo(0.5);
  });
});

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

describe("assertControlPasses", () => {
  it("passes when control is PASS", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")])]);
    expect(() => assertControlPasses(scan, "PR-01")).not.toThrow();
  });

  it("throws when control is FAIL", () => {
    const scan = new ScanResult([makeEvalResult([makeFailResult("PR-01")])]);
    expect(() => assertControlPasses(scan, "PR-01")).toThrow(/FAIL/);
  });

  it("throws with available controls when control not evaluated", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")])]);
    expect(() => assertControlPasses(scan, "PR-99")).toThrow(/PR-01/);
  });

  it("accepts raw EvaluationResult", () => {
    const ev = makeEvalResult([makePassResult("PR-01")]);
    expect(() => assertControlPasses(ev, "PR-01")).not.toThrow();
  });
});

describe("assertControlFails", () => {
  it("passes when control is FAIL", () => {
    const scan = new ScanResult([makeEvalResult([makeFailResult("PR-01")])]);
    expect(() => assertControlFails(scan, "PR-01")).not.toThrow();
  });

  it("passes when control is ERROR", () => {
    const ev = makeEvalResult([{ ...makeFailResult("PR-01"), result: "ERROR" }]);
    const scan = new ScanResult([ev]);
    expect(() => assertControlFails(scan, "PR-01")).not.toThrow();
  });

  it("throws when control is PASS", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")])]);
    expect(() => assertControlFails(scan, "PR-01")).toThrow(/PASS/);
  });
});

describe("assertControlFlags", () => {
  it("passes when control is FLAG", () => {
    const scan = new ScanResult([makeEvalResult([makeFlagResult("DE-01")])]);
    expect(() => assertControlFlags(scan, "DE-01")).not.toThrow();
  });

  it("throws when control is PASS", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("DE-01")])]);
    expect(() => assertControlFlags(scan, "DE-01")).toThrow(/PASS/);
  });
});

describe("assertPostureAbove", () => {
  it("passes when score meets threshold", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01"), makePassResult("PR-02")])]);
    expect(() => assertPostureAbove(scan, 0.8)).not.toThrow();
  });

  it("throws when score is below threshold", () => {
    const scan = new ScanResult([makeEvalResult([makeFailResult("PR-01"), makeFailResult("PR-02")])]);
    expect(() => assertPostureAbove(scan, 0.8)).toThrow(/below/);
  });

  it("passes at exact threshold", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01"), makeFailResult("PR-02")])]);
    expect(() => assertPostureAbove(scan, 0.5)).not.toThrow();
  });
});

describe("assertDecisionAllows", () => {
  it("passes when decision is ALLOW", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")], "ALLOW")]);
    expect(() => assertDecisionAllows(scan)).not.toThrow();
  });

  it("throws when decision is BLOCK", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")], "BLOCK")]);
    expect(() => assertDecisionAllows(scan)).toThrow(/BLOCK/);
  });
});

describe("assertDecisionBlocks", () => {
  it("passes when decision is BLOCK", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")], "BLOCK")]);
    expect(() => assertDecisionBlocks(scan)).not.toThrow();
  });

  it("throws when decision is ALLOW", () => {
    const scan = new ScanResult([makeEvalResult([makePassResult("PR-01")], "ALLOW")]);
    expect(() => assertDecisionBlocks(scan)).toThrow(/ALLOW/);
  });
});

// ---------------------------------------------------------------------------
// FakeProducer
// ---------------------------------------------------------------------------

describe("FakeProducer", () => {
  it("creates action with default producer name as tool", () => {
    const producer = new FakeProducer("identity");
    const action = producer.makeAction();
    expect(action.tool.name).toBe("identity");
    expect(action.agentId).toBe("test-agent");
  });

  it("emit accumulates key-value pairs", () => {
    const producer = new FakeProducer();
    producer.emit("user.id", "alice");
    producer.emit("role", "admin");
    expect(producer.emittedData).toEqual({ "user.id": "alice", role: "admin" });
  });

  it("emitted data is included in action parameters", () => {
    const producer = new FakeProducer();
    producer.emit("session.start", "2026-04-12T00:00:00Z");
    const action = producer.makeAction();
    expect(action.parameters.raw["session.start"]).toBe("2026-04-12T00:00:00Z");
  });

  it("makeAction options override emitted data", () => {
    const producer = new FakeProducer();
    producer.emit("key", "original");
    const action = producer.makeAction({ parameters: { key: "override" } });
    expect(action.parameters.raw["key"]).toBe("override");
  });

  it("clear resets emitted data", () => {
    const producer = new FakeProducer();
    producer.emit("key", "value");
    producer.clear();
    expect(producer.emittedData).toEqual({});
  });

  it("producerType is MANUAL", () => {
    const producer = new FakeProducer();
    expect(producer.producerType).toBe("manual");
  });

  it("computeToolHash returns consistent SHA-256 hex", () => {
    const producer = new FakeProducer();
    const hash1 = producer.computeToolHash("tool-name");
    const hash2 = producer.computeToolHash("tool-name");
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it("translate handles dict invocation", () => {
    const producer = new FakeProducer("fake");
    const action = producer.translate({ tool: "my_tool", parameters: { key: "val" } });
    expect(action.tool.name).toBe("my_tool");
    expect(action.parameters.raw["key"]).toBe("val");
  });

  it("registerTools adds the producer name to the registry", async () => {
    const { ToolRegistry } = await import("../src/ancilis/engine/index.js");
    const producer = new FakeProducer("my-tool");
    const registry = new ToolRegistry();
    const registered = producer.registerTools(registry);
    expect(registered).toContain("my-tool");
    expect(registry.lookup("my-tool")).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// ComplianceScenarios
// ---------------------------------------------------------------------------

describe("ComplianceScenarios", () => {
  it("financialCompliant — all controls pass, score 1.0", () => {
    const scan = ComplianceScenarios.financialCompliant();
    expect(scan.score).toBe(1.0);
    assertControlPasses(scan, "PR-01");
    assertControlPasses(scan, "PR-02");
    assertDecisionAllows(scan);
  });

  it("missingIdentity — PR-01 fails, others pass", () => {
    const scan = ComplianceScenarios.missingIdentity();
    assertControlFails(scan, "PR-01");
    assertControlPasses(scan, "PR-02");
    expect(scan.score).toBeLessThan(1.0);
  });

  it("minimalViable — PR-01 passes, rest skipped, score 1.0", () => {
    const scan = ComplianceScenarios.minimalViable();
    assertControlPasses(scan, "PR-01");
    expect(scan.score).toBe(1.0);
  });

  it("allFailing — score < 0.5, controls fail or flag", () => {
    const scan = ComplianceScenarios.allFailing();
    assertControlFails(scan, "PR-01");
    assertControlFlags(scan, "PR-04");
    assertPostureAbove(scan, 0.0);
    expect(() => assertPostureAbove(scan, 0.5)).toThrow();
  });

  it("enforceBlocked — decision is BLOCK in enforce mode", () => {
    const scan = ComplianceScenarios.enforceBlocked();
    assertDecisionBlocks(scan);
    assertControlFails(scan, "PR-01");
  });
});

// ---------------------------------------------------------------------------
// MockEvidenceStore
// ---------------------------------------------------------------------------

describe("MockEvidenceStore", () => {
  let store: MockEvidenceStore;

  beforeEach(() => {
    store = new MockEvidenceStore();
  });

  afterEach(async () => {
    await store.close();
  });

  it("starts with zero records", async () => {
    expect(await store.count()).toBe(0);
  });

  it("stores evaluation and count increases", async () => {
    const config = makeTestConfig();
    const engine = new Engine(config);
    const action = makeAction();
    const result = await engine.evaluate(action);
    await store.store(result);
    expect(await store.count()).toBe(1);
  });

  it("verifyChain returns valid for empty store", async () => {
    const chainResult = await store.verifyChain();
    expect(chainResult.valid).toBe(true);
  });

  it("verifyChain is valid after storing records", async () => {
    const config = makeTestConfig();
    const engine = new Engine(config);
    const action = makeAction();
    const result = await engine.evaluate(action);
    await store.store(result);
    await store.store(result);
    const chainResult = await store.verifyChain();
    expect(chainResult.valid).toBe(true);
  });

  it("reset clears all records", async () => {
    const config = makeTestConfig();
    const engine = new Engine(config);
    const action = makeAction();
    const result = await engine.evaluate(action);
    await store.store(result);
    expect(await store.count()).toBe(1);
    await store.reset();
    expect(await store.count()).toBe(0);
  });

  it("uses custom agent name in config", () => {
    const customStore = new MockEvidenceStore("my-agent");
    expect(customStore).toBeDefined();
    void customStore.close();
  });
});
