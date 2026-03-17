/**
 * Tests for ancilis engine — Unit 2: Control Engine Core.
 */

import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { loadConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { ToolRegistry, ToolStatus } from "../src/ancilis/engine/registry.js";
import type { Action } from "../src/ancilis/engine/action.js";
import type { ControlResult } from "../src/ancilis/engine/result.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";

function makeAction(overrides: Partial<{
  agentId: string;
  agentOwner: string | null;
  toolName: string;
  toolVersion: string | null;
  descriptionHash: string | null;
  params: Record<string, unknown>;
  actionType: "tool_call" | "api_request" | "data_access";
}> = {}): Action {
  return {
    actionId: randomUUID(),
    timestamp: "2026-03-10T12:00:00Z",
    agentId: overrides.agentId ?? "test-agent",
    agentOwner: overrides.agentOwner ?? null,
    actionType: overrides.actionType ?? "tool_call",
    tool: {
      name: overrides.toolName ?? "test-tool",
      version: overrides.toolVersion ?? null,
      descriptionHash: overrides.descriptionHash ?? null,
    },
    parameters: {
      raw: overrides.params ?? {},
      parameterHash: "abc123",
    },
    context: {},
  };
}

function makeConfig(overrides: Record<string, unknown> = {}): ResolvedConfig {
  const raw: Record<string, unknown> = { agent: { name: "test-agent" }, ...overrides };
  return loadConfig({ raw });
}

function makeRegistry(...tools: Array<[string, string?, string?]>): ToolRegistry {
  const reg = new ToolRegistry();
  for (const [name, version, hash] of tools) {
    reg.register({
      name,
      version: version ?? null,
      descriptionHash: hash ?? null,
      status: ToolStatus.APPROVED,
      approvedBy: "config",
      firstSeen: new Date().toISOString(),
      statusChanged: new Date().toISOString(),
    });
  }
  return reg;
}

function getControlResult(results: ControlResult[], controlId: string): ControlResult {
  const r = results.find(r => r.controlId === controlId);
  if (!r) throw new Error(`Control ${controlId} not found`);
  return r;
}

// --- Action Object Tests ---

describe("Action Object", () => {
  it("creates valid action with all fields", () => {
    const a = makeAction({ agentId: "x", toolName: "y" });
    expect(a.agentId).toBe("x");
    expect(a.tool.name).toBe("y");
  });

  it("creates minimal action", () => {
    const a: Action = {
      actionId: "1", timestamp: "2026-01-01T00:00:00Z", agentId: "a",
      actionType: "tool_call", tool: { name: "t" },
      parameters: { raw: {}, parameterHash: "h" },
    };
    expect(a.agentOwner).toBeUndefined();
  });

  it("handles empty agent_id", () => {
    const a = makeAction({ agentId: "" });
    expect(a.agentId).toBe("");
  });
});

// --- PR-01 Identity Tests ---

describe("PR-01 Identity", () => {
  it("matching agent_id passes", () => {
    const config = makeConfig();
    const action = makeAction({ agentId: "test-agent" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-01").result).toBe("PASS");
  });

  it("missing agent_id fails", () => {
    const config = makeConfig();
    const action = makeAction({ agentId: "" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-01").result).toBe("FAIL");
  });

  it("mismatched agent_id fails", () => {
    const config = makeConfig();
    const action = makeAction({ agentId: "wrong-agent" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-01").result).toBe("FAIL");
  });

  it("matching owner passes", () => {
    const config = makeConfig({ agent: { name: "test-agent", owner: "alice" } });
    const action = makeAction({ agentId: "test-agent", agentOwner: "alice" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-01").result).toBe("PASS");
  });

  it("mismatched owner fails", () => {
    const config = makeConfig({ agent: { name: "test-agent", owner: "alice" } });
    const action = makeAction({ agentId: "test-agent", agentOwner: "bob" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-01").result).toBe("FAIL");
  });
});

// --- PR-02 Scope Tests ---

describe("PR-02 Scope", () => {
  it("tool in allowed list passes", () => {
    const config = makeConfig({ security: { tools: { allowed: ["test-tool"] } } });
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-02").result).toBe("PASS");
  });

  it("tool not in allowed list fails", () => {
    const config = makeConfig({ security: { tools: { allowed: ["other-tool"] } } });
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-02").result).toBe("FAIL");
  });

  it("tool in blocked list fails (precedence over allowed)", () => {
    const config = makeConfig({ security: { tools: { allowed: ["test-tool"], blocked: ["test-tool"] } } });
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-02").result).toBe("FAIL");
  });

  it("empty allowed list permits all", () => {
    const config = makeConfig();
    const action = makeAction({ toolName: "any-tool" });
    const engine = new Engine(config, { registry: makeRegistry(["any-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-02").result).toBe("PASS");
  });

  it("blocked destination fails", () => {
    const config = makeConfig({ security: { scope: { blocked_destinations: ["evil.com"] } } });
    const action = makeAction({ params: { url: "evil.com" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-02").result).toBe("FAIL");
  });
});

// --- PR-03 Provenance Tests ---

describe("PR-03 Provenance", () => {
  it("registered tool with matching hash passes", () => {
    const reg = makeRegistry(["test-tool", "1.0", "hash123"]);
    const config = makeConfig();
    const action = makeAction({ toolVersion: "1.0", descriptionHash: "hash123" });
    const engine = new Engine(config, { registry: reg });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-03").result).toBe("PASS");
  });

  it("unregistered tool fails", () => {
    const config = makeConfig();
    const action = makeAction({ toolName: "unknown-tool" });
    const engine = new Engine(config, { registry: new ToolRegistry() });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-03").result).toBe("FAIL");
  });

  it("hash mismatch fails", () => {
    const reg = makeRegistry(["test-tool", "1.0", "hash123"]);
    const config = makeConfig();
    const action = makeAction({ toolVersion: "1.0", descriptionHash: "hash999" });
    const engine = new Engine(config, { registry: reg });
    const result = engine.evaluate(action);
    const pr03 = getControlResult(result.controlResults, "PR-03");
    expect(pr03.result).toBe("FAIL");
    expect(pr03.detail.toLowerCase()).toContain("tampering");
  });

  it("no hash stored flags with note", () => {
    const reg = makeRegistry(["test-tool", "1.0"]);
    const config = makeConfig();
    const action = makeAction({ toolVersion: "1.0" });
    const engine = new Engine(config, { registry: reg });
    const result = engine.evaluate(action);
    const pr03 = getControlResult(result.controlResults, "PR-03");
    expect(pr03.result).toBe("FLAG");
    expect(pr03.evidenceData.hash_match).toBe("no_hash");
  });

  it("version mismatch fails", () => {
    const reg = makeRegistry(["test-tool", "1.0", "hash123"]);
    const config = makeConfig();
    const action = makeAction({ toolVersion: "2.0", descriptionHash: "hash123" });
    const engine = new Engine(config, { registry: reg });
    const result = engine.evaluate(action);
    const pr03 = getControlResult(result.controlResults, "PR-03");
    expect(pr03.result).toBe("FAIL");
    expect(pr03.detail.toLowerCase()).toContain("version");
  });
});

// --- PR-04 Data Exposure Tests ---

describe("PR-04 Data Exposure", () => {
  it("clean parameters pass", () => {
    const config = makeConfig();
    const action = makeAction({ params: { query: "SELECT * FROM users" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    const pr04 = getControlResult(result.controlResults, "PR-04");
    expect(pr04.result).toBe("PASS");
    expect(pr04.evidenceData.scan_result).toBe("clean");
  });

  it("SSN pattern detected", () => {
    const config = makeConfig();
    const action = makeAction({ params: { data: "SSN: 123-45-6789" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    const pr04 = getControlResult(result.controlResults, "PR-04");
    expect(pr04.evidenceData.scan_result).toBe("patterns_found");
    const patterns = pr04.evidenceData.patterns_detected as Array<{ type: string; redacted_sample: string }>;
    expect(patterns.some(p => p.type === "ssn")).toBe(true);
    const ssn = patterns.find(p => p.type === "ssn")!;
    expect(ssn.redacted_sample).toContain("6789");
    expect(ssn.redacted_sample).not.toContain("123-45");
  });

  it("credit card detected", () => {
    const config = makeConfig();
    const action = makeAction({ params: { card: "4111 1111 1111 1111" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    const pr04 = getControlResult(result.controlResults, "PR-04");
    const patterns = pr04.evidenceData.patterns_detected as Array<{ type: string }>;
    expect(patterns.some(p => p.type === "credit_card")).toBe(true);
  });

  it("sensitive data to blocked destination fails", () => {
    const config = makeConfig({ security: { scope: { blocked_destinations: ["evil.com"] } } });
    const action = makeAction({ params: { data: "SSN: 123-45-6789", url: "evil.com" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-04").result).toBe("FAIL");
  });

  it("sensitive data to allowed destination passes", () => {
    const config = makeConfig({ security: { scope: { allowed_destinations: ["safe.com"] } } });
    const action = makeAction({ params: { data: "SSN: 123-45-6789", url: "safe.com" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-04").result).toBe("PASS");
  });

  it("no data classifications passes with note", () => {
    const config = makeConfig();
    const action = makeAction({ params: { query: "clean data" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    const pr04 = getControlResult(result.controlResults, "PR-04");
    expect(pr04.result).toBe("PASS");
    expect(pr04.detail.toLowerCase()).toContain("no data classifications");
  });
});

// --- Decision Engine Tests ---

describe("Decision Engine", () => {
  it("all pass audit allows", () => {
    const config = makeConfig();
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(result.decision).toBe("ALLOW");
  });

  it("all pass enforce allows", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(result.decision).toBe("ALLOW");
  });

  it("failure audit still allows", () => {
    const config = makeConfig();
    const action = makeAction({ agentId: "wrong-agent" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(result.decision).toBe("ALLOW");
    expect(result.decisionReason.toLowerCase()).toContain("audit");
  });

  it("failure enforce blocks", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction({ agentId: "wrong-agent" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(result.decision).toBe("BLOCK");
  });

  it("multiple failures enforce lists all", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction({ agentId: "wrong-agent", toolName: "unknown-tool" });
    const engine = new Engine(config, { registry: new ToolRegistry() });
    const result = engine.evaluate(action);
    expect(result.decision).toBe("BLOCK");
    expect(result.decisionReason).toContain("PR-01");
    expect(result.decisionReason).toContain("PR-03");
  });

  it("disabled control skipped", () => {
    const config = makeConfig({ security: { controls: { "PR-01": { enabled: false } } } });
    const action = makeAction({ agentId: "wrong-agent" });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    const pr01 = getControlResult(result.controlResults, "PR-01");
    expect(pr01.result).toBe("SKIP");
    expect(result.decision).toBe("ALLOW");
  });

  it("evaluator error handled", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });

    engine._setEvaluator("PR-01", {
      controlId: "PR-01",
      controlName: "Agent Identity & Authentication",
      evaluate: () => { throw new Error("boom"); },
    });

    const result = engine.evaluate(action);
    const pr01 = getControlResult(result.controlResults, "PR-01");
    expect(pr01.result).toBe("ERROR");
    expect(result.decision).toBe("BLOCK");
  });

  it("result has metadata", () => {
    const config = makeConfig({ my_agent_handles: ["credit_cards"] });
    const action = makeAction();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(result.agentId).toBe("test-agent");
    expect(result.mode).toBe("audit");
    expect(result.activeOverlays).toContain("pci-dss-v4");
    expect(result.dataClassifications).toContain("DC-CHD");
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });
});
