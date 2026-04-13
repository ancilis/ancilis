/**
 * Tests for ancilis engine — Unit 2: Control Engine Core.
 */

import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { loadConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { ToolRegistry, ToolStatus } from "../src/ancilis/engine/registry.js";
import { PR07TransportEvaluator } from "../src/ancilis/engine/evaluators/pr07-transport.js";
import { PR08InputEvaluator } from "../src/ancilis/engine/evaluators/pr08-input.js";
import { GOV01PolicyEvaluator } from "../src/ancilis/engine/evaluators/gov01-policy.js";
import type { Action } from "../src/ancilis/engine/action.js";
import type { ControlResult } from "../src/ancilis/engine/result.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";

function makeAction(overrides: Partial<{
  agentId: string;
  agentOwner: string | null;
  toolName: string;
  toolVersion: string | null;
  toolServer: string | null;
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
      server: overrides.toolServer ?? null,
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
    const pr03 = getControlResult(result.controlResults, "PR-03");
    expect(pr03.result).toBe("PASS");
    expect(pr03.detail).toBe("Tool provenance verified — approved and hash-consistent.");
    expect(pr03.evidenceData).toMatchObject({
      tool_name: "test-tool",
      tool_version: "1.0",
      registered: true,
      approved: true,
      tool_status: "approved",
      hash_match: true,
      registry_entry: {
        name: "test-tool",
        version: "1.0",
        status: "approved",
      },
    });
  });

  it("unregistered tool fails", () => {
    const config = makeConfig();
    const action = makeAction({ toolName: "unknown-tool" });
    const engine = new Engine(config, { registry: new ToolRegistry() });
    const result = engine.evaluate(action);
    const pr03 = getControlResult(result.controlResults, "PR-03");
    expect(pr03.result).toBe("FAIL");
    expect(pr03.detail).toBe("Tool 'unknown-tool' is not registered.");
    expect(pr03.evidenceData).toMatchObject({
      tool_name: "unknown-tool",
      tool_version: null,
      registered: false,
      approved: false,
      hash_match: "no_hash",
    });
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

  it("no hash baseline flags with python-equivalent detail", () => {
    const reg = makeRegistry(["test-tool", "1.0"]);
    const config = makeConfig();
    const action = makeAction({ toolVersion: "1.0" });
    const engine = new Engine(config, { registry: reg });
    const result = engine.evaluate(action);
    const pr03 = getControlResult(result.controlResults, "PR-03");
    expect(pr03.result).toBe("FLAG");
    expect(pr03.detail).toBe(
      "Tool 'test-tool' is approved but has no description baseline. Provenance will be fully verified after first discovery.",
    );
    expect(pr03.evidenceData).toMatchObject({
      tool_name: "test-tool",
      tool_version: "1.0",
      registered: true,
      approved: true,
      tool_status: "approved",
      hash_match: "no_baseline",
      registry_entry: {
        name: "test-tool",
        version: "1.0",
        status: "approved",
      },
    });
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

// --- DE-02 Configuration Drift Tests ---

describe("DE-02 Configuration Drift", () => {
  it("records the first observed configuration fingerprint", () => {
    const config = makeConfig();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });

    const result = engine.evaluate(makeAction({ descriptionHash: "hash-v1" }));

    const de02 = getControlResult(result.controlResults, "DE-02");
    expect(de02.result).toBe("PASS");
    expect(de02.detail).toContain("first observation");
    expect(de02.evidenceData).toMatchObject({
      drift_detected: false,
      first_observation: true,
      tool_name: "test-tool",
    });
  });

  it("detects description hash drift on the same engine instance", () => {
    const config = makeConfig();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });

    engine.evaluate(makeAction({ descriptionHash: "hash-v1" }));
    const result = engine.evaluate(makeAction({ descriptionHash: "hash-v2" }));

    const de02 = getControlResult(result.controlResults, "DE-02");
    expect(de02.result).toBe("FAIL");
    expect(de02.detail).toContain("Configuration drift detected");
    expect(de02.evidenceData).toMatchObject({ drift_detected: true });
    expect(de02.evidenceData.previous_fingerprint).toBeDefined();
  });

  it("skips missing description hashes without establishing a false baseline", () => {
    const config = makeConfig();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });

    const skipped = engine.evaluate(makeAction({ descriptionHash: null }));
    const observed = engine.evaluate(makeAction({ descriptionHash: "hash-v1" }));

    const skippedDe02 = getControlResult(skipped.controlResults, "DE-02");
    expect(skippedDe02.result).toBe("SKIP");
    expect(skippedDe02.detail).toContain("Cannot compute fingerprint");
    expect(skippedDe02.evidenceData).toMatchObject({
      drift_detected: false,
      tool_name: "test-tool",
    });

    const observedDe02 = getControlResult(observed.controlResults, "DE-02");
    expect(observedDe02.result).toBe("PASS");
    expect(observedDe02.evidenceData).toMatchObject({ first_observation: true });
  });

  it("includes version and server in the configuration fingerprint", () => {
    const config = makeConfig();
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });

    engine.evaluate(makeAction({
      descriptionHash: "same-hash",
      toolVersion: "1.0",
      toolServer: "mcp://server-a",
    }));
    const result = engine.evaluate(makeAction({
      descriptionHash: "same-hash",
      toolVersion: "1.0",
      toolServer: "mcp://server-b",
    }));

    const de02 = getControlResult(result.controlResults, "DE-02");
    expect(de02.result).toBe("FAIL");
    expect(de02.evidenceData).toMatchObject({ drift_detected: true });
  });
});

// --- Helpers for direct evaluator tests ---

function makeMinimalConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    agentName: "test-agent",
    agentId: null,
    agentOwner: "",
    mode: "audit",
    controls: new Map(),
    dataClassifications: new Map(),
    activeOverlays: new Map(),
    unavailableOverlays: [],
    overlayAdjustments: [],
    evidenceRetentionDays: 365,
    humanOversightRequired: false,
    warnings: [],
    toolsAllowed: [],
    toolsBlocked: [],
    scopeMaxActionsPerMinute: null,
    scopeAllowedDestinations: [],
    scopeBlockedDestinations: [],
    activeCertifications: [],
    scanDependenciesEnabled: true,
    scanDependenciesSeverityThreshold: "high",
    scanDependenciesIgnore: [],
    ...overrides,
  };
}

// --- PR-07 Transport Security Tests ---

describe("PR-07 Transport Security", () => {
  it("passes with no URLs in parameters", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { message: "hello world" } }), makeMinimalConfig());
    expect(result.result).toBe("PASS");
    expect(result.detail).toContain("No URLs found");
  });

  it("passes with https:// URL", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { url: "https://api.example.com/v1" } }), makeMinimalConfig());
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.insecure_urls).toHaveLength(0);
  });

  it("passes with wss:// URL", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { endpoint: "wss://stream.example.com/ws" } }), makeMinimalConfig());
    expect(result.result).toBe("PASS");
  });

  it("fails with http:// URL to non-localhost", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { url: "http://api.example.com/v1" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.insecure_urls).toContain("http://api.example.com/v1");
  });

  it("fails with ws:// URL to non-localhost", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { url: "ws://chat.example.com/ws" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.insecure_urls).toContain("ws://chat.example.com/ws");
  });

  it("exempts http://localhost from failure", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { url: "http://localhost:8080/api" } }), makeMinimalConfig());
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.localhost_exempt).toContain("http://localhost:8080/api");
  });

  it("exempts http://127.0.0.1 from failure", () => {
    const evaluator = new PR07TransportEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { url: "http://127.0.0.1:3000" } }), makeMinimalConfig());
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.localhost_exempt).toContain("http://127.0.0.1:3000");
  });

  it("checks alternative URL keys (endpoint, server, api_url)", () => {
    const evaluator = new PR07TransportEvaluator();
    const r1 = evaluator.evaluate(makeAction({ params: { endpoint: "http://evil.com" } }), makeMinimalConfig());
    const r2 = evaluator.evaluate(makeAction({ params: { server: "http://evil.com" } }), makeMinimalConfig());
    const r3 = evaluator.evaluate(makeAction({ params: { api_url: "http://evil.com" } }), makeMinimalConfig());
    expect(r1.result).toBe("FAIL");
    expect(r2.result).toBe("FAIL");
    expect(r3.result).toBe("FAIL");
  });

  it("integrated: transport failure in enforce mode blocks", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction({ params: { url: "http://evil.com/api" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-07").result).toBe("FAIL");
    expect(result.decision).toBe("BLOCK");
  });

  it("integrated: https URL passes in enforce mode", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction({ params: { url: "https://api.example.com" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-07").result).toBe("PASS");
  });
});

// --- PR-08 Input Validation Tests ---

describe("PR-08 Input Validation", () => {
  it("passes with clean input", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { query: "list all users" } }), makeMinimalConfig());
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.scan_result).toBe("clean");
    expect(result.evidenceData.patterns_found).toHaveLength(0);
  });

  it("fails on SQL injection (OR 1=1)", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { input: "' OR 1=1" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("sql_or_injection");
  });

  it("fails on DROP TABLE injection", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { input: "; DROP TABLE users" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("sql_drop_table");
  });

  it("fails on UNION SELECT injection", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { query: "UNION SELECT * FROM secrets" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("sql_union_select");
  });

  it("fails on command injection (rm)", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { cmd: "ls; rm -rf /" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("cmd_rm");
  });

  it("fails on subshell injection", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { input: "echo $(cat /etc/passwd)" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("cmd_subshell");
  });

  it("fails on backtick injection", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { input: "run `id`" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("cmd_backtick");
  });

  it("fails on path traversal (../)", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { path: "../../etc/shadow" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("path_traversal_unix");
  });

  it("fails on /etc/passwd reference", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { file: "/etc/passwd" } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.patterns_found).toContain("path_etc_passwd");
  });

  it("flags on suspicious-only SQL comment pattern", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { input: "'value--" } }), makeMinimalConfig());
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData.scan_result).toBe("suspicious");
  });

  it("scans nested parameter values", () => {
    const evaluator = new PR08InputEvaluator();
    const result = evaluator.evaluate(makeAction({ params: { nested: { deep: "'; DROP TABLE x" } } }), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
  });

  it("integrated: injection in enforce mode blocks", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction({ params: { input: "'; DROP TABLE users" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-08").result).toBe("FAIL");
    expect(result.decision).toBe("BLOCK");
  });

  it("integrated: clean input passes in enforce mode", () => {
    const config = makeConfig({ security: { mode: "enforce" } });
    const action = makeAction({ params: { query: "get user profile" } });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(action);
    expect(getControlResult(result.controlResults, "PR-08").result).toBe("PASS");
  });
});

// --- GOV-01 Governance Policy Tests ---

describe("GOV-01 Governance Policy", () => {
  it("passes with complete governance policy (all 4 fields)", () => {
    const config = makeMinimalConfig({
      agentName: "my-agent",
      mode: "enforce",
      dataClassifications: new Map([["credit_cards", ["DC-CHD"]]]),
      toolsAllowed: ["read_file"],
    });
    const evaluator = new GOV01PolicyEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.policy_completeness).toBe("complete");
    expect(result.evidenceData.fields_present).toEqual(
      expect.arrayContaining(["agent_name", "mode", "data_classifications", "scope_constraints"])
    );
  });

  it("flags with partial governance policy (2 fields: agent_name + mode)", () => {
    // Default makeConfig gives agent_name="test-agent", mode="audit", no data_class, no scope
    const config = makeConfig();
    const evaluator = new GOV01PolicyEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData.policy_completeness).toBe("partial");
    expect(result.evidenceData.fields_missing).toContain("data_classifications");
    expect(result.evidenceData.fields_missing).toContain("scope_constraints");
  });

  it("flags with 3 fields (agent_name + mode + scope)", () => {
    const config = makeConfig({ security: { tools: { allowed: ["test-tool"] } } });
    const evaluator = new GOV01PolicyEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData.fields_present).toContain("scope_constraints");
    expect(result.evidenceData.fields_missing).toContain("data_classifications");
  });

  it("recognizes tools_blocked as valid scope constraint", () => {
    const config = makeMinimalConfig({
      agentName: "my-agent",
      mode: "enforce",
      dataClassifications: new Map([["pii", ["DC-PII"]]]),
      toolsBlocked: ["dangerous-tool"],
    });
    const evaluator = new GOV01PolicyEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.fields_present).toContain("scope_constraints");
  });

  it("fails with insufficient governance policy (only mode present)", () => {
    const config = makeMinimalConfig({ agentName: "", mode: "audit" });
    const evaluator = new GOV01PolicyEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData.policy_completeness).toBe("insufficient");
    expect(result.evidenceData.fields_missing).toContain("agent_name");
  });

  it("fails with no fields present", () => {
    const config = makeMinimalConfig({ agentName: "", mode: "" });
    const evaluator = new GOV01PolicyEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
    expect((result.evidenceData.fields_present as string[]).length).toBe(0);
  });

  it("integrated: partial policy is allowed in audit mode (FLAG not FAIL)", () => {
    const config = makeConfig(); // 2 fields → FLAG
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(makeAction());
    const gov01 = getControlResult(result.controlResults, "GOV-01");
    expect(gov01.result).toBe("FLAG");
    expect(result.decision).toBe("ALLOW"); // FLAG doesn't trigger BLOCK
  });

  it("integrated: complete policy passes in enforce mode", () => {
    const config = makeConfig({
      security: { mode: "enforce", tools: { allowed: ["test-tool"] } },
      my_agent_handles: ["credit_cards"],
    });
    const engine = new Engine(config, { registry: makeRegistry(["test-tool"]) });
    const result = engine.evaluate(makeAction());
    expect(getControlResult(result.controlResults, "GOV-01").result).toBe("PASS");
  });
});
