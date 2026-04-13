/**
 * Programmatic engine integration tests — AKSI importability parity.
 * Mirrors Python test_aksi_importability.py (ANC-836).
 *
 * Validates that the Ancilis TypeScript SDK engine can be driven entirely
 * through direct imports with no subprocess or CLI layer involved.
 */

import { describe, it, expect } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import * as evaluators from "../src/ancilis/engine/evaluators/index.js";
import type { Action } from "../src/ancilis/engine/action.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_CONFIG_PATH = join(__dirname, "../../examples/demo/ancilis.yaml");

// Implemented evaluator control IDs that must appear in every evaluation
const EVALUATOR_CONTROL_IDS = new Set([
  "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08",
  "DE-01", "DE-02",
]);
const VALID_RESULTS = new Set(["PASS", "FAIL", "SKIP", "ERROR"]);

function makeAction(
  toolName: string = "check_balance",
  agentId: string = "test-agent",
  params: Record<string, unknown> = {},
): Action {
  return {
    actionId: crypto.randomUUID(),
    timestamp: "2026-04-07T00:00:00Z",
    agentId,
    actionType: "tool_call",
    tool: { name: toolName },
    parameters: { raw: params, parameterHash: "abc123" },
    context: {},
  } as Action;
}

// ---------------------------------------------------------------------------
// Programmatic engine invocation — no subprocess
// ---------------------------------------------------------------------------

describe("TestProgrammaticEngineInvocation", () => {
  it("loads config from demo YAML path without subprocess", () => {
    const config = loadConfig({ path: DEMO_CONFIG_PATH });
    expect(config.agentName).toBe("finance-demo-agent");
    expect(config.mode).toBe("enforce");
  });

  it("instantiates Engine from YAML-loaded config", () => {
    const config = loadConfig({ path: DEMO_CONFIG_PATH });
    const engine = new Engine(config);
    expect(engine).toBeDefined();
    expect(engine.config).toBe(config);
  });

  it("evaluate() returns EvaluationResult with required fields", () => {
    const config = loadConfig({ path: DEMO_CONFIG_PATH });
    const engine = new Engine(config);
    const action = makeAction();

    const result = engine.evaluate(action);

    expect(result.evaluationId).toBeTruthy();
    expect(result.actionId).toBe(action.actionId);
    expect(["ALLOW", "BLOCK"]).toContain(result.decision);
    expect(Array.isArray(result.controlResults)).toBe(true);
    expect(result.controlResults.length).toBeGreaterThan(0);
  });

  it("all implemented evaluators appear in results", () => {
    const config = loadConfig({ path: DEMO_CONFIG_PATH });
    const engine = new Engine(config);
    const action = makeAction();

    const result = engine.evaluate(action);

    const resultIds = new Set(result.controlResults.map(cr => cr.controlId));
    for (const expected of EVALUATOR_CONTROL_IDS) {
      expect(resultIds.has(expected), `Missing evaluator: ${expected}`).toBe(true);
    }
  });

  it("DE-02 evaluator is exported from the evaluators package", () => {
    expect(evaluators.DE02ConfigDriftEvaluator).toBeDefined();
  });

  it("every ControlResult has a valid result value (PASS/FAIL/SKIP/ERROR)", () => {
    const config = loadConfig({ path: DEMO_CONFIG_PATH });
    const engine = new Engine(config);
    const action = makeAction();

    const result = engine.evaluate(action);

    for (const cr of result.controlResults) {
      expect(cr.controlId).toBeTruthy();
      expect(
        VALID_RESULTS.has(cr.result),
        `Control ${cr.controlId} returned unexpected result: ${cr.result}`,
      ).toBe(true);
    }
  });

  it("PR-01 identity control is present in results", () => {
    const config = loadConfig({ path: DEMO_CONFIG_PATH });
    const engine = new Engine(config);
    const action = makeAction("check_balance", "test-agent");

    const result = engine.evaluate(action);

    const pr01 = result.controlResults.find(cr => cr.controlId === "PR-01");
    expect(pr01).toBeDefined();
    expect(VALID_RESULTS.has(pr01!.result)).toBe(true);
  });

  it("end-to-end programmatic flow: YAML → config → engine → evaluate → assert", () => {
    // Step 1: Load config from YAML path (no subprocess)
    const config = loadConfig({ path: DEMO_CONFIG_PATH });

    // Step 2: Create engine instance
    const engine = new Engine(config);

    // Step 3: Feed a test action
    const action = makeAction("check_balance", "test-agent", { account_id: "123" });

    // Step 4: Receive evaluation result
    const result = engine.evaluate(action);

    // Step 5: Assert results contain expected control evaluations
    expect(result.controlResults[0]?.controlId).toBeTruthy();
    expect(VALID_RESULTS.has(result.controlResults[0]!.result)).toBe(true);
    expect(result.agentId).toBe("test-agent");
    expect(result.sourceType).toBe("agent");
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Engine constructor validation
// ---------------------------------------------------------------------------

describe("TestEngineConstructorValidatesConfig", () => {
  it("Engine rejects raw dict config at evaluate time", () => {
    const rawConfig = { agent: { name: "test" } };
    const badEngine = new Engine(rawConfig as unknown as ConstructorParameters<typeof Engine>[0]);

    expect(() => badEngine.evaluate(makeAction())).toThrow(TypeError);
  });

  it("Engine built from minimal programmatic raw config", () => {
    const config = loadConfig({ raw: { agent: { name: "minimal-agent" } } });
    const engine = new Engine(config);
    const action = makeAction();
    const result = engine.evaluate(action);
    expect(["ALLOW", "BLOCK"]).toContain(result.decision);
    expect(result.controlResults.length).toBeGreaterThan(0);
  });

  it("Engine evaluates tool not in allowlist as BLOCK in enforce mode", () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { mode: "enforce", tools: { allowed: ["safe_tool"] } },
      },
    });
    const engine = new Engine(config);
    const result = engine.evaluate(makeAction("unsafe_tool"));
    // PR-02 scope failure → BLOCK in enforce mode
    expect(result.decision).toBe("BLOCK");
    const pr02 = result.controlResults.find(cr => cr.controlId === "PR-02");
    expect(pr02?.result).toBe("FAIL");
  });

  it("Engine evaluates blocked tool as BLOCK in enforce mode", () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { mode: "enforce", tools: { blocked: ["drop_audit_log"] } },
      },
    });
    const engine = new Engine(config);
    const result = engine.evaluate(makeAction("drop_audit_log"));
    expect(result.decision).toBe("BLOCK");
  });

  it("Engine in audit mode returns ALLOW even for blocked tools (observe only)", () => {
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { mode: "audit", tools: { blocked: ["some_tool"] } },
      },
    });
    const engine = new Engine(config);
    const result = engine.evaluate(makeAction("some_tool"));
    expect(result.decision).toBe("ALLOW");
  });
});
