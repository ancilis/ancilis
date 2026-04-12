/**
 * Coverage gap fill — targets uncovered lines in core modules.
 * Parity with Python test_coverage_gaps.py.
 *
 * Modules addressed:
 * - config/index.ts      (UnavailableOverlay, formatResolvedConfig)
 * - engine/patterns.ts   (scanForPatterns — email, phone, api_key, MRN, Luhn edge cases)
 * - engine/evaluators/pr02-scope.ts  (RateTracker window logic)
 * - engine/evaluators/pr04-exposure.ts  (unauthorized destination, blocked destination)
 */

import { describe, it, expect } from "vitest";
import { loadConfig, formatResolvedConfig } from "../src/ancilis/config/index.js";
import type { UnavailableOverlay, ResolvedConfig } from "../src/ancilis/config/index.js";
import { scanForPatterns, scanParameters } from "../src/ancilis/engine/patterns.js";
import { PR02ScopeEvaluator } from "../src/ancilis/engine/evaluators/pr02-scope.js";
import type { RateTracker } from "../src/ancilis/engine/evaluators/pr02-scope.js";
import { PR04ExposureEvaluator } from "../src/ancilis/engine/evaluators/pr04-exposure.js";
import type { Action } from "../src/ancilis/engine/action.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides: Record<string, unknown> = {}): ResolvedConfig {
  return loadConfig({ raw: { agent: { name: "test-agent" }, ...overrides } });
}

function makeAction(
  toolName: string = "test-tool",
  params: Record<string, unknown> = {},
  agentId: string = "test-agent",
): Action {
  return {
    actionId: "act-001",
    timestamp: "2025-01-01T00:00:00Z",
    agentId,
    actionType: "tool_call",
    tool: { name: toolName },
    parameters: {
      raw: params,
      parameterHash: "test-hash",
    },
  } as Action;
}

// ---------------------------------------------------------------------------
// UnavailableOverlay
// ---------------------------------------------------------------------------

describe("UnavailableOverlay", () => {
  it("stores overlayId, triggeredBy, dataType", () => {
    const uo: UnavailableOverlay = {
      overlayId: "future-overlay",
      triggeredBy: "DC-PHI",
      dataType: "health_records",
    };
    expect(uo.overlayId).toBe("future-overlay");
    expect(uo.triggeredBy).toBe("DC-PHI");
    expect(uo.dataType).toBe("health_records");
  });

  it("config with a known data type activates overlays (hipaa for health_records)", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "test" },
        my_agent_handles: ["health_records"],
      },
    });
    // hipaa overlay should either be active or flagged unavailable — never silently dropped
    const hasActive = [...resolved.activeOverlays.keys()].includes("hipaa");
    const hasUnavailable = resolved.unavailableOverlays.some(u => u.overlayId === "hipaa");
    expect(hasActive || hasUnavailable).toBe(true);
  });

  it("resolved config exposes unavailableOverlays as an array", () => {
    const resolved = makeConfig();
    expect(Array.isArray(resolved.unavailableOverlays)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// formatResolvedConfig
// ---------------------------------------------------------------------------

describe("formatResolvedConfig", () => {
  it("contains agent name and Mode: line", () => {
    const resolved = makeConfig();
    const output = formatResolvedConfig(resolved);
    expect(output).toContain("test-agent");
    expect(output).toContain("Mode:");
  });

  it("shows active overlays when present", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "test" },
        compliance: { overlays: ["soc2"] },
      },
    });
    const output = formatResolvedConfig(resolved);
    expect(output).toContain("Active Overlays");
    expect(output.toLowerCase()).toContain("soc");
  });

  it("shows baseline controls section", () => {
    const resolved = makeConfig();
    const output = formatResolvedConfig(resolved);
    expect(output).toContain("Baseline Controls");
    expect(output).toContain("PR-01");
  });

  it("shows data classifications when declared", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "test" },
        my_agent_handles: ["financial_data"],
      },
    });
    const output = formatResolvedConfig(resolved);
    expect(output).toContain("Data Classifications");
  });
});

// ---------------------------------------------------------------------------
// scanForPatterns — email
// ---------------------------------------------------------------------------

describe("scanForPatterns — email", () => {
  it("detects single email and returns redacted sample", () => {
    const matches = scanForPatterns("Contact us at alice@example.com for support.");
    const email = matches.find(m => m.patternType === "email");
    expect(email).toBeDefined();
    expect(email!.count).toBe(1);
    expect(email!.redactedSample).toContain("***@");
    expect(email!.redactedSample).toContain("a");
  });

  it("counts multiple emails correctly", () => {
    const matches = scanForPatterns("a@x.com b@y.com c@z.com");
    const email = matches.find(m => m.patternType === "email");
    expect(email).toBeDefined();
    expect(email!.count).toBe(3);
  });

  it("returns empty array when no patterns found", () => {
    const matches = scanForPatterns("no sensitive data here");
    expect(matches).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// scanForPatterns — phone
// ---------------------------------------------------------------------------

describe("scanForPatterns — phone", () => {
  it("detects US phone number", () => {
    const matches = scanForPatterns("Call me at 555-867-5309.");
    const phone = matches.find(m => m.patternType === "phone");
    expect(phone).toBeDefined();
    expect(phone!.count).toBe(1);
    expect(phone!.redactedSample).toMatch(/\*{3}-\*{3}-\d{4}/);
  });

  it("detects phone with parentheses format", () => {
    const matches = scanForPatterns("Phone: (800) 555-1234");
    const phone = matches.find(m => m.patternType === "phone");
    expect(phone).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// scanForPatterns — API key
// ---------------------------------------------------------------------------

describe("scanForPatterns — api_key", () => {
  it("detects sk- prefixed API key", () => {
    const key = "sk-abcdefghijklmnopqrstuvwxyz123456";
    const matches = scanForPatterns(`Authorization: Bearer ${key}`);
    const apiKey = matches.find(m => m.patternType === "api_key");
    expect(apiKey).toBeDefined();
    expect(apiKey!.redactedSample).toContain("***");
  });

  it("detects token- prefixed secret", () => {
    const matches = scanForPatterns("token-ABCDEFGHIJKLMNOPQRSTUVwxyz1234");
    const apiKey = matches.find(m => m.patternType === "api_key");
    expect(apiKey).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// scanForPatterns — MRN
// ---------------------------------------------------------------------------

describe("scanForPatterns — MRN", () => {
  it("detects MRN pattern", () => {
    // Pattern: /\bMRN[-:\s]?\d{6,}\b/gi — allows 0 or 1 separator char
    const matches = scanForPatterns("Patient MRN:1234567 discharged");
    const mrn = matches.find(m => m.patternType === "mrn");
    expect(mrn).toBeDefined();
    expect(mrn!.redactedSample).toContain("MRN-***");
  });

  it("detects MRN with dash separator", () => {
    const matches = scanForPatterns("MRN-9876543");
    const mrn = matches.find(m => m.patternType === "mrn");
    expect(mrn).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// scanForPatterns — Luhn credit card validation
// ---------------------------------------------------------------------------

describe("scanForPatterns — Luhn / credit card", () => {
  it("detects a valid Luhn credit card number", () => {
    // Visa test number — passes Luhn check
    const matches = scanForPatterns("Card: 4532015112830366");
    const cc = matches.find(m => m.patternType === "credit_card");
    expect(cc).toBeDefined();
    expect(cc!.redactedSample).toContain("****-****-****-");
  });

  it("does not flag a random digit string that fails Luhn", () => {
    // 16 digits that do NOT pass Luhn
    const matches = scanForPatterns("1234567890123456");
    const cc = matches.find(m => m.patternType === "credit_card");
    expect(cc).toBeUndefined();
  });

  it("detects formatted card number with spaces", () => {
    // 4532 0151 1283 0366 — valid Luhn
    const matches = scanForPatterns("4532 0151 1283 0366");
    const cc = matches.find(m => m.patternType === "credit_card");
    expect(cc).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// scanParameters — JSON serialised params
// ---------------------------------------------------------------------------

describe("scanParameters", () => {
  it("detects patterns inside JSON-serialised parameter map", () => {
    const params = { user_email: "user@test.com", note: "call me" };
    const matches = scanParameters(params);
    const email = matches.find(m => m.patternType === "email");
    expect(email).toBeDefined();
  });

  it("returns empty array for clean parameters", () => {
    const matches = scanParameters({ action: "list_tools", page: 1 });
    expect(matches).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// PR02ScopeEvaluator — RateTracker window logic
// ---------------------------------------------------------------------------

describe("PR02ScopeEvaluator — RateTracker", () => {
  it("PASSes when rate tracker returns count below limit", () => {
    const rateTracker: RateTracker = { getActionCount: () => 5 };
    const evaluator = new PR02ScopeEvaluator(rateTracker);
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { scope: { max_actions_per_minute: 10 } },
      },
    });
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
  });

  it("FAILs when rate tracker returns count at limit", () => {
    const rateTracker: RateTracker = { getActionCount: () => 10 };
    const evaluator = new PR02ScopeEvaluator(rateTracker);
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { scope: { max_actions_per_minute: 10 } },
      },
    });
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("Rate limit");
  });

  it("FAILs when rate tracker returns count above limit", () => {
    const rateTracker: RateTracker = { getActionCount: () => 99 };
    const evaluator = new PR02ScopeEvaluator(rateTracker);
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { scope: { max_actions_per_minute: 5 } },
      },
    });
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
  });

  it("PASSes when no rate limit configured (null)", () => {
    const rateTracker: RateTracker = { getActionCount: () => 999 };
    const evaluator = new PR02ScopeEvaluator(rateTracker);
    const config = makeConfig(); // no scope.max_actions_per_minute
    expect(config.scopeMaxActionsPerMinute).toBeNull();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
  });

  it("FAILs when tool is in blocked list (blocked takes precedence)", () => {
    const evaluator = new PR02ScopeEvaluator();
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { tools: { blocked: ["bad_tool"] } },
      },
    });
    const result = evaluator.evaluate(makeAction("bad_tool"), config);
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("blocked");
  });

  it("FAILs when allowlist is set and tool is not in it", () => {
    const evaluator = new PR02ScopeEvaluator();
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { tools: { allowed: ["safe_tool"] } },
      },
    });
    const result = evaluator.evaluate(makeAction("unsafe_tool"), config);
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("allowlist");
  });
});

// ---------------------------------------------------------------------------
// PR04ExposureEvaluator — unauthorized destination
// ---------------------------------------------------------------------------

describe("PR04ExposureEvaluator — unauthorized destination", () => {
  it("PASSes when parameters are clean (no PII)", () => {
    const evaluator = new PR04ExposureEvaluator();
    const result = evaluator.evaluate(
      makeAction("tool", { action: "list_items" }),
      makeConfig(),
    );
    expect(result.result).toBe("PASS");
    expect(result.detail).toContain("No sensitive data");
  });

  it("PASSes when PII detected but no destination restrictions", () => {
    const evaluator = new PR04ExposureEvaluator();
    const result = evaluator.evaluate(
      makeAction("tool", { email: "alice@example.com" }),
      makeConfig(),
    );
    expect(result.result).toBe("PASS");
    expect(result.detail).toContain("no destination restrictions");
  });

  it("FAILs when PII detected and destination is in blocked list", () => {
    const evaluator = new PR04ExposureEvaluator();
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { scope: { blocked_destinations: ["bad-sink.example.com"] } },
      },
    });
    const result = evaluator.evaluate(
      makeAction("tool", {
        email: "alice@example.com",
        destination: "bad-sink.example.com",
      }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("blocked destination");
  });

  it("FAILs when PII detected and destination not in allowed list", () => {
    const evaluator = new PR04ExposureEvaluator();
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { scope: { allowed_destinations: ["trusted.example.com"] } },
      },
    });
    const result = evaluator.evaluate(
      makeAction("tool", {
        email: "alice@example.com",
        url: "https://untrusted.example.com/upload",
      }),
      config,
    );
    expect(result.result).toBe("FAIL");
    expect(result.detail).toContain("unauthorized destination");
  });

  it("PASSes when PII detected but destination is in allowed list", () => {
    const evaluator = new PR04ExposureEvaluator();
    const config = loadConfig({
      raw: {
        agent: { name: "test-agent" },
        security: { scope: { allowed_destinations: ["trusted.example.com"] } },
      },
    });
    const result = evaluator.evaluate(
      makeAction("tool", {
        email: "alice@example.com",
        url: "trusted.example.com",
      }),
      config,
    );
    expect(result.result).toBe("PASS");
  });

  it("records pattern detection in evidenceData", () => {
    const evaluator = new PR04ExposureEvaluator();
    const result = evaluator.evaluate(
      makeAction("tool", { ssn: "123-45-6789" }),
      makeConfig(),
    );
    const evidence = result.evidenceData as Record<string, unknown>;
    const patterns = evidence.patterns_detected as Array<{ type: string }>;
    expect(Array.isArray(patterns)).toBe(true);
    expect(patterns.length).toBeGreaterThan(0);
    expect(patterns[0]?.type).toBe("ssn");
  });
});
