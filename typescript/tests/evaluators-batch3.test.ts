/**
 * Tests for DE-04, GOV-02, ID-01 evaluators (ANC-519).
 * Also covers PR-01 parity tests (ANC-555).
 */

import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import type { Action } from "../src/ancilis/engine/action.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { DE04IntegrityEvaluator, type DE04StoreAdapter } from "../src/ancilis/engine/evaluators/de04-integrity.js";
import { GOV02OwnershipEvaluator } from "../src/ancilis/engine/evaluators/gov02-ownership.js";
import { ID01InventoryEvaluator } from "../src/ancilis/engine/evaluators/id01-inventory.js";
import { PR01IdentityEvaluator } from "../src/ancilis/engine/evaluators/pr01-identity.js";

// --- Helpers ---

function makeAction(): Action {
  return {
    actionId: randomUUID(),
    timestamp: "2026-04-12T00:00:00Z",
    agentId: "test-agent",
    agentOwner: null,
    actionType: "tool_call",
    tool: { name: "test-tool", version: null, descriptionHash: null },
    parameters: { raw: {}, parameterHash: "abc" },
    context: {},
  };
}

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

function makeStore(total: number, chainValid: boolean, errors: string[] = []): DE04StoreAdapter {
  return {
    count: () => total,
    verifyChain: () => ({ valid: chainValid, errors }),
  };
}

// --- DE-04 Evidence Integrity ---

describe("DE-04 Evidence Integrity Verification", () => {
  it("passes with a valid non-empty chain", () => {
    const ev = new DE04IntegrityEvaluator(makeStore(5, true));
    const result = ev.evaluate(makeAction(), makeMinimalConfig());
    expect(result.result).toBe("PASS");
    expect(result.controlId).toBe("DE-04");
    expect(result.evidenceData?.["chain_valid"]).toBe(true);
    expect(result.evidenceData?.["total_records"]).toBe(5);
    expect(result.evidenceData?.["errors"]).toEqual([]);
    expect(result.detail).toContain("5 record(s)");
  });

  it("flags when store is empty", () => {
    const ev = new DE04IntegrityEvaluator(makeStore(0, true));
    const result = ev.evaluate(makeAction(), makeMinimalConfig());
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData?.["total_records"]).toBe(0);
    expect(result.detail).toContain("empty");
  });

  it("fails when chain integrity is broken", () => {
    const errors = ["Record abc123: hash mismatch. Expected aabbcc..., got 112233..."];
    const ev = new DE04IntegrityEvaluator(makeStore(3, false, errors));
    const result = ev.evaluate(makeAction(), makeMinimalConfig());
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData?.["chain_valid"]).toBe(false);
    expect((result.evidenceData?.["errors"] as string[]).length).toBe(1);
    expect(result.detail).toContain("1 error(s)");
  });

  it("flags when no store is configured", () => {
    const ev = new DE04IntegrityEvaluator(null);
    const result = ev.evaluate(makeAction(), makeMinimalConfig());
    expect(result.result).toBe("FLAG");
    expect(result.detail).toContain("No evidence store");
  });

  it("has required evidence fields", () => {
    const ev = new DE04IntegrityEvaluator(makeStore(2, true));
    const result = ev.evaluate(makeAction(), makeMinimalConfig());
    expect(result.evidenceData).toHaveProperty("chain_valid");
    expect(result.evidenceData).toHaveProperty("total_records");
    expect(result.evidenceData).toHaveProperty("errors");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// --- GOV-02 Agent Ownership & Accountability ---

describe("GOV-02 Agent Ownership & Accountability", () => {
  const ev = new GOV02OwnershipEvaluator();

  it("passes when a real owner is set", () => {
    const config = makeMinimalConfig({ agentOwner: "alice@example.com" });
    const result = ev.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
    expect(result.controlId).toBe("GOV-02");
    expect(result.evidenceData?.["owner_declared"]).toBe(true);
    expect(result.evidenceData?.["owner_value"]).toBe("alice@example.com");
  });

  it("flags placeholder 'todo'", () => {
    const result = ev.evaluate(makeAction(), makeMinimalConfig({ agentOwner: "TODO" }));
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData?.["owner_declared"]).toBe(true);
  });

  it("flags placeholder 'unknown'", () => {
    const result = ev.evaluate(makeAction(), makeMinimalConfig({ agentOwner: "unknown" }));
    expect(result.result).toBe("FLAG");
  });

  it("flags placeholder 'changeme'", () => {
    const result = ev.evaluate(makeAction(), makeMinimalConfig({ agentOwner: "changeme" }));
    expect(result.result).toBe("FLAG");
  });

  it("flags placeholder 'tbd' (case insensitive)", () => {
    const result = ev.evaluate(makeAction(), makeMinimalConfig({ agentOwner: "TBD" }));
    expect(result.result).toBe("FLAG");
  });

  it("fails when no owner is configured", () => {
    const config = makeMinimalConfig({ agentOwner: "" });
    const result = ev.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData?.["owner_declared"]).toBe(false);
    expect(result.evidenceData?.["owner_value"]).toBeNull();
  });

  it("has required evidence fields", () => {
    const result = ev.evaluate(makeAction(), makeMinimalConfig({ agentOwner: "bob@corp.com" }));
    expect(result.evidenceData).toHaveProperty("owner_declared");
    expect(result.evidenceData).toHaveProperty("owner_value");
    expect(result.evidenceData).toHaveProperty("source_field");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// --- ID-01 Agent Inventory & Registry ---

describe("ID-01 Agent Inventory & Registry", () => {
  const ev = new ID01InventoryEvaluator();

  it("passes when name and id are both set", () => {
    const config = makeMinimalConfig({ agentName: "my-agent", agentId: "agt-1234" });
    const result = ev.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
    expect(result.controlId).toBe("ID-01");
    expect(result.evidenceData?.["inventory_status"]).toBe("registered");
    expect((result.evidenceData?.["fields"] as Record<string, unknown>)["name"]).toBe("my-agent");
    expect((result.evidenceData?.["fields"] as Record<string, unknown>)["id"]).toBe("agt-1234");
  });

  it("flags when name is set but id is missing", () => {
    const config = makeMinimalConfig({ agentName: "my-agent", agentId: null });
    const result = ev.evaluate(makeAction(), config);
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData?.["inventory_status"]).toBe("partial");
    expect((result.evidenceData?.["fields"] as Record<string, unknown>)["id"]).toBeNull();
  });

  it("fails when neither name nor id is set", () => {
    const config = makeMinimalConfig({ agentName: "", agentId: null });
    const result = ev.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
    expect(result.evidenceData?.["inventory_status"]).toBe("unregistered");
  });

  it("has required evidence fields", () => {
    const config = makeMinimalConfig({ agentName: "my-agent", agentId: "agt-001" });
    const result = ev.evaluate(makeAction(), config);
    expect(result.evidenceData).toHaveProperty("inventory_status");
    expect(result.evidenceData).toHaveProperty("fields");
    expect((result.evidenceData?.["fields"] as Record<string, unknown>)).toHaveProperty("name");
    expect((result.evidenceData?.["fields"] as Record<string, unknown>)).toHaveProperty("id");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// --- PR-01 Parity Tests (ANC-555) ---

describe("PR-01 Identity — null/undefined agentOwner parity with Python", () => {
  const ev = new PR01IdentityEvaluator();

  function makeParityAction(agentOwner: string | null | undefined): Action {
    return {
      actionId: randomUUID(),
      timestamp: "2026-04-12T00:00:00Z",
      agentId: "test-agent",
      agentOwner,
      actionType: "tool_call",
      tool: { name: "test-tool", version: null, descriptionHash: null },
      parameters: { raw: {}, parameterHash: "abc" },
      context: {},
    };
  }

  const configWithOwner = makeMinimalConfig({ agentName: "test-agent", agentOwner: "alice@example.com" });

  it("parity: null agentOwner passes when owner configured (Python: agent_owner is not None → PASS)", () => {
    const result = ev.evaluate(makeParityAction(null), configWithOwner);
    expect(result.result).toBe("PASS");
  });

  it("parity: undefined agentOwner passes when owner configured (Python: agent_owner is not None → PASS)", () => {
    const result = ev.evaluate(makeParityAction(undefined), configWithOwner);
    expect(result.result).toBe("PASS");
  });

  it("parity: matching agentOwner still passes", () => {
    const result = ev.evaluate(makeParityAction("alice@example.com"), configWithOwner);
    expect(result.result).toBe("PASS");
  });

  it("parity: mismatched non-null agentOwner fails", () => {
    const result = ev.evaluate(makeParityAction("bob@example.com"), configWithOwner);
    expect(result.result).toBe("FAIL");
  });
});
