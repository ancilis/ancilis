/**
 * Tests for ancilis config — Unit 1: Policy Schema & Configuration.
 */

import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/ancilis/config/index.js";

describe("Minimal Config", () => {
  it("loads with just agent name", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.agentName).toBe("my-agent");
    expect(resolved.mode).toBe("audit");
  });

  it("activates all 6 controls by default", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.controls.size).toBe(6);
    for (const cs of resolved.controls.values()) {
      expect(cs.enabled).toBe(true);
    }
  });

  it("has no overlays or data classifications", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.activeOverlays.size).toBe(0);
    expect(resolved.dataClassifications.size).toBe(0);
  });
});

describe("Full Config", () => {
  it("loads all options correctly", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "claims-processor", description: "Test agent", owner: "team" },
        security: {
          mode: "enforce",
          controls: { "PR-01": { enabled: true }, "DE-01": { enabled: false } },
          tools: { allowed: ["tool-a"], blocked: ["tool-b"] },
          scope: {
            max_actions_per_minute: 100,
            allowed_destinations: ["api.example.com"],
            blocked_destinations: ["evil.com"],
          },
        },
        data_handling: ["health_records", "personal_info"],
        compliance: {
          overlays: ["hipaa", "gdpr"],
          evidence: { storage: "local", retention_days: 730 },
        },
      },
    });
    expect(resolved.agentName).toBe("claims-processor");
    expect(resolved.mode).toBe("enforce");
    expect(resolved.controls.get("DE-01")?.enabled).toBe(false);
    expect(resolved.activeOverlays.has("hipaa")).toBe(true);
    expect(resolved.activeOverlays.has("gdpr")).toBe(true);
  });
});

describe("Validation", () => {
  it("rejects missing agent", () => {
    expect(() => loadConfig({ raw: {} })).toThrow();
  });

  it("rejects empty agent name", () => {
    expect(() => loadConfig({ raw: { agent: { name: "" } } })).toThrow();
  });

  it("rejects invalid mode", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "x" }, security: { mode: "invalid" } } })
    ).toThrow();
  });

  it("rejects unknown data type", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "x" }, data_handling: ["not_a_type"] } })
    ).toThrow(/Unknown data type/);
  });

  it("rejects unknown control ID", () => {
    expect(() =>
      loadConfig({
        raw: {
          agent: { name: "x" },
          security: { controls: { "XX-99": { enabled: true } } },
        },
      })
    ).toThrow(/Unknown control ID/);
  });
});

describe("Data Type Translation", () => {
  it("maps health_records to DC-PHI and DC-PII", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["health_records"] },
    });
    const codes = resolved.dataClassifications.get("health_records")!;
    expect(codes).toContain("DC-PHI");
    expect(codes).toContain("DC-PII");
  });

  it("maps personal_info to DC-PII", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["personal_info"] },
    });
    expect(resolved.dataClassifications.get("personal_info")).toEqual(["DC-PII"]);
  });
});

describe("Overlay Activation", () => {
  it("activates HIPAA and GDPR for health_records", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["health_records"] },
    });
    expect(resolved.activeOverlays.has("hipaa")).toBe(true);
    expect(resolved.activeOverlays.has("gdpr")).toBe(true);
  });

  it("stacks overlays from multiple data types", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["health_records", "credit_cards"] },
    });
    expect(resolved.activeOverlays.has("hipaa")).toBe(true);
    expect(resolved.activeOverlays.has("gdpr")).toBe(true);
    expect(resolved.activeOverlays.has("soc2")).toBe(true);
  });

  it("reports unavailable overlays for government_documents", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["government_documents"] },
    });
    const unavailableIds = resolved.unavailableOverlays.map(u => u.overlayId);
    expect(unavailableIds.some(id => id === "fedramp" || id === "cmmc")).toBe(true);
  });

  it("activates EU AI Act for ai_training_data", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["ai_training_data"] },
    });
    expect(resolved.activeOverlays.has("eu-ai-act")).toBe(true);
  });

  it("sets strict thresholds for HIPAA controls", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["health_records"] },
    });
    expect(resolved.controls.get("PR-01")?.threshold).toBe("strict");
    expect(resolved.controls.get("PR-04")?.threshold).toBe("strict");
  });

  it("sets HIPAA retention to 2190 days", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["health_records"] },
    });
    expect(resolved.evidenceRetentionDays).toBe(2190);
  });

  it("requires human oversight for EU AI Act", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, data_handling: ["ai_training_data"] },
    });
    expect(resolved.humanOversightRequired).toBe(true);
  });
});

describe("Control Override", () => {
  it("disables a control", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "x" },
        security: { controls: { "PR-01": { enabled: false } } },
      },
    });
    expect(resolved.controls.get("PR-01")?.enabled).toBe(false);
    expect(resolved.controls.get("PR-02")?.enabled).toBe(true);
  });

  it("does not apply overlay adjustments to disabled controls", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "x" },
        security: { controls: { "PR-01": { enabled: false } } },
        data_handling: ["health_records"],
      },
    });
    expect(resolved.controls.get("PR-01")?.enabled).toBe(false);
    expect(resolved.controls.get("PR-01")?.threshold).toBe("standard");
  });
});
