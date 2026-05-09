/**
 * Tests for ancilis config — Unit 1: Policy Schema & Configuration.
 */

import { describe, it, expect } from "vitest";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sharedPathFrom } from "../src/ancilis/shared-path.js";
import { CURRENT_CONFIG_VERSION, inspectConfigMigration, loadConfig, migrateConfigFile } from "../src/ancilis/config/index.js";
import { ConfigError } from "../src/ancilis/errors.js";

function loadSharedControlIds(): string[] {
  const controlsDir = sharedPathFrom(import.meta.url, "controls");
  return readdirSync(controlsDir)
    .filter(file => file.endsWith(".json"))
    .map(file => {
      const raw = readFileSync(sharedPathFrom(import.meta.url, "controls", file), "utf-8");
      const parsed = JSON.parse(raw) as { id: string };
      return parsed.id;
    })
    .sort();
}

describe("Minimal Config", () => {
  it("finds packaged shared assets from the installed package root", () => {
    expect(existsSync(sharedPathFrom(import.meta.url, "controls", "pr-01.json"))).toBe(true);
    expect(existsSync(sharedPathFrom(import.meta.url, "classifications", "taxonomy.json"))).toBe(true);
  });

  it("loads with just agent name", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.agentName).toBe("my-agent");
    expect(resolved.mode).toBe("audit");
  });

  it("activates all 26 controls by default", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.controls.size).toBe(26);
    for (const cs of resolved.controls.values()) {
      expect(cs.enabled).toBe(true);
    }
  });

  it("has no overlays or data classifications", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.activeOverlays.size).toBe(0);
    expect(resolved.dataClassifications.size).toBe(0);
  });

  it("marks default control activation sources", () => {
    const resolved = loadConfig({ raw: { agent: { name: "my-agent" } } });
    expect(resolved.controlActivationSources.get("DE-04")).toEqual(new Set(["default"]));
    expect(
      resolved.controlHasActivationSource(
        "DE-04",
        "explicit:security.controls",
        "certification_targets:",
      ),
    ).toBe(false);
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
        my_agent_handles: ["health_records", "personal_info"],
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

  it("normalizes the NIST CSF 2.0 overlay alias to the canonical overlay", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "claims-processor" },
        compliance: { overlays: ["nist-csf-2"] },
      },
    });

    expect([...resolved.activeOverlays.keys()]).toEqual(["nist-csf"]);
    expect(resolved.activeOverlays.get("nist-csf")?.overlayId).toBe("nist-csf");
    expect(resolved.activeOverlays.get("nist-csf")?.name).toBe("NIST Cybersecurity Framework 2.0");
    expect(resolved.unavailableOverlays.some(item => item.overlayId === "nist-csf-2")).toBe(false);
  });

  it("normalizes the financial overlay alias to the canonical GLBA overlay", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "claims-processor" },
        compliance: { overlays: ["financial"] },
      },
    });

    expect([...resolved.activeOverlays.keys()]).toEqual(["glba"]);
    expect(resolved.activeOverlays.get("glba")?.overlayId).toBe("glba");
    expect(resolved.unavailableOverlays.some(item => item.overlayId === "financial")).toBe(false);
  });
});

describe("Validation", () => {
  it("recognizes config_version and migrates unversioned legacy config in memory", () => {
    const versioned = loadConfig({ raw: { config_version: 2, agent: { name: "x" } } });
    expect(versioned.configVersion).toBe(CURRENT_CONFIG_VERSION);

    const migration = inspectConfigMigration({ agent_name: "legacy-agent" });
    expect(migration).toMatchObject({
      originalVersion: 1,
      currentVersion: CURRENT_CONFIG_VERSION,
      changed: true,
    });
    expect((migration.config.agent as Record<string, unknown>).name).toBe("legacy-agent");

    const resolved = loadConfig({ raw: { agent_name: "legacy-agent" } });
    expect(resolved.agentName).toBe("legacy-agent");
    expect(resolved.configVersion).toBe(CURRENT_CONFIG_VERSION);
  });

  it("writes migrated configs with a backup when explicitly applied", () => {
    const dir = mkdtempSync(join(tmpdir(), "ancilis-config-"));
    const path = join(dir, "ancilis.yaml");
    writeFileSync(path, "agent_name: legacy-agent\n", "utf-8");

    const preview = migrateConfigFile(path);
    expect(preview.changed).toBe(true);
    expect(existsSync(`${path}.bak`)).toBe(false);

    const applied = migrateConfigFile(path, { apply: true });
    expect(applied.backupPath).toBe(`${path}.bak`);
    expect(existsSync(`${path}.bak`)).toBe(true);
    expect(readFileSync(path, "utf-8")).toContain("config_version: 2");
    expect(loadConfig({ path }).agentName).toBe("legacy-agent");
  });

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
      loadConfig({ raw: { agent: { name: "x" }, my_agent_handles: ["not_a_type"] } })
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

  it("suggests close matches for typoed keys and overlay IDs", () => {
    const resolved = loadConfig({ raw: { agent: { name: "x", nme: "typo" } } });
    expect(resolved.warnings.join("\n")).toContain("Did you mean 'agent.name'");

    expect(() =>
      loadConfig({ raw: { agent: { name: "x" }, compliance: { overlays: ["fedram"] } } }),
    ).toThrow(/Did you mean 'fedramp'/);
  });

  it("accepts DE-02 control overrides", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "x" },
        security: { controls: { "DE-02": { enabled: false } } },
      },
    });
    expect(resolved.controls.get("DE-02")?.enabled).toBe(false);
  });

  it("accepts control overrides for all shared control definitions", () => {
    const controlIds = loadSharedControlIds();
    expect(controlIds).toEqual(expect.arrayContaining(["PR-08", "GOV-01"]));

    for (const controlId of controlIds) {
      const resolved = loadConfig({
        raw: {
          agent: { name: "x" },
          security: { controls: { [controlId]: { enabled: false } } },
        },
      });
      expect(resolved.controls.get(controlId)?.enabled).toBe(false);
    }
  });

  it("throws ConfigError (not plain Error) for invalid data types", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "x" }, my_agent_handles: ["not_a_type"] } })
    ).toThrow(ConfigError);
  });

  it("throws ConfigError (not plain Error) for unknown control IDs", () => {
    expect(() =>
      loadConfig({
        raw: {
          agent: { name: "x" },
          security: { controls: { "XX-99": { enabled: true } } },
        },
      })
    ).toThrow(ConfigError);
  });

  it("throws ConfigError with structured code E002 for unknown data type", () => {
    let caught: unknown;
    try {
      loadConfig({ raw: { agent: { name: "x" }, my_agent_handles: ["not_a_type"] } });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as ConfigError).code).toBe("E002");
  });
});

describe("Data Type Translation", () => {
  it("maps health_records to DC-PHI and DC-PII", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["health_records"] },
    });
    const codes = resolved.dataClassifications.get("health_records")!;
    expect(codes).toContain("DC-PHI");
    expect(codes).toContain("DC-PII");
  });

  it("maps personal_info to DC-PII", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["personal_info"] },
    });
    expect(resolved.dataClassifications.get("personal_info")).toEqual(["DC-PII"]);
  });
});

describe("Overlay Activation", () => {
  it("activates HIPAA and GDPR for health_records", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["health_records"] },
    });
    expect(resolved.activeOverlays.has("hipaa")).toBe(true);
    expect(resolved.activeOverlays.has("gdpr")).toBe(true);
  });

  it("stacks overlays from multiple data types", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["health_records", "credit_cards"] },
    });
    expect(resolved.activeOverlays.has("hipaa")).toBe(true);
    expect(resolved.activeOverlays.has("gdpr")).toBe(true);
    expect(resolved.activeOverlays.has("soc2")).toBe(true);
  });

  it("activates cmmc-l2 for government_cui", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["government_cui"] },
    });
    expect(resolved.activeOverlays.has("cmmc-l2")).toBe(true);
    expect(resolved.unavailableOverlays.some(u => u.overlayId === "cmmc-l2")).toBe(false);
  });

  it("activates EU AI Act for ai_training_data", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["ai_training_data"] },
    });
    expect(resolved.activeOverlays.has("eu-ai-act")).toBe(true);
  });

  it("sets strict thresholds for HIPAA controls", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["health_records"] },
    });
    expect(resolved.controls.get("PR-01")?.threshold).toBe("strict");
    expect(resolved.controls.get("PR-04")?.threshold).toBe("strict");
  });

  it("sets HIPAA retention to 2190 days", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["health_records"] },
    });
    expect(resolved.evidenceRetentionDays).toBe(2190);
  });

  it("requires human oversight for EU AI Act", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x" }, my_agent_handles: ["ai_training_data"] },
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

  it("marks enabled control overrides as explicit activation sources", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "x" },
        security: { controls: { "DE-04": { enabled: true } } },
      },
    });
    expect(resolved.controlActivationSources.get("DE-04")).toContain("explicit:security.controls");
    expect(resolved.controlHasActivationSource("DE-04", "explicit:security.controls")).toBe(true);
  });

  it("does not apply overlay adjustments to disabled controls", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "x" },
        security: { controls: { "PR-01": { enabled: false } } },
        my_agent_handles: ["health_records"],
      },
    });
    expect(resolved.controls.get("PR-01")?.enabled).toBe(false);
    expect(resolved.controls.get("PR-01")?.threshold).toBe("standard");
  });
});

describe("Certification Targets", () => {
  it("marks certification-required controls with certification activation sources", () => {
    const resolved = loadConfig({
      raw: {
        agent: { name: "x" },
        certification_targets: ["gov-contractor"],
      },
    });
    expect(resolved.controlActivationSources.get("DE-04")).toContain("certification_targets:gov-contractor");
    expect(resolved.controlHasActivationSource("DE-04", "certification_targets:")).toBe(true);
  });
});

describe("Agent ID", () => {
  it("accepts a valid UUID", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x", agent_id: "12345678-1234-1234-1234-123456789abc" } },
    });
    expect(resolved.agentId).toBe("12345678-1234-1234-1234-123456789abc");
  });

  it("defaults to null when not set", () => {
    const resolved = loadConfig({ raw: { agent: { name: "x" } } });
    expect(resolved.agentId).toBeNull();
  });

  it("rejects a non-UUID value", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "x", agent_id: "not-a-uuid" } } })
    ).toThrow(/agent.agent_id must be a valid UUID/);
  });

  it("rejects a too-short UUID-like value", () => {
    expect(() =>
      loadConfig({ raw: { agent: { name: "x", agent_id: "1234" } } })
    ).toThrow(/agent.agent_id must be a valid UUID/);
  });

  it("accepts an uppercase UUID", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "x", agent_id: "12345678-1234-1234-1234-123456789ABC" } },
    });
    expect(resolved.agentId).toBe("12345678-1234-1234-1234-123456789ABC");
  });
});
