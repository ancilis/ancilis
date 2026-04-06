/** Focused parity tests for the cmmc-l2 and securities-mnpi overlays. */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { stringify as stringifyYaml } from "yaml";
import {
  ActivationResolver,
  ALL_AKSI_CONTROLS,
} from "../src/ancilis/activation/resolver.js";
import {
  loadOverlayProfiles,
  loadTaxonomy,
} from "../src/ancilis/activation/loader.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import { validateAndFormat } from "../src/ancilis/cli/validate.js";
import { ReportGenerator, renderTerminal } from "../src/ancilis/report/index.js";
import type { EvidenceSummary } from "../src/ancilis/report/index.js";

// --- Helpers ---

function tmpDir(): string {
  const dir = join(tmpdir(), `ancilis-overlay-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(dir: string, data: Record<string, unknown>): string {
  const path = join(dir, "ancilis.yaml");
  writeFileSync(path, stringifyYaml(data));
  return path;
}

function populatedSummary(n = 3): EvidenceSummary {
  return {
    total_evaluations: n,
    decisions: { ALLOW: n },
    tools_evaluated: ["read_file"],
    control_pass_rates: {
      "PR-01": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-02": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-03": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-04": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "PR-05": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
      "DE-01": { PASS: n, FAIL: 0, FLAG: 0, SKIP: 0, ERROR: 0 },
    },
    chain_valid: true,
    chain_errors: [],
  };
}

// ===== CMMC-L2 Overlay =====

describe("CMMC-L2 — Profile", () => {
  it("cmmc-l2 profile loads", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.has("cmmc-l2")).toBe(true);
  });

  it("cmmc-l2 metadata matches government activation", () => {
    const profile = loadOverlayProfiles().get("cmmc-l2")!;
    expect(profile.trigger_type).toBe("data_classification");
    const triggeredBy = new Set(profile.triggered_by as string[]);
    expect(triggeredBy.has("DC-CUI")).toBe(true);
    expect(triggeredBy.has("DC-GOV")).toBe(true);
    expect((profile.applicable_data_types as string[])).toContain("government_cui");
  });

  it("cmmc-l2 framework mapping covers all AKSI controls", () => {
    const profile = loadOverlayProfiles().get("cmmc-l2")!;
    const keys = new Set(Object.keys(profile.framework_mapping as Record<string, unknown>));
    expect(keys).toEqual(ALL_AKSI_CONTROLS);
  });

  it("cmmc-l2 active controls reference CMMC Level 2 and NIST", () => {
    const profile = loadOverlayProfiles().get("cmmc-l2")!;
    const controls = profile.controls as Record<string, Record<string, unknown>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      const ref = controls[controlId]!.framework_reference as string;
      expect(ref, `${controlId} missing CMMC reference`).toContain("CMMC Level 2");
      expect(ref, `${controlId} missing NIST reference`).toContain("NIST SP 800-171 Rev. 3");
    }
  });

  it("cmmc-l2 sets strict thresholds for all active controls", () => {
    const profile = loadOverlayProfiles().get("cmmc-l2")!;
    const adjustments = profile.control_adjustments as Record<string, Record<string, unknown>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      expect(adjustments[controlId]!.threshold_adjustment, controlId).toBe("strict");
    }
  });

  it("cmmc-l2 evidence retention minimum is 1095 days", () => {
    const profile = loadOverlayProfiles().get("cmmc-l2")!;
    expect(profile.evidence_retention_minimum_days).toBe(1095);
  });
});

describe("CMMC-L2 — Taxonomy", () => {
  it("DC-GOV taxonomy entry is active and linked to cmmc-l2", () => {
    const taxonomy = loadTaxonomy();
    const classifications = taxonomy.classifications as Array<Record<string, unknown>>;
    const gov = classifications.find(e => e.code === "DC-GOV")!;
    expect(gov.overlay_status).toBe("active");
    expect((gov.overlays as string[])).toContain("cmmc-l2");
  });

  it("DC-CUI taxonomy entry is active and linked to cmmc-l2", () => {
    const taxonomy = loadTaxonomy();
    const classifications = taxonomy.classifications as Array<Record<string, unknown>>;
    const cui = classifications.find(e => e.code === "DC-CUI")!;
    expect(cui.overlay_status).toBe("active");
    expect((cui.overlays as string[])).toContain("cmmc-l2");
  });
});

describe("CMMC-L2 — Resolver", () => {
  it("government_cui activates cmmc-l2 with strict controls", () => {
    const spec = new ActivationResolver().resolve({ dataHandling: ["government_cui"] });
    expect(spec.activeOverlays).toContain("cmmc-l2");
    expect(spec.dataClassifications).toContain("DC-CUI");
    expect(spec.controlThresholds["PR-01"]).toBe("strict");
    expect(spec.controlThresholds["PR-05"]).toBe("strict");
    expect((spec.evidenceRequirements["PR-01"] ?? []).length).toBeGreaterThan(0);
  });

  it("controlled_unclassified alias activates cmmc-l2 via DC-CUI", () => {
    const spec = new ActivationResolver().resolve({ dataHandling: ["controlled_unclassified"] });
    expect(spec.dataClassifications).toContain("DC-CUI");
    expect(spec.activeOverlays).toContain("cmmc-l2");
  });
});

describe("CMMC-L2 — Config", () => {
  it("government_cui config activates cmmc-l2 and is not in unavailable", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "gov-agent" }, my_agent_handles: ["government_cui"] },
    });
    expect(resolved.activeOverlays.has("cmmc-l2")).toBe(true);
    expect(resolved.unavailableOverlays.some(u => u.overlayId === "cmmc-l2")).toBe(false);
  });

  it("government_cui config sets retention to at least 1095 days", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "gov-agent" }, my_agent_handles: ["government_cui"] },
    });
    expect(resolved.evidenceRetentionDays).toBeGreaterThanOrEqual(1095);
  });
});

describe("CMMC-L2 — Validate", () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("config validate surfaces CMMC Level 2 overlay name", () => {
    const path = writeConfig(dir, {
      agent: { name: "gov-agent" },
      my_agent_handles: ["government_cui"],
    });
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(true);
    expect(message).toContain("CMMC Level 2");
  });
});

describe("CMMC-L2 — Report", () => {
  it("report includes cmmc-l2 compliance section", () => {
    const config = loadConfig({
      raw: { agent: { name: "gov-agent" }, my_agent_handles: ["government_cui"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    expect(
      report.complianceSections.some(s => s.overlayId === "cmmc-l2"),
    ).toBe(true);
  });

  it("terminal output includes CMMC Level 2 overlay name", () => {
    const config = loadConfig({
      raw: { agent: { name: "gov-agent" }, my_agent_handles: ["government_cui"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    const output = renderTerminal(report);
    expect(output).toContain("CMMC Level 2");
  });
});

// ===== Securities MNPI Overlay =====

describe("Securities MNPI — Profile", () => {
  it("securities-mnpi profile loads", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.has("securities-mnpi")).toBe(true);
  });

  it("securities-mnpi metadata matches MNPI activation", () => {
    const profile = loadOverlayProfiles().get("securities-mnpi")!;
    expect(profile.trigger_type).toBe("data_classification");
    expect(profile.triggered_by).toEqual(["DC-MNPI"]);
    expect((profile.applicable_data_types as string[])).toContain("material_nonpublic");
    expect((profile.applicable_data_types as string[])).toContain("mnpi");
  });

  it("securities-mnpi framework mapping covers all AKSI controls", () => {
    const profile = loadOverlayProfiles().get("securities-mnpi")!;
    const keys = new Set(Object.keys(profile.framework_mapping as Record<string, unknown>));
    expect(keys).toEqual(ALL_AKSI_CONTROLS);
  });

  it("securities-mnpi active controls reference SEC Reg FD and SOX", () => {
    const profile = loadOverlayProfiles().get("securities-mnpi")!;
    const controls = profile.controls as Record<string, Record<string, unknown>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      const ref = controls[controlId]!.framework_reference as string;
      expect(ref, `${controlId} missing SEC Reg FD reference`).toContain("SEC Reg FD");
      expect(ref, `${controlId} missing SOX reference`).toContain("SOX");
    }
  });

  it("securities-mnpi sets strict thresholds for all active controls", () => {
    const profile = loadOverlayProfiles().get("securities-mnpi")!;
    const adjustments = profile.control_adjustments as Record<string, Record<string, unknown>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      expect(adjustments[controlId]!.threshold_adjustment, controlId).toBe("strict");
    }
  });

  it("securities-mnpi evidence retention minimum is 2555 days", () => {
    const profile = loadOverlayProfiles().get("securities-mnpi")!;
    expect(profile.evidence_retention_minimum_days).toBe(2555);
  });
});

describe("Securities MNPI — Taxonomy", () => {
  it("DC-MNPI taxonomy entry is active and linked to securities-mnpi", () => {
    const taxonomy = loadTaxonomy();
    const classifications = taxonomy.classifications as Array<Record<string, unknown>>;
    const mnpi = classifications.find(e => e.code === "DC-MNPI")!;
    expect(mnpi.overlay_status).toBe("active");
    expect((mnpi.overlays as string[])).toContain("securities-mnpi");
  });
});

describe("Securities MNPI — Resolver", () => {
  it("mnpi activates securities-mnpi with strict controls and evidence requirements", () => {
    const spec = new ActivationResolver().resolve({ dataHandling: ["mnpi"] });
    expect(spec.dataClassifications).toContain("DC-MNPI");
    expect(spec.activeOverlays).toContain("securities-mnpi");
    expect(spec.controlThresholds["PR-01"]).toBe("strict");
    expect(spec.controlThresholds["PR-05"]).toBe("strict");
    expect((spec.evidenceRequirements["PR-01"] ?? []).length).toBeGreaterThan(0);
  });

  it("material_nonpublic alias activates securities-mnpi via DC-MNPI", () => {
    const spec = new ActivationResolver().resolve({ dataHandling: ["material_nonpublic"] });
    expect(spec.dataClassifications).toContain("DC-MNPI");
    expect(spec.activeOverlays).toContain("securities-mnpi");
  });
});

describe("Securities MNPI — Config", () => {
  it("mnpi config activates securities-mnpi and is not in unavailable", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "sec-agent" }, my_agent_handles: ["mnpi"] },
    });
    expect(resolved.activeOverlays.has("securities-mnpi")).toBe(true);
    expect(resolved.unavailableOverlays.some(u => u.overlayId === "securities-mnpi")).toBe(false);
  });

  it("mnpi config sets retention to 2555 days", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "sec-agent" }, my_agent_handles: ["mnpi"] },
    });
    expect(resolved.evidenceRetentionDays).toBe(2555);
  });
});

describe("Securities MNPI — Validate", () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("config validate surfaces Securities Markets overlay name", () => {
    const path = writeConfig(dir, {
      agent: { name: "sec-agent" },
      my_agent_handles: ["mnpi"],
    });
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(true);
    expect(message).toContain("Securities Markets");
  });
});

describe("Securities MNPI — Report", () => {
  it("report includes securities-mnpi compliance section", () => {
    const config = loadConfig({
      raw: { agent: { name: "sec-agent" }, my_agent_handles: ["mnpi"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    expect(
      report.complianceSections.some(s => s.overlayId === "securities-mnpi"),
    ).toBe(true);
  });

  it("terminal output includes Securities Markets overlay name", () => {
    const config = loadConfig({
      raw: { agent: { name: "sec-agent" }, my_agent_handles: ["mnpi"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    const output = renderTerminal(report);
    expect(output).toContain("Securities Markets");
  });
});
