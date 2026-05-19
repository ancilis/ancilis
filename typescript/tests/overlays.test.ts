/** Focused parity tests for the cmmc-l2 and securities-mnpi overlays. */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { stringify as stringifyYaml } from "yaml";
import {
  ActivationResolver,
  COMMON_AKSI_CONTROLS,
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
    expect(keys).toEqual(COMMON_AKSI_CONTROLS);
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
    expect(keys).toEqual(COMMON_AKSI_CONTROLS);
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

// ===== FedRAMP Overlay =====

describe("FedRAMP — Profile", () => {
  it("fedramp profile loads", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.has("fedramp")).toBe(true);
  });

  it("fedramp metadata matches federal activation", () => {
    const profile = loadOverlayProfiles().get("fedramp")!;
    expect(profile.trigger_type).toBe("data_classification");
    expect((profile.triggered_by as string[])).toContain("DC-FCI");
    expect((profile.triggered_by as string[])).toContain("DC-GOV");
    expect((profile.applicable_data_types as string[])).toContain("federal_contract");
    expect((profile.applicable_data_types as string[])).toContain("fedramp_system");
  });

  it("fedramp framework mapping covers all AKSI controls", () => {
    const profile = loadOverlayProfiles().get("fedramp")!;
    const mappingKeys = new Set(Object.keys(profile.framework_mapping as Record<string, unknown>));
    for (const ctrl of COMMON_AKSI_CONTROLS) {
      expect(mappingKeys.has(ctrl)).toBe(true);
    }
  });

  it("fedramp active controls reference NIST 800-53 Rev 5 and FedRAMP Moderate", () => {
    const profile = loadOverlayProfiles().get("fedramp")!;
    const controls = profile.controls as Record<string, Record<string, string>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      const reference = controls[controlId].framework_reference;
      expect(reference).toContain("NIST SP 800-53 Rev 5");
      expect(reference).toContain("FedRAMP Moderate");
    }
  });

  it("fedramp sets strict thresholds for all active controls", () => {
    const profile = loadOverlayProfiles().get("fedramp")!;
    const adjustments = profile.control_adjustments as Record<string, Record<string, string>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      expect(adjustments[controlId].threshold_adjustment).toBe("strict");
    }
  });

  it("fedramp evidence fields do not overlap with cmmc-l2", () => {
    const profiles = loadOverlayProfiles();
    const fedrampFields = new Set<string>();
    const cmmcFields = new Set<string>();
    for (const fields of Object.values(
      (profiles.get("fedramp")!.evidence_requirements as Record<string, string[]>),
    )) {
      fields.forEach(f => fedrampFields.add(f));
    }
    for (const fields of Object.values(
      (profiles.get("cmmc-l2")!.evidence_requirements as Record<string, string[]>),
    )) {
      fields.forEach(f => cmmcFields.add(f));
    }
    const overlap = [...fedrampFields].filter(f => cmmcFields.has(f));
    expect(overlap).toHaveLength(0);
  });

  it("fedramp breach notification is 1 hour", () => {
    const profile = loadOverlayProfiles().get("fedramp")!;
    const obligations = profile.reporting_obligations as Record<string, unknown>;
    expect(obligations.breach_notification_hours).toBe(1);
  });

  it("fedramp evidence retention minimum is 1095 days", () => {
    const profile = loadOverlayProfiles().get("fedramp")!;
    expect(profile.evidence_retention_minimum_days).toBe(1095);
  });
});

describe("FedRAMP — Taxonomy", () => {
  it("DC-FCI taxonomy entry is active and linked to fedramp", () => {
    const taxonomy = loadTaxonomy();
    const classifications = taxonomy.classifications as Array<Record<string, unknown>>;
    const fci = classifications.find(e => e.code === "DC-FCI")!;
    expect(fci.overlay_status).toBe("active");
    expect((fci.overlays as string[])).toContain("fedramp");
  });

  it("DC-GOV taxonomy entry is active and linked to fedramp", () => {
    const taxonomy = loadTaxonomy();
    const classifications = taxonomy.classifications as Array<Record<string, unknown>>;
    const gov = classifications.find(e => e.code === "DC-GOV")!;
    expect(gov.overlay_status).toBe("active");
    expect((gov.overlays as string[])).toContain("fedramp");
  });
});

describe("FedRAMP — Resolver", () => {
  it("federal_contract activates fedramp with DC-FCI and strict controls", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["federal_contract"] });
    expect(spec.activeOverlays).toContain("fedramp");
    expect(spec.dataClassifications).toContain("DC-FCI");
    expect(spec.controlThresholds["PR-01"]).toBe("strict");
    expect(spec.controlThresholds["PR-05"]).toBe("strict");
    expect((spec.evidenceRequirements["PR-01"] ?? []).length).toBeGreaterThan(0);
  });

  it("fedramp_system activates fedramp via DC-FCI", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["fedramp_system"] });
    expect(spec.dataClassifications).toContain("DC-FCI");
    expect(spec.activeOverlays).toContain("fedramp");
  });

  it("government_system activates fedramp via DC-GOV", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["government_system"] });
    expect(spec.dataClassifications).toContain("DC-GOV");
    expect(spec.activeOverlays).toContain("fedramp");
  });

  it("government_system activates both fedramp and cmmc-l2", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["government_system"] });
    expect(spec.activeOverlays).toContain("fedramp");
    expect(spec.activeOverlays).toContain("cmmc-l2");
  });
});

describe("FedRAMP — Config", () => {
  it("federal_contract config activates fedramp and is not in unavailable", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "fedramp-agent" }, my_agent_handles: ["federal_contract"] },
    });
    expect(resolved.activeOverlays.has("fedramp")).toBe(true);
    expect(resolved.unavailableOverlays.some(u => u.overlayId === "fedramp")).toBe(false);
  });

  it("federal_contract config sets retention to at least 1095 days", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "fedramp-agent" }, my_agent_handles: ["federal_contract"] },
    });
    expect(resolved.evidenceRetentionDays).toBeGreaterThanOrEqual(1095);
  });
});

describe("FedRAMP — Validate", () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("config validate surfaces FedRAMP overlay name", () => {
    const path = writeConfig(dir, {
      agent: { name: "fedramp-agent" },
      my_agent_handles: ["federal_contract"],
    });
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(true);
    expect(message).toContain("FedRAMP");
  });
});

describe("FedRAMP — Report", () => {
  it("report includes fedramp compliance section", () => {
    const config = loadConfig({
      raw: { agent: { name: "fedramp-agent" }, my_agent_handles: ["federal_contract"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    expect(
      report.complianceSections.some(s => s.overlayId === "fedramp"),
    ).toBe(true);
  });

  it("terminal output includes FedRAMP overlay name", () => {
    const config = loadConfig({
      raw: { agent: { name: "fedramp-agent" }, my_agent_handles: ["federal_contract"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    const output = renderTerminal(report);
    expect(output).toContain("FedRAMP");
  });
});

// ===== GLBA / Financial Services Overlay =====

describe("GLBA Financial — Profile", () => {
  it("glba profile loads", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.has("glba")).toBe(true);
  });

  it("glba metadata matches financial activation", () => {
    const profile = loadOverlayProfiles().get("glba")!;
    expect(profile.trigger_type).toBe("data_classification");
    expect((profile.triggered_by as string[])).toContain("DC-FIN");
    expect((profile.applicable_data_types as string[])).toContain("financial_data");
    expect((profile.applicable_data_types as string[])).toContain("financial_records");
  });

  it("glba framework mapping covers all AKSI controls", () => {
    const profile = loadOverlayProfiles().get("glba")!;
    const mappingKeys = new Set(Object.keys(profile.framework_mapping as Record<string, unknown>));
    for (const ctrl of COMMON_AKSI_CONTROLS) {
      expect(mappingKeys.has(ctrl)).toBe(true);
    }
  });

  it("glba active controls reference GLBA, SOX, and DORA", () => {
    const profile = loadOverlayProfiles().get("glba")!;
    const controls = profile.controls as Record<string, Record<string, string>>;
    for (const controlId of ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]) {
      const reference = controls[controlId].framework_reference;
      expect(reference).toContain("314.4");
      expect(reference).toContain("SOX");
      expect(reference).toContain("DORA");
    }
  });

  it("glba sets strict thresholds for financial high-risk controls", () => {
    const profile = loadOverlayProfiles().get("glba")!;
    const adjustments = profile.control_adjustments as Record<string, Record<string, string>>;
    for (const controlId of ["PR-01", "PR-02", "PR-04", "PR-05", "DE-01"]) {
      expect(adjustments[controlId].threshold_adjustment).toBe("strict");
    }
  });

  it("glba evidence retention minimum is 2555 days", () => {
    const profile = loadOverlayProfiles().get("glba")!;
    expect(profile.evidence_retention_minimum_days).toBe(2555);
  });
});

describe("GLBA Financial — Taxonomy", () => {
  it("DC-FIN taxonomy entry is active and linked to glba", () => {
    const taxonomy = loadTaxonomy();
    const classifications = taxonomy.classifications as Array<Record<string, unknown>>;
    const fin = classifications.find(e => e.code === "DC-FIN")!;
    expect(fin.overlay_status).toBe("active");
    expect((fin.overlays as string[])).toContain("glba");
  });
});

describe("GLBA Financial — Resolver", () => {
  it("financial_data activates glba and soc2 with strict controls", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["financial_data"] });
    expect(spec.activeOverlays).toContain("glba");
    expect(spec.activeOverlays).toContain("soc2");
    expect(spec.dataClassifications).toContain("DC-FIN");
    expect(spec.controlThresholds["PR-01"]).toBe("strict");
    expect(spec.controlThresholds["PR-05"]).toBe("strict");
  });

  it("financial_records activates glba via DC-FIN", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["financial_records"] });
    expect(spec.dataClassifications).toContain("DC-FIN");
    expect(spec.activeOverlays).toContain("glba");
  });
});

describe("GLBA Financial — Config", () => {
  it("financial_data config activates glba and is not in unavailable", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "fin-agent" }, my_agent_handles: ["financial_data"] },
    });
    expect(resolved.activeOverlays.has("glba")).toBe(true);
    expect(resolved.unavailableOverlays.some(u => u.overlayId === "glba")).toBe(false);
  });

  it("financial_data config sets retention to 2555 days", () => {
    const resolved = loadConfig({
      raw: { agent: { name: "fin-agent" }, my_agent_handles: ["financial_data"] },
    });
    expect(resolved.evidenceRetentionDays).toBe(2555);
  });
});

describe("GLBA Financial — Validate", () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("config validate surfaces Financial Services overlay name", () => {
    const path = writeConfig(dir, {
      agent: { name: "fin-agent" },
      my_agent_handles: ["financial_data"],
    });
    const { valid, message } = validateAndFormat(path);
    expect(valid).toBe(true);
    expect(message).toContain("Financial Services");
  });
});

describe("GLBA Financial — Report", () => {
  it("report includes glba compliance section", () => {
    const config = loadConfig({
      raw: { agent: { name: "fin-agent" }, my_agent_handles: ["financial_data"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    expect(
      report.complianceSections.some(s => s.overlayId === "glba"),
    ).toBe(true);
  });

  it("terminal output includes Financial Services overlay name", () => {
    const config = loadConfig({
      raw: { agent: { name: "fin-agent" }, my_agent_handles: ["financial_data"] },
    });
    const report = new ReportGenerator(config, populatedSummary()).generate();
    const output = renderTerminal(report);
    expect(output).toContain("Financial Services");
  });
});
