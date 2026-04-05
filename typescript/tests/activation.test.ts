/**
 * Tests for ancilis activation — Unit 5: Overlay Activation & Remaining Controls.
 */

import { describe, it, expect } from "vitest";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import {
  ActivationResolver,
  BASELINE_CONTROLS,
  EXTENDED_CONTROLS,
  ClassificationAdvisory,
} from "../src/ancilis/activation/index.js";
import {
  loadCertificationProfile,
  loadOverlayProfiles,
  loadControlDefinitions,
} from "../src/ancilis/activation/loader.js";
import { PR05AuditEvaluator } from "../src/ancilis/controls/pr05Audit.js";
import { DE01BaselineEvaluator } from "../src/ancilis/controls/de01Baseline.js";
import type { BaselineWindow } from "../src/ancilis/controls/de01Baseline.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { ToolRegistry } from "../src/ancilis/engine/registry.js";
import type { Action } from "../src/ancilis/engine/action.js";

function makeConfig(overrides: Record<string, unknown> = {}): ResolvedConfig {
  return loadConfig({ raw: { agent: { name: "test-agent" }, ...overrides } });
}

function makeAction(overrides: Partial<Action> = {}): Action {
  return {
    actionId: "act-001",
    timestamp: "2025-01-15T10:30:00Z",
    agentId: "test-agent",
    actionType: "tool_call",
    tool: { name: "my-tool" },
    parameters: { raw: {}, parameterHash: "" },
    context: { dataClassifications: [], activeOverlays: [] },
    ...overrides,
  };
}

// --- Activation Resolver: Path 1 ---

describe("Path 1 — Data Classification", () => {
  it("health_records activates HIPAA", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records"] });
    expect(spec.activeOverlays).toContain("hipaa");
    expect(spec.dataClassifications).toContain("DC-PHI");
  });

  it("health_records PR-04 strict", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records"] });
    expect(spec.controlThresholds["PR-04"]).toBe("strict");
  });

  it("personal_info activates GDPR", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["personal_info"] });
    expect(spec.activeOverlays).toContain("gdpr");
    expect(spec.dataClassifications).toContain("DC-PII");
  });

  it("both data types both overlays", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records", "personal_info"] });
    expect(spec.activeOverlays).toContain("hipaa");
    expect(spec.activeOverlays).toContain("gdpr");
  });

  it("no data handling keeps baseline overlay and full control set", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve();
    expect(spec.activeOverlays).toEqual(["nist-csf"]);
    expect(spec.activeControls.length).toBe(26);
    expect(spec.dataClassifications).toEqual([]);
  });
});

// --- Activation Resolver: Path 2 ---

describe("Path 2 — Certification Intent", () => {
  it("aiuc-1 all controls active", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ certificationTargets: ["aiuc-1"] });
    expect(spec.activeControls).toContain("PR-01");
    expect(spec.activeControls).toContain("PR-05");
    expect(spec.activeControls).toContain("DE-01");
    expect(spec.activeCertifications).toContain("aiuc-1");
  });

  it("aiuc-1 activation source", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ certificationTargets: ["aiuc-1"] });
    expect(spec.activationSource["PR-05"]).toContain("certification_targets:aiuc-1");
  });

  it("unknown certification skipped", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ certificationTargets: ["unknown-cert"] });
    expect(spec.activeCertifications).not.toContain("unknown-cert");
  });

  it("certification profile version required", () => {
    const profile = loadCertificationProfile("aiuc-1");
    expect(profile).not.toBeNull();
    expect(profile!.version).toBeDefined();
  });
});

// --- Both Paths Composing ---

describe("Both Paths Composing", () => {
  it("both declared", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({
      dataHandling: ["health_records"],
      certificationTargets: ["aiuc-1"],
    });
    expect(spec.activeOverlays).toContain("hipaa");
    expect(spec.activeCertifications).toContain("aiuc-1");
    expect(spec.activeControls.length).toBe(26);
  });

  it("conflict strictest wins", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({
      dataHandling: ["health_records"],
      certificationTargets: ["aiuc-1"],
    });
    expect(spec.controlThresholds["PR-04"]).toBe("strict");
  });

  it("activation source correct", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({
      dataHandling: ["health_records"],
      certificationTargets: ["aiuc-1"],
    });
    expect(spec.activationSource["hipaa"]).toContain("my_agent_handles:health_records");
  });
});

// --- Baseline Controls ---

describe("Baseline Controls", () => {
  it("empty config baseline active", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve();
    for (const cid of BASELINE_CONTROLS) {
      expect(spec.activeControls).toContain(cid);
    }
  });

  it("empty config no extended", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve();
    for (const cid of EXTENDED_CONTROLS) {
      expect(spec.activeControls).not.toContain(cid);
    }
  });

  it("overlay activates extended", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records"] });
    expect(spec.activeControls).toContain("PR-05");
    expect(spec.activeControls).toContain("DE-01");
  });
});

// --- Overlay Profiles ---

describe("Overlay Profiles", () => {
  it("HIPAA loads", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.has("hipaa")).toBe(true);
    expect(profiles.get("hipaa")!.evidence_retention_minimum_days).toBe(2190);
  });

  it("SOC2 framework mappings", () => {
    const profiles = loadOverlayProfiles();
    const soc2 = profiles.get("soc2")!;
    const fm = soc2.framework_mapping as Record<string, string[]>;
    expect(fm["PR-01"]).toBeDefined();
    expect(fm["PR-05"]).toBeDefined();
    expect(fm["DE-01"]).toBeDefined();
  });

  it("EU AI Act human oversight", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.get("eu-ai-act")!.human_oversight_required).toBe(true);
  });

  it("retention days", () => {
    const profiles = loadOverlayProfiles();
    expect(profiles.get("hipaa")!.evidence_retention_minimum_days).toBe(2190);
    expect(profiles.get("eu-ai-act")!.evidence_retention_minimum_days).toBe(3650);
    expect(profiles.get("soc2")!.evidence_retention_minimum_days).toBe(365);
    expect(profiles.get("gdpr")!.evidence_retention_minimum_days).toBe(365);
  });
});

// --- Certification Profile ---

describe("Certification Profile", () => {
  it("aiuc-1 loads", () => {
    const profile = loadCertificationProfile("aiuc-1");
    expect(profile).not.toBeNull();
    expect(profile!.id).toBe("aiuc-1");
  });

  it("aiuc-1 required controls", () => {
    const profile = loadCertificationProfile("aiuc-1")!;
    const required = new Set(profile.required_aksi_controls as string[]);
    expect(required).toEqual(new Set(["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"]));
  });

  it("aiuc-1 requirement map", () => {
    const profile = loadCertificationProfile("aiuc-1")!;
    const reqMap = profile.aksi_to_requirement_map as Record<string, string[]>;
    expect(reqMap["PR-01"]).toContain("B001");
  });

  it("aiuc-1 operator actions", () => {
    const profile = loadCertificationProfile("aiuc-1")!;
    expect((profile.operator_action_required as unknown[]).length).toBe(3);
  });

  it("aiuc-1 quarterly summary", () => {
    const profile = loadCertificationProfile("aiuc-1")!;
    expect((profile.evidence_packaging as Record<string, unknown>).quarterly_summary).toBe(true);
  });
});

// --- PR-05 Evaluator ---

describe("PR-05 Evaluator", () => {
  it("logging enabled pass", () => {
    const config = makeConfig();
    const evaluator = new PR05AuditEvaluator();
    const action = makeAction();
    const result = evaluator.evaluate(action, config);
    expect(result.result).toBe("PASS");
    expect(result.evidenceData.logging_enabled).toBe(true);
    expect(result.evidenceData.log_format).toBe("json");
  });

  it("logging disabled fail", () => {
    const config = makeConfig();
    config.evidenceRetentionDays = 0;
    const evaluator = new PR05AuditEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("FAIL");
  });

  it("evidence no raw logs", () => {
    const config = makeConfig();
    const evaluator = new PR05AuditEvaluator();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.evidenceData.log_format).toBeDefined();
    expect(result.evidenceData.sample_entry_field_count).toBeDefined();
  });
});

// --- DE-01 Evaluator ---

describe("DE-01 Evaluator", () => {
  it("empty baseline pass", () => {
    const evaluator = new DE01BaselineEvaluator();
    const config = makeConfig();
    const result = evaluator.evaluate(makeAction(), config);
    expect(result.result).toBe("PASS");
    expect(result.detail.toLowerCase()).toContain("baseline not yet established");
  });

  it("normal behavior pass", () => {
    const baseline: BaselineWindow = { toolCalls: ["tool-a", "tool-b", "tool-a"], callCount: 3, windowMinutes: 5 };
    const evaluator = new DE01BaselineEvaluator(baseline);
    const result = evaluator.evaluate(makeAction({ tool: { name: "tool-a" } }), makeConfig());
    expect(result.result).toBe("PASS");
  });

  it("new tool flag", () => {
    const baseline: BaselineWindow = { toolCalls: ["tool-a", "tool-b"], callCount: 10, windowMinutes: 5 };
    const evaluator = new DE01BaselineEvaluator(baseline);
    const result = evaluator.evaluate(makeAction({ tool: { name: "unknown-tool" } }), makeConfig());
    expect(result.result).toBe("FLAG");
    expect(result.evidenceData.new_tools_detected).toContain("unknown-tool");
  });

  it("frequency spike flag", () => {
    const baseline: BaselineWindow = { toolCalls: Array(10).fill("tool-a"), callCount: 10, windowMinutes: 10 };
    const evaluator = new DE01BaselineEvaluator(baseline);
    const result = evaluator.evaluateWithRate(makeAction({ tool: { name: "tool-a" } }), makeConfig(), 5.0);
    expect(result.result).toBe("FLAG");
    const flags = result.evidenceData.deviation_flags as Array<{ type: string }>;
    expect(flags.some(f => f.type === "frequency_spike")).toBe(true);
  });

  it("DE-01 never blocks", () => {
    const baseline: BaselineWindow = { toolCalls: ["tool-a"], callCount: 5, windowMinutes: 5 };
    const evaluator = new DE01BaselineEvaluator(baseline);
    const result = evaluator.evaluate(makeAction({ tool: { name: "suspicious-tool" } }), makeConfig());
    expect(["PASS", "FLAG"]).toContain(result.result);
    expect(result.result).not.toBe("BLOCK");
  });

  it("deviation flags are objects", () => {
    const baseline: BaselineWindow = { toolCalls: ["tool-a"], callCount: 5, windowMinutes: 5 };
    const evaluator = new DE01BaselineEvaluator(baseline);
    const result = evaluator.evaluate(makeAction({ tool: { name: "new-tool" } }), makeConfig());
    const flags = result.evidenceData.deviation_flags as Array<Record<string, unknown>>;
    for (const flag of flags) {
      expect(flag.type).toBeDefined();
      expect(flag.displayMessage).toBeDefined();
      expect(flag.severity).toBeDefined();
    }
  });
});

// --- Pattern Detection Advisory ---

describe("Pattern Advisory", () => {
  it("SSN recommends personal_info", () => {
    const advisor = new ClassificationAdvisory();
    const { recommendations } = advisor.generate([{ patternType: "ssn", count: 5 }]);
    expect(recommendations.length).toBeGreaterThanOrEqual(1);
    expect(recommendations[0]!.suggestedValue).toBe("personal_info");
  });

  it("credit card recommends credit_cards", () => {
    const advisor = new ClassificationAdvisory();
    const { recommendations } = advisor.generate([{ patternType: "credit_card", count: 3 }]);
    expect(recommendations.some(r => r.suggestedValue === "credit_cards")).toBe(true);
  });

  it("already covered no duplicate", () => {
    const advisor = new ClassificationAdvisory();
    const { recommendations } = advisor.generate(
      [{ patternType: "ssn", count: 5 }],
      { activeDataHandling: ["personal_info"] },
    );
    expect(recommendations.length).toBe(0);
  });

  it("certification upgrade advisory", () => {
    const advisor = new ClassificationAdvisory();
    const { upgradeAdvisories } = advisor.generate(
      [{ patternType: "mrn", count: 10 }],
      { activeCertifications: ["aiuc-1"] },
    );
    expect(upgradeAdvisories.length).toBeGreaterThanOrEqual(1);
    expect(upgradeAdvisories[0]!.certificationId).toBe("aiuc-1");
    expect(upgradeAdvisories[0]!.severity).toBe("info");
  });

  it("advisory has example config", () => {
    const advisor = new ClassificationAdvisory();
    const { recommendations } = advisor.generate([{ patternType: "ssn", count: 5 }]);
    expect(recommendations[0]!.exampleConfig).toContain("my_agent_handles:");
  });

  it("recommendation has severity", () => {
    const advisor = new ClassificationAdvisory();
    const { recommendations } = advisor.generate([{ patternType: "ssn", count: 5 }]);
    expect(["info", "warning", "alert"]).toContain(recommendations[0]!.severity);
  });

  it("SSN severity alert", () => {
    const advisor = new ClassificationAdvisory();
    const { recommendations } = advisor.generate([{ patternType: "ssn", count: 5 }]);
    expect(recommendations[0]!.severity).toBe("alert");
  });
});

// --- Conflict Resolution ---

describe("Conflict Resolution", () => {
  it("HIPAA+GDPR PR-04 strict", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records", "personal_info"] });
    expect(spec.controlThresholds["PR-04"]).toBe("strict");
  });

  it("HIPAA+SOC2 retention longest", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records"] });
    expect(spec.evidenceRetentionDays).toBeGreaterThanOrEqual(2190);
  });

  it("evidence requirements union", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records"] });
    expect((spec.evidenceRequirements["PR-04"] ?? []).length).toBeGreaterThan(0);
  });

  it("certification still works with baseline controls", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ certificationTargets: ["aiuc-1"] });
    expect(spec.activeCertifications).toContain("aiuc-1");
    expect(spec.activeControls.length).toBe(26);
  });

  it("combined certification and data keeps nist-csf baseline active", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({
      certificationTargets: ["aiuc-1"],
      dataHandling: ["credit_cards"],
    });
    expect(spec.activeCertifications).toContain("aiuc-1");
    expect(spec.activeOverlays).toContain("pci-dss-v4");
    expect(spec.activeOverlays).toContain("nist-csf");
  });

  it("controlled_unclassified activates cmmc-l2 without dropping baseline coverage", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["controlled_unclassified"] });
    expect(spec.dataClassifications).toContain("DC-CUI");
    expect(spec.activeOverlays).toContain("cmmc-l2");
    expect(spec.activeOverlays).toContain("nist-csf");
    expect(spec.activeControls.length).toBe(26);
  });
});

// --- Engine Integration ---

describe("Engine Integration", () => {
  it("engine has PR-05 and DE-01", () => {
    const config = makeConfig();
    const engine = new Engine(config);
    const action = makeAction();
    const result = engine.evaluate(action);
    const controlIds = result.controlResults.map(cr => cr.controlId);
    expect(controlIds).toContain("PR-05");
    expect(controlIds).toContain("DE-01");
  });
});

// --- Output Disclosure Contract ---

describe("Output Disclosure", () => {
  it("control definitions have display fields", () => {
    const controls = loadControlDefinitions();
    for (const [cid, cdef] of controls) {
      expect(cdef.display_name, `${cid} missing display_name`).toBeDefined();
      expect(cdef.display_detail, `${cid} missing display_detail`).toBeDefined();
      expect(cdef.remediation_hint_template, `${cid} missing remediation_hint_template`).toBeDefined();
      expect(cdef.display_name).not.toBe("");
      expect(cdef.display_detail).not.toBe("");
    }
  });

  it("display name not raw control ID", () => {
    const controls = loadControlDefinitions();
    for (const [cid, cdef] of controls) {
      expect(cdef.display_name).not.toBe(cid);
    }
  });

  it("activation summary populated", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ certificationTargets: ["aiuc-1"] });
    expect(spec.activationSummary.length).toBeGreaterThanOrEqual(1);
    expect(spec.activationSummary.some(s => s.includes("AIUC-1"))).toBe(true);
  });

  it("activation summary overlay", () => {
    const resolver = new ActivationResolver();
    const spec = resolver.resolve({ dataHandling: ["health_records"] });
    expect(spec.activationSummary.length).toBeGreaterThanOrEqual(1);
  });
});

// --- Overlay Data Integrity ---

describe("Overlay Data Integrity", () => {
  it("all overlays have framework_mapping", () => {
    const profiles = loadOverlayProfiles();
    for (const [oid, profile] of profiles) {
      expect(profile.framework_mapping, `${oid} missing framework_mapping`).toBeDefined();
    }
  });

  it("all overlays have evidence_requirements", () => {
    const profiles = loadOverlayProfiles();
    for (const [oid, profile] of profiles) {
      expect(profile.evidence_requirements, `${oid} missing evidence_requirements`).toBeDefined();
    }
  });
});
