/** AKSI v0.6 shared catalog and activation parity tests. */

import { describe, expect, it } from "vitest";
import { loadControlDefinitions, loadTaxonomy } from "../src/ancilis/activation/loader.js";
import { ActivationResolver } from "../src/ancilis/activation/resolver.js";

const V06_COMMON_CONTROLS = new Set([
  "GOV-01",
  "GOV-02",
  "GOV-03",
  "GOV-04",
  "GOV-05",
  "GOV-06",
  "GOV-07",
  "ID-01",
  "ID-02",
  "ID-03",
  "ID-04",
  "ID-05",
  "PR-01",
  "PR-02",
  "PR-03",
  "PR-04",
  "PR-05",
  "PR-06",
  "PR-07",
  "PR-08",
  "PR-09",
  "PR-10",
  "PR-11",
  "PR-12",
  "DE-01",
  "DE-02",
  "DE-03",
  "DE-04",
  "DE-05",
  "DE-06",
  "RS-01",
  "RS-02",
  "RS-03",
  "RS-04",
  "RS-05",
  "RS-06",
  "RC-01",
  "RC-02",
  "RC-03",
]);

const V06_EXTENSION_CONTROLS = new Set(["PAY-01", "PAY-02"]);

const V06_DATA_CLASSES = new Set([
  "DC-PHI",
  "DC-CHD",
  "DC-SAD",
  "DC-CUI",
  "DC-FCI",
  "DC-MNPI",
  "DC-PII",
  "DC-FIN",
  "DC-NPI",
  "DC-GOV",
  "DC-AI",
  "DC-GEN",
  "DC-ITAR",
  "DC-CRIT",
  "DC-MINOR",
  "DC-BIO",
  "DC-LEGAL",
  "DC-IP",
  "DC-PAY",
  "DC-EDU",
  "DC-CJI",
  "DC-EAR",
  "DC-MEDDEV",
]);

function union<T>(left: Set<T>, right: Set<T>): Set<T> {
  return new Set([...left, ...right]);
}

describe("AKSI v0.6 catalog", () => {
  it("contains the exact v0.6 control set", () => {
    const controls = loadControlDefinitions();

    expect(new Set(controls.keys())).toEqual(union(V06_COMMON_CONTROLS, V06_EXTENSION_CONTROLS));
    expect(controls.size).toBe(41);
  });

  it("marks common and extension controls", () => {
    const controls = loadControlDefinitions();
    const commonIds = new Set<string>();
    const extensionIds = new Set<string>();

    for (const [controlId, control] of controls) {
      if (control.common === true) commonIds.add(controlId);
      if (control.common === false) extensionIds.add(controlId);
    }

    expect(commonIds).toEqual(V06_COMMON_CONTROLS);
    expect(extensionIds).toEqual(V06_EXTENSION_CONTROLS);
    expect(controls.get("PAY-01")?.trigger_classifications).toEqual(["DC-PAY"]);
    expect(controls.get("PAY-02")?.trigger_certification_targets).toEqual(["AGENT_PAYMENTS", "X402"]);
  });

  it("defaults to common controls only", () => {
    const spec = new ActivationResolver().resolve();

    expect(new Set(spec.activeControls)).toEqual(V06_COMMON_CONTROLS);
    expect(spec.activeControls).not.toContain("PAY-01");
    expect(spec.activeControls).not.toContain("PAY-02");
  });

  it("activates payment controls for payment classification", () => {
    const spec = new ActivationResolver().resolve({ dataHandling: ["agent_payments"] });

    expect(new Set(spec.activeControls)).toEqual(union(V06_COMMON_CONTROLS, V06_EXTENSION_CONTROLS));
    expect(spec.dataClassifications).toContain("DC-PAY");
    expect(spec.activationSource["PAY-01"]).toBe("classification:DC-PAY");
    expect(spec.activationSource["PAY-02"]).toBe("classification:DC-PAY");
  });

  it("activates payment controls for payment certification target", () => {
    const spec = new ActivationResolver().resolve({ certificationTargets: ["X402"] });

    expect(new Set(spec.activeControls)).toEqual(union(V06_COMMON_CONTROLS, V06_EXTENSION_CONTROLS));
    expect(spec.activationSource["PAY-01"]).toBe("certification_targets:X402");
    expect(spec.activationSource["PAY-02"]).toBe("certification_targets:X402");
  });

  it("contains the exact v0.6 data classes", () => {
    const taxonomy = loadTaxonomy() as {
      classifications: Array<{ code: string }>;
      developer_type_mapping: Record<string, string[]>;
    };
    const codes = new Set(taxonomy.classifications.map((entry) => entry.code));

    expect(codes).toEqual(V06_DATA_CLASSES);
    expect(codes.size).toBe(23);
    expect(codes.has("DC-Code-Execution")).toBe(false);
    expect(codes.has("DC-External-API")).toBe(false);
    expect(taxonomy.developer_type_mapping.agent_payments).toEqual(["DC-PAY"]);
  });
});
