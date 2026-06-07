import { convertToSarif } from "../src/sarif";
import type { ScanResult } from "../src/scanner";
import scanFixture from "./fixtures/scan-output.json";

const scan = scanFixture as unknown as ScanResult;

describe("convertToSarif", () => {
  let sarif: ReturnType<typeof convertToSarif>;

  beforeEach(() => {
    sarif = convertToSarif(scan);
  });

  it("produces SARIF 2.1.0", () => {
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
  });

  it("has exactly one run", () => {
    expect(sarif.runs).toHaveLength(1);
  });

  it("tool driver is Ancilis", () => {
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe("Ancilis");
    expect(driver.informationUri).toBe("https://ancilis.ai");
  });

  it("has one rule per control", () => {
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(scan.controls.length);
  });

  it("rule ids match control ids", () => {
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
    const controlIds = scan.controls.map((c) => c.id);
    expect(ruleIds).toEqual(controlIds);
  });

  it("has one result per control", () => {
    expect(sarif.runs[0].results).toHaveLength(scan.controls.length);
  });

  it("failing controls have level=error", () => {
    const failingControl = scan.controls.find((c) => c.status === "fail");
    expect(failingControl).toBeDefined();
    const result = sarif.runs[0].results.find((r) => r.ruleId === failingControl!.id);
    expect(result?.level).toBe("error");
    expect(result?.kind).toBeUndefined();
  });

  it("passing controls have level=note and kind=pass", () => {
    const passingControl = scan.controls.find((c) => c.status === "pass");
    expect(passingControl).toBeDefined();
    const result = sarif.runs[0].results.find((r) => r.ruleId === passingControl!.id);
    expect(result?.level).toBe("note");
    expect(result?.kind).toBe("pass");
  });

  it("skipped controls have kind=notApplicable", () => {
    const skippedControl = scan.controls.find((c) => c.status === "skip");
    expect(skippedControl).toBeDefined();
    const result = sarif.runs[0].results.find((r) => r.ruleId === skippedControl!.id);
    expect(result?.kind).toBe("notApplicable");
  });

  it("invocation reflects posture", () => {
    const invocation = sarif.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(scan.posture === "compliant");
  });

  it("all results have at least one location", () => {
    for (const result of sarif.runs[0].results) {
      expect(result.locations.length).toBeGreaterThan(0);
    }
  });

  it("handles empty controls array", () => {
    const emptyScan: ScanResult = { ...scan, controls: [], summary: { ...scan.summary, total_controls: 0 } };
    const emptySarif = convertToSarif(emptyScan);
    expect(emptySarif.runs[0].tool.driver.rules).toHaveLength(0);
    expect(emptySarif.runs[0].results).toHaveLength(0);
  });
});
