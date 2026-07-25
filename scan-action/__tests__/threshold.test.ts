import { applyThreshold } from "../src/threshold";
import type { ScanResult } from "../src/scanner";
import scanFixture from "./fixtures/scan-output.json";

const baseScan = scanFixture as unknown as ScanResult;

// Fully compliant scan (all pass, no flags)
const compliantScan: ScanResult = {
  ...baseScan,
  controls: baseScan.controls.map((c) => ({
    ...c,
    status: "pass" as const,
    failures: 0,
    flags: 0,
    evaluations: 5,
  })),
  summary: { total_controls: 6, passing: 6, failing: 0, skipped: 0, total_evaluations: 30 },
  posture: "compliant",
  exit_code: 0,
};

// Scan with only flags (no failures)
const flaggedScan: ScanResult = {
  ...compliantScan,
  controls: compliantScan.controls.map((c, i) =>
    i === 0 ? { ...c, flags: 1 } : c
  ),
};

// Scan with one skip (non-pass but not fail)
const skippedScan: ScanResult = {
  ...compliantScan,
  controls: compliantScan.controls.map((c, i) =>
    i === 0 ? { ...c, status: "skip" as const, evaluations: 0 } : c
  ),
  summary: { total_controls: 6, passing: 5, failing: 0, skipped: 1, total_evaluations: 25 },
};

describe("applyThreshold", () => {
  describe("fail-on: none", () => {
    it("never fails", () => {
      expect(applyThreshold(baseScan, "none").shouldFail).toBe(false);
      expect(applyThreshold(compliantScan, "none").shouldFail).toBe(false);
    });
  });

  describe("fail-on: low", () => {
    it("fails when any control is not passing (fail)", () => {
      expect(applyThreshold(baseScan, "low").shouldFail).toBe(true);
    });

    it("fails when any control is skipped", () => {
      expect(applyThreshold(skippedScan, "low").shouldFail).toBe(true);
    });

    it("does not fail when all controls pass", () => {
      expect(applyThreshold(compliantScan, "low").shouldFail).toBe(false);
    });
  });

  describe("fail-on: medium", () => {
    it("fails when controls are failing", () => {
      expect(applyThreshold(baseScan, "medium").shouldFail).toBe(true);
    });

    it("fails when controls have flags", () => {
      expect(applyThreshold(flaggedScan, "medium").shouldFail).toBe(true);
    });

    it("does not fail on skip alone", () => {
      expect(applyThreshold(skippedScan, "medium").shouldFail).toBe(false);
    });

    it("does not fail when all pass with no flags", () => {
      expect(applyThreshold(compliantScan, "medium").shouldFail).toBe(false);
    });
  });

  describe("fail-on: high", () => {
    it("fails when controls are failing", () => {
      expect(applyThreshold(baseScan, "high").shouldFail).toBe(true);
    });

    it("does not fail on flags only", () => {
      expect(applyThreshold(flaggedScan, "high").shouldFail).toBe(false);
    });

    it("does not fail on skip alone", () => {
      expect(applyThreshold(skippedScan, "high").shouldFail).toBe(false);
    });

    it("does not fail when all pass", () => {
      expect(applyThreshold(compliantScan, "high").shouldFail).toBe(false);
    });
  });

  describe("fail-on: critical", () => {
    it("does not fail for audit-mode failures (no block decisions)", () => {
      // baseScan has failures but exit_code=1 from non_compliant, not from BLOCK
      // With no block decisions specifically, critical threshold holds
      const result = applyThreshold(baseScan, "critical");
      // baseScan has failures=3 in PR-03, which are audit failures (not enforced blocks)
      // The threshold passes since critical only triggers on BLOCK decisions in enforce mode
      expect(result.shouldFail).toBe(false);
    });

    it("does not fail when scan is compliant", () => {
      expect(applyThreshold(compliantScan, "critical").shouldFail).toBe(false);
    });
  });

  describe("reason messages", () => {
    it("includes reason for none", () => {
      const { reason } = applyThreshold(baseScan, "none");
      expect(reason).toContain("none");
    });

    it("includes reason for failing check", () => {
      const { reason } = applyThreshold(baseScan, "high");
      expect(reason).toContain("fail");
    });
  });
});

// Scan with one pending control (SKIP-only evidence — not passing)
const pendingScan: ScanResult = {
  ...compliantScan,
  controls: compliantScan.controls.map((c, i) =>
    i === 0 ? { ...c, status: "pending" as const, evaluations: 3 } : c
  ),
  summary: { total_controls: 6, passing: 5, failing: 0, skipped: 0, pending: 1, total_evaluations: 30 },
};

describe("applyThreshold — pending controls", () => {
  it("low threshold fails when a control is pending (not counted as passing)", () => {
    const result = applyThreshold(pendingScan, "low");
    expect(result.shouldFail).toBe(true);
    expect(result.reason).toContain("not passing");
  });

  it("high threshold does not treat pending as a failure", () => {
    expect(applyThreshold(pendingScan, "high").shouldFail).toBe(false);
  });

  it("medium threshold does not treat pending as a failure or flag", () => {
    expect(applyThreshold(pendingScan, "medium").shouldFail).toBe(false);
  });
});
