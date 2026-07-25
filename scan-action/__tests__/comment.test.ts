import { formatComment } from "../src/comment";
import type { ScanResult } from "../src/scanner";
import scanFixture from "./fixtures/scan-output.json";

const scan = scanFixture as unknown as ScanResult;

const compliantScan: ScanResult = {
  ...scan,
  controls: scan.controls.map((c) => ({
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

const emptyControlsScan: ScanResult = {
  ...scan,
  controls: [],
  summary: { total_controls: 0, passing: 0, failing: 0, skipped: 0, total_evaluations: 0 },
  posture: "compliant",
  exit_code: 0,
};

describe("formatComment", () => {
  it("includes ancilis-scan marker", () => {
    expect(formatComment(scan)).toContain("<!-- ancilis-scan -->");
  });

  it("shows non-compliant for failing scan", () => {
    const comment = formatComment(scan);
    expect(comment).toContain("Non-Compliant");
    expect(comment).toContain("❌");
  });

  it("shows compliant for passing scan", () => {
    const comment = formatComment(compliantScan);
    expect(comment).toContain("Compliant");
    expect(comment).toContain("✅");
  });

  it("includes all control ids", () => {
    const comment = formatComment(scan);
    for (const control of scan.controls) {
      expect(comment).toContain(control.id);
    }
  });

  it("shows pass emoji for passing controls", () => {
    const comment = formatComment(compliantScan);
    expect(comment).toContain("✅ pass");
  });

  it("shows fail emoji for failing controls", () => {
    const comment = formatComment(scan);
    expect(comment).toContain("❌ fail");
  });

  it("shows skip emoji for skipped controls", () => {
    const comment = formatComment(scan);
    expect(comment).toContain("⏭️ skip");
  });

  it("shows flag count in failures column when present", () => {
    const comment = formatComment(scan);
    // PR-02 has 2 flags
    expect(comment).toContain("2 flags");
  });

  it("shows summary line with mode", () => {
    const comment = formatComment(scan);
    expect(comment).toContain("Mode: audit");
    expect(comment).toContain("51 evaluations");
  });

  it("handles 0 controls gracefully", () => {
    const comment = formatComment(emptyControlsScan);
    expect(comment).toContain("No controls configured");
    expect(comment).toContain("<!-- ancilis-scan -->");
  });

  it("includes help collapsible section", () => {
    const comment = formatComment(scan);
    expect(comment).toContain("<details>");
    expect(comment).toContain("ancilis.ai");
  });

  it("includes skipped count in summary when non-zero", () => {
    const comment = formatComment(scan);
    expect(comment).toContain("1 skipped");
  });

  it("does not include skipped count when zero", () => {
    const comment = formatComment(compliantScan);
    expect(comment).not.toContain("skipped");
  });
});

describe("formatComment — pending controls", () => {
  const pendingScan: ScanResult = {
    ...compliantScan,
    controls: compliantScan.controls.map((c, i) =>
      i === 0 ? { ...c, status: "pending" as const, evaluations: 3 } : c
    ),
    summary: { total_controls: 6, passing: 5, failing: 0, skipped: 0, pending: 1, total_evaluations: 30 },
  };

  it("renders pending controls with a pending marker, not a pass", () => {
    const comment = formatComment(pendingScan);
    expect(comment).toContain("⏳ pending");
    expect(comment).toContain("5/6 controls passing");
  });

  it("summary line reports the pending count", () => {
    const comment = formatComment(pendingScan);
    expect(comment).toContain("1 pending");
  });

  it("falls back to counting pending statuses when summary lacks the field", () => {
    const legacy: ScanResult = {
      ...pendingScan,
      summary: { total_controls: 6, passing: 5, failing: 0, skipped: 0, total_evaluations: 30 },
    };
    expect(formatComment(legacy)).toContain("1 pending");
  });
});
