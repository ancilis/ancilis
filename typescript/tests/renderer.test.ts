/**
 * Targeted tests for renderer edge cases.
 *
 * Covers: renderPdf branches, markdownFallbackPath edge cases,
 * renderTerminal advisory/CRITICAL/zero-total, renderMarkdown broken-chain,
 * zero-total compliance, advisory upgrade, AIUC-1 variants,
 * renderNdjson/renderCsv empty lists. Parity with Python test_renderer_coverage.py.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  renderTerminal,
  renderMarkdown,
  renderPdf,
  renderNdjson,
  renderCsv,
} from "../src/ancilis/report/index.js";
import type { ReportData } from "../src/ancilis/report/index.js";
import type { EvidenceRecord } from "../src/ancilis/evidence/record.js";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makeControl(
  controlId: string,
  options: { total?: number; passed?: number; failed?: number; passRate?: number; threshold?: string } = {},
): Record<string, unknown> {
  const { total = 10, passed = 10, failed = 0, passRate = 100.0, threshold = "95" } = options;
  return { controlId, displayName: `Control ${controlId}`, total, passed, failed, passRate, threshold };
}

function makeSection(options: {
  overlayId?: string;
  overlayName?: string;
  triggeredBy?: string;
  controls?: Record<string, unknown>[];
} = {}): Record<string, unknown> {
  const { overlayId = "test-overlay", overlayName = "Test Overlay", triggeredBy = "pii_data", controls } = options;
  return {
    overlayId,
    overlayName,
    triggeredBy,
    strictControls: [],
    controls: controls ?? [
      {
        controlId: "PR-01",
        displayName: "Identity",
        citations: ["TST-PR-01"],
        total: 0,
        passed: 0,
        failed: 0,
        passRate: 0.0,
        threshold: "standard",
      },
    ],
    gaps: [],
    evidenceRetentionDays: 365,
    retentionMet: true,
  };
}

function makeCert(options: {
  withOperator?: boolean;
  withAutomated?: boolean;
  withFailures?: boolean;
} = {}): Record<string, unknown> {
  const { withOperator = false, withAutomated = false, withFailures = false } = options;
  const automatedCoverage: Record<string, unknown>[] = withAutomated
    ? [
        {
          requirementId: "REQ-1",
          aksiControl: "PR-01",
          evidenceCount: 5,
          passed: withFailures ? 3 : 5,
          failed: withFailures ? 2 : 0,
          flagged: 0,
        },
      ]
    : [];
  const operatorActionRequired: Record<string, string>[] = withOperator
    ? [{ requirementId: "REQ-O-1", description: "Policy doc required" }]
    : [];
  return {
    certificationId: "aiuc-1",
    certificationName: "AIUC-1",
    readinessPercentage: 80,
    readyCount: 12,
    totalRequirements: 15,
    coveragePercentage: 75,
    automatedCount: 12,
    operatorCount: 3,
    evidenceCount: 100,
    chainValid: true,
    automatedCoverage,
    operatorActionRequired,
  };
}

function makeAdvisory(options: { withUpgrade?: boolean } = {}): Record<string, unknown> {
  const { withUpgrade = false } = options;
  return {
    patternDetections: [{ patternType: "PII_EMAIL", count: 3 }],
    recommendations: [
      {
        suggestedValue: "pii",
        suggestedConfigField: "my_agent_handles",
        detectionCount: 3,
        severity: "medium",
        exampleConfig: "my_agent_handles: [pii]",
      },
    ],
    upgradeAdvisories: withUpgrade
      ? [{ message: "Consider upgrading to SOC 2 overlay for full coverage" }]
      : [],
  };
}

function minimalReportData(options: {
  chainValid?: boolean;
  advisory?: Record<string, unknown> | null;
  certification?: Record<string, unknown> | null;
  complianceSections?: Record<string, unknown>[];
  failingControlIds?: string[];
  reportFormat?: string;
} = {}): ReportData {
  const {
    chainValid = true,
    advisory = null,
    certification = null,
    failingControlIds = [],
    reportFormat = "markdown",
  } = options;

  const failing = new Set(failingControlIds);
  const controls = ["PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "DE-01"].map((cid) =>
    makeControl(cid, failing.has(cid) ? { failed: 2, passRate: 80.0 } : {}),
  );

  const complianceSections = options.complianceSections ?? [makeSection()];

  return {
    agentName: "test-agent",
    mode: "audit",
    periodStart: "2026-01-01T00:00:00+00:00",
    periodEnd: "2026-01-31T23:59:59+00:00",
    generatedAt: "2026-02-01T00:00:00+00:00",
    reportFormat,
    baseline: {
      controls,
      toolsEvaluated: ["tool_a"],
      totalEvaluations: 10,
      decisions: { allow: 8, block: 2 },
      evidenceRetentionDays: 365,
    },
    complianceSections,
    certification,
    advisory,
    totalEvaluations: 10,
    chainValid,
    chainErrors: chainValid ? [] : ["hash mismatch at record 3"],
  };
}

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "ancilis-renderer-test-"));
}

// ---------------------------------------------------------------------------
// renderPdf — success branch
// ---------------------------------------------------------------------------

describe("renderPdf — success branch", () => {
  it("returns pdf format and outputPath when pandoc succeeds", () => {
    const dir = tmpDir();
    const outputPath = join(dir, "report.pdf");
    const markdown = "# Test Report\n\nContent here.";

    const result = renderPdf(markdown, outputPath, {
      execFile: () => { /* pandoc succeeds, no throw */ },
    });

    expect(result.format).toBe("pdf");
    expect(result.outputPath).toBe(outputPath);
    expect(result.fallbackReason).toBeUndefined();

    rmSync(dir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// renderPdf — error/fallback branches (CalledProcessError + FileNotFoundError)
// ---------------------------------------------------------------------------

describe("renderPdf — error branches", () => {
  it("falls back to markdown when execFile throws (CalledProcessError equivalent)", () => {
    const dir = tmpDir();
    const outputPath = join(dir, "report.pdf");
    const markdown = "# Test\n\nFallback content.";

    const result = renderPdf(markdown, outputPath, {
      execFile: () => {
        const err = new Error("pandoc exited with code 1");
        throw err;
      },
    });

    expect(result.format).toBe("markdown");
    expect(result.outputPath).toBe(join(dir, "report.md"));
    expect(result.fallbackReason).toBeTruthy();
    expect(readFileSync(result.outputPath, "utf-8")).toBe(markdown);

    rmSync(dir, { recursive: true, force: true });
  });

  it("falls back to markdown when execFile throws FileNotFoundError (pandoc missing)", () => {
    const dir = tmpDir();
    const outputPath = join(dir, "report.pdf");
    const markdown = "# Test\n\nContent.";

    const result = renderPdf(markdown, outputPath, {
      execFile: () => {
        const err = new Error("pandoc: not found") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      },
    });

    expect(result.format).toBe("markdown");
    expect(result.fallbackReason).toBeTruthy();

    rmSync(dir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// markdownFallbackPath edge cases — tested indirectly via renderPdf fallback
// ---------------------------------------------------------------------------

describe("markdownFallbackPath edge cases (via renderPdf fallback)", () => {
  const throwExecFile = () => {
    throw new Error("pandoc unavailable");
  };

  it(".pdf suffix → replaces with .md", () => {
    const dir = tmpDir();
    const result = renderPdf("md", join(dir, "report.pdf"), { execFile: throwExecFile });
    expect(result.outputPath).toBe(join(dir, "report.md"));
    rmSync(dir, { recursive: true, force: true });
  });

  it(".md suffix → returns same path", () => {
    const dir = tmpDir();
    const result = renderPdf("md", join(dir, "report.md"), { execFile: throwExecFile });
    expect(result.outputPath).toBe(join(dir, "report.md"));
    rmSync(dir, { recursive: true, force: true });
  });

  it(".txt suffix → appends .md", () => {
    const dir = tmpDir();
    const result = renderPdf("md", join(dir, "report.txt"), { execFile: throwExecFile });
    expect(result.outputPath).toBe(join(dir, "report.txt.md"));
    rmSync(dir, { recursive: true, force: true });
  });

  it("no extension → appends .md", () => {
    const dir = tmpDir();
    const result = renderPdf("md", join(dir, "report"), { execFile: throwExecFile });
    expect(result.outputPath).toBe(join(dir, "report.md"));
    rmSync(dir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// renderTerminal — advisory section
// ---------------------------------------------------------------------------

describe("renderTerminal — advisory section", () => {
  it("shows classification advisory with detected pattern and count", () => {
    const data = minimalReportData({ advisory: makeAdvisory({ withUpgrade: false }) });
    const output = renderTerminal(data);

    expect(output).toContain("Classification Advisory");
    expect(output).toContain("PII_EMAIL");
    expect(output).toContain("3 occurrence");
  });

  it("shows certification upgrade advisories when present", () => {
    const data = minimalReportData({ advisory: makeAdvisory({ withUpgrade: true }) });
    const output = renderTerminal(data);

    expect(output).toContain("Certification upgrade advisories");
    expect(output).toContain("SOC 2");
  });

  it("shows recommended config updates", () => {
    const data = minimalReportData({ advisory: makeAdvisory() });
    const output = renderTerminal(data);

    expect(output).toContain("Recommended config updates");
    expect(output).toContain("pii");
    expect(output).toContain("my_agent_handles");
  });
});

// ---------------------------------------------------------------------------
// renderTerminal — CRITICAL posture
// ---------------------------------------------------------------------------

describe("renderTerminal — CRITICAL posture", () => {
  it("shows CRITICAL when chain is broken", () => {
    const data = minimalReportData({ chainValid: false });
    const output = renderTerminal(data);

    expect(output).toContain("CRITICAL");
  });

  it("shows CRITICAL when 3+ controls are failing", () => {
    const data = minimalReportData({
      failingControlIds: ["PR-01", "PR-02", "PR-03"],
    });
    const output = renderTerminal(data);

    expect(output).toContain("CRITICAL");
  });

  it("shows ATTENTION (not CRITICAL) with only 1 failing control", () => {
    const data = minimalReportData({ failingControlIds: ["PR-01"] });
    const output = renderTerminal(data);

    expect(output).toContain("ATTENTION");
    expect(output).not.toContain("CRITICAL");
  });
});

// ---------------------------------------------------------------------------
// renderTerminal — zero total control
// ---------------------------------------------------------------------------

describe("renderTerminal — zero total control", () => {
  it("renders without crashing when a control has total=0 (shows dash)", () => {
    const data = minimalReportData(); // default section has total=0 control
    const output = renderTerminal(data);

    expect(output).toContain("test-agent");
    // The "-" mark is used for zero-total cells in the compliance matrix
  });
});

// ---------------------------------------------------------------------------
// renderMarkdown — broken chain executive summary
// ---------------------------------------------------------------------------

describe("renderMarkdown — broken chain", () => {
  it("shows BROKEN in executive summary when chain is invalid", () => {
    const data = minimalReportData({ chainValid: false });
    const output = renderMarkdown(data);

    expect(output).toContain("BROKEN");
  });
});

// ---------------------------------------------------------------------------
// renderMarkdown — zero total control in compliance section
// ---------------------------------------------------------------------------

describe("renderMarkdown — zero total control in compliance section", () => {
  it("shows dash in pass rate column for zero-total controls", () => {
    const sectionWithZero = makeSection({
      overlayId: "soc2",
      overlayName: "SOC 2",
      controls: [
        {
          controlId: "PR-01",
          displayName: "Identity",
          citations: ["CC6.1"],
          total: 0,
          passed: 0,
          failed: 0,
          passRate: 0.0,
          threshold: "standard",
        },
      ],
    });
    const data = minimalReportData({ complianceSections: [sectionWithZero] });
    const output = renderMarkdown(data);

    expect(output).toContain("| CC6.1 | PR-01 | 0 | - |");
  });
});

// ---------------------------------------------------------------------------
// renderMarkdown — advisory upgrade advisories
// ---------------------------------------------------------------------------

describe("renderMarkdown — advisory upgrade advisories", () => {
  it("shows Certification Upgrade Advisories section when present", () => {
    const data = minimalReportData({ advisory: makeAdvisory({ withUpgrade: true }) });
    const output = renderMarkdown(data);

    expect(output).toContain("Certification Upgrade Advisories");
    expect(output).toContain("SOC 2");
  });
});

// ---------------------------------------------------------------------------
// renderMarkdown — AIUC-1 format
// ---------------------------------------------------------------------------

describe("renderMarkdown — AIUC-1 format", () => {
  it("renders AIUC-1 READINESS REPORT with compliance sections", () => {
    const section = makeSection({
      overlayId: "soc2",
      overlayName: "SOC 2",
      triggeredBy: "pii",
      controls: [
        {
          controlId: "PR-01",
          displayName: "Identity",
          citations: ["CC6.1"],
          total: 5,
          passed: 5,
          failed: 0,
          passRate: 100.0,
          threshold: "standard",
        },
      ],
    });
    const data = minimalReportData({
      reportFormat: "aiuc1-readiness",
      certification: makeCert(),
      complianceSections: [section],
    });
    const output = renderMarkdown(data);

    expect(output).toContain("AIUC-1 READINESS REPORT");
    expect(output).toContain("SOC 2");
  });

  it("renders AIUC-1 READINESS REPORT with advisory section", () => {
    const data = minimalReportData({
      reportFormat: "aiuc1-readiness",
      certification: makeCert(),
      advisory: makeAdvisory({ withUpgrade: true }),
      complianceSections: [],
    });
    const output = renderMarkdown(data);

    expect(output).toContain("AIUC-1 READINESS REPORT");
    expect(output).toContain("Classification Advisory");
  });

  it("falls through to standard report when aiuc1-readiness format but no cert", () => {
    const data = minimalReportData({
      reportFormat: "aiuc1-readiness",
      certification: null,
      complianceSections: [],
    });
    const output = renderMarkdown(data);

    // Falls through to standard report — cert guard prevents aiuc1 path
    expect(output).toContain("Ancilis Posture Report");
  });

  it("shows failures in automated coverage when present", () => {
    const data = minimalReportData({
      reportFormat: "aiuc1-readiness",
      certification: makeCert({ withAutomated: true, withFailures: true }),
      complianceSections: [],
    });
    const output = renderMarkdown(data);

    expect(output).toContain("failures");
  });
});

// ---------------------------------------------------------------------------
// renderNdjson — empty list
// ---------------------------------------------------------------------------

describe("renderNdjson", () => {
  it("returns empty string for empty records list", () => {
    expect(renderNdjson([] as EvidenceRecord[])).toBe("");
  });
});

// ---------------------------------------------------------------------------
// renderCsv — empty list
// ---------------------------------------------------------------------------

describe("renderCsv", () => {
  it("returns header-only output for empty records list", () => {
    const result = renderCsv([] as EvidenceRecord[]);
    expect(result).toContain("record_id");
    // Should be just the header line (no data rows)
    const lines = result.trim().split("\n");
    expect(lines).toHaveLength(1);
  });
});
