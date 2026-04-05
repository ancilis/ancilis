/** Output format rendering — terminal, markdown, PDF. */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalJsonStringify } from "../evidence/chain.js";
import type { EvidenceRecord } from "../evidence/record.js";
import type { ReportData } from "./generator.js";

const EXPORT_FIELDNAMES = [
  "record_id",
  "evaluation_id",
  "timestamp",
  "agent_id",
  "source_type",
  "tool_name",
  "decision",
  "mode",
  "control_results",
  "active_overlays",
  "data_classifications",
  "active_certifications",
  "record_hash",
  "previous_hash",
  "total_duration_ms",
  "output_summary",
] as const;

function shortDate(iso: string): string {
  return iso.includes("T") ? (iso.split("T")[0] ?? iso.slice(0, 10)) : iso.slice(0, 10);
}

function formatPassRate(value: unknown): string {
  return typeof value === "number" ? value.toFixed(1) : String(value);
}

const ANSI_PATTERN = /\u001b\[[0-9;]*m/g;

function useColor(): boolean {
  if (process.env.NO_COLOR) return false;
  return process.stdout.isTTY === true;
}

function style(text: string, enabled: boolean, options?: { color?: "green" | "red" | "yellow"; bold?: boolean }): string {
  if (!enabled) return text;
  const codes: string[] = [];
  if (options?.bold) codes.push("1");
  if (options?.color === "green") codes.push("32");
  if (options?.color === "red") codes.push("31");
  if (options?.color === "yellow") codes.push("33");
  if (codes.length === 0) return text;
  return `\u001b[${codes.join(";")}m${text}\u001b[0m`;
}

function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, "");
}

function padCell(text: string, width: number): string {
  const visibleWidth = stripAnsi(text).length;
  if (visibleWidth >= width) return text;
  return `${text}${" ".repeat(width - visibleWidth)}`;
}

function numericThreshold(value: unknown): number | null {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function controlRequiresAttention(control: Record<string, unknown>): boolean {
  const total = Number(control.total ?? 0);
  if (total <= 0) return false;
  const threshold = numericThreshold(control.threshold);
  if (threshold === null) {
    return Number(control.failed ?? 0) > 0;
  }
  return Number(control.failed ?? 0) > 0 || Number(control.passRate ?? 0) < threshold;
}

function controlMark(control: Record<string, unknown>, colorEnabled: boolean): string {
  const total = Number(control.total ?? 0);
  if (total <= 0) return "-";
  if (controlRequiresAttention(control)) {
    return style("\u2717", colorEnabled, { color: "red" });
  }
  return style("\u2713", colorEnabled, { color: "green" });
}

function buildPostureSummary(data: ReportData): Record<string, unknown> {
  const baseline = data.baseline as Record<string, unknown>;
  const controls = (baseline.controls as Record<string, unknown>[]) ?? [];
  const failingControls = controls.filter(controlRequiresAttention);
  const passingControls = controls.filter((control) => Number(control.total ?? 0) > 0 && !controlRequiresAttention(control));

  let status: "HEALTHY" | "ATTENTION" | "CRITICAL" = "HEALTHY";
  let statusColor: "green" | "yellow" | "red" = "green";
  if (!data.chainValid || failingControls.length >= 3) {
    status = "CRITICAL";
    statusColor = "red";
  } else if (failingControls.length > 0) {
    status = "ATTENTION";
    statusColor = "yellow";
  }

  const certificationLabel = data.certification
    ? `${data.certification.certificationName ?? "AIUC-1"} (${data.certification.readinessPercentage ?? 0}% ready)`
    : "none";

  return {
    status,
    statusColor,
    failingControls,
    passingControls,
    passingControlCount: passingControls.length,
    totalControls: controls.length,
    allowedEvaluations: (baseline.decisions as Record<string, number> | undefined)?.allow ?? 0,
    blockedEvaluations: (baseline.decisions as Record<string, number> | undefined)?.block ?? 0,
    overlayLabel: data.complianceSections.map((section) => String(section.overlayName)).join(", ") || "none",
    certificationLabel,
    chainMark: data.chainValid ? "\u2713" : "\u2717",
    chainLabel: data.chainValid ? "intact" : "BROKEN",
    chainColor: data.chainValid ? "green" : "red",
  };
}

function renderBaselineTerminal(lines: string[], baseline: Record<string, unknown>, colorEnabled: boolean): void {
  const controls = (baseline.controls as Record<string, unknown>[]) ?? [];
  const failingControls = controls.filter(controlRequiresAttention);
  const passingControls = controls.filter((control) => Number(control.total ?? 0) > 0 && !controlRequiresAttention(control));

  lines.push(style("Baseline Controls:", colorEnabled, { bold: true }));
  if (failingControls.length > 0) {
    for (const control of failingControls) {
      lines.push(
        `  ${controlMark(control, colorEnabled)} ${control.displayName} — `
        + `${formatPassRate(control.passRate)}% pass rate (${control.total} evaluations)`,
      );
    }
  }
  if (passingControls.length > 0) {
    const passingMark = style("\u2713", colorEnabled, { color: "green" });
    lines.push(`  ${passingMark} ${passingControls.length} controls passing (full detail preserved in markdown)`);
  } else if (failingControls.length === 0) {
    lines.push("  - No evaluations recorded");
  }

  const tools = (baseline.toolsEvaluated as string[]) ?? [];
  if (tools.length > 0) {
    lines.push(`Tools evaluated: ${tools.join(", ")}`);
  }
}

function matrixCell(control: Record<string, unknown> | undefined, colorEnabled: boolean): string {
  if (!control) return "-";
  if (Number(control.failed ?? 0) > 0) {
    return style(`\u2717(${control.failed})`, colorEnabled, { color: "red" });
  }
  if (Number(control.total ?? 0) > 0) {
    return style("\u2713", colorEnabled, { color: "green" });
  }
  return "-";
}

function renderComplianceMatrixTerminal(lines: string[], sections: Record<string, unknown>[], colorEnabled: boolean): void {
  lines.push(style("Compliance Matrix:", colorEnabled, { bold: true }));

  const overlayNames = sections.map((section) => String(section.overlayName));
  const controlIds = [...new Set(sections.flatMap((section) => ((section.controls as Record<string, unknown>[]) ?? []).map((control) => String(control.controlId))))].sort();
  const sectionMaps = new Map<string, Map<string, Record<string, unknown>>>();
  for (const section of sections) {
    sectionMaps.set(
      String(section.overlayName),
      new Map((((section.controls as Record<string, unknown>[]) ?? []).map((control) => [String(control.controlId), control]))),
    );
  }

  const rows: string[][] = [["Control", ...overlayNames]];
  for (const controlId of controlIds) {
    const row = [controlId];
    for (const overlayName of overlayNames) {
      row.push(matrixCell(sectionMaps.get(overlayName)?.get(controlId), colorEnabled));
    }
    rows.push(row);
  }

  const widths = rows[0]!.map((_, columnIndex) => Math.max(...rows.map((row) => stripAnsi(row[columnIndex] ?? "").length)));
  for (const row of rows) {
    lines.push(`  ${row.map((cell, index) => padCell(cell, widths[index] ?? 0)).join(" | ")}`);
  }
}

function renderExecutiveSummaryMarkdown(lines: string[], data: ReportData): void {
  const posture = buildPostureSummary(data);
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(
    `**Posture: ${posture.status}** — `
    + `${posture.passingControlCount} of ${posture.totalControls} controls passing `
    + `across ${data.complianceSections.length} active overlays.`,
  );
  lines.push("");
  lines.push(
    `- ${data.totalEvaluations.toLocaleString()} evaluations in period | `
    + `${posture.blockedEvaluations} blocked | `
    + `${Number(posture.allowedEvaluations).toLocaleString()} allowed`,
  );
  lines.push(`- Active overlays: ${posture.overlayLabel}`);
  lines.push(`- Active certifications: ${posture.certificationLabel}`);
  if (data.chainValid) {
    lines.push(`- Evidence chain: intact (${data.totalEvaluations.toLocaleString()} records, SHA-256 verified)`);
  } else {
    lines.push(`- Evidence chain: **BROKEN** (${data.totalEvaluations.toLocaleString()} records)`);
  }

  const failingControls = posture.failingControls as Record<string, unknown>[];
  if (failingControls.length > 0) {
    lines.push("");
    lines.push("### Attention Required");
    lines.push("");
    for (const control of failingControls) {
      lines.push(`- **${control.displayName}**: ${control.failed} failures in reporting period`);
    }
  }
  lines.push("");
}

export function renderTerminal(data: ReportData): string {
  const lines: string[] = [];
  const posture = buildPostureSummary(data);
  const colorEnabled = useColor();

  lines.push(style(`Ancilis Posture Report — ${data.agentName}`, colorEnabled, { bold: true }));
  lines.push(`Period: ${shortDate(data.periodStart)} to ${shortDate(data.periodEnd)}`);
  lines.push(`Mode: ${data.mode}`);
  lines.push(
    `Posture: ${style(String(posture.status), colorEnabled, { color: posture.statusColor as "green" | "yellow" | "red", bold: true })} `
    + `(${posture.passingControlCount}/${posture.totalControls} controls passing)`,
  );
  lines.push(
    `Evaluations: ${data.totalEvaluations.toLocaleString()} total | `
    + `${posture.blockedEvaluations} blocked | `
    + `${Number(posture.allowedEvaluations).toLocaleString()} allowed`,
  );
  lines.push(`Active overlays: ${posture.overlayLabel}`);
  lines.push(`Active certifications: ${posture.certificationLabel}`);
  lines.push(
    `Evidence chain: ${style(String(posture.chainMark), colorEnabled, { color: posture.chainColor as "green" | "red" })} `
    + `${posture.chainLabel} (${data.totalEvaluations.toLocaleString()} records)`,
  );
  lines.push("");

  const baseline = data.baseline as Record<string, unknown>;
  renderBaselineTerminal(lines, baseline, colorEnabled);

  if (data.complianceSections.length > 0) {
    lines.push("");
    renderComplianceMatrixTerminal(lines, data.complianceSections as Record<string, unknown>[], colorEnabled);
  }

  if (data.certification) {
    const cert = data.certification;
    lines.push("");
    lines.push(style(`${cert.certificationName} Readiness`, colorEnabled, { bold: true }));
    lines.push(`  Readiness: ${cert.readinessPercentage}% (${cert.readyCount} of ${cert.totalRequirements} requirements passing)`);
    lines.push(`  Coverage: ${cert.coveragePercentage}% (${cert.automatedCount} automated, ${cert.operatorCount} operator)`);
    const chainStr = cert.chainValid ? "intact" : "BROKEN";
    lines.push(`  Evidence records: ${(cert.evidenceCount as number).toLocaleString()}, hash chain ${chainStr}`);
  }

  if (data.advisory) {
    lines.push("");
    renderAdvisoryTerminal(lines, data.advisory);
  }

  return lines.join("\n");
}

export interface RenderPdfOptions {
  execFile?: typeof execFileSync;
}

export interface RenderPdfResult {
  format: "pdf" | "markdown";
  outputPath: string;
  fallbackReason?: string;
}

function markdownFallbackPath(outputPath: string): string {
  if (outputPath.toLowerCase().endsWith(".pdf")) {
    return outputPath.slice(0, -4) + ".md";
  }
  if (outputPath.toLowerCase().endsWith(".md")) {
    return outputPath;
  }
  return `${outputPath}.md`;
}

export function renderPdf(markdown: string, outputPath: string, options?: RenderPdfOptions): RenderPdfResult {
  const execFile = options?.execFile ?? execFileSync;
  const markdownPath = join(tmpdir(), `ancilis-report-${Date.now()}.md`);
  const fallbackPath = markdownFallbackPath(outputPath);
  writeFileSync(markdownPath, markdown);

  try {
    execFile("pandoc", [markdownPath, "-o", outputPath, "--pdf-engine=xelatex"], {
      stdio: "pipe",
    });
    return { format: "pdf", outputPath };
  } catch {
    if (fallbackPath !== outputPath && existsSync(outputPath)) {
      unlinkSync(outputPath);
    }
    writeFileSync(fallbackPath, markdown);
    return {
      format: "markdown",
      outputPath: fallbackPath,
      fallbackReason: "pandoc/xelatex unavailable",
    };
  } finally {
    unlinkSync(markdownPath);
  }
}

export function renderMarkdown(data: ReportData): string {
  const lines: string[] = [];

  const isAiuc1 = data.reportFormat === "aiuc1-readiness";

  if (isAiuc1 && data.certification) {
    renderAiuc1Markdown(lines, data);
    return lines.join("\n");
  }

  lines.push(`# Ancilis Posture Report — ${data.agentName}`);
  lines.push("");
  lines.push(`**Period:** ${shortDate(data.periodStart)} to ${shortDate(data.periodEnd)}  `);
  lines.push(`**Generated:** ${shortDate(data.generatedAt)}  `);
  lines.push(`**Mode:** ${data.mode}`);
  lines.push("");
  renderExecutiveSummaryMarkdown(lines, data);

  renderBaselineMarkdown(lines, data.baseline as Record<string, unknown>);

  // Compliance
  for (const section of data.complianceSections) {
    lines.push("");
    renderComplianceMarkdown(lines, section);
  }

  // Certification
  if (data.certification) {
    lines.push("");
    renderCertMarkdown(lines, data.certification);
  }

  if (data.advisory) {
    lines.push("");
    renderAdvisoryMarkdown(lines, data.advisory);
  }

  // Evidence
  lines.push("");
  lines.push("## Evidence Integrity");
  lines.push("");
  const chain = data.chainValid ? "intact (verified)" : "**BROKEN**";
  lines.push(`- Evidence records: ${data.totalEvaluations.toLocaleString()}`);
  lines.push(`- Hash chain: ${chain}`);
  lines.push("");
  lines.push("---");
  lines.push("*Generated by Ancilis SDK v0.1*");

  return lines.join("\n");
}

function reportRows(data: ReportData): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  const baseline = data.baseline as Record<string, unknown>;

  rows.push({
    recordType: "report",
    agentName: data.agentName,
    mode: data.mode,
    reportFormat: data.reportFormat,
    periodStart: data.periodStart,
    periodEnd: data.periodEnd,
    generatedAt: data.generatedAt,
    totalEvaluations: data.totalEvaluations,
    chainValid: data.chainValid,
  });

  for (const control of (baseline.controls as Record<string, unknown>[]) ?? []) {
    rows.push({
      recordType: "baseline_control",
      controlId: control.controlId,
      displayName: control.displayName,
      threshold: control.threshold,
      total: control.total,
      passed: control.passed,
      failed: control.failed,
      flagged: control.flagged,
      passRate: control.passRate,
    });
  }

  for (const section of data.complianceSections) {
    rows.push({
      recordType: "compliance_section",
      overlayName: section.overlayName,
      triggeredBy: section.triggeredBy ?? null,
      evidenceRetentionDays: section.evidenceRetentionDays,
      retentionMet: section.retentionMet,
    });
    for (const control of (section.controls as Record<string, unknown>[]) ?? []) {
      rows.push({
        recordType: "compliance_control",
        overlayName: section.overlayName,
        controlId: control.controlId,
        citations: control.citations ?? [],
        total: control.total,
        passRate: control.passRate,
        failed: control.failed,
      });
    }
  }

  if (data.certification) {
    rows.push({
      recordType: "certification",
      ...data.certification,
    });
  }

  return rows;
}

function exportRecord(record: EvidenceRecord): Record<(typeof EXPORT_FIELDNAMES)[number], unknown> {
  return {
    record_id: record.recordId,
    evaluation_id: record.evaluationId,
    timestamp: record.timestamp,
    agent_id: record.agentId,
    source_type: record.sourceType,
    tool_name: record.toolName,
    decision: record.decision,
    mode: record.mode,
    control_results: record.controlResults,
    active_overlays: record.activeOverlays,
    data_classifications: record.dataClassifications,
    active_certifications: record.activeCertifications,
    record_hash: record.recordHash,
    previous_hash: record.previousHash,
    total_duration_ms: record.totalDurationMs,
    output_summary: record.outputSummary ?? null,
  };
}

export function renderNdjson(records: EvidenceRecord[]): string {
  return records.map((record) => canonicalJsonStringify(exportRecord(record))).join("\n");
}

function toSnakeCase(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const raw =
    Array.isArray(value) || typeof value === "object"
      ? canonicalJsonStringify(value)
      : String(value);
  if (/[",\n]/.test(raw)) {
    return `"${raw.replace(/"/g, "\"\"")}"`;
  }
  return raw;
}

export function renderCsv(records: EvidenceRecord[]): string {
  const lines = [EXPORT_FIELDNAMES.join(",")];
  for (const record of records) {
    const row = exportRecord(record);
    const values = EXPORT_FIELDNAMES.map((header) => csvCell(row[header]));
    lines.push(values.join(","));
  }
  return lines.join("\n");
}

function stableId(...parts: string[]): string {
  return createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 32);
}

function findingStatus(row: Record<string, unknown>): string | undefined {
  if (typeof row.failed === "number") {
    return row.failed === 0 ? "satisfied" : "not-satisfied";
  }
  if (typeof row.retentionMet === "boolean") {
    return row.retentionMet ? "satisfied" : "not-satisfied";
  }
  return undefined;
}

function findingDescription(row: Record<string, unknown>): string {
  switch (row.recordType) {
    case "baseline_control":
      return `${row.displayName} recorded ${row.total} evaluations with ${row.failed} failures.`;
    case "compliance_section":
      return `${row.overlayName} retention requirement is ${row.evidenceRetentionDays} days.`;
    case "compliance_control":
      return `${row.overlayName} maps ${row.controlId} with ${row.total} evaluations and ${row.failed} failures.`;
    case "certification":
      return `${row.certificationName} readiness is ${row.readinessPercentage}% with ${row.readyCount} passing requirements.`;
    default:
      return `${row.recordType} generated by the Ancilis posture report.`;
  }
}

function findingProps(row: Record<string, unknown>): Array<{ name: string; value: string }> {
  return Object.entries(row)
    .filter(([key]) => key !== "recordType")
    .map(([key, value]) => ({
      name: toSnakeCase(key),
      value:
        value === null || value === undefined
          ? ""
          : Array.isArray(value) || typeof value === "object"
            ? JSON.stringify(value)
            : String(value),
    }));
}

export function renderOscalJson(data: ReportData): string {
  const findings = reportRows(data)
    .filter((row) => row.recordType !== "report")
    .map((row, index) => {
      const recordType = String(row.recordType);
      const finding: Record<string, unknown> = {
        uuid: stableId(data.agentName, data.periodStart, data.periodEnd, recordType, String(row.controlId ?? row.overlayName ?? index)),
        title: `${recordType.replace(/_/g, " ")} finding`,
        description: findingDescription(row),
        target: {
          type: recordType,
          controlId: row.controlId ?? null,
          overlayName: row.overlayName ?? null,
        },
        props: findingProps(row),
      };
      const status = findingStatus(row);
      if (status) {
        finding.status = status;
      }
      return finding;
    });

  return JSON.stringify(
    {
      "assessment-results": {
        uuid: stableId("assessment-results", data.agentName, data.generatedAt),
        metadata: {
          title: `Ancilis OSCAL Assessment Results - ${data.agentName}`,
          version: "0.1.0",
          "oscal-version": "1.1.2",
          "last-modified": data.generatedAt,
          remarks: `Generated from Ancilis posture data for ${data.periodStart} to ${data.periodEnd}.`,
        },
        results: [
          {
            uuid: stableId("result", data.agentName, data.periodStart, data.periodEnd),
            title: `${data.agentName} posture assessment`,
            description: `Ancilis ${data.mode} posture report exported in OSCAL-compatible JSON.`,
            start: data.periodStart,
            end: data.periodEnd,
            findings,
          },
        ],
      },
    },
    null,
    2,
  );
}

function renderBaselineMarkdown(lines: string[], baseline: Record<string, unknown>): void {
  lines.push("## Baseline Security");
  lines.push("");
  const total = (baseline.totalEvaluations as number) ?? 0;
  const decisions = (baseline.decisions as Record<string, number>) ?? {};
  lines.push(`- Evaluations: ${total.toLocaleString()}`);
  lines.push(`- Blocked: ${decisions.block ?? 0}`);
  lines.push("");
  lines.push("| Control | Pass Rate | Evaluations | Status |");
  lines.push("|---------|-----------|-------------|--------|");
  for (const c of (baseline.controls as Record<string, unknown>[]) ?? []) {
    const cTotal = c.total as number;
    if (cTotal > 0) {
      const status = (c.failed as number) === 0 ? "Pass" : `${c.failed} failures`;
      lines.push(`| ${c.displayName} | ${formatPassRate(c.passRate)}% | ${cTotal} | ${status} |`);
    } else {
      lines.push(`| ${c.displayName} | - | 0 | No data |`);
    }
  }
  const tools = (baseline.toolsEvaluated as string[]) ?? [];
  if (tools.length > 0) {
    lines.push("");
    lines.push(`**Tools evaluated:** ${tools.join(", ")}`);
  }
}

function renderComplianceMarkdown(lines: string[], section: Record<string, unknown>): void {
  lines.push(`## ${section.overlayName} Compliance Posture`);
  lines.push("");
  if (section.triggeredBy) lines.push(`**Activated by:** ${section.triggeredBy} declaration  `);
  const strict = (section.strictControls as string[]) ?? [];
  if (strict.length) lines.push(`**Controls at strict threshold:** ${strict.join(", ")}  `);
  lines.push("");
  lines.push("| Citation | Control | Evaluations | Pass Rate |");
  lines.push("|----------|---------|-------------|-----------|");
  for (const c of (section.controls as Record<string, unknown>[]) ?? []) {
    const citations = ((c.citations as string[]) ?? []).join(", ");
    const cTotal = c.total as number;
    if (cTotal > 0) {
      lines.push(`| ${citations} | ${c.controlId} | ${cTotal} | ${formatPassRate(c.passRate)}% |`);
    } else {
      lines.push(`| ${citations} | ${c.controlId} | 0 | - |`);
    }
  }
  const retention = (section.evidenceRetentionDays as number) ?? 365;
  const retentionMark = section.retentionMet ? "\u2713" : "\u2717";
  lines.push("");
  lines.push(`Evidence retention: ${retention} days ${retentionMark}`);

  const gaps = (section.gaps as Record<string, unknown>[]) ?? [];
  if (gaps.length > 0) {
    lines.push("");
    lines.push("### Areas for Improvement");
    lines.push("");
    for (const g of gaps) {
      lines.push(`- **${g.displayName}**: ${g.failed} issues in reporting period`);
    }
  }
}

function renderCertMarkdown(lines: string[], cert: Record<string, unknown>): void {
  lines.push("## AIUC-1 Certification Readiness");
  lines.push("");
  lines.push(`- Readiness: ${cert.readinessPercentage}% (${cert.readyCount} of ${cert.totalRequirements} requirements passing)`);
  lines.push(`- Coverage: ${cert.coveragePercentage}% (${cert.automatedCount} automated, ${cert.operatorCount} operator)`);
  const chain = cert.chainValid ? "intact (verified)" : "**BROKEN**";
  lines.push(`- Evidence records: ${(cert.evidenceCount as number).toLocaleString()}`);
  lines.push(`- Hash chain: ${chain}`);

  lines.push("");
  lines.push("### Automated Coverage");
  lines.push("");
  lines.push("| Requirement | AKSI Control | Evidence |");
  lines.push("|-------------|-------------|----------|");
  for (const item of (cert.automatedCoverage as Record<string, unknown>[]) ?? []) {
    const count = item.evidenceCount as number;
    const status = count > 0 ? `${count} records` : "No data";
    lines.push(`| ${item.requirementId} | ${item.aksiControl} | ${status} |`);
  }

  const operator = (cert.operatorActionRequired as Record<string, string>[]) ?? [];
  if (operator.length > 0) {
    lines.push("");
    lines.push("### Operator Action Required");
    lines.push("");
    lines.push("These items require governance documentation from your team.");
    lines.push("Ancilis generates the evidence these documents cite.");
    lines.push("");
    for (const item of operator) {
      lines.push(`- **${item.requirementId}**: ${item.description}`);
    }
  }
}

function renderAdvisoryTerminal(lines: string[], advisory: Record<string, unknown>): void {
  lines.push("Classification Advisory");
  for (const pattern of (advisory.patternDetections as Record<string, unknown>[]) ?? []) {
    lines.push(`  Detected ${pattern.patternType}: ${pattern.count} occurrence(s) in the reporting period`);
  }

  const recommendations = (advisory.recommendations as Record<string, unknown>[]) ?? [];
  if (recommendations.length > 0) {
    lines.push("  Recommended config updates:");
    for (const recommendation of recommendations) {
      lines.push(
        "    - Add "
        + `${recommendation.suggestedValue} to `
        + `${recommendation.suggestedConfigField} `
        + `(${recommendation.detectionCount} detections, severity: ${recommendation.severity})`,
      );
    }
  }

  const upgradeAdvisories = (advisory.upgradeAdvisories as Record<string, unknown>[]) ?? [];
  if (upgradeAdvisories.length > 0) {
    lines.push("  Certification upgrade advisories:");
    for (const upgrade of upgradeAdvisories) {
      lines.push(`    - ${upgrade.message}`);
    }
  }
}

function renderAdvisoryMarkdown(lines: string[], advisory: Record<string, unknown>): void {
  lines.push("## Classification Advisory");
  lines.push("");

  const detections = (advisory.patternDetections as Record<string, unknown>[]) ?? [];
  if (detections.length > 0) {
    lines.push("### Detected Patterns");
    lines.push("");
    for (const pattern of detections) {
      lines.push(`- \`${pattern.patternType}\`: ${pattern.count} occurrence(s) in the reporting period`);
    }
  }

  const recommendations = (advisory.recommendations as Record<string, unknown>[]) ?? [];
  if (recommendations.length > 0) {
    lines.push("");
    lines.push("### Recommended Config Updates");
    lines.push("");
    for (const recommendation of recommendations) {
      lines.push(
        "- Add "
        + `\`${recommendation.suggestedValue}\` to `
        + `\`${recommendation.suggestedConfigField}\` `
        + `(${recommendation.detectionCount} detections, severity: \`${recommendation.severity}\`)`,
      );
      lines.push(`  Example config: \`${recommendation.exampleConfig}\``);
    }
  }

  const upgradeAdvisories = (advisory.upgradeAdvisories as Record<string, unknown>[]) ?? [];
  if (upgradeAdvisories.length > 0) {
    lines.push("");
    lines.push("### Certification Upgrade Advisories");
    lines.push("");
    for (const upgrade of upgradeAdvisories) {
      lines.push(`- ${upgrade.message}`);
    }
  }
}

function renderAiuc1Markdown(lines: string[], data: ReportData): void {
  const cert = data.certification!;

  lines.push("# AIUC-1 READINESS REPORT");
  lines.push("");
  lines.push(`**Agent:** ${data.agentName}  `);
  lines.push(`**Period:** ${shortDate(data.periodStart)} to ${shortDate(data.periodEnd)}  `);
  lines.push(`**Generated:** ${shortDate(data.generatedAt)}`);
  lines.push("");

  lines.push("## Readiness Summary");
  lines.push("");
  lines.push(`- Readiness: ${cert.readinessPercentage}% (${cert.readyCount} of ${cert.totalRequirements} requirements passing)`);
  lines.push(`- Coverage: ${cert.coveragePercentage}% (${cert.automatedCount} automated, ${cert.operatorCount} operator)`);
  lines.push(`- Evidence records: ${(cert.evidenceCount as number).toLocaleString()} over reporting period`);
  const chain = cert.chainValid ? "intact (verified)" : "**BROKEN**";
  lines.push(`- Hash chain: ${chain}`);

  lines.push("");
  lines.push("## Automated Coverage");
  lines.push("");
  lines.push("| Requirement | AKSI Control | Evidence |");
  lines.push("|-------------|-------------|----------|");
  for (const item of (cert.automatedCoverage as Record<string, unknown>[]) ?? []) {
    const count = item.evidenceCount as number;
    const parts: string[] = [];
    if (count > 0) {
      parts.push(`${count} records`);
      if ((item.failed as number) > 0) parts.push(`${item.failed} failures`);
      if ((item.flagged as number) > 0) parts.push(`${item.flagged} flags`);
    } else {
      parts.push("No data");
    }
    lines.push(`| ${item.requirementId} | ${item.aksiControl} | ${parts.join(", ")} |`);
  }

  const operator = (cert.operatorActionRequired as Record<string, string>[]) ?? [];
  if (operator.length > 0) {
    lines.push("");
    lines.push("## Operator Action Required");
    lines.push("");
    lines.push("These items require governance documentation from your team.");
    lines.push("Ancilis generates the evidence these documents cite.");
    lines.push("");
    for (const item of operator) {
      lines.push(`**${item.requirementId}** — ${item.description}`);
      lines.push("");
    }
  }

  for (const section of data.complianceSections) {
    lines.push("");
    renderComplianceMarkdown(lines, section);
  }

  if (data.advisory) {
    lines.push("");
    renderAdvisoryMarkdown(lines, data.advisory);
  }

  lines.push("");
  lines.push("---");
  lines.push("*Generated by Ancilis SDK v0.1*");
}
