/** Output format rendering — terminal, markdown, PDF. */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReportData } from "./generator.js";

function shortDate(iso: string): string {
  return iso.includes("T") ? (iso.split("T")[0] ?? iso.slice(0, 10)) : iso.slice(0, 10);
}

function formatPassRate(value: unknown): string {
  return typeof value === "number" ? value.toFixed(1) : String(value);
}

export function renderTerminal(data: ReportData): string {
  const lines: string[] = [];

  lines.push(`Ancilis Posture Report — ${data.agentName}`);
  lines.push(`Period: ${shortDate(data.periodStart)} to ${shortDate(data.periodEnd)}`);
  lines.push(`Mode: ${data.mode}`);
  lines.push("");

  // Baseline
  const baseline = data.baseline as Record<string, unknown>;
  const total = (baseline.totalEvaluations as number) ?? 0;
  const decisions = (baseline.decisions as Record<string, number>) ?? {};
  lines.push(`Evaluations: ${total.toLocaleString()} total, ${decisions.block ?? 0} blocked`);
  lines.push("");
  lines.push("Controls:");
  for (const c of (baseline.controls as Record<string, unknown>[]) ?? []) {
    const cTotal = c.total as number;
    const failed = c.failed as number;
    if (cTotal > 0) {
      const mark = failed === 0 ? "\u2713" : "\u2717";
      lines.push(`  ${mark} ${c.displayName} — ${formatPassRate(c.passRate)}% pass rate (${cTotal} evaluations)`);
    } else {
      lines.push(`  - ${c.displayName} — no evaluations recorded`);
    }
  }
  const tools = (baseline.toolsEvaluated as string[]) ?? [];
  if (tools.length > 0) {
    lines.push("");
    lines.push(`Tools evaluated: ${tools.join(", ")}`);
  }

  // Compliance
  for (const section of data.complianceSections) {
    lines.push("");
    lines.push(`${section.overlayName} Compliance Posture`);
    if (section.triggeredBy) lines.push(`Activated by: ${section.triggeredBy} declaration`);
    const strict = (section.strictControls as string[]) ?? [];
    if (strict.length) lines.push(`Controls at strict threshold: ${strict.join(", ")}`);
    lines.push("");
    for (const c of (section.controls as Record<string, unknown>[]) ?? []) {
      const citations = ((c.citations as string[]) ?? []).join(", ");
      const cTotal = c.total as number;
      if (cTotal > 0) {
        const mark = (c.failed as number) === 0 ? "\u2713" : "\u2717";
        lines.push(`  ${citations}  ${mark} ${c.controlId}: ${cTotal} evaluations, ${formatPassRate(c.passRate)}% pass`);
      } else {
        lines.push(`  ${citations}  - ${c.controlId}: no evaluations`);
      }
    }
    const retention = (section.evidenceRetentionDays as number) ?? 365;
    const retentionMark = section.retentionMet ? "\u2713" : "\u2717";
    lines.push(`  Evidence retention: ${retention} days ${retentionMark}`);
    const gaps = (section.gaps as Record<string, unknown>[]) ?? [];
    if (gaps.length > 0) {
      lines.push("");
      lines.push("  Areas for improvement:");
      for (const gap of gaps) {
        lines.push(`    - ${gap.displayName}: ${gap.failed} issues in reporting period`);
      }
    }
  }

  // Certification
  if (data.certification) {
    const cert = data.certification;
    lines.push("");
    lines.push(`${cert.certificationName} Readiness`);
    lines.push(`  Readiness: ${cert.readinessPercentage}% (${cert.readyCount} of ${cert.totalRequirements} requirements passing)`);
    lines.push(`  Coverage: ${cert.coveragePercentage}% (${cert.automatedCount} automated, ${cert.operatorCount} operator)`);
    const chainStr = cert.chainValid ? "intact" : "BROKEN";
    lines.push(`  Evidence records: ${(cert.evidenceCount as number).toLocaleString()}, hash chain ${chainStr}`);
  }

  if (data.advisory) {
    lines.push("");
    renderAdvisoryTerminal(lines, data.advisory);
  }

  // Evidence
  lines.push("");
  const chainStatus = data.chainValid ? "\u2713 intact" : "\u2717 BROKEN";
  lines.push(`Evidence: ${data.totalEvaluations.toLocaleString()} records, hash chain ${chainStatus}`);

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

  // Baseline
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

export function renderNdjson(data: ReportData): string {
  return reportRows(data).map((row) => JSON.stringify(row)).join("\n");
}

function toSnakeCase(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const raw =
    Array.isArray(value) || typeof value === "object"
      ? JSON.stringify(value)
      : String(value);
  if (/[",\n]/.test(raw)) {
    return `"${raw.replace(/"/g, "\"\"")}"`;
  }
  return raw;
}

export function renderCsv(data: ReportData): string {
  const rows = reportRows(data);
  const headerKeys: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      const snakeKey = toSnakeCase(key);
      if (!headerKeys.includes(snakeKey)) headerKeys.push(snakeKey);
    }
  }

  const lines = [headerKeys.join(",")];
  for (const row of rows) {
    const values = headerKeys.map((header) => {
      const sourceKey = Object.keys(row).find((key) => toSnakeCase(key) === header);
      return csvCell(sourceKey ? row[sourceKey] : "");
    });
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
