/** Remediation guidance loading and current-gap recommendations. */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { ResolvedConfig } from "../config/index.js";
import { sharedPathFrom } from "../shared-path.js";

const REMEDIATION_DIR = sharedPathFrom(import.meta.url, "remediation", "controls");

export interface RemediationGuide {
  controlId: string;
  title: string;
  difficulty: string;
  timeEstimate: string;
  evidenceNeeded: string[];
  fixSteps: string[];
  codeExample: string;
  explanation: string;
  docsUrl: string | null;
}

export interface RemediationRecommendation {
  guide: RemediationGuide;
  status: "GAP" | "PARTIAL" | "NO_EVIDENCE" | "HEALTHY";
  evaluations: number;
  failures: number;
  flags: number;
  passRate: number;
  codeExample: string;
}

function parseFrontmatter(markdown: string): { data: Record<string, unknown>; body: string } {
  if (!markdown.startsWith("---\n")) {
    throw new Error("Remediation markdown must start with frontmatter");
  }
  const end = markdown.indexOf("\n---", 4);
  if (end === -1) {
    throw new Error("Remediation markdown frontmatter is not closed");
  }
  const frontmatter = markdown.slice(4, end);
  const body = markdown.slice(end + 4).trim();
  const data = parseYaml(frontmatter) as Record<string, unknown>;
  return { data, body };
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(item => String(item)) : [];
}

function guideFromMarkdown(markdown: string): RemediationGuide {
  const { data, body } = parseFrontmatter(markdown);
  const controlId = String(data["control_id"]);
  return {
    controlId,
    title: String(data["title"] ?? controlId),
    difficulty: String(data["difficulty"] ?? "medium"),
    timeEstimate: String(data["time_estimate"] ?? "unknown"),
    evidenceNeeded: asStringArray(data["evidence_needed"]),
    fixSteps: asStringArray(data["fix_steps"]),
    codeExample: String(data["code_example"] ?? ""),
    explanation: body,
    docsUrl: data["docs_url"] ? String(data["docs_url"]) : null,
  };
}

export function loadRemediationGuides(): Map<string, RemediationGuide> {
  const guides = new Map<string, RemediationGuide>();
  for (const file of readdirSync(REMEDIATION_DIR).filter(name => name.endsWith(".md")).sort()) {
    const guide = guideFromMarkdown(readFileSync(join(REMEDIATION_DIR, file), "utf-8"));
    guides.set(guide.controlId, guide);
  }
  return guides;
}

function statsFor(summary: Record<string, unknown>, controlId: string): {
  total: number;
  failures: number;
  flags: number;
  passRate: number;
} {
  const rates = (summary["controlPassRates"] ?? summary["control_pass_rates"] ?? {}) as Record<string, Record<string, number>>;
  const stats = rates[controlId] ?? {};
  const passed = stats.PASS ?? 0;
  const failures = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
  const flags = stats.FLAG ?? 0;
  const skipped = stats.SKIP ?? 0;
  const total = passed + failures + flags + skipped;
  const passRate = total > 0 ? Math.round((passed / total) * 1000) / 10 : 0;
  return { total, failures, flags, passRate };
}

function statusFor(total: number, failures: number, flags: number): RemediationRecommendation["status"] {
  if (failures > 0) return "GAP";
  if (flags > 0) return "PARTIAL";
  if (total === 0) return "NO_EVIDENCE";
  return "HEALTHY";
}

export function buildRemediationRecommendations(
  config: ResolvedConfig,
  summary: Record<string, unknown>,
  options: { controlId?: string } = {},
): RemediationRecommendation[] {
  const guides = loadRemediationGuides();
  const wanted = options.controlId ? [options.controlId.toUpperCase()] : [...guides.keys()];
  const recommendations: RemediationRecommendation[] = [];

  for (const controlId of wanted.sort()) {
    const guide = guides.get(controlId);
    if (!guide) continue;
    const control = config.controls.get(controlId);
    if (control && !control.enabled) continue;
    const { total, failures, flags, passRate } = statsFor(summary, controlId);
    const status = statusFor(total, failures, flags);
    if (!options.controlId && status !== "GAP" && status !== "PARTIAL") continue;
    recommendations.push({
      guide,
      status,
      evaluations: total,
      failures,
      flags,
      passRate,
      codeExample: guide.codeExample.replaceAll("{{agent_name}}", config.agentName),
    });
  }

  return recommendations.sort((a, b) => {
    const rank = (status: RemediationRecommendation["status"]): number => status === "GAP" ? 0 : status === "PARTIAL" ? 1 : 2;
    return rank(a.status) - rank(b.status) || a.guide.controlId.localeCompare(b.guide.controlId);
  });
}

export function renderRemediationRecommendations(
  recommendations: RemediationRecommendation[],
  options: { controlId?: string } = {},
): string {
  if (recommendations.length === 0) {
    if (options.controlId) return `No remediation guidance found for ${options.controlId.toUpperCase()}.`;
    return "No current remediation guidance needed for this evidence window.";
  }

  const lines: string[] = [];
  for (const rec of recommendations) {
    const guide = rec.guide;
    lines.push(`${guide.controlId} (${guide.title}) — ${rec.status}`);
    lines.push(
      `  Time: ${guide.timeEstimate} | Difficulty: ${guide.difficulty[0]?.toUpperCase() ?? ""}${guide.difficulty.slice(1)} | `
      + `Evidence: ${rec.evaluations} evals, ${rec.failures} failures, ${rec.flags} flags`,
    );
    if (guide.explanation) lines.push(`  What is wrong: ${guide.explanation}`);
    if (guide.fixSteps.length > 0) {
      lines.push("  How to fix:");
      for (const step of guide.fixSteps) lines.push(`    - ${step}`);
    }
    if (guide.evidenceNeeded.length > 0) {
      lines.push("  Evidence needed:");
      for (const evidence of guide.evidenceNeeded) lines.push(`    - ${evidence}`);
    }
    if (rec.codeExample) {
      lines.push("  Example:");
      for (const codeLine of rec.codeExample.trimEnd().split("\n")) lines.push(`    ${codeLine}`);
    }
    if (guide.docsUrl) lines.push(`  Docs: ${guide.docsUrl}`);
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
