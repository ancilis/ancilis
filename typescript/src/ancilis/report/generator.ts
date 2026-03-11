/** Core report generation — queries evidence, assembles sections. */

import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ResolvedConfig } from "../config/index.js";

const __reportFilename = fileURLToPath(import.meta.url);
const SHARED_DIR = resolve(__reportFilename, "..", "..", "..", "..", "..", "shared");
const CONTROLS_DIR = join(SHARED_DIR, "controls");
const OVERLAYS_DIR = join(SHARED_DIR, "overlays");
const CERTIFICATIONS_DIR = join(OVERLAYS_DIR, "certifications");

function loadControlDefs(): Map<string, Record<string, unknown>> {
  const controls = new Map<string, Record<string, unknown>>();
  try {
    const files = readdirSync(CONTROLS_DIR).filter(f => f.endsWith(".json")).sort();
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CONTROLS_DIR, file), "utf-8"));
      controls.set(data.id, data);
    }
  } catch { /* ok */ }
  return controls;
}

function loadOverlayProfiles(): Map<string, Record<string, unknown>> {
  const profiles = new Map<string, Record<string, unknown>>();
  try {
    const files = readdirSync(OVERLAYS_DIR).filter(f => f.endsWith(".json")).sort();
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(OVERLAYS_DIR, file), "utf-8"));
      profiles.set(data.id, data);
    }
  } catch { /* ok */ }
  return profiles;
}

function loadCertProfile(certId: string): Record<string, unknown> | null {
  try {
    const path = join(CERTIFICATIONS_DIR, `${certId}.json`);
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return null;
  }
}

export interface ReportData {
  agentName: string;
  mode: string;
  periodStart: string;
  periodEnd: string;
  generatedAt: string;
  reportFormat: string;
  baseline: Record<string, unknown>;
  complianceSections: Record<string, unknown>[];
  certification: Record<string, unknown> | null;
  advisory: Record<string, unknown> | null;
  totalEvaluations: number;
  chainValid: boolean;
  chainErrors: string[];
}

export interface EvidenceSummary {
  total_evaluations: number;
  decisions: Record<string, number>;
  tools_evaluated: string[];
  control_pass_rates?: Record<string, Record<string, number>>;
  chain_valid: boolean;
  chain_errors: string[];
}

function parsePeriod(period: string): number {
  if (period.endsWith("d")) return parseInt(period) * 86400000;
  if (period.endsWith("h")) return parseInt(period) * 3600000;
  return 30 * 86400000;
}

export class ReportGenerator {
  private config: ResolvedConfig;
  private summary: EvidenceSummary;
  private controlDefs: Map<string, Record<string, unknown>>;
  private overlayProfiles: Map<string, Record<string, unknown>>;

  constructor(config: ResolvedConfig, summary: EvidenceSummary) {
    this.config = config;
    this.summary = summary;
    this.controlDefs = loadControlDefs();
    this.overlayProfiles = loadOverlayProfiles();
  }

  generate(period = "30d", reportFormat = "terminal"): ReportData {
    const now = new Date();
    const delta = parsePeriod(period);
    const periodStart = new Date(now.getTime() - delta);

    const data: ReportData = {
      agentName: this.config.agentName,
      mode: this.config.mode,
      periodStart: periodStart.toISOString(),
      periodEnd: now.toISOString(),
      generatedAt: now.toISOString(),
      reportFormat,
      baseline: this.buildBaseline(),
      complianceSections: [],
      certification: null,
      advisory: null,
      totalEvaluations: this.summary.total_evaluations,
      chainValid: this.summary.chain_valid,
      chainErrors: this.summary.chain_errors,
    };

    // Compliance sections
    if (this.config.activeOverlays.size > 0) {
      data.complianceSections = this.buildComplianceSections();
    }

    // Certification
    if (this.config.activeCertifications.length > 0 || reportFormat === "aiuc1-readiness") {
      if (this.config.activeCertifications.includes("aiuc-1") || reportFormat === "aiuc1-readiness") {
        data.certification = this.buildCertificationSection();
      }
    }

    return data;
  }

  private buildBaseline(): Record<string, unknown> {
    const controlStats = this.summary.control_pass_rates ?? {};
    const controls: Record<string, unknown>[] = [];

    for (const [, cs] of [...this.config.controls.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      if (!cs.enabled) continue;
      const cdef = this.controlDefs.get(cs.controlId) ?? {};
      const stats = controlStats[cs.controlId] ?? {};
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      const passed = stats.PASS ?? 0;
      const failed = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
      const flagged = stats.FLAG ?? 0;
      const passRate = total > 0 ? Math.round(passed / total * 1000) / 10 : 0;

      controls.push({
        controlId: cs.controlId,
        displayName: (cdef.display_name as string) ?? cs.name,
        displayDetail: (cdef.display_detail as string) ?? "",
        threshold: cs.threshold,
        total, passed, failed, flagged, passRate,
      });
    }

    const decisions = this.summary.decisions;
    return {
      controls,
      toolsEvaluated: this.summary.tools_evaluated,
      totalEvaluations: this.summary.total_evaluations,
      decisions: {
        allow: decisions.ALLOW ?? 0,
        block: decisions.BLOCK ?? 0,
        flag: decisions.FLAG ?? 0,
      },
      evidenceRetentionDays: this.config.evidenceRetentionDays,
    };
  }

  private buildComplianceSections(): Record<string, unknown>[] {
    const sections: Record<string, unknown>[] = [];
    const controlStats = this.summary.control_pass_rates ?? {};

    for (const [oid, activation] of [...this.config.activeOverlays.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const profile = this.overlayProfiles.get(oid) ?? {};
      const frameworkMapping = (profile.framework_mapping ?? {}) as Record<string, string[]>;
      const adjustments = (profile.control_adjustments ?? {}) as Record<string, Record<string, string>>;

      let trigger = "";
      if (activation.triggeredBy.length > 0) {
        const first = activation.triggeredBy[0];
        if (first.includes(" via ")) {
          trigger = first.split(" via ")[1];
        }
      }

      const controls: Record<string, unknown>[] = [];
      const strictControls: string[] = [];
      for (const [cid, citations] of Object.entries(frameworkMapping).sort((a, b) => a[0].localeCompare(b[0]))) {
        const cdef = this.controlDefs.get(cid) ?? {};
        const stats = controlStats[cid] ?? {};
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        const passed = stats.PASS ?? 0;
        const failed = (stats.FAIL ?? 0) + (stats.ERROR ?? 0);
        const passRate = total > 0 ? Math.round(passed / total * 1000) / 10 : 0;

        const adj = adjustments[cid] ?? {};
        const threshold = adj.threshold_adjustment ?? "standard";
        if (threshold === "strict") strictControls.push(cid);

        controls.push({
          controlId: cid,
          displayName: (cdef.display_name as string) ?? cid,
          citations, total, passed, failed, passRate, threshold,
        });
      }

      const gaps = controls.filter(c => (c.failed as number) > 0);

      sections.push({
        overlayId: oid,
        overlayName: (profile.name as string) ?? oid,
        triggeredBy: trigger,
        strictControls,
        controls,
        gaps,
        evidenceRetentionDays: (profile.evidence_retention_minimum_days as number) ?? 365,
        retentionMet: this.config.evidenceRetentionDays >= ((profile.evidence_retention_minimum_days as number) ?? 365),
      });
    }

    return sections;
  }

  private buildCertificationSection(): Record<string, unknown> | null {
    const profile = loadCertProfile("aiuc-1");
    if (!profile) return null;

    const controlStats = this.summary.control_pass_rates ?? {};
    const reqMap = (profile.aksi_to_requirement_map ?? {}) as Record<string, string[]>;
    const operatorItems = (profile.operator_action_required ?? []) as Record<string, string>[];

    const automated: Record<string, unknown>[] = [];
    let totalAutomated = 0;
    for (const [aksiId, reqIds] of Object.entries(reqMap).sort((a, b) => a[0].localeCompare(b[0]))) {
      const stats = controlStats[aksiId] ?? {};
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      const passed = stats.PASS ?? 0;
      const failed = stats.FAIL ?? 0;
      const flagged = stats.FLAG ?? 0;

      for (const reqId of reqIds) {
        totalAutomated++;
        automated.push({
          requirementId: reqId,
          aksiControl: aksiId,
          evidenceCount: total,
          passed, failed, flagged,
        });
      }
    }

    const operator = operatorItems.map(item => ({
      requirementId: item.requirement_id,
      description: item.description,
      category: item.category,
    }));

    const totalRequirements = totalAutomated + operator.length;
    const automatedPct = totalRequirements > 0 ? Math.round(totalAutomated / totalRequirements * 100) : 0;

    return {
      certificationId: "aiuc-1",
      certificationName: (profile.name as string) ?? "AIUC-1",
      automatedCoverage: automated,
      operatorActionRequired: operator,
      totalRequirements,
      automatedCount: totalAutomated,
      operatorCount: operator.length,
      automatedPercentage: automatedPct,
      evidenceCount: this.summary.total_evaluations,
      chainValid: this.summary.chain_valid,
    };
  }
}
