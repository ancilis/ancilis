/** Deterministic, threshold-based drift detection — mirrors Python DriftDetector. */

import { randomUUID } from "node:crypto";
import type { Baseline, ControlDrift, DriftReport } from "./models.js";

export const DEGRADATION_THRESHOLD = 0.10;
export const MAJOR_DEGRADATION_THRESHOLD = 0.20;

export interface ControlStats {
  controlName: string;
  pass: number;
  fail: number;
  flag: number;
  skip: number;
  error: number;
  total: number;
}

export function computeControlStats(
  rows: Array<{ control_results: unknown }>,
): Record<string, ControlStats> {
  const stats: Record<string, ControlStats> = {};
  for (const row of rows) {
    const raw = row.control_results;
    const results = typeof raw === "string" ? JSON.parse(raw) as Array<Record<string, unknown>> : raw as Array<Record<string, unknown>>;
    for (const cr of results) {
      const cid = cr.control_id as string;
      if (!stats[cid]) {
        stats[cid] = {
          controlName: (cr.control_name as string | undefined) ?? cid,
          pass: 0, fail: 0, flag: 0, skip: 0, error: 0, total: 0,
        };
      }
      const result = ((cr.result as string | undefined) ?? "SKIP").toUpperCase();
      const key = (["pass", "fail", "flag", "skip", "error"].includes(result.toLowerCase())
        ? result.toLowerCase()
        : "skip") as keyof Pick<ControlStats, "pass" | "fail" | "flag" | "skip" | "error">;
      stats[cid]![key]++;
      stats[cid]!.total++;
    }
  }
  return stats;
}

export function passRate(stats: ControlStats): number {
  if (stats.total === 0) return 1.0;
  return stats.pass / stats.total;
}

export function dominantResult(stats: ControlStats): string {
  if (stats.total === 0) return "SKIP";
  for (const key of ["pass", "fail", "flag", "error", "skip"] as const) {
    if (stats[key] === stats.total) return key.toUpperCase();
  }
  const best = (["pass", "fail", "flag", "error", "skip"] as const).reduce(
    (a, b) => (stats[a] >= stats[b] ? a : b),
  );
  return best.toUpperCase();
}

function classifySeverity(
  baselinePassRate: number,
  baselineResult: string,
  currentPassRate: number,
  currentResult: string,
): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null {
  const drop = baselinePassRate - currentPassRate;
  if (drop <= 0) return null; // improved or unchanged

  // 100% pass rate that now fails/flags is CRITICAL
  if (baselinePassRate >= 1.0 && currentPassRate < 1.0 && ["FAIL", "FLAG"].includes(currentResult)) {
    return "CRITICAL";
  }

  // PASS → FAIL or PASS → FLAG is HIGH
  if (baselineResult === "PASS" && ["FAIL", "FLAG"].includes(currentResult)) {
    return "HIGH";
  }

  if (drop >= MAJOR_DEGRADATION_THRESHOLD) return "MEDIUM";
  if (drop >= DEGRADATION_THRESHOLD) return "LOW";

  return null;
}

export class DriftDetector {
  detect(
    baseline: Baseline,
    currentStats: Record<string, ControlStats>,
    firstFailures: Record<string, string | null>,
    newFailureIds: Record<string, string[]>,
    failureTools: Record<string, string[]>,
    checkedAt?: string,
  ): DriftReport {
    const now = checkedAt ?? new Date().toISOString();
    const drifts: ControlDrift[] = [];

    for (const snap of baseline.controlSnapshots) {
      const cid = snap.controlId;
      const cur = currentStats[cid];

      if (!cur) {
        // Control disappeared — treat as drift if it was passing
        if (snap.result === "PASS" && snap.passRate > 0) {
          drifts.push({
            controlId: cid,
            controlName: cid,
            baselineResult: snap.result,
            baselinePassRate: snap.passRate,
            currentResult: "SKIP",
            currentPassRate: 0.0,
            severity: "HIGH",
            firstFailureAt: null,
            failureCount: 0,
            evidenceDelta: { newFailures: [], failureTools: [] },
          });
        }
        continue;
      }

      const cRate = passRate(cur);
      const cResult = dominantResult(cur);
      const severity = classifySeverity(snap.passRate, snap.result, cRate, cResult);
      if (severity === null) continue;

      drifts.push({
        controlId: cid,
        controlName: cur.controlName,
        baselineResult: snap.result,
        baselinePassRate: snap.passRate,
        currentResult: cResult,
        currentPassRate: cRate,
        severity,
        firstFailureAt: firstFailures[cid] ?? null,
        failureCount: cur.fail,
        evidenceDelta: {
          newFailures: newFailureIds[cid] ?? [],
          failureTools: failureTools[cid] ?? [],
        },
      });
    }

    const overallStatus: "STABLE" | "DRIFTED" = drifts.length > 0 ? "DRIFTED" : "STABLE";
    const severities = drifts.map(d => d.severity);
    const regressed = severities.filter(s => s === "CRITICAL" || s === "HIGH").length;
    const degraded = severities.filter(s => s === "MEDIUM" || s === "LOW").length;

    return {
      driftReportId: randomUUID(),
      baselineId: baseline.baselineId,
      baselineLabel: baseline.label,
      checkedAt: now,
      agentId: baseline.agentId,
      overlayId: baseline.overlayId,
      overallStatus,
      summary: {
        totalControls: baseline.controlSnapshots.length,
        regressed,
        degraded,
        stable: baseline.controlSnapshots.length - drifts.length,
      },
      controlDrifts: drifts,
    };
  }
}
