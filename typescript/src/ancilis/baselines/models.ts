/** Baseline and drift detection models. */

export interface ControlSnapshot {
  controlId: string;
  result: string; // "PASS" | "FAIL" | "FLAG" | "SKIP" | "ERROR"
  passRate: number; // 0.0–1.0
  totalEvaluations: number;
  evidenceWindowStart: string; // ISO timestamp
  evidenceWindowEnd: string; // ISO timestamp
}

export interface Baseline {
  baselineId: string;
  createdAt: string; // ISO timestamp
  agentId: string;
  overlayId: string | null;
  label: string;
  controlSnapshots: ControlSnapshot[];
  metadata: Record<string, unknown> | null;
  isActive: boolean;
}

export interface EvidenceDelta {
  newFailures: string[]; // evaluation IDs of new failures since baseline
  failureTools: string[]; // tool names involved in failures
}

export interface ControlDrift {
  controlId: string;
  controlName: string;
  baselineResult: string;
  baselinePassRate: number;
  currentResult: string;
  currentPassRate: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  firstFailureAt: string | null;
  failureCount: number;
  evidenceDelta: EvidenceDelta;
}

export interface DriftSummary {
  totalControls: number;
  regressed: number;
  degraded: number;
  stable: number;
}

export interface DriftReport {
  driftReportId: string;
  baselineId: string;
  baselineLabel: string;
  checkedAt: string; // ISO timestamp
  agentId: string;
  overlayId: string | null;
  overallStatus: "STABLE" | "DRIFTED";
  summary: DriftSummary;
  controlDrifts: ControlDrift[];
}
