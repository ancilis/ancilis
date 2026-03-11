/** Evaluation result models. */

export interface ControlResult {
  controlId: string;
  controlName: string;
  result: "PASS" | "FAIL" | "SKIP" | "ERROR" | "FLAG";
  detail: string;
  evidenceData: Record<string, unknown>;
  durationMs: number;
  displayName?: string;
  displayDetail?: string;
  remediationHint?: string;
}

export interface EvaluationResult {
  evaluationId: string;
  actionId: string;
  timestamp: string;
  agentId: string;
  mode: "audit" | "enforce";
  controlResults: ControlResult[];
  decision: "ALLOW" | "BLOCK" | "FLAG";
  decisionReason: string;
  activeOverlays: string[];
  dataClassifications: string[];
  totalDurationMs: number;
}
