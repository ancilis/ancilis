/** Baseline and drift detection module exports. */

export { BaselineManager } from "./manager.js";
export { DriftDetector, computeControlStats, passRate, dominantResult, DEGRADATION_THRESHOLD, MAJOR_DEGRADATION_THRESHOLD } from "./drift.js";
export type { Baseline, ControlSnapshot, ControlDrift, DriftReport, DriftSummary, EvidenceDelta } from "./models.js";
