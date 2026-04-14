/** ScanResult — wrapper around evaluation results for assertion helpers. */

import type { ControlResult, EvaluationResult } from "../engine/result.js";

const SCORED_RESULTS = new Set(["PASS", "FAIL", "FLAG", "ERROR"]);

/**
 * Wraps one or more EvaluationResult objects with computed posture score.
 *
 * Returned by ComplianceScenarios factory methods and accepted by compliance
 * assertion helpers.
 */
export class ScanResult {
  readonly evaluations: EvaluationResult[];

  constructor(evaluations: EvaluationResult[]) {
    if (evaluations.length === 0) {
      throw new Error("ScanResult requires at least one EvaluationResult");
    }
    this.evaluations = evaluations;
  }

  static fromSingle(evaluation: EvaluationResult): ScanResult {
    return new ScanResult([evaluation]);
  }

  /** Pass rate across all scored controls in all evaluations. SKIP excluded from denominator. */
  get score(): number {
    let passCount = 0;
    let total = 0;
    for (const ev of this.evaluations) {
      for (const cr of ev.controlResults) {
        if (SCORED_RESULTS.has(cr.result)) {
          total += 1;
          if (cr.result === "PASS") passCount += 1;
        }
      }
    }
    return total > 0 ? passCount / total : 1.0;
  }

  /** Return the ControlResult for the given controlId (latest evaluation). */
  getControlResult(controlId: string): ControlResult | undefined {
    for (let i = this.evaluations.length - 1; i >= 0; i--) {
      const ev = this.evaluations[i]!;
      for (const cr of ev.controlResults) {
        if (cr.controlId === controlId) return cr;
      }
    }
    return undefined;
  }

  /** Decision from the most recent evaluation. */
  decision(): string {
    return this.evaluations[this.evaluations.length - 1]!.decision;
  }

  toString(): string {
    return `ScanResult(evaluations=${this.evaluations.length}, score=${this.score.toFixed(2)}, decision=${this.decision()})`;
  }
}
