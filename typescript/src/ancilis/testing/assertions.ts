/** Compliance assertion helpers for use in vitest/jest tests. */

import type { EvaluationResult } from "../engine/result.js";
import { ScanResult } from "./scan-result.js";

type ScanOrResult = ScanResult | EvaluationResult;

function toScanResult(target: ScanOrResult): ScanResult {
  if (target instanceof ScanResult) return target;
  return ScanResult.fromSingle(target);
}

function availableControls(result: ScanResult): string[] {
  if (result.evaluations.length === 0) return [];
  return result.evaluations[result.evaluations.length - 1]!.controlResults.map((cr) => cr.controlId);
}

function failingControls(result: ScanResult): string[] {
  const failing: string[] = [];
  for (const ev of result.evaluations) {
    for (const cr of ev.controlResults) {
      if (cr.result === "FAIL" || cr.result === "ERROR" || cr.result === "FLAG") {
        failing.push(`${cr.controlId}=${cr.result}: ${cr.detail}`);
      }
    }
  }
  return failing;
}

/**
 * Assert that the given control passed.
 *
 * Throws AssertionError with detailed context if the control did not pass.
 *
 * @example
 * assertControlPasses(scan, "PR-01");
 */
export function assertControlPasses(scan: ScanOrResult, controlId: string): void {
  const result = toScanResult(scan);
  const cr = result.getControlResult(controlId);
  if (cr === undefined) {
    throw new Error(
      `Control '${controlId}' was not evaluated. Available controls: ${availableControls(result).join(", ")}`,
    );
  }
  if (cr.result !== "PASS") {
    throw new Error(
      `Expected control '${controlId}' to PASS but got '${cr.result}'.\n  Detail: ${cr.detail}\n  Evidence: ${JSON.stringify(cr.evidenceData)}`,
    );
  }
}

/**
 * Assert that the given control failed (result is FAIL or ERROR).
 *
 * @example
 * assertControlFails(scan, "PR-01");
 */
export function assertControlFails(scan: ScanOrResult, controlId: string): void {
  const result = toScanResult(scan);
  const cr = result.getControlResult(controlId);
  if (cr === undefined) {
    throw new Error(
      `Control '${controlId}' was not evaluated. Available controls: ${availableControls(result).join(", ")}`,
    );
  }
  if (cr.result !== "FAIL" && cr.result !== "ERROR") {
    throw new Error(
      `Expected control '${controlId}' to FAIL but got '${cr.result}'.\n  Detail: ${cr.detail}\n  Evidence: ${JSON.stringify(cr.evidenceData)}`,
    );
  }
}

/**
 * Assert that the given control raised a FLAG.
 *
 * @example
 * assertControlFlags(scan, "DE-01");
 */
export function assertControlFlags(scan: ScanOrResult, controlId: string): void {
  const result = toScanResult(scan);
  const cr = result.getControlResult(controlId);
  if (cr === undefined) {
    throw new Error(
      `Control '${controlId}' was not evaluated. Available controls: ${availableControls(result).join(", ")}`,
    );
  }
  if (cr.result !== "FLAG") {
    throw new Error(
      `Expected control '${controlId}' to FLAG but got '${cr.result}'.\n  Detail: ${cr.detail}\n  Evidence: ${JSON.stringify(cr.evidenceData)}`,
    );
  }
}

/**
 * Assert that the overall posture score is above a threshold.
 *
 * Score is the pass rate across all scored controls (SKIP excluded).
 *
 * @param threshold - Float in [0.0, 1.0]. For example, 0.80 means 80% pass rate.
 *
 * @example
 * assertPostureAbove(scan, 0.80);
 */
export function assertPostureAbove(scan: ScanOrResult, threshold: number): void {
  const result = toScanResult(scan);
  const score = result.score;
  if (score < threshold) {
    throw new Error(
      `Posture score ${(score * 100).toFixed(1)}% is below required threshold ${(threshold * 100).toFixed(1)}%.\n  Failing controls: ${failingControls(result).join("; ")}`,
    );
  }
}

/**
 * Assert that the most recent evaluation decision is ALLOW.
 *
 * @example
 * assertDecisionAllows(scan);
 */
export function assertDecisionAllows(scan: ScanOrResult): void {
  const result = toScanResult(scan);
  const decision = result.decision();
  if (decision !== "ALLOW") {
    throw new Error(
      `Expected decision ALLOW but got '${decision}'.\n  Failing controls: ${failingControls(result).join("; ")}`,
    );
  }
}

/**
 * Assert that the most recent evaluation decision is BLOCK.
 *
 * @example
 * assertDecisionBlocks(scan);
 */
export function assertDecisionBlocks(scan: ScanOrResult): void {
  const result = toScanResult(scan);
  const decision = result.decision();
  if (decision !== "BLOCK") {
    throw new Error(`Expected decision BLOCK but got '${decision}'.`);
  }
}
