/**
 * Compliance assertion helpers for Vitest / Jest.
 *
 * These are plain functions (not custom matchers) that throw descriptive
 * errors on failure, matching the style of the Python `assert_control_passes`
 * helpers.  They work with any test framework.
 *
 * @example
 * ```ts
 * import { expectControlToPass, expectPostureAbove } from "ancilis/testing";
 *
 * const { evaluation } = await producer.evaluate("read_file");
 * expectControlToPass(evaluation, "PR-01");
 * expectDecisionToBe(evaluation, "ALLOW");
 * ```
 */

import type { EvaluationResult, ControlResult } from "../engine/result.js";

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

function findControl(evaluation: EvaluationResult, controlId: string): ControlResult {
  const result = evaluation.controlResults.find((r) => r.controlId === controlId);
  if (!result) {
    const available = evaluation.controlResults.map((r) => r.controlId).join(", ");
    throw new AssertionError(
      `Control "${controlId}" not found in evaluation. ` +
        `Available controls: ${available || "(none)"}`,
    );
  }
  return result;
}

function passRate(evaluations: EvaluationResult[]): number {
  if (evaluations.length === 0) return 1;
  const allowed = evaluations.filter((e) => e.decision === "ALLOW").length;
  return allowed / evaluations.length;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/** Thrown by compliance assertion helpers when an assertion fails. */
export class AssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AncilisAssertionError";
  }
}

// ---------------------------------------------------------------------------
// Per-evaluation assertions
// ---------------------------------------------------------------------------

/**
 * Assert that `controlId` PASSED in `evaluation`.
 *
 * @throws {AssertionError} if the control did not pass.
 */
export function expectControlToPass(
  evaluation: EvaluationResult,
  controlId: string,
): void {
  const cr = findControl(evaluation, controlId);
  if (cr.result !== "PASS") {
    throw new AssertionError(
      `Expected control "${controlId}" to PASS, but got "${cr.result}".\n` +
        `  Detail: ${cr.detail}\n` +
        `  Tool: ${evaluation.controlResults[0]?.controlId ?? "(unknown)"}`,
    );
  }
}

/**
 * Assert that `controlId` FAILED (result is `FAIL` or `ERROR`) in `evaluation`.
 *
 * @throws {AssertionError} if the control did not fail.
 */
export function expectControlToFail(
  evaluation: EvaluationResult,
  controlId: string,
): void {
  const cr = findControl(evaluation, controlId);
  if (cr.result !== "FAIL" && cr.result !== "ERROR") {
    throw new AssertionError(
      `Expected control "${controlId}" to FAIL, but got "${cr.result}".\n` +
        `  Detail: ${cr.detail}`,
    );
  }
}

/**
 * Assert that `controlId` was SKIPPED in `evaluation`.
 *
 * @throws {AssertionError} if the control was not skipped.
 */
export function expectControlToSkip(
  evaluation: EvaluationResult,
  controlId: string,
): void {
  const cr = findControl(evaluation, controlId);
  if (cr.result !== "SKIP") {
    throw new AssertionError(
      `Expected control "${controlId}" to be SKIP, but got "${cr.result}".\n` +
        `  Detail: ${cr.detail}`,
    );
  }
}

/**
 * Assert that the overall decision matches `expected`.
 *
 * @throws {AssertionError} if the decision does not match.
 */
export function expectDecisionToBe(
  evaluation: EvaluationResult,
  expected: "ALLOW" | "BLOCK" | "FLAG",
): void {
  if (evaluation.decision !== expected) {
    throw new AssertionError(
      `Expected decision to be "${expected}", but got "${evaluation.decision}".\n` +
        `  Reason: ${evaluation.decisionReason}`,
    );
  }
}

/**
 * Assert that the evaluation was ALLOWED.
 *
 * @throws {AssertionError} if the decision is not ALLOW.
 */
export function expectAllowed(evaluation: EvaluationResult): void {
  expectDecisionToBe(evaluation, "ALLOW");
}

/**
 * Assert that the evaluation was BLOCKED.
 *
 * @throws {AssertionError} if the decision is not BLOCK.
 */
export function expectBlocked(evaluation: EvaluationResult): void {
  expectDecisionToBe(evaluation, "BLOCK");
}

// ---------------------------------------------------------------------------
// Multi-evaluation posture assertions
// ---------------------------------------------------------------------------

/**
 * Assert that the pass-rate across `evaluations` is above `threshold` (0–1).
 *
 * A "pass" is any evaluation whose decision is `ALLOW`.
 *
 * @param evaluations  Array of `EvaluationResult` objects.
 * @param threshold    Minimum acceptable pass-rate, e.g. `0.80` for 80 %.
 *
 * @throws {AssertionError} if the posture falls at or below the threshold.
 */
export function expectPostureAbove(
  evaluations: EvaluationResult[],
  threshold: number,
): void {
  const rate = passRate(evaluations);
  if (rate <= threshold) {
    const pct = Math.round(rate * 100);
    const tPct = Math.round(threshold * 100);
    throw new AssertionError(
      `Expected posture above ${tPct}%, but got ${pct}% ` +
        `(${evaluations.filter((e) => e.decision === "ALLOW").length}/${evaluations.length} ALLOW).`,
    );
  }
}

/**
 * Assert that all evaluations in `evaluations` have decision `ALLOW`.
 *
 * @throws {AssertionError} if any evaluation is not ALLOW.
 */
export function expectAllPassed(evaluations: EvaluationResult[]): void {
  const failures = evaluations.filter((e) => e.decision !== "ALLOW");
  if (failures.length > 0) {
    const summary = failures
      .map((e) => `  - decision=${e.decision}: ${e.decisionReason}`)
      .join("\n");
    throw new AssertionError(
      `Expected all evaluations to ALLOW, but ${failures.length} did not:\n${summary}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Vitest / Jest custom matchers (optional — call setupAncilisMatchers once)
// ---------------------------------------------------------------------------

const customMatchers = {
  toPassControl(received: EvaluationResult, controlId: string) {
    try {
      expectControlToPass(received, controlId);
      return { pass: true, message: () => `Expected control "${controlId}" NOT to pass.` };
    } catch (e) {
      return { pass: false, message: () => (e as Error).message };
    }
  },

  toFailControl(received: EvaluationResult, controlId: string) {
    try {
      expectControlToFail(received, controlId);
      return { pass: true, message: () => `Expected control "${controlId}" NOT to fail.` };
    } catch (e) {
      return { pass: false, message: () => (e as Error).message };
    }
  },

  toSkipControl(received: EvaluationResult, controlId: string) {
    try {
      expectControlToSkip(received, controlId);
      return { pass: true, message: () => `Expected control "${controlId}" NOT to be skipped.` };
    } catch (e) {
      return { pass: false, message: () => (e as Error).message };
    }
  },

  toHaveDecision(received: EvaluationResult, expected: "ALLOW" | "BLOCK" | "FLAG") {
    try {
      expectDecisionToBe(received, expected);
      return { pass: true, message: () => `Expected decision NOT to be "${expected}".` };
    } catch (e) {
      return { pass: false, message: () => (e as Error).message };
    }
  },

  toBeAllowed(received: EvaluationResult) {
    try {
      expectAllowed(received);
      return { pass: true, message: () => `Expected evaluation NOT to be ALLOWED.` };
    } catch (e) {
      return { pass: false, message: () => (e as Error).message };
    }
  },

  toBeBlocked(received: EvaluationResult) {
    try {
      expectBlocked(received);
      return { pass: true, message: () => `Expected evaluation NOT to be BLOCKED.` };
    } catch (e) {
      return { pass: false, message: () => (e as Error).message };
    }
  },
};

/** Minimal interface satisfied by both Vitest and Jest `expect`. */
export interface ExpectLike {
  extend(matchers: Record<string, unknown>): void;
}

/**
 * Register Ancilis custom matchers with Vitest or Jest.
 *
 * Pass your test framework's `expect` function to register the matchers:
 * ```ts
 * // vitest.setup.ts  (or inside a describe block)
 * import { expect } from "vitest";
 * import { setupAncilisMatchers } from "ancilis/testing";
 * setupAncilisMatchers(expect);
 * ```
 *
 * After setup you can write:
 * ```ts
 * expect(evaluation).toPassControl("PR-01");
 * expect(evaluation).toBeAllowed();
 * ```
 *
 * If no argument is provided the function falls back to `globalThis.expect`
 * (useful in environments that run with `globals: true`).
 */
export function setupAncilisMatchers(expectFn?: ExpectLike): void {
  const target: ExpectLike | undefined =
    expectFn ??
    ((globalThis as Record<string, unknown>).expect as ExpectLike | undefined);

  if (target && typeof target.extend === "function") {
    target.extend(customMatchers);
  }
}
