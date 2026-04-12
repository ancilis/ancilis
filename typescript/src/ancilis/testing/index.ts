/**
 * @ancilis/testing — test utilities for Ancilis SDK.
 *
 * Import from `ancilis/testing`:
 * ```ts
 * import {
 *   MockEvidenceStore,
 *   FakeProducer,
 *   ComplianceScenarios,
 *   expectControlToPass,
 *   expectControlToFail,
 *   expectPostureAbove,
 *   setupAncilisMatchers,
 * } from "ancilis/testing";
 * ```
 *
 * All utilities work fully offline — no platform API calls or filesystem
 * access required.
 */

export { MockEvidenceStore } from "./mock-evidence-store.js";
export { FakeProducer } from "./fake-producer.js";
export type { FakeEvaluationResult } from "./fake-producer.js";
export { ComplianceScenarios } from "./scenarios.js";
export {
  AssertionError,
  expectControlToPass,
  expectControlToFail,
  expectControlToSkip,
  expectDecisionToBe,
  expectAllowed,
  expectBlocked,
  expectPostureAbove,
  expectAllPassed,
  setupAncilisMatchers,
} from "./matchers.js";
