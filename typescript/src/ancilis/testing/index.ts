/**
 * ancilis/testing — test utilities for agent compliance testing.
 *
 * Provides mocks, assertion helpers, and pre-built scenarios so developers
 * can write unit tests for their agent code against compliance requirements
 * without hitting the platform API or writing to disk.
 *
 * @example
 * import {
 *   MockEvidenceStore,
 *   FakeProducer,
 *   ComplianceScenarios,
 *   assertControlPasses,
 *   assertPostureAbove,
 * } from "ancilis/testing";
 *
 * test("identity control passes", () => {
 *   const scenario = ComplianceScenarios.financialCompliant();
 *   assertControlPasses(scenario, "PR-01");
 *   assertPostureAbove(scenario, 0.80);
 * });
 */

export { MockEvidenceStore } from "./mock-store.js";
export { FakeProducer } from "./fake-producer.js";
export { ScanResult } from "./scan-result.js";
export { ComplianceScenarios } from "./scenarios.js";
export {
  assertControlPasses,
  assertControlFails,
  assertControlFlags,
  assertPostureAbove,
  assertDecisionAllows,
  assertDecisionBlocks,
} from "./assertions.js";
export { makeTestConfig, makeAction } from "./helpers.js";
export type { MakeTestConfigOptions, MakeActionOptions } from "./helpers.js";
