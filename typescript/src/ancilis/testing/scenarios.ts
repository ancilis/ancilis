/** ComplianceScenarios — pre-built test datasets for common compliance states. */

import { randomUUID } from "node:crypto";
import type { ControlResult, EvaluationResult } from "../engine/result.js";
import { ScanResult } from "./scan-result.js";

function makeEvaluation(
  controlResults: ControlResult[],
  options: {
    agentId?: string;
    mode?: "audit" | "enforce";
    toolName?: string;
    activeOverlays?: string[];
    dataClassifications?: string[];
  } = {},
): EvaluationResult {
  const { agentId = "test-agent", mode = "audit", activeOverlays = [], dataClassifications = [] } = options;
  const hasFailure = controlResults.some((cr) => cr.result === "FAIL" || cr.result === "ERROR");
  const decision = mode === "enforce" && hasFailure ? "BLOCK" : "ALLOW";

  return {
    evaluationId: randomUUID(),
    actionId: randomUUID(),
    timestamp: new Date().toISOString(),
    agentId,
    sourceType: "agent",
    mode,
    controlResults,
    decision,
    decisionReason: "Pre-built test scenario",
    activeOverlays,
    dataClassifications,
    totalDurationMs: 0,
  };
}

/**
 * Factory for pre-built compliance test scenarios.
 *
 * All scenarios work fully offline — no platform API, no DuckDB file.
 *
 * @example
 * const scenario = ComplianceScenarios.financialCompliant();
 * assertPostureAbove(scenario, 0.80);
 *
 * const failing = ComplianceScenarios.missingIdentity();
 * assertControlFails(failing, "PR-01");
 */
export class ComplianceScenarios {
  /**
   * All controls passing for a financial services overlay context.
   *
   * Simulates a well-configured agent with identity, scope, provenance,
   * and exposure controls all PASS. Active overlays: financial.
   */
  static financialCompliant(): ScanResult {
    const results: ControlResult[] = [
      {
        controlId: "PR-01",
        controlName: "Agent Identity & Authentication",
        result: "PASS",
        detail: "Agent identity verified.",
        evidenceData: { agentId: "test-agent", verificationResult: "verified" },
        durationMs: 0,
      },
      {
        controlId: "PR-02",
        controlName: "Scope & Boundary Enforcement",
        result: "PASS",
        detail: "Tool is allowed. Rate limit: 0/60 actions per minute.",
        evidenceData: { toolName: "test_tool", rateLimitOk: true },
        durationMs: 0,
      },
      {
        controlId: "PR-03",
        controlName: "Tool Provenance Verification",
        result: "PASS",
        detail: "Tool registered and approved.",
        evidenceData: { toolName: "test_tool", approved: true },
        durationMs: 0,
      },
      {
        controlId: "PR-04",
        controlName: "Data Exposure Prevention",
        result: "PASS",
        detail: "No sensitive data patterns detected.",
        evidenceData: { patternsDetected: [] },
        durationMs: 0,
      },
      {
        controlId: "PR-05",
        controlName: "Audit Trail Completeness",
        result: "PASS",
        detail: "Audit trail complete.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "DE-01",
        controlName: "Baseline Behavior Detection",
        result: "PASS",
        detail: "No anomalous baseline drift detected.",
        evidenceData: {},
        durationMs: 0,
      },
    ];
    const ev = makeEvaluation(results, {
      activeOverlays: ["financial"],
      dataClassifications: ["DC-03", "DC-07"],
    });
    return new ScanResult([ev]);
  }

  /**
   * PR-01 fails — agent identity is missing.
   *
   * Simulates an agent that forgot to configure its name, or is calling
   * from an unrecognized agentId. All other controls pass.
   */
  static missingIdentity(): ScanResult {
    const results: ControlResult[] = [
      {
        controlId: "PR-01",
        controlName: "Agent Identity & Authentication",
        result: "FAIL",
        detail: "Agent identity missing.",
        evidenceData: {
          agentId: null,
          verificationResult: "failed",
          failureReason: "agentId is empty or missing",
        },
        durationMs: 0,
      },
      {
        controlId: "PR-02",
        controlName: "Scope & Boundary Enforcement",
        result: "PASS",
        detail: "Tool is allowed.",
        evidenceData: { toolName: "test_tool" },
        durationMs: 0,
      },
      {
        controlId: "PR-03",
        controlName: "Tool Provenance Verification",
        result: "PASS",
        detail: "Tool registered.",
        evidenceData: { toolName: "test_tool" },
        durationMs: 0,
      },
      {
        controlId: "PR-04",
        controlName: "Data Exposure Prevention",
        result: "PASS",
        detail: "No sensitive data patterns detected.",
        evidenceData: { patternsDetected: [] },
        durationMs: 0,
      },
      {
        controlId: "PR-05",
        controlName: "Audit Trail Completeness",
        result: "PASS",
        detail: "Audit trail complete.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "DE-01",
        controlName: "Baseline Behavior Detection",
        result: "PASS",
        detail: "No anomalous baseline drift detected.",
        evidenceData: {},
        durationMs: 0,
      },
    ];
    const ev = makeEvaluation(results);
    return new ScanResult([ev]);
  }

  /**
   * Bare minimum passing scenario — only PR-01 scored, rest skipped.
   *
   * Useful for testing that your agent at least provides identity
   * before adding other controls.
   */
  static minimalViable(): ScanResult {
    const results: ControlResult[] = [
      {
        controlId: "PR-01",
        controlName: "Agent Identity & Authentication",
        result: "PASS",
        detail: "Agent identity verified.",
        evidenceData: { agentId: "test-agent", verificationResult: "verified" },
        durationMs: 0,
      },
      {
        controlId: "PR-02",
        controlName: "Scope & Boundary Enforcement",
        result: "SKIP",
        detail: "Control is disabled.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "PR-03",
        controlName: "Tool Provenance Verification",
        result: "SKIP",
        detail: "Control is disabled.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "PR-04",
        controlName: "Data Exposure Prevention",
        result: "SKIP",
        detail: "Control is disabled.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "PR-05",
        controlName: "Audit Trail Completeness",
        result: "SKIP",
        detail: "Control is disabled.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "DE-01",
        controlName: "Baseline Behavior Detection",
        result: "SKIP",
        detail: "Control is disabled.",
        evidenceData: {},
        durationMs: 0,
      },
    ];
    const ev = makeEvaluation(results);
    return new ScanResult([ev]);
  }

  /**
   * All controls failing — useful for testing assertion error messages.
   */
  static allFailing(): ScanResult {
    const results: ControlResult[] = [
      {
        controlId: "PR-01",
        controlName: "Agent Identity & Authentication",
        result: "FAIL",
        detail: "Agent identity missing.",
        evidenceData: { failureReason: "agentId is empty or missing" },
        durationMs: 0,
      },
      {
        controlId: "PR-02",
        controlName: "Scope & Boundary Enforcement",
        result: "FAIL",
        detail: "Tool is blocked.",
        evidenceData: { toolName: "blocked_tool" },
        durationMs: 0,
      },
      {
        controlId: "PR-03",
        controlName: "Tool Provenance Verification",
        result: "FAIL",
        detail: "Tool not registered.",
        evidenceData: { toolName: "unknown_tool" },
        durationMs: 0,
      },
      {
        controlId: "PR-04",
        controlName: "Data Exposure Prevention",
        result: "FLAG",
        detail: "Sensitive data patterns detected.",
        evidenceData: { patternsDetected: [{ type: "pii", count: 2 }] },
        durationMs: 0,
      },
      {
        controlId: "PR-05",
        controlName: "Audit Trail Completeness",
        result: "FAIL",
        detail: "Missing required audit fields.",
        evidenceData: {},
        durationMs: 0,
      },
      {
        controlId: "DE-01",
        controlName: "Baseline Behavior Detection",
        result: "FLAG",
        detail: "Anomalous behavior detected.",
        evidenceData: {},
        durationMs: 0,
      },
    ];
    const ev = makeEvaluation(results);
    return new ScanResult([ev]);
  }

  /**
   * Enforce mode with a failing control — decision is BLOCK.
   *
   * Useful for testing that enforce mode blocks when controls fail.
   */
  static enforceBlocked(): ScanResult {
    const results: ControlResult[] = [
      {
        controlId: "PR-01",
        controlName: "Agent Identity & Authentication",
        result: "FAIL",
        detail: "Agent identity missing.",
        evidenceData: { failureReason: "agentId is empty or missing" },
        durationMs: 0,
      },
      {
        controlId: "PR-02",
        controlName: "Scope & Boundary Enforcement",
        result: "PASS",
        detail: "Tool is allowed.",
        evidenceData: { toolName: "test_tool" },
        durationMs: 0,
      },
    ];
    const ev = makeEvaluation(results, { mode: "enforce" });
    return new ScanResult([ev]);
  }
}
