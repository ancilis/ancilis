/** PR-01: Agent Identity & Authentication evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";

export class PR01IdentityEvaluator implements ControlEvaluator {
  controlId = "PR-01";
  controlName = "Agent Identity & Authentication";

  evaluate(action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();

    if (!action.agentId) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: "Agent identity missing.",
        evidenceData: {
          agent_id: null,
          agent_owner: action.agentOwner ?? null,
          verification_result: "failed",
          failure_reason: "agent_id is empty or missing",
        },
        durationMs: performance.now() - start,
      };
    }

    if (action.agentId !== config.agentName) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: `Agent identity mismatch: '${action.agentId}' does not match configured '${config.agentName}'.`,
        evidenceData: {
          agent_id: action.agentId,
          agent_owner: action.agentOwner ?? null,
          verification_result: "failed",
          failure_reason: "agent_id does not match configured agent name",
        },
        durationMs: performance.now() - start,
      };
    }

    if (config.agentOwner && action.agentOwner !== config.agentOwner) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: `Agent owner mismatch: '${action.agentOwner ?? ""}' does not match configured '${config.agentOwner}'.`,
        evidenceData: {
          agent_id: action.agentId,
          agent_owner: action.agentOwner ?? null,
          verification_result: "failed",
          failure_reason: "agent_owner does not match configured owner",
        },
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: "Agent identity verified.",
      evidenceData: {
        agent_id: action.agentId,
        agent_owner: action.agentOwner ?? null,
        verification_result: "verified",
      },
      durationMs: performance.now() - start,
    };
  }
}
