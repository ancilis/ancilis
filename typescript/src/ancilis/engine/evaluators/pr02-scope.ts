/** PR-02: Permission Scope Enforcement evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";
import { matchesToolList } from "../tool-matching.js";

export interface RateTracker {
  getActionCount(agentId: string): number;
}

export class PR02ScopeEvaluator implements ControlEvaluator {
  controlId = "PR-02";
  controlName = "Permission Scope Enforcement";
  private rateTracker: RateTracker;

  constructor(rateTracker?: RateTracker) {
    this.rateTracker = rateTracker ?? { getActionCount: () => 0 };
  }

  evaluate(action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();
    const toolName = action.tool.name;

    const evidence: Record<string, unknown> = {
      tool_name: toolName,
      allowed_tools: config.toolsAllowed,
      blocked_tools: config.toolsBlocked,
    };

    // Blocked takes precedence
    if (config.toolsBlocked.length > 0 && matchesToolList(toolName, config.toolsBlocked)) {
      evidence.scope_check = "out_of_scope";
      evidence.failure_reason = "tool is explicitly blocked";
      return {
        controlId: this.controlId, controlName: this.controlName,
        result: "FAIL", detail: `Tool '${toolName}' is explicitly blocked.`,
        evidenceData: evidence, durationMs: performance.now() - start,
      };
    }

    // Check allowed list
    if (config.toolsAllowed.length > 0 && !matchesToolList(toolName, config.toolsAllowed)) {
      evidence.scope_check = "out_of_scope";
      evidence.failure_reason = "tool not in allowlist";
      return {
        controlId: this.controlId, controlName: this.controlName,
        result: "FAIL", detail: `Tool '${toolName}' is not in the allowlist.`,
        evidenceData: evidence, durationMs: performance.now() - start,
      };
    }

    // Check blocked destinations
    if (config.scopeBlockedDestinations.length > 0) {
      const destination = this.extractDestination(action);
      if (destination && config.scopeBlockedDestinations.includes(destination)) {
        evidence.scope_check = "out_of_scope";
        evidence.failure_reason = "destination is blocked";
        evidence.destination = destination;
        return {
          controlId: this.controlId, controlName: this.controlName,
          result: "FAIL", detail: `Destination '${destination}' is blocked.`,
          evidenceData: evidence, durationMs: performance.now() - start,
        };
      }
    }

    // Check rate limit
    if (config.scopeMaxActionsPerMinute !== null) {
      const count = this.rateTracker.getActionCount(action.agentId);
      if (count >= config.scopeMaxActionsPerMinute) {
        evidence.scope_check = "out_of_scope";
        evidence.failure_reason = "rate limit exceeded";
        return {
          controlId: this.controlId, controlName: this.controlName,
          result: "FAIL", detail: "Rate limit exceeded.",
          evidenceData: evidence, durationMs: performance.now() - start,
        };
      }
    }

    evidence.scope_check = "within_scope";
    return {
      controlId: this.controlId, controlName: this.controlName,
      result: "PASS", detail: "Action within declared permission scope.",
      evidenceData: evidence, durationMs: performance.now() - start,
    };
  }

  private extractDestination(action: Action): string | null {
    const raw = action.parameters.raw;
    for (const key of ["url", "destination", "endpoint", "host", "server"]) {
      if (key in raw) {
        const val = raw[key];
        if (typeof val === "string") return val;
      }
    }
    return null;
  }
}
