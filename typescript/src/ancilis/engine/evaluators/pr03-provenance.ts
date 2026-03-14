/** PR-03: Tool Provenance Verification evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";
import { type ToolRegistry, ToolStatus } from "../registry.js";

export class PR03ProvenanceEvaluator implements ControlEvaluator {
  controlId = "PR-03";
  controlName = "Tool Provenance Verification";
  private registry: ToolRegistry;

  constructor(registry: ToolRegistry) {
    this.registry = registry;
  }

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();
    const toolName = action.tool.name;

    const evidence: Record<string, unknown> = {
      tool_name: toolName,
      tool_version: action.tool.version ?? null,
    };

    const entry = this.registry.lookup(toolName);

    if (!entry) {
      evidence.registered = false;
      evidence.hash_match = "no_hash";
      return {
        controlId: this.controlId, controlName: this.controlName,
        result: "FAIL", detail: `Tool '${toolName}' is not registered.`,
        evidenceData: evidence, durationMs: performance.now() - start,
      };
    }

    evidence.registered = true;
    evidence.registry_entry = {
      name: entry.name,
      version: entry.version ?? null,
      status: entry.status,
    };

    // FAIL if tool is OBSERVED (not approved by operator)
    if (entry.status === ToolStatus.OBSERVED) {
      evidence.hash_match = "no_hash";
      return {
        controlId: this.controlId, controlName: this.controlName,
        result: "FAIL",
        detail: `Tool '${toolName}' is registered but not approved. Run: ancilis approve-tool ${toolName}`,
        evidenceData: evidence, durationMs: performance.now() - start,
      };
    }

    // Check version
    if (action.tool.version && entry.version && action.tool.version !== entry.version) {
      evidence.hash_match = "no_hash";
      return {
        controlId: this.controlId, controlName: this.controlName,
        result: "FAIL",
        detail: `Tool version mismatch: action has '${action.tool.version}', registry has '${entry.version}'.`,
        evidenceData: evidence, durationMs: performance.now() - start,
      };
    }

    // Check description hash
    if (action.tool.descriptionHash && entry.descriptionHash) {
      if (action.tool.descriptionHash !== entry.descriptionHash) {
        evidence.hash_match = false;
        return {
          controlId: this.controlId, controlName: this.controlName,
          result: "FAIL", detail: "Description hash drift detected — possible tampering.",
          evidenceData: evidence, durationMs: performance.now() - start,
        };
      }
      evidence.hash_match = true;
    } else {
      evidence.hash_match = "no_hash";
      // FLAG if tool is APPROVED but no hash baseline exists
      if (entry.status === ToolStatus.APPROVED && !entry.descriptionHash) {
        return {
          controlId: this.controlId, controlName: this.controlName,
          result: "FLAG",
          detail: "Tool approved but no description hash baseline — provenance not fully verifiable.",
          evidenceData: evidence, durationMs: performance.now() - start,
        };
      }
    }

    return {
      controlId: this.controlId, controlName: this.controlName,
      result: "PASS", detail: "Tool provenance verified.",
      evidenceData: evidence, durationMs: performance.now() - start,
    };
  }
}
