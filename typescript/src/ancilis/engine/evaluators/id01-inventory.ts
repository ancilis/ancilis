/** ID-01: Agent Inventory & Registry evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";

export class ID01InventoryEvaluator implements ControlEvaluator {
  controlId = "ID-01";
  controlName = "Agent Inventory & Registry";

  evaluate(_action: Action, config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const agentName = (config.agentName ?? "").trim();
    const agentId = (config.agentId ?? "").trim();

    const hasName = agentName.length > 0;
    const hasId = agentId.length > 0;

    const evidence: Record<string, unknown> = {
      inventory_status: "unregistered",
      fields: {
        name: agentName || null,
        id: agentId || null,
      },
    };

    if (hasName && hasId) {
      evidence["inventory_status"] = "registered";
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: `Agent registered in inventory: name='${agentName}', id='${agentId}'.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    if (hasName && !hasId) {
      evidence["inventory_status"] = "partial";
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: `Agent '${agentName}' has a name but no agent_id. Add agent.agent_id in ancilis.yaml for complete inventory registration.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "FAIL",
      detail: "Agent is not registered. Set agent.name and agent.agent_id in ancilis.yaml.",
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
