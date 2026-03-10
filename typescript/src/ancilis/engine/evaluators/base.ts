/** Base interface for control evaluators. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";

export interface ControlEvaluator {
  controlId: string;
  controlName: string;
  evaluate(action: Action, config: ResolvedConfig): ControlResult;
}
