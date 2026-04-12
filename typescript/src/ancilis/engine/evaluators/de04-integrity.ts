/** DE-04: Evidence Integrity Verification evaluator. */

import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ResolvedConfig } from "../../config/index.js";
import type { ControlEvaluator } from "./base.js";

/**
 * Minimal synchronous interface for the evidence store, enabling testability
 * without requiring a live DuckDB connection. Implement this with a sync
 * adapter over EvidenceStore when running DE-04 in production health checks.
 */
export interface DE04StoreAdapter {
  count(): number;
  verifyChain(): { valid: boolean; errors: string[] };
}

export class DE04IntegrityEvaluator implements ControlEvaluator {
  controlId = "DE-04";
  controlName = "Evidence Integrity Verification";

  private readonly _store: DE04StoreAdapter | null;

  constructor(store: DE04StoreAdapter | null = null) {
    this._store = store;
  }

  evaluate(_action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();

    const evidence: Record<string, unknown> = {
      chain_valid: false,
      total_records: 0,
      errors: [],
    };

    if (this._store === null) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: "No evidence store configured — cannot verify chain integrity.",
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    const total = this._store.count();
    evidence["total_records"] = total;

    if (total === 0) {
      evidence["chain_valid"] = true;
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FLAG",
        detail: "Evidence store is empty — no chain to verify.",
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    const { valid: chainValid, errors } = this._store.verifyChain();
    evidence["chain_valid"] = chainValid;
    evidence["errors"] = errors;

    if (!chainValid) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "FAIL",
        detail: `Evidence chain integrity failure — ${errors.length} error(s) detected.`,
        evidenceData: evidence,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "PASS",
      detail: `Evidence chain integrity verified — ${total} record(s), no tampering detected.`,
      evidenceData: evidence,
      durationMs: performance.now() - start,
    };
  }
}
