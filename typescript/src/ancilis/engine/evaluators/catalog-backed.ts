/** Catalog-backed evaluator for controls that depend on attached or imported evidence. */

import type { ResolvedConfig } from "../../config/index.js";
import type { Action } from "../action.js";
import type { ControlResult } from "../result.js";
import type { ControlEvaluator } from "./base.js";

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function stringifyEvidenceSurface(action: Action): string {
  return JSON.stringify({
    parameters: action.parameters?.raw ?? {},
    context: action.context ?? {},
    tool: action.tool ?? {},
    sourceType: action.sourceType ?? null,
    producerType: action.producerType ?? null,
    producerVersion: action.producerVersion ?? null,
  }).toLowerCase();
}

function manualAttestationStatus(action: Action, controlId: string): unknown {
  const raw = action.parameters?.raw ?? {};
  const attestations = raw["manual_attestations"];
  if (!attestations || typeof attestations !== "object" || Array.isArray(attestations)) {
    return undefined;
  }
  return (attestations as Record<string, unknown>)[controlId];
}

function attestationPassed(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === "string") {
    return ["pass", "passed", "true", "attested", "approved"].includes(value.trim().toLowerCase());
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    return attestationPassed(record["status"] ?? record["result"]);
  }
  return false;
}

export class CatalogBackedEvaluator implements ControlEvaluator {
  controlId: string;
  controlName: string;
  private evidenceKeywords: string[];

  constructor(controlId: string, controlName: string, evidenceKeywords: string[] = []) {
    this.controlId = controlId;
    this.controlName = controlName;
    this.evidenceKeywords = evidenceKeywords;
  }

  evaluate(action: Action, _config: ResolvedConfig): ControlResult {
    const start = performance.now();
    const attestation = manualAttestationStatus(action, this.controlId);
    const keywords = this.evidenceKeywords.map(normalize).filter(Boolean);
    const evidenceSurface = stringifyEvidenceSurface(action);
    const matchedKeywords = keywords.filter(keyword => evidenceSurface.includes(keyword));

    const evidenceData: Record<string, unknown> = {
      support_mode: "catalog_backed_attestation",
      evidence_keywords: this.evidenceKeywords,
      matched_keywords: matchedKeywords,
      manual_attestation_present: attestation !== undefined,
    };

    if (attestationPassed(attestation)) {
      return {
        controlId: this.controlId,
        controlName: this.controlName,
        result: "PASS",
        detail: `Catalog-backed attestation accepted attached evidence for ${this.controlId}.`,
        evidenceData,
        durationMs: performance.now() - start,
      };
    }

    return {
      controlId: this.controlId,
      controlName: this.controlName,
      result: "FLAG",
      detail: matchedKeywords.length > 0
        ? `Catalog-backed attestation found evidence hints for ${this.controlId}; explicit attestation is still required.`
        : `Catalog-backed attestation requires explicit attestation for ${this.controlId}.`,
      evidenceData,
      durationMs: performance.now() - start,
    };
  }
}
