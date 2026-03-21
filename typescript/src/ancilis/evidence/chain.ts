/** Cryptographic hash chain for evidence records. */

import { createHash } from "node:crypto";

/** Genesis seed — the "previous_hash" for the very first record in any chain. */
export const GENESIS_SEED = createHash("sha256").update("ancilis-genesis-v1").digest("hex");

/** Build the canonical JSON string used as hash input. Fields sorted alphabetically. */
export function canonicalPayload(fields: {
  evaluationId: string;
  timestamp: string;
  agentId: string;
  sourceType?: string;
  toolName: string;
  decision: string;
  mode: string;
  controlResults: Array<Record<string, unknown>>;
  activeOverlays: string[];
  dataClassifications: string[];
  activeCertifications: string[];
  totalDurationMs: number;
  previousHash: string;
}): string {
  const payload: Record<string, unknown> = {
    active_certifications: fields.activeCertifications,
    active_overlays: fields.activeOverlays,
    agent_id: fields.agentId,
    control_results: fields.controlResults,
    data_classifications: fields.dataClassifications,
    decision: fields.decision,
    evaluation_id: fields.evaluationId,
    mode: fields.mode,
    previous_hash: fields.previousHash,
    source_type: fields.sourceType ?? "agent",
    timestamp: fields.timestamp,
    tool_name: fields.toolName,
    total_duration_ms: fields.totalDurationMs,
  };
  return JSON.stringify(payload);
}

/** SHA-256 hash of the canonical payload. */
export function computeHash(canonical: string): string {
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}
