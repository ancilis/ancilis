/** Cryptographic hash chain for evidence records. */

import { createHash } from "node:crypto";

/** Genesis seed — the "previous_hash" for the very first record in any chain. */
export const GENESIS_SEED = createHash("sha256").update("ancilis-genesis-v1").digest("hex");

const FLOAT_KEYS = new Set(["current_rate_vs_baseline", "duration_ms", "total_duration_ms"]);

function pythonJsonStringifyString(value: string): string {
  return JSON.stringify(value).replace(/[\u0080-\uFFFF]/g, (char) =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function canonicalJsonStringify(value: unknown, key?: string): string {
  if (value === null) return "null";

  if (typeof value === "string" || typeof value === "boolean") {
    return typeof value === "string" ? pythonJsonStringifyString(value) : JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return JSON.stringify(String(value));
    }
    if (key && FLOAT_KEYS.has(key) && Number.isInteger(value)) {
      return value.toFixed(1);
    }
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(item => canonicalJsonStringify(item)).join(",")}]`;
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${entries
      .map(([entryKey, entryValue]) => `${pythonJsonStringifyString(entryKey)}:${canonicalJsonStringify(entryValue, entryKey)}`)
      .join(",")}}`;
  }

  return pythonJsonStringifyString(String(value));
}

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
  outputSummary?: string | null;
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
  if (fields.outputSummary !== undefined && fields.outputSummary !== null) {
    payload.output_summary = fields.outputSummary;
  }
  return canonicalJsonStringify(payload);
}

/** SHA-256 hash of the canonical payload. */
export function computeHash(canonical: string): string {
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}
