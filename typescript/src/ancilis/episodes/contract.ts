/** Native collector assertions. Hashes in this module do not authenticate evidence. */
import { createHash } from "node:crypto";
import { types } from "node:util";
import { z } from "zod";

export const EPISODE_SURFACES = [
  "document",
  "tool",
  "execution",
  "memory",
  "output",
] as const;
export const EPISODE_REASONS = [
  "CONTENT_NOT_CAPTURED",
  "UNMAPPED_TOOL",
  "SDK_CLOSED",
  "EPISODE_FINISHED",
  "EPISODE_DISCARDED",
  "CONTEXT_EXIT_MISMATCH",
  "UNCORRELATED_CALL",
  "CAPTURE_CALLBACK_FAILED",
  "UNSUPPORTED_RETURN_PROTOCOL",
  "LEDGER_EVENT_CAP",
  "LEDGER_BYTE_CAP",
  "LEDGER_EPISODE_CAP",
  "ATTACHMENT_CAP",
  "BODY_SIZE_CAP",
  "EVENT_CONFLICT",
  "ARTIFACT_REBIND",
  "INVALID_OBSERVATION",
  "MISSING_START",
  "MISSING_END",
  "CHUNK_GAP",
  "SOURCE_MISMATCH",
  "DISCARDED_EPISODE",
  "REVISION_EXHAUSTED",
  "OTHER",
] as const;
export type EpisodeSurface = (typeof EPISODE_SURFACES)[number];
export type EpisodeReason = (typeof EPISODE_REASONS)[number];
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const safe = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const refs = z.array(digest).max(64);
const time = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/)
  .refine((s) => {
    const n = Date.parse(s);
    return (
      Number.isFinite(n) &&
      new Date(n).toISOString().slice(0, 19) === s.slice(0, 19)
    );
  });
export const observationAuthority = z
  .object({
    principal: id.nullable(),
    service: id.nullable(),
    delegation: id.nullable(),
    approval: id.nullable(),
    scope: id.nullable(),
    basis: z.literal("APPLICATION_ASSERTION"),
  })
  .strict();
export const artifactSchema = z
  .object({
    artifact: id,
    sha256: digest,
    byte_length: safe.max(16777216),
    role: z.enum(["INPUT", "OUTPUT"]),
    access_scope: id,
    classification_receipt_refs: refs,
  })
  .strict();
export type ContentReference = z.infer<typeof artifactSchema>;
const relationshipSchema = z
  .object({
    kind: z.enum([
      "ACCESSED",
      "OPERAND",
      "BYTE_EQUAL",
      "ASSERTED_ORIGIN",
      "WRITTEN",
      "READ",
      "SEMANTIC_PROPOSAL",
    ]),
    from_artifact: id,
    to_artifact: id,
    basis: z.literal("APPLICATION_ASSERTION"),
    method: z.literal("ancilis-application-assertion/1"),
    evidence_refs: refs,
  })
  .strict();
export type EpisodeRelationship = z.infer<typeof relationshipSchema>;
const inputSchema = z
  .object({
    call_id: id,
    occurred_at: time,
    surface: z.enum(EPISODE_SURFACES),
    operation: z.enum(["REQUEST", "READ", "EXECUTE", "WRITE", "RECEIVE"]),
    phase: z.enum(["START", "CHUNK", "END"]),
    chunk_index: safe.nullable(),
    outcome: z.enum([
      "STARTED",
      "OBSERVED",
      "SUCCEEDED",
      "FAILED",
      "CANCELLED",
      "CLOSED_EARLY",
      "CAPTURE_FAILED",
    ]),
    authority: observationAuthority,
    artifacts: z.array(artifactSchema).max(64),
    relationships: z.array(relationshipSchema).max(64),
    provenance_refs: refs,
    capture_gaps: z.array(z.enum(EPISODE_REASONS)).max(64),
  })
  .strict();
export type ObservationInput = z.infer<typeof inputSchema>;
export type Observation = ObservationInput & {
  schema: "ancilis-observation/1";
  tenant: string;
  episode: string;
  episode_open: string;
  event_id: string;
  source: { id: string; instance: string; sequence: number };
  captured_at: string;
  clock_basis: "COLLECTOR_CLOCK_ASSERTION";
  clock_evidence_refs: [];
};
export interface NativePolicy {
  schema: "ancilis-native-policy/1";
  max_events: number;
  max_bytes: number;
  max_episodes: number;
  max_attachments: number;
  max_body_bytes: number;
  max_diagnostic_keys: number;
  strict_capture: boolean;
}
export interface EpisodeOpen {
  schema: "ancilis-episode-open/1";
  tenant: string;
  episode: string;
  owner_source: string;
  open_nonce: string;
  allowed_source_instances: string[];
  expected_surfaces: EpisodeSurface[];
  correlation_basis: "APPLICATION_ASSIGNED";
  created_at: string;
  policy_sha256: string;
}
export interface EpisodeCoverage {
  expected_surfaces: EpisodeSurface[];
  observed_surfaces: EpisodeSurface[];
  missing_surfaces: EpisodeSurface[];
  complete: false;
  lost_events: number;
  incomplete_calls: number;
  reasons: EpisodeReason[];
  reconstruction_exclusions: [];
}
export interface EpisodeSnapshot {
  schema: "ancilis-episode/1";
  tenant: string;
  episode: string;
  open: EpisodeOpen;
  open_sha256: string;
  revision: number;
  revision_id: string;
  previous_revision_id: string | null;
  observations: Observation[];
  coverage: EpisodeCoverage;
  method: "ancilis-native-observation-ledger/1";
  claims_basis: "COLLECTOR_ASSERTION_NOT_INDEPENDENT_RECONSTRUCTION";
  determination_refs: [];
}
export class EpisodeError extends Error {
  constructor(readonly code: EpisodeReason) {
    super(code);
    this.name = "EpisodeError";
  }
}
export const validId = (value: unknown): string => {
  if (!id.safeParse(value).success)
    throw new EpisodeError("INVALID_OBSERVATION");
  return value as string;
};
export const now = (): string =>
  new Date().toISOString().replace(/(\.\d{3})Z$/, "$1000Z");
export const orderedSurfaces = (
  values: readonly EpisodeSurface[],
): EpisodeSurface[] => {
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.length > 5 ||
    new Set(values).size !== values.length ||
    values.some((x) => !EPISODE_SURFACES.includes(x))
  )
    throw new EpisodeError("INVALID_OBSERVATION");
  return EPISODE_SURFACES.filter((x) => values.includes(x));
};
function scalar(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(++i);
      if (!(n >= 0xdc00 && n <= 0xdfff))
        throw new EpisodeError("INVALID_OBSERVATION");
    } else if (c >= 0xdc00 && c <= 0xdfff)
      throw new EpisodeError("INVALID_OBSERVATION");
  }
}
function compare(a: string, b: string): number {
  const x = Array.from(a),
    y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d) return d;
  }
  return x.length - y.length;
}
/** Closed canonical JSON subset; does not call getters, toJSON, or legacy chain helpers. */
export function canonicalEpisodeJSON(value: unknown): string {
  const seen = new Set<object>();
  function encode(v: unknown, depth: number): string {
    if (depth > 64) throw new EpisodeError("INVALID_OBSERVATION");
    if (v === null || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || Object.is(v, -0))
        throw new EpisodeError("INVALID_OBSERVATION");
      return String(v);
    }
    if (typeof v === "string") {
      scalar(v);
      return JSON.stringify(v);
    }
    if (typeof v !== "object" || types.isProxy(v) || seen.has(v))
      throw new EpisodeError("INVALID_OBSERVATION");
    const proto = Object.getPrototypeOf(v);
    if (!Array.isArray(v) && proto !== Object.prototype && proto !== null)
      throw new EpisodeError("INVALID_OBSERVATION");
    seen.add(v);
    try {
      const ds = Object.getOwnPropertyDescriptors(v);
      if (Reflect.ownKeys(ds).some((k) => typeof k !== "string"))
        throw new EpisodeError("INVALID_OBSERVATION");
      if (Array.isArray(v)) {
        const items = [];
        for (let i = 0; i < v.length; i++) {
          const d = ds[String(i)];
          if (!d || !("value" in d))
            throw new EpisodeError("INVALID_OBSERVATION");
          items.push(encode(d.value, depth + 1));
        }
        if (
          Object.keys(ds).some(
            (k) => k !== "length" && !/^(0|[1-9]\d*)$/.test(k),
          )
        )
          throw new EpisodeError("INVALID_OBSERVATION");
        return "[" + items.join(",") + "]";
      }
      return (
        "{" +
        Object.keys(ds)
          .sort(compare)
          .map((k) => {
            scalar(k);
            if (
              ["__proto__", "prototype", "constructor"].includes(k) ||
              !("value" in ds[k]!)
            )
              throw new EpisodeError("INVALID_OBSERVATION");
            return JSON.stringify(k) + ":" + encode(ds[k]!.value, depth + 1);
          })
          .join(",") +
        "}"
      );
    } finally {
      seen.delete(v);
    }
  }
  return encode(value, 0);
}
export const hashEpisodePayload = (domain: string, value: unknown): string =>
  createHash("sha256")
    .update(domain + "\n")
    .update(canonicalEpisodeJSON(value))
    .digest("hex");
export const detached = <T>(v: T): T =>
  JSON.parse(canonicalEpisodeJSON(v)) as T;
export function validateObservationInput(value: unknown): ObservationInput {
  canonicalEpisodeJSON(value);
  const result = inputSchema.safeParse(value);
  if (!result.success) throw new EpisodeError("INVALID_OBSERVATION");
  const d = result.data;
  if (
    (d.phase === "START" &&
      (d.outcome !== "STARTED" || d.chunk_index !== null)) ||
    (d.phase === "CHUNK" &&
      (d.outcome !== "OBSERVED" || d.chunk_index === null)) ||
    (d.phase === "END" &&
      (["STARTED", "OBSERVED"].includes(d.outcome) || d.chunk_index !== null))
  )
    throw new EpisodeError("INVALID_OBSERVATION");
  return d;
}
/** Explicit bytes only. The returned reference retains no body or key. */
export class ContentEvidence {
  private constructor() {}
  static fromBytes(
    artifact: string,
    data: Uint8Array,
    options: {
      role?: "INPUT" | "OUTPUT";
      accessScope?: string;
      classificationReceiptRefs?: string[];
    } = {},
  ): ContentReference {
    if (!(data instanceof Uint8Array) || data.byteLength > 1048576)
      throw new EpisodeError("BODY_SIZE_CAP");
    return artifactSchema.parse({
      artifact,
      sha256: createHash("sha256").update(data).digest("hex"),
      byte_length: data.byteLength,
      role: options.role ?? "OUTPUT",
      access_scope: options.accessScope ?? "application",
      classification_receipt_refs: options.classificationReceiptRefs ?? [],
    });
  }
}
