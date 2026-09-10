/** Unsigned native snapshot integrity inspection; never signer or reconstruction verification. */
import { z } from "zod";
import {
  canonicalEpisodeJSON,
  detached,
  EPISODE_REASONS,
  EPISODE_SURFACES,
  hashEpisodePayload,
  nativeDigestSchema as digest,
  nativeIdSchema as id,
  nativeInputSchema,
  nativeIntegerSchema as integer,
  nativeTimeSchema as timestamp,
  now,
  orderedSurfaces,
  validateObservationInput,
} from "./contract.js";
import type { EpisodeSurface } from "./contract.js";

const surfaces = z.array(z.enum(EPISODE_SURFACES)).max(5);
const openSchema = z
  .object({
    schema: z.literal("ancilis-episode-open/1"),
    tenant: id,
    episode: id,
    owner_source: id,
    open_nonce: z.string().regex(/^[0-9a-f]{32}$/),
    allowed_source_instances: z.array(id).min(1).max(16),
    expected_surfaces: surfaces.min(1),
    correlation_basis: z.literal("APPLICATION_ASSIGNED"),
    created_at: timestamp,
    policy_sha256: digest,
  })
  .strict();
const rowSchema = nativeInputSchema
  .extend({
    schema: z.literal("ancilis-observation/1"),
    tenant: id,
    episode: id,
    episode_open: digest,
    event_id: digest,
    source: z.object({ id, instance: id, sequence: integer.min(1) }).strict(),
    captured_at: timestamp,
    clock_basis: z.literal("COLLECTOR_CLOCK_ASSERTION"),
    clock_evidence_refs: z.array(digest).length(0),
  })
  .strict();
const coverageSchema = z
  .object({
    expected_surfaces: surfaces,
    observed_surfaces: surfaces,
    missing_surfaces: surfaces,
    complete: z.literal(false),
    lost_events: integer,
    incomplete_calls: integer,
    reasons: z.array(z.enum(EPISODE_REASONS)).max(EPISODE_REASONS.length),
    reconstruction_exclusions: z.array(z.unknown()).length(0),
  })
  .strict();
const snapshotSchema = z
  .object({
    schema: z.literal("ancilis-episode/1"),
    tenant: id,
    episode: id,
    open: openSchema,
    open_sha256: digest,
    revision: integer.min(1),
    revision_id: digest,
    previous_revision_id: digest.nullable(),
    observations: z.array(rowSchema).max(10000),
    coverage: coverageSchema,
    method: z.literal("ancilis-native-observation-ledger/1"),
    claims_basis: z.literal(
      "COLLECTOR_ASSERTION_NOT_INDEPENDENT_RECONSTRUCTION",
    ),
    determination_refs: z.array(digest).length(0),
    observation_chain_sha256: digest,
    revision_method: z.literal("ancilis-native-revision/2"),
  })
  .strict();
export type NativeVerificationReason =
  | "NATIVE_CHAIN_MATCH"
  | "NATIVE_CHAIN_MISMATCH"
  | "INVALID_NATIVE_SNAPSHOT"
  | "NATIVE_HISTORY_DISCARDED";
export interface NativeVerification {
  schema: "ancilis-verification/1";
  status: "UNVERIFIED" | "REJECTED";
  envelope_authenticated: false;
  protected_bodies: "NOT_REQUESTED";
  reconstruction: "UNSUPPORTED";
  policy_sha256: string;
  assessed_at: string;
  reasons: NativeVerificationReason[];
  verified_claim_refs: [];
}
export interface NativeVerificationOptions {
  expectedTenant?: string;
  assessedAt?: string;
}
const same = (a: unknown, b: unknown) =>
  canonicalEpisodeJSON(a) === canonicalEpisodeJSON(b);

/** Self-consistency is at most UNVERIFIED. No body resolver, trust root or network access is used. */
export function verifyEpisodeSnapshot(
  value: unknown,
  options: NativeVerificationOptions = {},
): NativeVerification {
  const result: NativeVerification = {
    schema: "ancilis-verification/1",
    status: "UNVERIFIED",
    envelope_authenticated: false,
    protected_bodies: "NOT_REQUESTED",
    reconstruction: "UNSUPPORTED",
    policy_sha256: hashEpisodePayload("ancilis-native-verification-policy/1", {
      schema: "ancilis-native-verification-policy/1",
      mode: "INTEGRITY_ONLY",
      revision_method: "ancilis-native-revision/2",
      expected_tenant: options.expectedTenant ?? null,
    }),
    assessed_at: options.assessedAt ?? now(),
    reasons: [],
    verified_claim_refs: [],
  };
  const rejected = (reason: NativeVerificationReason): NativeVerification => ({
    ...result,
    status: "REJECTED",
    reasons: [reason],
  });
  try {
    timestamp.parse(result.assessed_at);
    if (options.expectedTenant !== undefined) id.parse(options.expectedTenant);
    canonicalEpisodeJSON(value);
    const s = snapshotSchema.parse(value);
    const open = s.open;
    if (
      s.tenant !== open.tenant ||
      s.episode !== open.episode ||
      (options.expectedTenant !== undefined &&
        s.tenant !== options.expectedTenant)
    )
      return rejected("INVALID_NATIVE_SNAPSHOT");
    if (hashEpisodePayload("ancilis-episode-open/1", open) !== s.open_sha256)
      return rejected("INVALID_NATIVE_SNAPSHOT");
    if (
      !same(orderedSurfaces(open.expected_surfaces), open.expected_surfaces) ||
      new Set(open.allowed_source_instances).size !==
        open.allowed_source_instances.length
    )
      return rejected("INVALID_NATIVE_SNAPSHOT");
    if (
      s.revision < s.observations.length + 1 ||
      (s.revision === 1) !== (s.previous_revision_id === null)
    )
      return rejected("INVALID_NATIVE_SNAPSHOT");
    let chain = hashEpisodePayload("ancilis-native-observation-chain/1", {
      open_sha256: s.open_sha256,
    });
    let sequence = 0;
    const observed = new Set<EpisodeSurface>();
    const ids = new Set<string>();
    const artifacts = new Map<
      string,
      { sha256: string; byte_length: number }
    >();
    const calls = new Map<
      string,
      { started: boolean; ended: boolean; failed: boolean; next: number }
    >();
    const requiredReasons = new Set<string>();
    for (const row of s.observations) {
      const {
        schema: _schema,
        tenant: _tenant,
        episode: _episode,
        episode_open: _open,
        event_id: _id,
        source: _source,
        captured_at: _captured,
        clock_basis: _clock,
        clock_evidence_refs: _refs,
        ...manual
      } = row;
      validateObservationInput(manual);
      if (
        row.tenant !== s.tenant ||
        row.episode !== s.episode ||
        row.episode_open !== s.open_sha256 ||
        row.source.id !== open.owner_source ||
        !open.allowed_source_instances.includes(row.source.instance) ||
        row.source.sequence <= sequence
      )
        return rejected("INVALID_NATIVE_SNAPSHOT");
      sequence = row.source.sequence;
      const eventId = hashEpisodePayload("ancilis-observation-id/1", {
        tenant: row.tenant,
        episode_open: row.episode_open,
        source_instance: row.source.instance,
        call_id: row.call_id,
        phase: row.phase,
        chunk_index: row.chunk_index,
      });
      if (eventId !== row.event_id || ids.has(eventId))
        return rejected("INVALID_NATIVE_SNAPSHOT");
      ids.add(eventId);
      for (const a of row.artifacts) {
        const old = artifacts.get(a.artifact);
        if (
          old &&
          (old.sha256 !== a.sha256 || old.byte_length !== a.byte_length)
        )
          return rejected("INVALID_NATIVE_SNAPSHOT");
        artifacts.set(a.artifact, a);
      }
      for (const r of row.relationships)
        if (!artifacts.has(r.from_artifact) || !artifacts.has(r.to_artifact))
          return rejected("INVALID_NATIVE_SNAPSHOT");
      const call = calls.get(row.call_id) ?? {
        started: false,
        ended: false,
        failed: false,
        next: 0,
      };
      if (call.ended) return rejected("INVALID_NATIVE_SNAPSHOT");
      if (row.phase === "START") call.started = true;
      else if (row.phase === "CHUNK") {
        if (row.chunk_index !== call.next) {
          call.failed = true;
          requiredReasons.add("CHUNK_GAP");
        }
        call.next = (row.chunk_index ?? 0) + 1;
        observed.add(row.surface);
      } else {
        call.ended = true;
        call.failed ||= row.outcome !== "SUCCEEDED";
        if (row.outcome === "SUCCEEDED") observed.add(row.surface);
      }
      if (row.phase !== "START" && !call.started)
        requiredReasons.add("MISSING_START");
      calls.set(row.call_id, call);
      for (const reason of row.capture_gaps) requiredReasons.add(reason);
      chain = hashEpisodePayload("ancilis-native-observation-chain/1", {
        previous_observation_chain_sha256: chain,
        observation_sha256: hashEpisodePayload(
          "ancilis-observation-payload/1",
          row,
        ),
      });
    }
    if (chain !== s.observation_chain_sha256)
      return rejected("NATIVE_CHAIN_MISMATCH");
    const c = s.coverage;
    if (
      !same(c.expected_surfaces, open.expected_surfaces) ||
      !same(
        c.observed_surfaces,
        EPISODE_SURFACES.filter((x) => observed.has(x)),
      ) ||
      !same(
        c.missing_surfaces,
        open.expected_surfaces.filter((x) => !observed.has(x)),
      ) ||
      c.incomplete_calls !==
        [...calls.values()].filter((x) => !x.started || !x.ended || x.failed)
          .length ||
      !same(
        c.reasons,
        EPISODE_REASONS.filter((x) => c.reasons.includes(x)),
      ) ||
      [...requiredReasons].some(
        (x) => !c.reasons.includes(x as (typeof EPISODE_REASONS)[number]),
      )
    )
      return rejected("INVALID_NATIVE_SNAPSHOT");
    const revision = hashEpisodePayload("ancilis-native-revision/2", {
      open_sha256: s.open_sha256,
      revision: s.revision,
      previous_revision_id: s.previous_revision_id,
      observation_chain_sha256: chain,
      coverage: c,
    });
    if (revision !== s.revision_id) return rejected("NATIVE_CHAIN_MISMATCH");
    if (c.reasons.includes("DISCARDED_EPISODE")) {
      if (s.observations.length) return rejected("INVALID_NATIVE_SNAPSHOT");
      result.reasons.push("NATIVE_HISTORY_DISCARDED");
    }
    result.reasons.push("NATIVE_CHAIN_MATCH");
    return detached(result);
  } catch {
    return rejected("INVALID_NATIVE_SNAPSHOT");
  }
}
