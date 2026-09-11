/** Explicit, advisory native collection. Persistence and reconstruction are separate capabilities. */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomUUID } from "node:crypto";
import { types } from "node:util";
import {
  canonicalEpisodeJSON,
  detached,
  EpisodeError,
  EPISODE_REASONS,
  EPISODE_SURFACES,
  hashEpisodePayload,
  hashCanonical,
  now,
  orderedSurfaces,
  validId,
  validateObservationInput,
} from "./contract.js";
import type {
  CaptureGap,
  ContentReference,
  EpisodeCoverage,
  EpisodeOpen,
  EpisodeReason,
  EpisodeRelationship,
  EpisodeSnapshot,
  EpisodeSurface,
  NativePolicy,
  Observation,
  ObservationInput,
} from "./contract.js";

export interface EpisodeOptions {
  tenant: string;
  source: string;
  sourceInstance?: string;
  maxEvents?: number;
  maxBytes?: number;
  maxEpisodes?: number;
  maxAttachments?: number;
  maxBodyBytes?: number;
  maxDiagnosticKeys?: number;
  strictCapture?: boolean;
}
export interface CaptureFrame {
  phase: ObservationInput["phase"];
  args: readonly unknown[];
  kwargs: Record<string, never>;
  result: unknown;
  error: unknown;
  chunk_index: number | null;
}
export interface CaptureResult {
  artifacts?: readonly ContentReference[];
  relationships?: readonly EpisodeRelationship[];
}
export interface AttachmentOptions {
  name: string;
  surface: EpisodeSurface;
  operation: ObservationInput["operation"];
  capture?: (frame: CaptureFrame) => CaptureResult | null | undefined;
}
export interface AttachmentDiagnostic {
  name: string;
  surface: EpisodeSurface;
  started: number;
  completed: number;
  failed: number;
  cancelled: number;
  events_admitted: number;
  active: boolean;
}
export interface EpisodeDiagnostics {
  storage: "MEMORY_ONLY";
  closed: boolean;
  events: number;
  accounted_bytes: number;
  episodes: number;
  lost: number;
  discarded_events: number;
  discarded_bytes: number;
  reasons: Partial<Record<EpisodeReason, number>>;
  attachments: AttachmentDiagnostic[];
  reconstruction: "UNAVAILABLE";
  semantic_recovery: "UNQUALIFIED";
}
export interface FlushReport {
  storage: "MEMORY_ONLY";
  admitted: number;
  pending: 0;
  durable: 0;
  lost: number;
}
interface Registration {
  original: AnyFunction;
  wrapped: AnyFunction;
  options: AttachmentOptions;
  diagnostic: AttachmentDiagnostic;
  active: boolean;
}
type AnyFunction = (this: any, ...args: any[]) => any;
const context = new AsyncLocalStorage<{
  owner: EpisodeClient;
  episode: EpisodeHandle;
}>();
const owners = new WeakMap<object, EpisodeClient>();
const maximum = Number.MAX_SAFE_INTEGER;
const nativeAsyncGeneratorPrototype = Object.getPrototypeOf(
  Object.getPrototypeOf((async function* () {})()),
);
function isAsyncGenerator(value: object): boolean {
  let p: object | null = value;
  for (let i = 0; p && i < 8; i++) {
    if (types.isProxy(p)) return false;
    if (p === nativeAsyncGeneratorPrototype) return true;
    p = Object.getPrototypeOf(p);
  }
  return false;
}
const increment = (n: number, amount = 1) => Math.min(maximum, n + amount);
const authority = () => ({
  principal: null,
  service: null,
  delegation: null,
  approval: null,
  scope: null,
  basis: "APPLICATION_ASSERTION" as const,
});

export class EpisodeHandle {
  private readonly opened: EpisodeOpen;
  readonly openHash: string;
  private rows: Observation[] = [];
  private ids = new Map<
    string,
    { comparison: string; observation: Observation }
  >();
  private artifacts = new Map<
    string,
    { sha256: string; byte_length: number }
  >();
  private calls = new Map<
    string,
    { started: boolean; ended: boolean; failed: boolean; nextChunk: number }
  >();
  private observed = new Set<EpisodeSurface>();
  private reasons = new Set<EpisodeReason>();
  private lost = 0;
  private revision = 1;
  private revisionId: string;
  private chain: string;
  private incompleteCalls = 0;
  private unterminatedCalls = 0;
  private previous: string | null = null;
  private bytes = 0;
  private finished = false;
  private discarded = false;
  private activeContexts = 0;
  private inFlight = 0;
  constructor(
    readonly owner: EpisodeClient,
    id: string,
    surfaces: EpisodeSurface[],
    private saturated = false,
  ) {
    this.opened = {
      schema: "ancilis-episode-open/1",
      tenant: owner.tenant,
      episode: id,
      owner_source: owner.source,
      open_nonce: randomBytes(16).toString("hex"),
      allowed_source_instances: [owner.sourceInstance],
      expected_surfaces: surfaces,
      correlation_basis: "APPLICATION_ASSIGNED",
      created_at: now(),
      policy_sha256: hashEpisodePayload(
        "ancilis-native-policy/1",
        owner.policy,
      ),
    };
    this.openHash = hashEpisodePayload("ancilis-episode-open/1", this.opened);
    if (saturated) {
      this.lost = 1;
      this.reasons.add("LEDGER_EPISODE_CAP");
    }
    this.chain = hashEpisodePayload("ancilis-native-observation-chain/1", {
      open_sha256: this.openHash,
    });
    this.revisionId = this.hashRevision();
  }
  get id(): string {
    return this.opened.episode;
  }
  _expected(): EpisodeSurface[] {
    return [...this.opened.expected_surfaces];
  }
  _enter(): void {
    this.activeContexts++;
  }
  _exit(): void {
    this.activeContexts = Math.max(0, this.activeContexts - 1);
  }
  _start(): void {
    this.inFlight++;
  }
  _end(): void {
    this.inFlight = Math.max(0, this.inFlight - 1);
  }
  _available(): boolean {
    return (
      !this.saturated &&
      !this.finished &&
      !this.discarded &&
      !this.owner.isClosed
    );
  }
  _unavailableReason(): EpisodeReason {
    return this.owner.isClosed
      ? "SDK_CLOSED"
      : this.discarded
        ? "EPISODE_DISCARDED"
        : this.finished
          ? "EPISODE_FINISHED"
          : "LEDGER_EPISODE_CAP";
  }
  _captureLoss(reason: EpisodeReason): void {
    if (this.revision === maximum) {
      this.owner._reason("REVISION_EXHAUSTED");
      this.finished = true;
      return;
    }
    this.lost = increment(this.lost);
    this.reasons.add(reason);
    this.advance();
  }
  private coverage(): EpisodeCoverage {
    const expected = this.opened.expected_surfaces;
    return {
      expected_surfaces: [...expected],
      observed_surfaces: EPISODE_SURFACES.filter((s) => this.observed.has(s)),
      missing_surfaces: expected.filter((s) => !this.observed.has(s)),
      complete: false,
      lost_events: this.lost,
      incomplete_calls: this.incompleteCalls,
      reasons: EPISODE_REASONS.filter((r) => this.reasons.has(r)),
      reconstruction_exclusions: [],
    };
  }
  private hashRevision(): string {
    return hashEpisodePayload("ancilis-native-revision/2", {
      open_sha256: this.openHash,
      revision: this.revision,
      previous_revision_id: this.previous,
      observation_chain_sha256: this.chain,
      coverage: this.coverage(),
    });
  }
  private advance(): void {
    if (this.revision === maximum) {
      this.owner._reason("REVISION_EXHAUSTED");
      this.finished = true;
      return;
    }
    this.previous = this.revisionId;
    this.revision++;
    this.revisionId = this.hashRevision();
  }
  /** Caller-assigned facts only; duplicates retain the first capture timestamp/sequence. */
  observe(raw: ObservationInput): Observation | undefined {
    if (this.revision === maximum) {
      this.owner._reason("REVISION_EXHAUSTED");
      if (this.owner.policy.strict_capture)
        throw new EpisodeError("REVISION_EXHAUSTED");
      return undefined;
    }
    if (
      this.saturated &&
      !this.owner.isClosed &&
      !this.finished &&
      !this.discarded
    ) {
      this.owner._loss("LEDGER_EPISODE_CAP", this);
      if (this.owner.policy.strict_capture)
        throw new EpisodeError("LEDGER_EPISODE_CAP");
      return undefined;
    }
    if (!this._available()) throw new EpisodeError(this._unavailableReason());
    let data: ObservationInput;
    try {
      data = validateObservationInput(raw);
    } catch {
      this.owner._loss("INVALID_OBSERVATION", this);
      throw new EpisodeError("INVALID_OBSERVATION");
    }
    if (
      data.artifacts.some(
        (a) => a.byte_length > this.owner.policy.max_body_bytes,
      )
    ) {
      this.owner._loss("BODY_SIZE_CAP", this);
      throw new EpisodeError("BODY_SIZE_CAP");
    }
    const eventId = hashEpisodePayload("ancilis-observation-id/1", {
      tenant: this.owner.tenant,
      episode_open: this.openHash,
      source_instance: this.owner.sourceInstance,
      call_id: data.call_id,
      phase: data.phase,
      chunk_index: data.chunk_index,
    });
    const fixed = {
      ...data,
      schema: "ancilis-observation/1" as const,
      tenant: this.owner.tenant,
      episode: this.id,
      episode_open: this.openHash,
      event_id: eventId,
      source: { id: this.owner.source, instance: this.owner.sourceInstance },
      clock_basis: "COLLECTOR_CLOCK_ASSERTION" as const,
      clock_evidence_refs: [],
    };
    const comparison = canonicalEpisodeJSON(fixed);
    const previous = this.ids.get(eventId);
    if (previous) {
      if (previous.comparison === comparison)
        return detached(previous.observation);
      this.owner._loss("EVENT_CONFLICT", this);
      throw new EpisodeError("EVENT_CONFLICT");
    }
    const existingCall = this.calls.get(data.call_id);
    if (existingCall?.ended) {
      this.owner._loss("INVALID_OBSERVATION", this);
      throw new EpisodeError("INVALID_OBSERVATION");
    }
    const staged = new Map<string, { sha256: string; byte_length: number }>();
    for (const a of data.artifacts) {
      const old = staged.get(a.artifact) ?? this.artifacts.get(a.artifact);
      if (
        old &&
        (old.sha256 !== a.sha256 || old.byte_length !== a.byte_length)
      ) {
        this.owner._loss("ARTIFACT_REBIND", this);
        throw new EpisodeError("ARTIFACT_REBIND");
      }
      staged.set(a.artifact, { sha256: a.sha256, byte_length: a.byte_length });
    }
    for (const relation of data.relationships) {
      if (
        ![relation.from_artifact, relation.to_artifact].every(
          (id) => staged.has(id) || this.artifacts.has(id),
        )
      )
        throw new EpisodeError("INVALID_OBSERVATION");
    }
    const observation: Observation = {
      ...fixed,
      source: { ...fixed.source, sequence: this.owner._nextSequence() },
      captured_at: now(),
      clock_evidence_refs: [],
    };
    // Conservative accounting covers the canonical record, dedupe bytes and indexes, not process RSS.
    const observationBytes = canonicalEpisodeJSON(observation);
    const nextChain = hashEpisodePayload("ancilis-native-observation-chain/1", {
      previous_observation_chain_sha256: this.chain,
      observation_sha256: hashCanonical(
        "ancilis-observation-payload/1",
        observationBytes,
      ),
    });
    const bytes =
      Buffer.byteLength(observationBytes) +
      Buffer.byteLength(comparison) +
      512 +
      staged.size * 384;
    if (!this.owner._reserve(bytes, this)) return undefined;
    for (const [id, a] of staged) this.artifacts.set(id, a);
    this.bytes += bytes;
    this.chain = nextChain;
    this.rows.push(observation);
    this.ids.set(eventId, { comparison, observation });
    const call = this.calls.get(data.call_id) ?? {
      started: false,
      ended: false,
      failed: false,
      nextChunk: 0,
    };
    const wasIncomplete = existingCall
      ? !existingCall.started || !existingCall.ended || existingCall.failed
      : false;
    const wasUnterminated = existingCall ? !existingCall.ended : false;
    if (data.phase === "START") call.started = true;
    else if (data.phase === "CHUNK") {
      if (data.chunk_index !== call.nextChunk) {
        this.reasons.add("CHUNK_GAP");
        call.failed = true;
      }
      call.nextChunk = (data.chunk_index ?? 0) + 1;
      this.observed.add(data.surface);
    } else {
      call.ended = true;
      call.failed ||= data.outcome !== "SUCCEEDED";
      if (data.outcome === "SUCCEEDED") this.observed.add(data.surface);
    }
    if (data.phase !== "START" && !call.started)
      this.reasons.add("MISSING_START");
    this.incompleteCalls +=
      Number(!call.started || !call.ended || call.failed) -
      Number(wasIncomplete);
    this.unterminatedCalls += Number(!call.ended) - Number(wasUnterminated);
    this.calls.set(data.call_id, call);
    for (const reason of data.capture_gaps) this.reasons.add(reason);
    this.advance();
    return detached(observation);
  }
  inspect(): EpisodeSnapshot {
    return detached({
      schema: "ancilis-episode/1",
      tenant: this.owner.tenant,
      episode: this.id,
      open: this.opened,
      open_sha256: this.openHash,
      revision: this.revision,
      revision_id: this.revisionId,
      previous_revision_id: this.previous,
      observations: this.rows,
      observation_chain_sha256: this.chain,
      revision_method: "ancilis-native-revision/2",
      coverage: this.coverage(),
      method: "ancilis-native-observation-ledger/1",
      claims_basis: "COLLECTOR_ASSERTION_NOT_INDEPENDENT_RECONSTRUCTION",
      determination_refs: [],
    } as EpisodeSnapshot);
  }
  finish(): void {
    if (this.finished) return;
    this.finished = true;
    if (this.revision === maximum) {
      this.owner._reason("REVISION_EXHAUSTED");
      return;
    }
    if (this.unterminatedCalls) this.reasons.add("MISSING_END");
    this.advance();
  }
  _discard(): { events: number; bytes: number } {
    if (this.revision === maximum) throw new EpisodeError("REVISION_EXHAUSTED");
    if (this.activeContexts || this.inFlight) throw new EpisodeError("OTHER");
    const stats = { events: this.rows.length, bytes: this.bytes };
    this.discarded = true;
    this.rows = [];
    this.ids.clear();
    this.artifacts.clear();
    this.calls.clear();
    this.observed.clear();
    this.incompleteCalls = 0;
    this.unterminatedCalls = 0;
    this.chain = hashEpisodePayload("ancilis-native-observation-chain/1", {
      open_sha256: this.openHash,
    });
    this.bytes = 0;
    this.reasons.add("DISCARDED_EPISODE");
    this.advance();
    return stats;
  }
}

export class EpisodeClient {
  readonly tenant: string;
  readonly source: string;
  readonly sourceInstance: string;
  readonly policy: NativePolicy;
  private episodes = new Map<string, EpisodeHandle>();
  private registrations = new Map<AnyFunction, Registration>();
  private wrapped = new Map<AnyFunction, Registration>();
  private mcp = new WeakMap<
    object,
    { adapter: object; signature: string; capture: unknown }
  >();
  private sequence = 0;
  private events = 0;
  private bytes = 0;
  private loss = 0;
  private discardedEvents = 0;
  private discardedBytes = 0;
  private reasons: Partial<Record<EpisodeReason, number>> = {};
  private closed = false;
  constructor(options: EpisodeOptions) {
    this.tenant = validId(options.tenant);
    this.source = validId(options.source);
    this.sourceInstance = validId(options.sourceInstance ?? randomUUID());
    this.policy = Object.freeze({
      schema: "ancilis-native-policy/1",
      max_events: options.maxEvents ?? 4096,
      max_bytes: options.maxBytes ?? 16777216,
      max_episodes: options.maxEpisodes ?? 256,
      max_attachments: options.maxAttachments ?? 256,
      max_body_bytes: options.maxBodyBytes ?? 1048576,
      max_diagnostic_keys: options.maxDiagnosticKeys ?? 128,
      strict_capture: options.strictCapture ?? false,
    });
    const limits = {
      max_events: 10000,
      max_bytes: 268435456,
      max_episodes: 4096,
      max_attachments: 4096,
      max_body_bytes: 16777216,
      max_diagnostic_keys: 4096,
    };
    for (const key of Object.keys(limits) as (keyof typeof limits)[]) {
      const n = this.policy[key];
      if (!Number.isSafeInteger(n) || n < 1 || n > limits[key])
        throw new EpisodeError("INVALID_OBSERVATION");
    }
    if (typeof this.policy.strict_capture !== "boolean")
      throw new EpisodeError("INVALID_OBSERVATION");
  }
  get isClosed(): boolean {
    return this.closed;
  }
  _reason(reason: EpisodeReason, n = 1): void {
    this.reasons[reason] = increment(this.reasons[reason] ?? 0, n);
  }
  _loss(reason: EpisodeReason, episode?: EpisodeHandle): void {
    this.loss = increment(this.loss);
    this._reason(reason);
    episode?._captureLoss(reason);
  }
  _lostWithoutIncident(episode: EpisodeHandle, reason: EpisodeReason): void {
    this.loss = increment(this.loss);
    episode._captureLoss(reason);
  }
  _nextSequence(): number {
    if (this.sequence === maximum) throw new EpisodeError("REVISION_EXHAUSTED");
    return ++this.sequence;
  }
  _reserve(bytes: number, episode: EpisodeHandle): boolean {
    const reason =
      this.events >= this.policy.max_events
        ? "LEDGER_EVENT_CAP"
        : this.bytes + bytes > this.policy.max_bytes
          ? "LEDGER_BYTE_CAP"
          : null;
    if (reason) {
      this._loss(reason, episode);
      if (this.policy.strict_capture) throw new EpisodeError(reason);
      return false;
    }
    this.events++;
    this.bytes += bytes;
    return true;
  }
  episode<T>(
    id: string,
    options: { expectedSurfaces: readonly EpisodeSurface[] },
    callback: (episode: EpisodeHandle) => T,
  ): T {
    if (this.closed) throw new EpisodeError("SDK_CLOSED");
    validId(id);
    const surfaces = orderedSurfaces(options.expectedSurfaces);
    let episode = this.episodes.get(id);
    if (
      episode &&
      canonicalEpisodeJSON(episode._expected()) !==
        canonicalEpisodeJSON(surfaces)
    )
      throw new EpisodeError("SOURCE_MISMATCH");
    if (!episode) {
      const saturated = this.episodes.size >= this.policy.max_episodes;
      if (saturated) {
        this._loss("LEDGER_EPISODE_CAP");
        if (this.policy.strict_capture)
          throw new EpisodeError("LEDGER_EPISODE_CAP");
      }
      episode = new EpisodeHandle(this, id, surfaces, saturated);
      if (!saturated) this.episodes.set(id, episode);
    }
    const active = episode;
    active._enter();
    try {
      const result = context.run({ owner: this, episode: active }, () =>
        callback(active),
      );
      if (types.isPromise(result))
        return result.finally(() => active._exit()) as T;
      active._exit();
      return result;
    } catch (error) {
      active._exit();
      throw error;
    }
  }
  getEpisode(id: string): EpisodeHandle {
    const e = this.episodes.get(id);
    if (!e) throw new EpisodeError("INVALID_OBSERVATION");
    return e;
  }
  bindEpisode<F extends AnyFunction>(fn: F, episode: EpisodeHandle): F {
    if (episode.owner !== this) throw new EpisodeError("SOURCE_MISMATCH");
    const owner = this;
    return function (this: any, ...args: any[]) {
      return context.run({ owner, episode }, () =>
        Reflect.apply(fn, this, args),
      );
    } as F;
  }
  discardEpisode(id: string): boolean {
    const e = this.episodes.get(id);
    if (!e) return false;
    const stat = e._discard();
    this.episodes.delete(id);
    this.events -= stat.events;
    this.bytes -= stat.bytes;
    this.discardedEvents = increment(this.discardedEvents, stat.events);
    this.discardedBytes = increment(this.discardedBytes, stat.bytes);
    this._reason("DISCARDED_EPISODE");
    return true;
  }
  attachTool<F extends AnyFunction>(fn: F, options: AttachmentOptions): F {
    if (this.closed) throw new EpisodeError("SDK_CLOSED");
    if (
      typeof fn !== "function" ||
      types.isProxy(fn) ||
      /^class\s/.test(Function.prototype.toString.call(fn))
    )
      throw new EpisodeError("INVALID_OBSERVATION");
    validId(options.name);
    orderedSurfaces([options.surface]);
    if (
      !["REQUEST", "READ", "EXECUTE", "WRITE", "RECEIVE"].includes(
        options.operation,
      ) ||
      (options.capture !== undefined &&
        (typeof options.capture !== "function" ||
          types.isAsyncFunction(options.capture)))
    )
      throw new EpisodeError("INVALID_OBSERVATION");
    const owner = owners.get(fn);
    if (owner && owner !== this) throw new EpisodeError("SOURCE_MISMATCH");
    const prior = this.registrations.get(fn) ?? this.wrapped.get(fn);
    if (prior) {
      if (
        prior.options.name !== options.name ||
        prior.options.surface !== options.surface ||
        prior.options.operation !== options.operation ||
        prior.options.capture !== options.capture
      )
        throw new EpisodeError("EVENT_CONFLICT");
      return prior.wrapped as F;
    }
    if (
      this.registrations.size >=
      Math.min(this.policy.max_attachments, this.policy.max_diagnostic_keys)
    ) {
      this._reason("ATTACHMENT_CAP");
      throw new EpisodeError("ATTACHMENT_CAP");
    }
    const sdk = this;
    const reg: Registration = {
      original: fn,
      wrapped: fn,
      options: { ...options },
      diagnostic: {
        name: options.name,
        surface: options.surface,
        started: 0,
        completed: 0,
        failed: 0,
        cancelled: 0,
        events_admitted: 0,
        active: true,
      },
      active: true,
    };
    function invoke(this: any, ...args: any[]): any {
      return sdk.invoke(reg, this, args);
    }
    const wrapper =
      types.isAsyncFunction(fn) && !types.isGeneratorFunction(fn)
        ? async function (this: any, ...args: any[]) {
            return sdk.invoke(reg, this, args);
          }
        : invoke;
    const descriptors = Object.getOwnPropertyDescriptors(fn);
    for (const key of ["name", "length", "prototype", "arguments", "caller"])
      delete descriptors[key];
    Object.defineProperties(wrapper, descriptors);
    reg.wrapped = wrapper;
    this.registrations.set(fn, reg);
    this.wrapped.set(wrapper, reg);
    owners.set(wrapper, this);
    return wrapper as F;
  }
  private invoke(reg: Registration, self: unknown, args: unknown[]): unknown {
    if (this.closed || !reg.active) {
      if (this.closed) this._reason("SDK_CLOSED");
      return Reflect.apply(reg.original, self, args);
    }
    const active = context.getStore();
    if (!active || active.owner !== this) {
      this._reason("UNCORRELATED_CALL");
      return Reflect.apply(reg.original, self, args);
    }
    const e = active.episode;
    if (!e._available()) {
      const reason = e._unavailableReason();
      if (reason === "LEDGER_EPISODE_CAP") this._lostWithoutIncident(e, reason);
      else this._loss(reason, e);
      return Reflect.apply(reg.original, self, args);
    }
    const callId = randomUUID();
    let chunk = 0;
    let ended = false;
    const stat = reg.diagnostic;
    stat.started = increment(stat.started);
    e._start();
    const emit = (
      phase: ObservationInput["phase"],
      outcome: ObservationInput["outcome"],
      result: unknown,
      error: unknown,
      index: number | null,
      gap?: CaptureGap,
    ) => {
      if (!e._available()) {
        this._loss(e._unavailableReason(), e);
        return;
      }
      let captured: CaptureResult | null | undefined;
      const gaps: CaptureGap[] = gap ? [gap] : [];
      try {
        captured = reg.options.capture?.({
          phase,
          args,
          kwargs: {},
          result,
          error,
          chunk_index: index,
        });
        if (types.isPromise(captured)) {
          // Reject unsupported asynchronous capture without leaking its rejection.
          Promise.prototype.then.call(captured, undefined, () => undefined);
          throw new Error();
        }
        if (captured !== undefined && captured !== null) {
          canonicalEpisodeJSON(captured);
          if (
            typeof captured !== "object" ||
            Array.isArray(captured) ||
            Object.keys(captured).some(
              (k) => !["artifacts", "relationships"].includes(k),
            ) ||
            (captured.artifacts !== undefined &&
              !Array.isArray(captured.artifacts)) ||
            (captured.relationships !== undefined &&
              !Array.isArray(captured.relationships))
          )
            throw new Error();
        }
      } catch {
        this._loss("CAPTURE_CALLBACK_FAILED", e);
        gaps.push("CAPTURE_CALLBACK_FAILED");
        captured = null;
      }
      if (!captured?.artifacts?.length) gaps.push("CONTENT_NOT_CAPTURED");
      try {
        const admitted = e.observe({
          call_id: callId,
          occurred_at: now(),
          surface: reg.options.surface,
          operation: reg.options.operation,
          phase,
          chunk_index: index,
          outcome,
          authority: authority(),
          artifacts: [...(captured?.artifacts ?? [])],
          relationships: [...(captured?.relationships ?? [])],
          provenance_refs: [],
          capture_gaps: gaps,
        });
        if (admitted) stat.events_admitted = increment(stat.events_admitted);
      } catch {
        /* observe recorded a fixed loss; capture never replaces upstream behavior */
      }
    };
    const finish = (
      outcome: ObservationInput["outcome"],
      result: unknown,
      error: unknown,
      gap?: CaptureGap,
    ) => {
      if (ended) return;
      ended = true;
      if (gap === "UNSUPPORTED_RETURN_PROTOCOL") this._reason(gap);
      e._end();
      if (outcome === "SUCCEEDED") stat.completed = increment(stat.completed);
      else if (outcome === "CANCELLED")
        stat.cancelled = increment(stat.cancelled);
      else stat.failed = increment(stat.failed);
      try {
        emit("END", outcome, result, error, null, gap);
      } finally {
        args = [];
      }
    };
    emit("START", "STARTED", undefined, undefined, null);
    let result: unknown;
    try {
      result = Reflect.apply(reg.original, self, args);
    } catch (error) {
      finish("FAILED", undefined, error);
      throw error;
    }
    const success = (value: unknown) => {
      finish("SUCCEEDED", value, undefined);
      return value;
    };
    const failure = (error: unknown): never => {
      finish("FAILED", undefined, error);
      throw error;
    };
    if (types.isPromise(result)) return result.then(success, failure);
    if (
      typeof result === "object" &&
      result !== null &&
      types.isGeneratorObject(result)
    ) {
      const iterator = result as Generator | AsyncGenerator;
      const handle = (
        method: "next" | "return" | "throw",
        value: unknown,
      ): unknown => {
        let step: IteratorResult<unknown> | Promise<IteratorResult<unknown>>;
        try {
          step = Reflect.apply(iterator[method], iterator, [value]);
        } catch (error) {
          return failure(error);
        }
        const observed = (s: IteratorResult<unknown>) => {
          if (!ended) {
            if (s.done)
              finish(
                method === "return" ? "CLOSED_EARLY" : "SUCCEEDED",
                s.value,
                undefined,
              );
            else emit("CHUNK", "OBSERVED", s.value, undefined, chunk++);
          }
          return s;
        };
        return types.isPromise(step)
          ? step.then(observed, failure)
          : observed(step);
      };
      const async = isAsyncGenerator(result);
      const proxy = {
        next: (v?: unknown) => handle("next", v),
        return: (v?: unknown) => handle("return", v),
        throw: (v?: unknown) => handle("throw", v),
      };
      Object.defineProperty(
        proxy,
        async ? Symbol.asyncIterator : Symbol.iterator,
        { value: () => proxy },
      );
      return proxy;
    }
    if (this.unsupported(result)) {
      finish(
        "CAPTURE_FAILED",
        undefined,
        undefined,
        "UNSUPPORTED_RETURN_PROTOCOL",
      );
      return result;
    }
    return success(result);
  }
  private unsupported(value: unknown): boolean {
    if (
      value === null ||
      (typeof value !== "object" && typeof value !== "function")
    )
      return false;
    if (types.isProxy(value)) return true;
    if (
      Array.isArray(value) ||
      types.isTypedArray(value) ||
      types.isDate(value) ||
      types.isMap(value) ||
      types.isSet(value)
    )
      return false;
    let current: object | null = value;
    for (
      let depth = 0;
      current && depth < 16;
      depth++, current = Object.getPrototypeOf(current)
    ) {
      if (types.isProxy(current)) return true;
      for (const name of [
        "then",
        "next",
        Symbol.iterator,
        Symbol.asyncIterator,
      ])
        if (Object.getOwnPropertyDescriptor(current, name)) return true;
    }
    return current !== null;
  }
  detach(fn: AnyFunction): boolean {
    const reg = this.registrations.get(fn) ?? this.wrapped.get(fn);
    if (!reg) return false;
    reg.active = false;
    reg.diagnostic.active = false;
    this.registrations.delete(reg.original);
    this.wrapped.delete(reg.wrapped);
    return true;
  }
  attachMcp<T extends { callTool: AnyFunction }>(
    client: T,
    options: {
      surfaces: Record<
        string,
        { surface: EpisodeSurface; operation: ObservationInput["operation"] }
      >;
      capture?: AttachmentOptions["capture"];
    },
  ): T {
    if (this.closed) throw new EpisodeError("SDK_CLOSED");
    if (owners.has(client)) throw new EpisodeError("SOURCE_MISMATCH");
    const map = detached(options.surfaces);
    const signature = canonicalEpisodeJSON(map);
    const prior = this.mcp.get(client);
    if (prior) {
      if (prior.signature !== signature || prior.capture !== options.capture)
        throw new EpisodeError("EVENT_CONFLICT");
      return prior.adapter as T;
    }
    const entries = Object.entries(map);
    if (
      this.registrations.size + entries.length >
      Math.min(this.policy.max_attachments, this.policy.max_diagnostic_keys)
    ) {
      this._reason("ATTACHMENT_CAP");
      throw new EpisodeError("ATTACHMENT_CAP");
    }
    // Validate every mapping before the first registration to keep refusal atomic.
    for (const [name, spec] of entries) {
      validId(name);
      orderedSurfaces([spec.surface]);
      if (!["REQUEST", "READ", "EXECUTE", "WRITE", "RECEIVE"].includes(spec.operation))
        throw new EpisodeError("INVALID_OBSERVATION");
    }
    const calls = new Map<string, AnyFunction>();
    for (const [name, spec] of entries) {
      calls.set(
        name,
        this.attachTool(
          function (...args: unknown[]) {
            return Reflect.apply(client.callTool, client, args);
          },
          {
            name,
            surface: spec.surface,
            operation: spec.operation,
            capture: options.capture,
          },
        ),
      );
    }
    const sdk = this;
    // Proxy a facade: frozen client methods cannot be substituted by a get trap
    // when the client itself is the proxy target. Calls still use the real client.
    const adapter = new Proxy(Object.create(client) as T, {
      get(_target, key) {
        if (key === "callTool")
          return function (...args: any[]) {
            const first = args[0];
            const descriptor =
              first && typeof first === "object" && !types.isProxy(first)
                ? Object.getOwnPropertyDescriptor(first, "name")
                : undefined;
            const name =
              descriptor && "value" in descriptor
                ? descriptor.value
                : undefined;
            const fn = typeof name === "string" ? calls.get(name) : undefined;
            if (fn) return Reflect.apply(fn, client, args);
            sdk._reason("UNMAPPED_TOOL");
            return Reflect.apply(client.callTool, client, args);
          };
        const value = Reflect.get(client, key, client);
        return typeof value === "function" ? value.bind(client) : value;
      },
      set(_target, key, value) {
        return Reflect.set(client, key, value, client);
      },
    });
    this.mcp.set(client, { adapter, signature, capture: options.capture });
    owners.set(adapter, this);
    return adapter;
  }
  diagnostics(): EpisodeDiagnostics {
    return detached({
      storage: "MEMORY_ONLY",
      closed: this.closed,
      events: this.events,
      accounted_bytes: this.bytes,
      episodes: this.episodes.size,
      lost: this.loss,
      discarded_events: this.discardedEvents,
      discarded_bytes: this.discardedBytes,
      reasons: this.reasons,
      attachments: [...this.registrations.values()].map((r) => r.diagnostic),
      reconstruction: "UNAVAILABLE",
      semantic_recovery: "UNQUALIFIED",
    });
  }
  async flush(): Promise<FlushReport> {
    return {
      storage: "MEMORY_ONLY",
      admitted: this.events,
      pending: 0,
      durable: 0,
      lost: this.loss,
    };
  }
  async close(): Promise<void> {
    if (this.closed) return;
    for (const episode of this.episodes.values()) episode.finish();
    this.closed = true;
    for (const reg of this.registrations.values()) {
      reg.active = false;
      reg.diagnostic.active = false;
    }
    this.registrations.clear();
    this.wrapped.clear();
    this.mcp = new WeakMap();
  }
}
