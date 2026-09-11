/** Adapter-attested classification continuity; never independent receipt verification. */
import { types } from 'node:util';
import { z } from 'zod';
import { canonicalEpisodeJSON, hashEpisodePayload, nativeIdSchema as id, nativeTimeSchema as time, artifactSchema as observationArtifact, compare } from './contract.js';
import { EpisodeTrustPolicy, verifySignedEpisode, MAX_SIGNED_EXPORT_BYTES } from './signed.js';
import type { BodyResolver } from './signed.js';
import type { EpisodeSnapshot } from './contract.js';
type Immutable<T> = T extends readonly (infer V)[] ? readonly Immutable<V>[] : T extends object ? {
    readonly [K in keyof T]: Immutable<T[K]>;
} : T;
const sha = z.string().regex(/^[0-9a-f]{64}(?![\s\S])/);
const ids = z.array(id).max(64), hashes = z.array(sha).max(64);
const descriptor = z.object({ provider_id: id, method_id: id, policy_sha256: sha, taxonomy: id, supported_classes: ids.min(1) }).strict();
const semanticDescriptor = z.object({ provider_id: id, method_id: id, runtime_id: id, qualification: z.literal('UNQUALIFIED') }).strict();
const requestSchema = z.object({ schema: z.literal('ancilis-classification-request/1'), tenant: id, episode: id, open_sha256: sha, revision_id: sha, event_id: sha, artifact_index: z.number().int().min(0).max(63), reference: observationArtifact, assessed_at: time, adapter: descriptor.nullable(), request_sha256: sha }).strict();
const outcomes = z.enum(['SUPPORTED_POSITIVE', 'UNKNOWN', 'ABSTAIN', 'ERROR', 'UNSUPPORTED']);
const responseSchema = z.object({ schema: z.literal('ancilis-classification-response/1'), request_sha256: sha, outcome: outcomes, classification: id.nullable(), evidence_refs: hashes, reasons: ids }).strict();
const semanticRequestSchema = z.object({ schema: z.literal('ancilis-semantic-request/1'), classification_request: requestSchema, trusted_response: responseSchema, provider: semanticDescriptor, request_sha256: sha }).strict();
const proposalSchema = z.object({ schema: z.literal('ancilis-semantic-proposal/1'), request_sha256: sha, status: z.enum(['PROPOSED', 'UNKNOWN', 'ABSTAIN', 'ERROR', 'UNSUPPORTED']), proposed_classification: id.nullable(), evidence_refs: hashes, reasons: ids }).strict();
const semanticAssessmentSchema = z.object({ state: z.enum(['NOT_REQUESTED', 'UNQUALIFIED']), request: semanticRequestSchema.nullable(), response: proposalSchema.nullable(), sdk_reason: z.enum(['SEMANTIC_PROVIDER_ERROR', 'INVALID_SEMANTIC_RESPONSE']).nullable() }).strict();
const rowSchema = z.object({ request: requestSchema, outcome: outcomes, classification: id.nullable(), response: responseSchema.nullable(), sdk_reason: z.enum(['CLASSIFICATION_PROVIDER_UNAVAILABLE', 'ADAPTER_CALL_FAILED', 'INVALID_ADAPTER_RESPONSE']).nullable(), trust_basis: z.enum(['NONE', 'ADAPTER_ATTESTED']), semantic: semanticAssessmentSchema }).strict();
const verificationSchema = z.object({ schema: z.literal('ancilis-signed-verification/1'), status: z.enum(['AUTHENTICATED', 'UNVERIFIED', 'REJECTED', 'ERROR']), envelope_authenticated: z.boolean(), protected_bodies: z.enum(['NOT_REQUESTED', 'VERIFIED', 'NO_REFERENCES', 'UNAVAILABLE', 'MISMATCH', 'ERROR', 'LIMIT_EXCEEDED']), reconstruction: z.literal('UNSUPPORTED'), policy_sha256: sha, assessed_at: time, export_sha256: sha.nullable(), verified_body_count: z.number().int().min(0).max(1024), reasons: z.array(z.enum(['INVALID_SIGNED_EXPORT', 'EXPORT_TOO_LARGE', 'SCOPE_MISMATCH', 'INVALID_NATIVE_SNAPSHOT', 'NATIVE_HISTORY_DISCARDED', 'UNTRUSTED_KEY', 'REVOKED_KEY', 'KEY_NOT_CURRENT', 'INVALID_SIGNATURE', 'SIGNATURE_VERIFICATION_ERROR', 'ENVELOPE_AUTHENTICATED', 'BODIES_NOT_REQUESTED', 'NO_BODY_REFERENCES', 'BODY_LIMIT_EXCEEDED', 'BODY_UNAVAILABLE', 'BODY_MISMATCH', 'BODY_RESOLVER_ERROR', 'BODIES_VERIFIED'])).min(1).max(2), verified_claim_refs: z.array(z.never()).max(0) }).strict();
const reportSchema = z.object({ schema: z.literal('ancilis-classification-report/1'), tenant: id.nullable(), episode: id.nullable(), open_sha256: sha.nullable(), revision_id: sha.nullable(), export_sha256: sha.nullable(), assessed_at: time, verification: verificationSchema, adapter: descriptor.nullable(), semantic_provider: semanticDescriptor.nullable(), classifications: z.array(rowSchema).max(1024), report_sha256: sha }).strict();
export type ClassificationOutcome = z.infer<typeof outcomes>;
export type ClassificationAdapterDescriptor = z.infer<typeof descriptor>;
export type SemanticProviderDescriptor = z.infer<typeof semanticDescriptor>;
export type ClassificationRequest = Immutable<z.infer<typeof requestSchema>>;
export type ClassificationResponse = z.infer<typeof responseSchema>;
export type SemanticRequest = Immutable<z.infer<typeof semanticRequestSchema>>;
export type SemanticProposal = z.infer<typeof proposalSchema>;
export type SemanticAssessment = z.infer<typeof semanticAssessmentSchema>;
export type ClassificationAssessment = z.infer<typeof rowSchema>;
export type EpisodeClassificationReportDocument = z.infer<typeof reportSchema>;
export type ReportOrigin = 'LOCAL_ASSESSMENT' | 'PARSED_UNAUTHENTICATED';
export type ClassificationResolver = (request: ClassificationRequest, body: Uint8Array, signal?: AbortSignal) => ClassificationResponse | Promise<ClassificationResponse>;
export type SemanticProposer = (request: SemanticRequest, body: Uint8Array, signal?: AbortSignal) => SemanticProposal | Promise<SemanticProposal>;
export class ClassificationError extends Error {
    constructor(readonly code: string) { super(code); this.name = 'ClassificationError'; }
}
function json(value: unknown): any { return JSON.parse(canonicalEpisodeJSON(value)); }
function equal(a: unknown, b: unknown): boolean { return canonicalEpisodeJSON(a) === canonicalEpisodeJSON(b); }
function freeze<T>(value: T): T { if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value))
        freeze(v);
    Object.freeze(value);
} return value; }
function ordered(a: readonly string[]): boolean { return equal(a, [...new Set(a)].sort(compare)); }
function checkDescriptor(value: unknown, semantic = false): any { const d = semantic ? semanticDescriptor.parse(json(value)) : descriptor.parse(json(value)); if (!semantic && !ordered((d as ClassificationAdapterDescriptor).supported_classes))
    throw new Error(); return d; }
const adapters = new WeakMap<TrustedClassificationAdapter, {
    document: ClassificationAdapterDescriptor;
    resolve: ClassificationResolver;
}>();
const semantics = new WeakMap<ExperimentalSemanticProvider, {
    document: SemanticProviderDescriptor;
    propose: SemanticProposer;
}>();
export class TrustedClassificationAdapter {
    constructor(options: ClassificationAdapterDescriptor & {
        resolve: ClassificationResolver;
    }) {
        try {
            const { resolve, ...document } = options;
            if (typeof resolve !== 'function')
                throw new Error();
            adapters.set(this, { document: freeze(checkDescriptor(document)), resolve });
            Object.freeze(this);
        }
        catch {
            throw new ClassificationError('INVALID_CLASSIFICATION_ADAPTER');
        }
    }
    toJSON(): ClassificationAdapterDescriptor { return json(adapters.get(this)!.document); }
}
export class ExperimentalSemanticProvider {
    constructor(options: Omit<SemanticProviderDescriptor, 'qualification'> & {
        propose: SemanticProposer;
    }) {
        try {
            const { propose, ...document } = options;
            if (typeof propose !== 'function')
                throw new Error();
            semantics.set(this, { document: freeze(checkDescriptor({ ...document, qualification: 'UNQUALIFIED' }, true)), propose });
            Object.freeze(this);
        }
        catch {
            throw new ClassificationError('INVALID_SEMANTIC_PROVIDER');
        }
    }
    toJSON(): SemanticProviderDescriptor { return json(semantics.get(this)!.document); }
}
function bound(d: any, field = 'request_sha256'): any { return { ...d, [field]: hashEpisodePayload(d.schema, d) }; }
function checkHash(d: any, field = 'request_sha256'): void { const copy = { ...d }; delete copy[field]; if (d[field] !== hashEpisodePayload(d.schema, copy))
    throw new Error(); }
function response(value: unknown, q: ClassificationRequest): ClassificationResponse {
    const d = responseSchema.parse(json(value));
    if (d.request_sha256 !== q.request_sha256 || !ordered(d.reasons) || !ordered(d.evidence_refs))
        throw new Error();
    if (d.outcome === 'SUPPORTED_POSITIVE') {
        if (d.classification === null || !d.evidence_refs.length || !q.adapter?.supported_classes.includes(d.classification) || !equal(d.evidence_refs, [...new Set(q.reference.classification_receipt_refs)].sort(compare)))
            throw new Error();
    }
    else if (d.classification !== null || !d.reasons.length)
        throw new Error();
    return d;
}
function proposal(value: unknown, q: SemanticRequest): SemanticProposal {
    const d = proposalSchema.parse(json(value));
    if (d.request_sha256 !== q.request_sha256 || !ordered(d.reasons) || !ordered(d.evidence_refs))
        throw new Error();
    if (d.status === 'PROPOSED') {
        if (d.proposed_classification === null || !d.evidence_refs.length)
            throw new Error();
    }
    else if (d.proposed_classification !== null || !d.reasons.length)
        throw new Error();
    return d;
}
function noSemantic(): SemanticAssessment { return { state: 'NOT_REQUESTED', request: null, response: null, sdk_reason: null }; }
function validateReport(value: unknown): EpisodeClassificationReportDocument {
    const d = reportSchema.parse(json(value));
    checkHash(d, 'report_sha256');
    const v = d.verification;
    if (d.assessed_at !== v.assessed_at || d.export_sha256 !== v.export_sha256 || new Set(v.reasons).size !== v.reasons.length)
        throw new Error();
    for (const k of ['tenant', 'episode', 'open_sha256', 'revision_id'] as const)
        if ((d[k] !== null) !== v.envelope_authenticated)
            throw new Error();
    if (d.semantic_provider !== null && d.adapter === null)
        throw new Error();
    if (d.adapter)
        checkDescriptor(d.adapter);
    if (d.semantic_provider)
        checkDescriptor(d.semantic_provider, true);
    if (d.classifications.length && (v.status !== 'AUTHENTICATED' || v.protected_bodies !== 'VERIFIED' || !v.envelope_authenticated))
        throw new Error();
    if (v.protected_bodies === 'VERIFIED' && d.classifications.length !== v.verified_body_count)
        throw new Error();
    const seen = new Set<string>();
    for (const row of d.classifications) {
        const q = row.request;
        checkHash(q);
        for (const k of ['tenant', 'episode', 'open_sha256', 'revision_id', 'assessed_at', 'adapter'] as const)
            if (!equal(q[k], d[k]))
                throw new Error();
        const key = JSON.stringify([q.event_id, q.artifact_index]);
        if (seen.has(key))
            throw new Error();
        seen.add(key);
        if (row.response) {
            if (!d.adapter || row.sdk_reason !== null || row.trust_basis !== 'ADAPTER_ATTESTED')
                throw new Error();
            response(row.response, q);
            if (row.outcome !== row.response.outcome || row.classification !== row.response.classification)
                throw new Error();
        }
        else {
            const outcome = row.sdk_reason === 'CLASSIFICATION_PROVIDER_UNAVAILABLE' ? 'UNKNOWN' : 'ERROR';
            if (!row.sdk_reason || row.trust_basis !== 'NONE' || row.outcome !== outcome || row.classification !== null || (row.sdk_reason === 'CLASSIFICATION_PROVIDER_UNAVAILABLE') !== (d.adapter === null))
                throw new Error();
        }
        const sem = row.semantic, runs = d.semantic_provider !== null && row.response?.outcome === 'UNKNOWN';
        if (!runs) {
            if (!equal(sem, noSemantic()))
                throw new Error();
        }
        else {
            const sq = sem.request;
            if (sem.state !== 'UNQUALIFIED' || !sq)
                throw new Error();
            checkHash(sq);
            if (!equal(sq.classification_request, q) || !equal(sq.trusted_response, row.response) || !equal(sq.provider, d.semantic_provider))
                throw new Error();
            if (sem.response) {
                if (sem.sdk_reason !== null)
                    throw new Error();
                proposal(sem.response, sq);
            }
            else if (!sem.sdk_reason)
                throw new Error();
        }
    }
    return d;
}
const reports = new WeakMap<EpisodeClassificationReport, {
    document: EpisodeClassificationReportDocument;
    origin: ReportOrigin;
}>();
export class EpisodeClassificationReport {
    constructor(document: EpisodeClassificationReportDocument) { try {
        reports.set(this, { document: freeze(validateReport(document)), origin: 'PARSED_UNAUTHENTICATED' });
        Object.freeze(this);
    }
    catch {
        throw new ClassificationError('INVALID_CLASSIFICATION_REPORT');
    } }
    get origin(): ReportOrigin { return reports.get(this)!.origin; }
    toJSON(): EpisodeClassificationReportDocument { return json(reports.get(this)!.document); }
}
export interface ClassificationHistoryEntry {
    origin: ReportOrigin;
    report: EpisodeClassificationReportDocument;
}
export class ClassificationHistory {
    #scope: readonly string[];
    #maxReports: number;
    #maxBytes: number;
    #entries: {
        origin: ReportOrigin;
        wire: string;
    }[] = [];
    #hashes = new Set<string>();
    #bytes = 0;
    constructor(tenant: string, episode: string, openSha256: string, options: {
        maxReports?: number;
        maxBytes?: number;
    } = {}) {
        const maxReports = options.maxReports ?? 64, maxBytes = options.maxBytes ?? 16777216;
        try {
            id.parse(tenant);
            id.parse(episode);
            sha.parse(openSha256);
            if (!Number.isInteger(maxReports) || maxReports < 1 || maxReports > 64 || !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 16777216)
                throw new Error();
        }
        catch {
            throw new ClassificationError('INVALID_CLASSIFICATION_HISTORY');
        }
        this.#scope = [tenant, episode, openSha256];
        this.#maxReports = maxReports;
        this.#maxBytes = maxBytes;
    }
    append(report: EpisodeClassificationReport): boolean {
        const state = reports.get(report);
        if (!state)
            throw new ClassificationError('INVALID_CLASSIFICATION_REPORT');
        const d = state.document;
        if (!equal([d.tenant, d.episode, d.open_sha256], this.#scope))
            throw new ClassificationError('HISTORY_SCOPE_MISMATCH');
        if (this.#hashes.has(d.report_sha256))
            return false;
        const wire = canonicalEpisodeJSON(d), size = Buffer.byteLength(wire);
        if (this.#entries.length >= this.#maxReports || this.#bytes + size > this.#maxBytes)
            throw new ClassificationError('HISTORY_LIMIT');
        this.#entries.push({ origin: state.origin, wire });
        this.#hashes.add(d.report_sha256);
        this.#bytes += size;
        return true;
    }
    inspect(): ClassificationHistoryEntry[] { return this.#entries.map(e => ({ origin: e.origin, report: JSON.parse(e.wire) })); }
}
const arrayProto = Object.getPrototypeOf(Uint8Array.prototype);
const len = Object.getOwnPropertyDescriptor(arrayProto, 'byteLength')!.get!, buf = Object.getOwnPropertyDescriptor(arrayProto, 'buffer')!.get!, offset = Object.getOwnPropertyDescriptor(arrayProto, 'byteOffset')!.get!;
function length(value: Uint8Array): number { return Reflect.apply(len, value, []) as number; }
function copyBytes(value: Uint8Array): Buffer { return Buffer.from(new Uint8Array(Reflect.apply(buf, value, []) as ArrayBuffer, Reflect.apply(offset, value, []) as number, length(value))); }
export interface ClassificationAssessmentOptions {
    trust: EpisodeTrustPolicy;
    adapter?: TrustedClassificationAdapter;
    bodyResolver?: BodyResolver;
    assessedAt?: string;
    experimentalSemantic?: ExperimentalSemanticProvider;
    signal?: AbortSignal;
}
export async function assessEpisodeClassifications(wire: string | Uint8Array, options: ClassificationAssessmentOptions): Promise<EpisodeClassificationReport> {
    const { trust, adapter, bodyResolver, experimentalSemantic, signal } = options;
    signal?.throwIfAborted();
    if (!(trust instanceof EpisodeTrustPolicy) || trust.toJSON().body_mode !== 'ALL_REFERENCED')
        throw new ClassificationError('BODY_VERIFICATION_REQUIRED');
    const a = adapter === undefined ? undefined : adapters.get(adapter), s = experimentalSemantic === undefined ? undefined : semantics.get(experimentalSemantic);
    if (adapter !== undefined && !a)
        throw new ClassificationError('INVALID_CLASSIFICATION_ADAPTER');
    if (experimentalSemantic !== undefined && !s)
        throw new ClassificationError('INVALID_SEMANTIC_PROVIDER');
    if (s && !a)
        throw new ClassificationError('SEMANTIC_REQUIRES_TRUSTED_ADAPTER');
    if (bodyResolver !== undefined && typeof bodyResolver !== 'function')
        throw new ClassificationError('INVALID_CALLBACK');
    let input = wire;
    // Freeze mutable transport before the first await. Oversized input is rejected by the existing verifier without a copy.
    try {
        if (types.isUint8Array(wire) && length(wire as Uint8Array) <= MAX_SIGNED_EXPORT_BYTES)
            input = copyBytes(wire as Uint8Array);
    }
    catch {
        input = '';
    }
    const cache: Buffer[] = [];
    const verification = await verifySignedEpisode(input, { trust, assessedAt: options.assessedAt, signal, bodyResolver: async (request, abort) => {
            const body = bodyResolver ? await bodyResolver(request, abort) : null;
            if (body instanceof Uint8Array && types.isUint8Array(body)) {
                if (length(body) !== request.reference.byte_length)
                    return Buffer.alloc(request.reference.byte_length === 0 ? 1 : 0);
                const copy = copyBytes(body);
                cache.push(copy);
                return copy;
            }
            return body;
        } });
    signal?.throwIfAborted();
    const snapshot: EpisodeSnapshot | null = verification.envelope_authenticated ? JSON.parse(typeof input === 'string' ? input : Buffer.from(input).toString('utf8')).snapshot : null;
    const d: EpisodeClassificationReportDocument = { schema: 'ancilis-classification-report/1', tenant: snapshot?.tenant ?? null, episode: snapshot?.episode ?? null, open_sha256: snapshot?.open_sha256 ?? null, revision_id: snapshot?.revision_id ?? null, export_sha256: verification.export_sha256, assessed_at: verification.assessed_at, verification: json(verification), adapter: a ? json(a.document) : null, semantic_provider: s ? json(s.document) : null, classifications: [], report_sha256: '' };
    if (snapshot && verification.status === 'AUTHENTICATED' && verification.protected_bodies === 'VERIFIED') {
        let occurrence = 0;
        for (const event of snapshot.observations)
            for (const [index, reference] of event.artifacts.entries()) {
                signal?.throwIfAborted();
                const body = cache[occurrence++];
                if (!body)
                    throw new ClassificationError('BODY_CACHE_MISMATCH');
                const q: ClassificationAssessment['request'] = bound({ schema: 'ancilis-classification-request/1', tenant: d.tenant, episode: d.episode, open_sha256: d.open_sha256, revision_id: d.revision_id, event_id: event.event_id, artifact_index: index, reference, assessed_at: d.assessed_at, adapter: d.adapter });
                let result: ClassificationResponse | null = null, reason: ClassificationAssessment['sdk_reason'] = 'CLASSIFICATION_PROVIDER_UNAVAILABLE';
                if (a) {
                    let raw: unknown;
                    try {
                        raw = await a.resolve(freeze(json(q)), Buffer.from(body), signal);
                        signal?.throwIfAborted();
                    }
                    catch {
                        signal?.throwIfAborted();
                        reason = 'ADAPTER_CALL_FAILED';
                    }
                    if (reason !== 'ADAPTER_CALL_FAILED') {
                        try {
                            result = response(raw, q);
                            reason = null;
                        }
                        catch {
                            reason = 'INVALID_ADAPTER_RESPONSE';
                        }
                    }
                }
                const row: ClassificationAssessment = { request: q, outcome: result?.outcome ?? (reason === 'CLASSIFICATION_PROVIDER_UNAVAILABLE' ? 'UNKNOWN' : 'ERROR'), classification: result?.classification ?? null, response: result, sdk_reason: reason, trust_basis: result ? 'ADAPTER_ATTESTED' : 'NONE', semantic: noSemantic() };
                if (s && result?.outcome === 'UNKNOWN') {
                    const sq: NonNullable<SemanticAssessment['request']> = bound({ schema: 'ancilis-semantic-request/1', classification_request: q, trusted_response: result, provider: d.semantic_provider });
                    let p: SemanticProposal | null = null, r: SemanticAssessment['sdk_reason'] = null, raw: unknown;
                    try {
                        signal?.throwIfAborted();
                        raw = await s.propose(freeze(json(sq)), Buffer.from(body), signal);
                        signal?.throwIfAborted();
                    }
                    catch {
                        signal?.throwIfAborted();
                        r = 'SEMANTIC_PROVIDER_ERROR';
                    }
                    if (r === null) {
                        try {
                            p = proposal(raw, sq);
                        }
                        catch {
                            r = 'INVALID_SEMANTIC_RESPONSE';
                        }
                    }
                    row.semantic = { state: 'UNQUALIFIED', request: sq, response: p, sdk_reason: r };
                }
                d.classifications.push(row);
            }
    }
    signal?.throwIfAborted();
    const report = new EpisodeClassificationReport(bound(digestless(d), 'report_sha256'));
    reports.get(report)!.origin = 'LOCAL_ASSESSMENT';
    return report;
}
function digestless(d: EpisodeClassificationReportDocument): Omit<EpisodeClassificationReportDocument, 'report_sha256'> { const { report_sha256: _ignored, ...rest } = d; return rest; }
