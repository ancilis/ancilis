/** Native authentication under caller-provisioned trust; never reconstruction. */
import { createHash, createPrivateKey, createPublicKey, KeyObject, sign, verify } from "node:crypto";
import { types } from "node:util";
import { z } from "zod";
import { canonicalEpisodeJSON, detached, hashEpisodePayload, nativeIdSchema, nativeTimeSchema, now } from "./contract.js";
import type { ContentReference, EpisodeSnapshot } from "./contract.js";
import { verifyEpisodeSnapshot } from "./verification.js";
export const MAX_SIGNED_EXPORT_BYTES = 32 * 1024 * 1024;
const DOMAIN = "ancilis-signed-episode/1\n";
const hex = (size: number) => z.string().regex(new RegExp(`^[0-9a-f]{${size}}(?![\\s\\S])`));
const keySchema = z.object({ key_id: nativeIdSchema, public_key: hex(64), not_before: nativeTimeSchema.nullable(), not_after: nativeTimeSchema.nullable(), revoked: z.boolean() }).strict();
const policySchema = z.object({
    schema: z.literal("ancilis-episode-trust-policy/1"), tenant: nativeIdSchema, source: nativeIdSchema,
    keys: z.array(keySchema).max(64), body_mode: z.enum(["NONE", "ALL_REFERENCED"]),
    max_body_bytes: z.number().int().min(1).max(16777216), max_total_body_bytes: z.number().int().min(1).max(67108864), max_body_requests: z.number().int().min(1).max(1024),
}).strict();
export type EpisodeTrustKey = z.infer<typeof keySchema>;
export type EpisodeTrustPolicyDocument = z.infer<typeof policySchema>;
export class SignedEpisodeError extends Error {
    constructor(readonly code: string) { super(code); this.name = "SignedEpisodeError"; }
}
function freeze<T>(value: T): T {
    if (value !== null && typeof value === "object") {
        for (const child of Object.values(value))
            freeze(child);
        Object.freeze(value);
    }
    return value;
}
const arrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const intrinsicLength = Object.getOwnPropertyDescriptor(arrayPrototype, "byteLength")!.get!;
const intrinsicBuffer = Object.getOwnPropertyDescriptor(arrayPrototype, "buffer")!.get!;
const intrinsicOffset = Object.getOwnPropertyDescriptor(arrayPrototype, "byteOffset")!.get!;
function byteLength(value: Uint8Array): number { return Reflect.apply(intrinsicLength, value, []) as number; }
function copyBytes(value: Uint8Array): Buffer {
    const length = byteLength(value);
    const buffer = Reflect.apply(intrinsicBuffer, value, []) as ArrayBuffer;
    const offset = Reflect.apply(intrinsicOffset, value, []) as number;
    return Buffer.from(new Uint8Array(buffer, offset, length));
}
function scalars(text: string): void {
    for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = text.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                throw Error();
        }
        else if (code >= 0xdc00 && code <= 0xdfff)
            throw Error();
    }
}
/** No key discovery: this policy must come from an independently trusted channel. */
const policyKeys = new WeakMap<EpisodeTrustPolicy, ReadonlyMap<string, KeyObject>>();
const signerKeys = new WeakMap<EpisodeSigner, KeyObject>();

export class EpisodeTrustPolicy {
    readonly sha256: string;
    readonly #document: EpisodeTrustPolicyDocument;
    constructor(document: EpisodeTrustPolicyDocument) {
        try {
            const value = policySchema.parse(detached(document));
            const importedKeys = new Map<string, KeyObject>();
            let previous = "";
            for (const key of value.keys) {
                if (key.key_id <= previous || (key.not_before !== null && key.not_after !== null && key.not_before >= key.not_after))
                    throw Error();
                const bytes = Buffer.from(key.public_key, "hex");
                const imported = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), bytes]), format: "der", type: "spki" });
                if (imported.asymmetricKeyType !== "ed25519" || Buffer.from(imported.export({ format: "jwk" }).x!, "base64url").toString("hex") !== key.public_key)
                    throw Error();
                importedKeys.set(key.key_id, imported);
                previous = key.key_id;
            }
            policyKeys.set(this, importedKeys);
            this.#document = freeze(value);
            this.sha256 = hashEpisodePayload("ancilis-episode-trust-policy/1", value);
            Object.freeze(this);
        }
        catch {
            throw new SignedEpisodeError("INVALID_TRUST_POLICY");
        }
    }
    toJSON(): EpisodeTrustPolicyDocument { return detached(this.#document); }

}
export interface EpisodeSignerOptions {
    tenant: string;
    source: string;
    keyId: string;
    privateKey: KeyObject;
}
export class EpisodeSigner {
    readonly tenant: string;
    readonly source: string;
    readonly keyId: string;
    constructor(options: EpisodeSignerOptions) {
        try {
            this.tenant = nativeIdSchema.parse(options.tenant);
            this.source = nativeIdSchema.parse(options.source);
            this.keyId = nativeIdSchema.parse(options.keyId);
            if (!(options.privateKey instanceof KeyObject) || options.privateKey.type !== "private" || options.privateKey.asymmetricKeyType !== "ed25519")
                throw Error();
            signerKeys.set(this, options.privateKey);
            Object.freeze(this);
        }
        catch {
            throw new SignedEpisodeError("INVALID_SIGNER");
        }
    }
    static fromSeed(options: Omit<EpisodeSignerOptions, "privateKey"> & {
        seed: Uint8Array;
    }): EpisodeSigner {
        try {
            if (!(options.seed instanceof Uint8Array) || !types.isUint8Array(options.seed) || byteLength(options.seed) !== 32)
                throw Error();
            const seed = copyBytes(options.seed);
            const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
            if (!Buffer.from(key.export({ format: "jwk" }).d!, "base64url").equals(seed))
                throw Error();
            return new EpisodeSigner({ ...options, privateKey: key });
        }
        catch {
            throw new SignedEpisodeError("INVALID_SIGNER");
        }
    }
}
export function signEpisodeSnapshot(snapshot: EpisodeSnapshot, signer: EpisodeSigner): string {
    const privateKey = signerKeys.get(signer);
    if (!(signer instanceof EpisodeSigner) || !privateKey)
        throw new SignedEpisodeError("INVALID_SIGNER");
    let value: EpisodeSnapshot;
    try {
        value = detached(snapshot);
    }
    catch {
        throw new SignedEpisodeError("INVALID_NATIVE_SNAPSHOT");
    }
    const reason = nativeReason(value, now());
    if (reason)
        throw new SignedEpisodeError(reason);
    if (value.tenant !== signer.tenant || value.open.owner_source !== signer.source)
        throw new SignedEpisodeError("SCOPE_MISMATCH");
    const unsigned = { schema: "ancilis-signed-episode/1", algorithm: "Ed25519", key_id: signer.keyId, snapshot: value };
    const canonical = canonicalEpisodeJSON(unsigned);
    if (Buffer.byteLength(canonical) + 143 > MAX_SIGNED_EXPORT_BYTES)
        throw new SignedEpisodeError("EXPORT_TOO_LARGE");
    let signature: string;
    try {
        signature = sign(null, Buffer.from(DOMAIN + canonical), privateKey).toString("hex");
    }
    catch {
        throw new SignedEpisodeError("SIGNATURE_VERIFICATION_ERROR");
    }
    return canonicalEpisodeJSON({ ...unsigned, signature });
}

function nativeReason(snapshot: unknown, assessedAt: string): string | null {
    const checked = verifyEpisodeSnapshot(snapshot, { assessedAt });
    if (checked.status === "REJECTED")
        return "INVALID_NATIVE_SNAPSHOT";
    return checked.reasons.includes("NATIVE_HISTORY_DISCARDED") ? "NATIVE_HISTORY_DISCARDED" : null;
}
export interface ProtectedBodyRequest {
    readonly tenant: string;
    readonly episode: string;
    readonly open_sha256: string;
    readonly revision_id: string;
    readonly event_id: string;
    readonly reference: Readonly<Omit<ContentReference, "classification_receipt_refs"> & {
        classification_receipt_refs: readonly string[];
    }>;
}
export type BodyResolver = (request: ProtectedBodyRequest, signal?: AbortSignal) => Uint8Array | null | Promise<Uint8Array | null>;
export interface SignedVerificationOptions {
    trust: EpisodeTrustPolicy;
    assessedAt?: string;
    bodyResolver?: BodyResolver;
    signal?: AbortSignal;
}
export interface SignedEpisodeVerification {
    readonly schema: "ancilis-signed-verification/1";
    readonly status: "AUTHENTICATED" | "UNVERIFIED" | "REJECTED" | "ERROR";
    readonly envelope_authenticated: boolean;
    readonly protected_bodies: "NOT_REQUESTED" | "VERIFIED" | "NO_REFERENCES" | "UNAVAILABLE" | "MISMATCH" | "ERROR" | "LIMIT_EXCEEDED";
    readonly reconstruction: "UNSUPPORTED";
    readonly policy_sha256: string;
    readonly assessed_at: string;
    readonly export_sha256: string | null;
    readonly verified_body_count: number;
    readonly reasons: readonly string[];
    readonly verified_claim_refs: [
    ];
}
type Result = { -readonly [K in keyof SignedEpisodeVerification]: SignedEpisodeVerification[K] };
function out(result: Result, status: Result["status"], reason: string, bodies: Result["protected_bodies"] = "NOT_REQUESTED"): Result {
    result.status = status;
    result.protected_bodies = bodies;
    result.reasons = [...(result.envelope_authenticated ? ["ENVELOPE_AUTHENTICATED"] : []), reason];
    return result;
}
const envelopeSchema = z.object({ schema: z.literal("ancilis-signed-episode/1"), algorithm: z.literal("Ed25519"), key_id: nativeIdSchema, signature: hex(128), snapshot: z.unknown().refine(value => value !== undefined) }).strict();
function prepare(wire: string | Uint8Array, options: SignedVerificationOptions): [
    Result,
    ProtectedBodyRequest[]
] {
    if (!(options.trust instanceof EpisodeTrustPolicy))
        throw new SignedEpisodeError("INVALID_TRUST_POLICY");
    const assessed = options.assessedAt ?? now();
    if (!nativeTimeSchema.safeParse(assessed).success)
        throw new SignedEpisodeError("INVALID_ASSESSMENT_TIME");
    const result: Result = { schema: "ancilis-signed-verification/1", status: "UNVERIFIED", envelope_authenticated: false, protected_bodies: "NOT_REQUESTED", reconstruction: "UNSUPPORTED", policy_sha256: options.trust.sha256, assessed_at: assessed, export_sha256: null, verified_body_count: 0, reasons: [], verified_claim_refs: [] };
    let raw: Buffer, value: unknown;
    try {
        if (typeof wire === "string") {
            if (wire.length > MAX_SIGNED_EXPORT_BYTES)
                return [out(result, "REJECTED", "EXPORT_TOO_LARGE"), []];
            scalars(wire);
            raw = Buffer.from(wire, "utf8");
        }
        else if (wire instanceof Uint8Array && types.isUint8Array(wire)) {
            if (byteLength(wire) > MAX_SIGNED_EXPORT_BYTES)
                return [out(result, "REJECTED", "EXPORT_TOO_LARGE"), []];
            raw = copyBytes(wire);
        }
        else
            throw Error();
        if (raw.length > MAX_SIGNED_EXPORT_BYTES)
            return [out(result, "REJECTED", "EXPORT_TOO_LARGE"), []];
        value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw));
        if (!Buffer.from(canonicalEpisodeJSON(value)).equals(raw))
            throw Error();
    }
    catch {
        return [out(result, "REJECTED", "INVALID_SIGNED_EXPORT"), []];
    }
    result.export_sha256 = createHash("sha256").update(raw).digest("hex");
    const parsed = envelopeSchema.safeParse(value);
    if (!parsed.success)
        return [out(result, "REJECTED", "INVALID_SIGNED_EXPORT"), []];
    const envelope = parsed.data;
    const snapshot = envelope.snapshot as EpisodeSnapshot;
    const reason = nativeReason(snapshot, assessed);
    if (reason)
        return [out(result, "REJECTED", reason), []];
    const policy = options.trust.toJSON();
    if (snapshot.tenant !== policy.tenant || snapshot.open.owner_source !== policy.source)
        return [out(result, "REJECTED", "SCOPE_MISMATCH"), []];
    const key = policy.keys.find(k => k.key_id === envelope.key_id);
    if (!key)
        return [out(result, "UNVERIFIED", "UNTRUSTED_KEY"), []];
    if (key.revoked)
        return [out(result, "UNVERIFIED", "REVOKED_KEY"), []];
    if ((key.not_before !== null && assessed < key.not_before) || (key.not_after !== null && assessed >= key.not_after))
        return [out(result, "UNVERIFIED", "KEY_NOT_CURRENT"), []];
    const { signature, ...unsigned } = envelope;
    try {
        if (!verify(null, Buffer.from(DOMAIN + canonicalEpisodeJSON(unsigned)), policyKeys.get(options.trust)!.get(key.key_id)!, Buffer.from(signature, "hex")))
            return [out(result, "REJECTED", "INVALID_SIGNATURE"), []];
    }
    catch {
        return [out(result, "ERROR", "SIGNATURE_VERIFICATION_ERROR"), []];
    }
    result.envelope_authenticated = true;
    if (policy.body_mode === "NONE")
        return [out(result, "AUTHENTICATED", "BODIES_NOT_REQUESTED"), []];
    const requests: ProtectedBodyRequest[] = [];
    let total = 0;
    for (const row of snapshot.observations)
        for (const reference of row.artifacts) {
            total += reference.byte_length;
            if (requests.length >= policy.max_body_requests || reference.byte_length > policy.max_body_bytes || total > policy.max_total_body_bytes)
                return [out(result, "UNVERIFIED", "BODY_LIMIT_EXCEEDED", "LIMIT_EXCEEDED"), []];
            requests.push(freeze({ tenant: snapshot.tenant, episode: snapshot.episode, open_sha256: snapshot.open_sha256, revision_id: snapshot.revision_id, event_id: row.event_id, reference: detached(reference) }));
        }
    if (!requests.length)
        out(result, "UNVERIFIED", "NO_BODY_REFERENCES", "NO_REFERENCES");
    return [result, requests];
}
/** Resolve nothing before authentication. Cancellation remains a caller action. */
export async function verifySignedEpisode(wire: string | Uint8Array, options: SignedVerificationOptions): Promise<SignedEpisodeVerification> {
    if (options.bodyResolver !== undefined && typeof options.bodyResolver !== "function")
        throw new SignedEpisodeError("INVALID_BODY_RESOLVER");
    options.signal?.throwIfAborted();
    const [result, requests] = prepare(wire, options);
    for (const request of requests) {
        options.signal?.throwIfAborted();
        let body: unknown;
        try {
            body = options.bodyResolver ? await options.bodyResolver(request, options.signal) : null;
        }
        catch {
            options.signal?.throwIfAborted();
            return freeze(out(result, "ERROR", "BODY_RESOLVER_ERROR", "ERROR"));
        }
        options.signal?.throwIfAborted();
        if (body === null)
            return freeze(out(result, "UNVERIFIED", "BODY_UNAVAILABLE", "UNAVAILABLE"));
        if (!(body instanceof Uint8Array) || !types.isUint8Array(body))
            return freeze(out(result, "ERROR", "BODY_RESOLVER_ERROR", "ERROR"));
        try {
            if (byteLength(body) !== request.reference.byte_length)
                return freeze(out(result, "REJECTED", "BODY_MISMATCH", "MISMATCH"));
            const copy = copyBytes(body);
            if (copy.length !== request.reference.byte_length || createHash("sha256").update(copy).digest("hex") !== request.reference.sha256)
                return freeze(out(result, "REJECTED", "BODY_MISMATCH", "MISMATCH"));
        }
        catch {
            return freeze(out(result, "ERROR", "BODY_RESOLVER_ERROR", "ERROR"));
        }
        result.verified_body_count++;
    }
    if (requests.length)
        out(result, "AUTHENTICATED", "BODIES_VERIFIED", "VERIFIED");
    return freeze(result);
}
