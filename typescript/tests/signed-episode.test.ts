import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as SDK from "../src/ancilis/index.js";
const v = JSON.parse(readFileSync("tests/fixtures/episodes/signed-vectors.json", "utf8"));
const body = Buffer.from(v.body_hex, "hex");
function api(name: string): any {
    const value = (SDK as any)[name];
    expect(value, `missing public signed-episode API: ${name}`).toBeTypeOf("function");
    return value;
}
const trust = (changes = {}) => new (api("EpisodeTrustPolicy"))({ ...structuredClone(v.trust_policy), ...changes });
const verify = (wire: unknown = v.export, options = {}) => api("verifySignedEpisode")(wire, { trust: trust(), assessedAt: v.assessed_at, ...options });
const signer = (tenant = "tenant") => api("EpisodeSigner").fromSeed({ tenant, source: "source", keyId: "key-1", seed: Buffer.from(v.seed_hex, "hex") });
describe("signed native contract", () => {
    it("matches the independent primitive signature and result vector", async () => {
        expect(api("signEpisodeSnapshot")(v.snapshot, signer())).toBe(v.export);
        expect(await verify(v.export, { bodyResolver: () => body })).toEqual(v.expected);
    });
    it.each([
        ["schema", "ancilis-signed-episode/0", "INVALID_SIGNED_EXPORT"],
        ["algorithm", "none", "INVALID_SIGNED_EXPORT"],
        ["key_id", "unknown", "UNTRUSTED_KEY"],
        ["signature", "00".repeat(64), "INVALID_SIGNATURE"],
        ["signature", "00".repeat(64) + "\n", "INVALID_SIGNED_EXPORT"],
        ["extra", "field", "INVALID_SIGNED_EXPORT"],
    ])("refuses %s without invoking the resolver", async (field, value, reason) => {
        const envelope = JSON.parse(v.export);
        envelope[field!] = value;
        const called: unknown[] = [];
        const result = await verify(SDK.canonicalEpisodeJSON(envelope), { bodyResolver: (r: unknown) => called.push(r) });
        expect(result.reasons).toEqual([reason]);
        expect(result.envelope_authenticated).toBe(false);
        expect(called).toEqual([]);
    });
    it.each([
        " " + v.export, "\ufeff" + v.export, "\ud800", Buffer.from([255]),
        Buffer.concat([Buffer.from([239, 187, 191]), Buffer.from(v.export)]),
        '{"schema":"a","schema":"b"}', "[".repeat(80) + "0" + "]".repeat(80),
    ])("rejects malformed encoding and noncanonical input", async (wire) => {
        const result = await verify(wire);
        expect(result.status).toBe("REJECTED");
        expect(result.reasons).toEqual(["INVALID_SIGNED_EXPORT"]);
        expect(result.export_sha256).toBeNull();
    });
    it("rejects native tampering", async () => {
        const envelope = JSON.parse(v.export);
        envelope.snapshot.observations[1].artifacts[0].sha256 = "00".repeat(32);
        expect((await verify(SDK.canonicalEpisodeJSON(envelope))).reasons).toEqual(["INVALID_NATIVE_SNAPSHOT"]);
    });
    it.each([
        [{ tenant: "other" }, "SCOPE_MISMATCH"], [{ source: "other" }, "SCOPE_MISMATCH"], [{ keys: [] }, "UNTRUSTED_KEY"],
    ])("requires external scoped trust", async (changes, reason) => {
        expect((await verify(v.export, { trust: trust(changes as any) })).reasons).toEqual([reason]);
    });
    it("enforces validity boundaries and revocation precedence", async () => {
        const key = structuredClone(v.trust_policy.keys[0]);
        expect((await verify(v.export, { assessedAt: key.not_before })).envelope_authenticated).toBe(true);
        expect((await verify(v.export, { assessedAt: key.not_after })).reasons).toEqual(["KEY_NOT_CURRENT"]);
        key.revoked = true;
        expect((await verify(v.export, { trust: trust({ keys: [key] }), assessedAt: key.not_after })).reasons).toEqual(["REVOKED_KEY"]);
    });
    it.each([
        { max_body_bytes: true }, { max_body_requests: 0 }, { body_mode: "TRUST_ALL" }, { unknown: 1 }, { keys: [...v.trust_policy.keys, ...v.trust_policy.keys] },
    ])("rejects malformed policy", (change) => {
        api("EpisodeTrustPolicy");
        expect(() => trust(change)).toThrow("INVALID_TRUST_POLICY");
    });
    it("detaches policy and freezes the full request", async () => {
        const original = structuredClone(v.trust_policy);
        const policy = new (api("EpisodeTrustPolicy"))(original);
        original.keys.length = 0;
        policy.toJSON().keys.length = 0;
        expect(await verify(v.export, { trust: policy, bodyResolver: (r: any) => {
                expect(r.tenant).toBe("tenant");
                expect(r.reference.access_scope).toBe("scope");
                expect(r.event_id).toBe(v.snapshot.observations[1].event_id);
                expect(() => { r.reference.sha256 = "00".repeat(32); }).toThrow();
                return body;
            } })).toEqual(v.expected);
    });
    it.each([
        [null, "UNAVAILABLE", "UNVERIFIED"], [Buffer.from("wrong"), "MISMATCH", "REJECTED"], [undefined, "ERROR", "ERROR"], ["private type", "ERROR", "ERROR"],
    ])("retains only authentication on body failure", async (returned, state, status) => {
        const result = await verify(v.export, { bodyResolver: () => returned });
        expect(result.envelope_authenticated).toBe(true);
        expect(result.protected_bodies).toBe(state);
        expect(result.status).toBe(status);
        expect(result.verified_body_count).toBe(0);
        expect(result.verified_claim_refs).toEqual([]);
        expect(JSON.stringify(result)).not.toContain("private");
    });
    it("refuses oversized requests before resolving and keeps NONE mode explicit", async () => {
        const called: unknown[] = [];
        const bodyResolver = (r: unknown) => called.push(r);
        expect((await verify(v.export, { trust: trust({ max_total_body_bytes: 1 }), bodyResolver })).protected_bodies).toBe("LIMIT_EXCEEDED");
        const result = await verify(v.export, { trust: trust({ body_mode: "NONE" }), bodyResolver });
        expect(result.status).toBe("AUTHENTICATED");
        expect(result.protected_bodies).toBe("NOT_REQUESTED");
        expect(result.reconstruction).toBe("UNSUPPORTED");
        expect(called).toEqual([]);
    });
    it("provides the episode method without claiming empty body verification", async () => {
        api("EpisodeSigner");
        const owner = SDK.Ancilis.open({ tenant: "tenant", source: "source" });
        let wire = "";
        owner.episode("empty", { expectedSurfaces: ["tool"] }, e => { wire = e.exportSigned(signer()); });
        expect((await verify(wire)).protected_bodies).toBe("NO_REFERENCES");
        expect(() => api("signEpisodeSnapshot")(v.snapshot, signer("other"))).toThrow("SCOPE_MISMATCH");
    });
    it("propagates pre-call and post-await cancellation", async () => {
        const controller = new AbortController();
        const reason = new Error("cancelled");
        const called: unknown[] = [];
        controller.abort(reason);
        await expect(verify(v.export, { signal: controller.signal, bodyResolver: (r: unknown) => called.push(r) })).rejects.toBe(reason);
        expect(called).toEqual([]);
        const later = new AbortController();
        await expect(verify(v.export, { signal: later.signal, bodyResolver: async () => { later.abort(reason); return body; } })).rejects.toBe(reason);
    });
    it("does not trust shadowed typed-array length", async () => {
        const wrong = new Uint8Array([1]);
        Object.defineProperty(wrong, "length", { value: body.length });
        Object.defineProperty(wrong, "byteLength", { value: body.length });
        expect((await verify(v.export, { bodyResolver: () => wrong })).protected_bodies).toBe("MISMATCH");
    });
});

it("caps wire input before parsing", async () => {
    const result = await verify(Buffer.alloc(32 * 1024 * 1024 + 1));
    expect(result.reasons).toEqual(["EXPORT_TOO_LARGE"]);
    expect(result.export_sha256).toBeNull();
});
it("sanitizes resolver failures without retry", async () => {
    let calls = 0;
    const result = await verify(v.export, { bodyResolver: () => { calls++; throw new Error("private-body-or-secret"); } });
    expect(result.reasons).toEqual(["ENVELOPE_AUTHENTICATED", "BODY_RESOLVER_ERROR"]);
    expect(calls).toBe(1); expect(JSON.stringify(result)).not.toContain("private-body-or-secret");
});
it("rejects bad seeds and unsorted or malformed policy keys", () => {
    expect(() => api("EpisodeSigner").fromSeed({ tenant: "tenant", source: "source", keyId: "key-1", seed: Buffer.from("bad") })).toThrow("INVALID_SIGNER");
    const key = structuredClone(v.trust_policy.keys[0]);
    for (const keys of [[{ ...key, key_id: "key-2" }, key], [{ ...key, public_key: "00" }], [{ ...key, not_before: "invalid" }]])
        expect(() => trust({ keys })).toThrow("INVALID_TRUST_POLICY");
});

it.each(["schema", "algorithm", "key_id", "snapshot", "signature"])("requires envelope field %s", async (field) => {
    const envelope = JSON.parse(v.export); delete envelope[field];
    expect((await verify(SDK.canonicalEpisodeJSON(envelope))).reasons).toEqual(["INVALID_SIGNED_EXPORT"]);
});

it("pins the exact preimage and preserves ordered repeated occurrences", async () => {
    const envelope = JSON.parse(v.export); delete envelope.signature;
    expect(Buffer.from("ancilis-signed-episode/1\n" + SDK.canonicalEpisodeJSON(envelope)).toString("hex")).toBe(v.signing_preimage_hex);
    const calls: unknown[] = [];
    const result = await verify(v.multiple_export, { bodyResolver: (r: any) => { calls.push([r.event_id, r.reference.access_scope, r.reference.role]); return body; } });
    const rows = v.multiple_snapshot.observations;
    expect(calls).toEqual([[rows[1].event_id,"scope-one","INPUT"],[rows[1].event_id,"scope-two","OUTPUT"],[rows[3].event_id,"scope-three","INPUT"]]);
    expect(result.verified_body_count).toBe(3); expect(result.status).toBe("AUTHENTICATED");
});
it.each([{max_body_bytes:body.length-1},{max_body_requests:2},{max_total_body_bytes:body.length*3-1}])("preflights every body budget", async (change) => {
    const calls: unknown[] = [];
    const result = await verify(v.multiple_export, { trust:trust(change), bodyResolver:(r:unknown)=>calls.push(r) });
    expect(result.protected_bodies).toBe("LIMIT_EXCEEDED"); expect(calls).toEqual([]);
});
it("admits exact budgets and retains partial counts on early failure", async () => {
    const policy=trust({max_body_bytes:body.length,max_total_body_bytes:body.length*3,max_body_requests:3});
    expect((await verify(v.multiple_export,{trust:policy,bodyResolver:()=>body})).verified_body_count).toBe(3);
    let calls=0;
    const result=await verify(v.multiple_export,{trust:policy,bodyResolver:()=>++calls===1?body:null});
    expect(calls).toBe(2);expect(result.verified_body_count).toBe(1);expect(result.protected_bodies).toBe("UNAVAILABLE");
});
it("validates real TypeScript outputs with the shipped JSON schemas", async () => {
    const ajv=new Ajv2020({strict:true,allErrors:true});addFormats(ajv);
    for (const [file,value] of [["signed-episode",JSON.parse(api("signEpisodeSnapshot")(v.snapshot,signer()))],["trust-policy",trust().toJSON()],["signed-verification",await verify(v.export,{bodyResolver:()=>body})]] as const) {
        const schema=JSON.parse(readFileSync(`shared/episodes/v1/${file}.schema.json`,"utf8"));
        const validate=ajv.compile(schema);
        expect(validate(value),JSON.stringify(validate.errors)).toBe(true);
        expect(validate({...value,unexpected:"field"})).toBe(false);
    }
});
