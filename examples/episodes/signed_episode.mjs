// Synthetic same-operator trust demo. Real receivers provision their own policy.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Ancilis, ContentEvidence, EpisodeSigner, EpisodeTrustPolicy, verifySignedEpisode } from "ancilis";

const document = Buffer.from("Synthetic public document used only by this signing example.");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = new EpisodeSigner({ tenant: "demo", source: "application", keyId: "demo-key", privateKey });
const trust = new EpisodeTrustPolicy({
  schema: "ancilis-episode-trust-policy/1", tenant: "demo", source: "application",
  keys: [{ key_id: "demo-key", public_key: Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("hex"), not_before: null, not_after: null, revoked: false }],
  body_mode: "ALL_REFERENCED", max_body_bytes: 16777216, max_total_body_bytes: 67108864, max_body_requests: 1024,
});
const owner = Ancilis.open({ tenant: "demo", source: "application" });
const readDocument = owner.attachTool(() => document, {
  name: "read-document", surface: "document", operation: "READ",
  capture(frame) {
    return frame.phase === "END" && frame.error === undefined
      ? { artifacts: [ContentEvidence.fromBytes("document", frame.result, { role: "INPUT", accessScope: "synthetic" })] }
      : { artifacts: [] };
  },
});
let episode;
owner.episode("signed-example", { expectedSurfaces: ["document"] }, current => {
  episode = current;
  assert.equal(readDocument(), document);
});
const exported = episode.exportSigned(signer);
await owner.close();
function bodyResolver(request) {
  return request.tenant === "demo" && request.reference.access_scope === "synthetic" && request.reference.artifact === "document" ? document : null;
}
const result = await verifySignedEpisode(exported, { trust, bodyResolver });
assert.equal(result.status, "AUTHENTICATED");
assert.equal(result.protected_bodies, "VERIFIED");
assert.equal(result.reconstruction, "UNSUPPORTED");
assert.deepEqual(result.verified_claim_refs, []);
const missing = await verifySignedEpisode(exported, { trust });
assert.equal(missing.envelope_authenticated, true);
assert.equal(missing.protected_bodies, "UNAVAILABLE");
const tampered = await verifySignedEpisode(exported, { trust, bodyResolver: () => Buffer.from("changed") });
assert.equal(tampered.status, "REJECTED");
assert.equal(tampered.protected_bodies, "MISMATCH");
console.log(JSON.stringify(result, null, 2));
