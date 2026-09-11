// Synthetic same-operator trust demo. Real receivers provision their own policy.
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { Ancilis, ContentEvidence, EpisodeSigner, EpisodeTrustPolicy, TrustedClassificationAdapter, ExperimentalSemanticProvider, ClassificationHistory, assessEpisodeClassifications } from "ancilis";

const receipt=createHash("sha256").update("SYNTHETIC DEMO RECEIPT").digest("hex");
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
      ? { artifacts: [ContentEvidence.fromBytes("document", frame.result, { role: "INPUT", accessScope: "synthetic", classificationReceiptRefs:[receipt] })] }
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
// Toy trusted-code callback only: not GE receipt authentication or qualified semantics.
const trusted=(request,body)=>{
  assert.deepEqual(Buffer.from(body),document);assert.deepEqual(request.reference.classification_receipt_refs,[receipt]);
  return {schema:"ancilis-classification-response/1",request_sha256:request.request_sha256,outcome:"SUPPORTED_POSITIVE",classification:"SYNTHETIC-SENSITIVE",evidence_refs:[receipt],reasons:[]};
};
const stale=request=>({schema:"ancilis-classification-response/1",request_sha256:request.request_sha256,outcome:"UNKNOWN",classification:null,evidence_refs:[],reasons:["STALE_LABEL"]});
const propose=request=>({schema:"ancilis-semantic-proposal/1",request_sha256:request.request_sha256,status:"PROPOSED",proposed_classification:"SYNTHETIC-SENSITIVE",evidence_refs:[receipt],reasons:[]});
const adapter=new TrustedClassificationAdapter({provider_id:"synthetic",method_id:"demo/1",policy_sha256:createHash("sha256").update("demo policy").digest("hex"),taxonomy:"DEMO-v1",supported_classes:["SYNTHETIC-SENSITIVE"],resolve:trusted});
const first=await assessEpisodeClassifications(exported,{trust,adapter,bodyResolver});
const changed=new TrustedClassificationAdapter({...adapter.toJSON(),policy_sha256:createHash("sha256").update("changed demo policy").digest("hex"),resolve:stale});
const second=await assessEpisodeClassifications(exported,{trust,adapter:changed,bodyResolver,experimentalSemantic:new ExperimentalSemanticProvider({provider_id:"synthetic",method_id:"proposal/1",runtime_id:"no-model",propose})});
const d=first.toJSON(),history=new ClassificationHistory(d.tenant,d.episode,d.open_sha256);history.append(first);history.append(second);
assert.equal(second.toJSON().classifications[0].outcome,"UNKNOWN");assert.equal(second.toJSON().classifications[0].semantic.state,"UNQUALIFIED");assert.equal(first.toJSON().export_sha256,second.toJSON().export_sha256);
console.log(JSON.stringify(history.inspect(),null,2));
