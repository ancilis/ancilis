# Signed native episodes

Use signed export when a consumer needs to authenticate an episode's collector assertions and, when requested, check the referenced protected bytes. Python and TypeScript use the same canonical format and Ed25519 signature preimage. Existing unsigned `verify_episode_snapshot` / `verifyEpisodeSnapshot` behavior is unchanged.

The complete public-import examples are [Python](../examples/episodes/signed_episode.py) and [Node/TypeScript API](../examples/episodes/signed_episode.mjs). Each attaches a real function, captures a reference to an explicitly synthetic document, exports its episode, and checks successful, missing and altered body retrieval. They generate an ephemeral same-operator demo key. This is a demonstration of the mechanism, not independent trust provisioning or an end-to-end reconstructed middleware episode.

## Export and verify

With an application-owned Ed25519 key, configure `EpisodeSigner(tenant, source, key_id, private_key)` in Python or `new EpisodeSigner({tenant, source, keyId, privateKey})` in TypeScript. Call `episode.export_signed(signer)` / `episode.exportSigned(signer)` after collecting observations. Standalone `sign_episode_snapshot` / `signEpisodeSnapshot` accepts an inspected snapshot. Signing rejects inconsistent native history, discarded history and signer scope mismatch. It takes a detached snapshot and does not hold the collector lock while signing.

The receiver separately constructs `EpisodeTrustPolicy` from its own trusted configuration. Its required fields are `schema: "ancilis-episode-trust-policy/1"`, `tenant`, `source`, `keys`, `body_mode`, `max_body_bytes`, `max_total_body_bytes`, and `max_body_requests`. Every key has `key_id`, a 64-character lowercase raw public-key hex string, nullable `not_before` and `not_after`, and `revoked`. Key IDs must be unique and sorted. Never build this policy from the received envelope or an adjacent purported public key.

Verify with `verify_signed_episode(exported, trust, body_resolver=resolver)` or `await verifySignedEpisode(exported, {trust, bodyResolver})`. Python also provides `await averify_signed_episode(...)` for asynchronous retrieval. A malformed policy or invalid signer raises a fixed-code `SignedEpisodeError`. Untrusted exports and body failures return structured results with sanitized reasons.

The policy fixes one tenant and owner source. At assessment time, a key must be admitted, unrevoked and within `not_before <= assessed_at < not_after` where bounds are supplied. Revocation is checked before validity. `assessed_at` / `assessedAt` allows an explicit reassessment time; otherwise the verifier uses its local UTC clock. This assesses admission under the selected policy and time. It does not establish historical signing time or authoritative policy currentness. Rotation and revocation require an explicitly updated policy; neither API fetches policy or keys.

## Reading the result

| Result | Meaning |
|---|---|
| `AUTHENTICATED` + `NOT_REQUESTED` | Signature admitted; the policy requested no body verification. |
| `AUTHENTICATED` + `VERIFIED` | Signature admitted and every referenced body occurrence matched its digest and length. |
| `UNVERIFIED` + `UNAVAILABLE` | Signature may be admitted, but required bytes were unavailable. |
| `UNVERIFIED` + `NO_REFERENCES` | No body references exist; no positive body verification is claimed. |
| `UNVERIFIED` + `LIMIT_EXCEEDED` | Body requirements exceed the configured budget; no body resolver was called. |
| `REJECTED` | Malformed, altered or wrong-scope evidence, or a body mismatch; inspect the fixed reason. |
| `ERROR` | Verification or the body resolver failed operationally; no success is substituted. |

Always examine `envelope_authenticated`, `protected_bodies`, the reasons and the policy digest together. A body failure preserves any established envelope authentication but fails the body's requirement. `verified_body_count` counts occurrences checked before termination; it is not a count of verified classifications. `reconstruction` remains `UNSUPPORTED` and `verified_claim_refs` remains empty in this native verifier.

Signing collector assertions does not prove actual semantic use, classification truth, control operation, authority, complete capture, a complete predecessor history, or the globally latest episode. Native loss, gaps and incomplete coverage remain visible. A consumer needing those determinations must also use an admissible reconstruction/provider path. Authenticating the same export twice is allowed; durable receiver replay, ordering and idempotency are separate requirements.

## Authorized protected-body retrieval

`ProtectedBodyRequest` supplies `tenant`, `episode`, `open_sha256`, `revision_id`, `event_id` and the complete `reference`. Python uses the existing frozen `ContentEvidence` class for `request.reference`; TypeScript uses a recursively frozen readonly reference object. The reference retains artifact ID, digest, byte length, role, access scope and classification receipt references. Authorize this context before retrieving bytes. Identifiers are data, never instructions to open a path or URL.

Return Python `bytes` or Node `Uint8Array`/`Buffer`, or `None`/`null` when unavailable. Unsupported types, including TypeScript `undefined`, produce a resolver error. Requests run in observation and artifact order without deduplication across authorization contexts. All count and declared byte budgets are checked before the first callback; actual length is checked before a defensive copy and digest comparison. No resolver runs before structure, native integrity, scope, key admission and signature checks pass. No callback is retried.

`body_mode` is `NONE` or `ALL_REFERENCED`. Policy limits are 1–16 MiB per body, 1–64 MiB total declared bytes and 1–1024 requests. The examples use those maximums explicitly. No body or signing key is embedded in the export or result. Digests and metadata are not anonymous.

Resolvers are caller-owned; configure their I/O deadlines. Python async cancellation propagates. TypeScript accepts `signal`, passes it as the resolver's second argument and checks abort before and after awaited retrieval. It cannot stop a resolver that ignores cancellation. The verifier creates no network client, worker, durable queue or body store, and closes none of your resources.

## Format and support

The closed `ancilis-signed-episode/1` envelope has `algorithm`, `key_id`, `schema`, `signature` and `snapshot`. Pure Ed25519 signs `UTF8("ancilis-signed-episode/1\n")` followed by the existing native canonical JSON of the object with the signature member removed. The signature is 128 lowercase hex characters. The export ID is SHA256 of the complete canonical export bytes. Schema assets are in `shared/episodes/v1/`.

Signed verification requires canonical UTF-8 JSON without a BOM, additional whitespace or trailing newline. Duplicate members, unknown fields/schemas, floats, unsafe integers, malformed Unicode and excessive nesting are rejected. The transport cap is 32 MiB before parsing. Reformatting signed JSON requires restoring its canonical bytes before this API accepts it; it does not change existing unsigned JSON handling.

The implementation uses [cryptography's Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) and [Node crypto](https://nodejs.org/docs/latest-v22.x/api/crypto.html), with the primitive defined by [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032). Python loads cryptography when signing/trust configuration is constructed. Native capture imports do not require loading it. Node uses built-in crypto; no remote key discovery or algorithm negotiation is performed. Source and installed-artifact checks are distinct from the final release acceptance matrix.

Python policy documents and standalone snapshot documents must be plain JSON dictionaries, rather than arbitrary `Mapping` implementations. Use `policy.sha256` as a stable policy identity; the policy object is not a supported dictionary key. A damaged installation with missing schema assets is a configuration failure: signing reports `INVALID_NATIVE_SNAPSHOT`, while verification can propagate the schema-loading error. The installed-package checks verify those assets are present.
