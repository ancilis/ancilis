# Classification providers and history

`assess_episode_classifications` / `assessEpisodeClassifications` connects a signed native episode to an explicitly configured, trusted-code classification adapter. The SDK authenticates the collector export and checks every protected body before invoking that adapter. It binds each response to its exact artifact occurrence, selected receipt references, native revision, assessment time, method and provider policy.

**This is an adapter interface. The current SDK does not ship the reviewed GE provider, a deployable reconstruction gateway, or a qualified semantic classifier.** A configured adapter must authenticate original receipts and any remote responses itself. The SDK checks bindings and response structure; it cannot establish that arbitrary caller-installed code correctly verifies receipts. A positive row is labeled `ADAPTER_ATTESTED`; `verified_claim_refs` remains empty and the signed verifier's `reconstruction` remains `UNSUPPORTED`.

The runnable [Python example](../examples/episodes/classification.py) and [Node example](../examples/episodes/classification.mjs) use public imports, real function attachment, ephemeral same-operator signing keys, an explicitly synthetic receipt callback and no model. They demonstrate an earlier positive assertion followed by an unresolved reassessment of the same signed episode. The synthetic callback is an orchestration demonstration, not a production receipt verifier or GE integration.

## Configure and assess

Create `TrustedClassificationAdapter` with `provider_id`, `method_id`, `policy_sha256`, `taxonomy`, sorted unique `supported_classes`, and a `resolve` callback. Obtain policy and adapter identity independently of the received export. The descriptor is detached and frozen; changing provider policy requires a new adapter. A policy digest is an identity, not proof that the policy is authorized or current.

Python calls `assess_episode_classifications(exported, trust=trust, adapter=adapter, body_resolver=resolver)` or awaits `aassess_episode_classifications(...)`. TypeScript awaits `assessEpisodeClassifications(exported, {trust, adapter, bodyResolver})`. The existing `EpisodeTrustPolicy` must require `ALL_REFERENCED`. Use `assessed_at` / `assessedAt` for explicit reassessment; the default is the local UTC clock. Malformed configuration raises `ClassificationError` with a fixed code.

The trusted callback receives `(request, body)` in Python and `(request, body, signal)` in TypeScript. Python requests have `request_sha256` and a typed `to_dict()` snapshot; TypeScript requests are recursively readonly and frozen. Bodies are immutable Python bytes or a private Node byte copy. The request includes tenant, episode, open and revision hashes, event ID, artifact index, full protected reference, time, and adapter descriptor. Authorize receipt retrieval for this context; references are data, never instructions to open paths or URLs.

Return the closed `ancilis-classification-response/1` object with `request_sha256`, `outcome`, `classification`, `evidence_refs` and `reasons`. Supported outcomes are `SUPPORTED_POSITIVE`, `UNKNOWN`, `ABSTAIN`, `ERROR` and `UNSUPPORTED`. A positive response needs an admitted configured class and evidence hashes matching the complete selected receipt-reference set. It does not mean sensitive vocabulary proves use or authority. Every other outcome has a null class and nonempty reasons. Missing labels never imply benign content; `DC-GEN` is not a universal negative finding. Negative and not-applicable determinations are outside this trusted-label interface and are rejected here.

Response identifiers use the native bounded identifier syntax. Reasons and evidence hashes are sorted unique lists of at most 64 entries. The SDK canonicalizes and validates every response, rejecting additional fields, wrong request bindings, unsupported positive classes, arbitrary mappings/prototypes, getters and malformed values. A callback exception yields `ADAPTER_CALL_FAILED`, separately from `INVALID_ADAPTER_RESPONSE`; neither error is represented as a fabricated adapter response. Processing continues with later occurrences. Error messages and body contents are excluded from reports.

## Semantic recovery is explicit and unqualified

`ExperimentalSemanticProvider` takes `provider_id`, `method_id`, `runtime_id` and `propose`. Supply it through `experimental_semantic` / `experimentalSemantic` only when deliberately evaluating an experimental method. A trusted adapter must also be configured. The proposal callback runs only after a valid trusted response of `UNKNOWN`; it never replaces a positive, abstention, error or unsupported result. The SDK never starts a model or network client implicitly.

The semantic request binds the entire trusted request and response plus the semantic descriptor; bytes are passed separately. Return `ancilis-semantic-proposal/1` with `request_sha256`, `status`, `proposed_classification`, `evidence_refs` and `reasons`. Status is `PROPOSED`, `UNKNOWN`, `ABSTAIN`, `ERROR` or `UNSUPPORTED`. Proposals require a class and evidence references; other statuses require a null class and reasons. No `qualification` or confidence claim in the response can activate a qualified method.

**All experimental proposals remain `UNQUALIFIED`; the row's classification stays null and its outcome stays `UNKNOWN`.** A byte match, ancestor relationship or semantic proposal establishes neither inherited classification, actual use, control operation nor authority. A supported qualified route requires a separately reviewed adapter and qualification evidence; none is enabled by this API.

## Preserve and consume history

The immutable report has a domain-separated `report_sha256` integrity identity. It retains input verification, each original request, the validated adapter response or a distinct SDK reason, and the separate semantic component. `to_dict()` / `toJSON()` returns a detached document. This report does not modify or re-sign the native episode. Empty episodes retain authenticated scope with no classifications and `NO_REFERENCES`; missing or mismatched required bodies prevent all adapter calls.

Use `ClassificationHistory(tenant, episode, open_sha256, ...)` for bounded in-memory history. Python options are `max_reports` and `max_bytes`; TypeScript's fourth argument takes `maxReports` and `maxBytes`. Defaults and hard maxima are 64 reports and 16 MiB. `append` returns true for a new report, false for an exact duplicate, and raises `HISTORY_SCOPE_MISMATCH` or `HISTORY_LIMIT` before changing history. Python serializes history operations across threads. `inspect` returns detached entries in local append order. A later policy, time or native revision produces a separate report; it never erases earlier handling.

Constructing `EpisodeClassificationReport(document)` validates its schema, digests and internal consistency but does not authenticate imported claims. Each history entry therefore exposes `LOCAL_ASSESSMENT` or `PARSED_UNAUTHENTICATED` origin outside the canonical report. Duplicate import history never silently upgrades to local origin. Even local origin means an assessment ran with caller-trusted code, not independent receipt replay. A consumer must not treat parsed positive rows or a recomputable digest as authenticated findings.

History is volatile and caller-owned. It is not a durable receiver, proof of complete prior history, a withdrawal mechanism, or an authoritative global latest head. Persist and authenticate reports through an appropriate receiving integration before relying on them remotely.

## Limits and cancellation

The input/body limits are the signed verifier's limits: 32 MiB export, up to 1,024 body occurrences, 16 MiB per body and 64 MiB total. Retrieval occurs in observation/artifact order, without deduplication across authorization contexts. The SDK caches exactly the checked bytes for this assessment; TypeScript gives each adapter/proposal call a separate copy. Cache memory can reach 64 MiB, plus one callback copy and parsed metadata. Reports retain no bodies. Caller code may retain its callback copy and owns that retention.

Python offers separate synchronous and asynchronous APIs. The sync API rejects configured async callbacks and does not run accidentally returned coroutines. Async cancellation propagates. TypeScript passes the same optional `AbortSignal` and checks it around awaited callbacks; it cannot stop a callback that ignores cancellation. No callback is retried or closed. Configure I/O timeouts in your adapter and body resolver.

The five closed schemas and cross-language synthetic vectors cover requests, trusted responses, semantic requests/proposals and reports. The examples and local checks exercise this SDK interface; they do not establish GE deployment, production disclosure rights, semantic fidelity, final runtime-matrix acceptance, or release readiness.
