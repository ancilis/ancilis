# Ancilis SDK v0.6 Adoption Design

## Goal

Move the SDK from a partial 26-control AKSI snapshot to the frozen v0.6 framework contract: 41 controls, 23 canonical data classes, framework-aware evidence/result schemas, and consistent Python/TypeScript activation behavior.

## Authoritative Source

- Platform repo: `ancilis-one-shot`
- Frozen commit: `aeda1839054090a8384f3d9d2700a656fab519a2`
- Framework doc: `docs/framework/aksi-framework-master.md`
- Machine source: `AKSI_GRAPH.json`, `platform/backend/app/engine/control_catalog.py`
- Existing SDK freeze metadata: `shared/aksi_version.json`

Catalog content must be generated or reconciled from those frozen artifacts. Do not invent control names, descriptions, evidence sources, evidence keywords, data classes, or activation semantics.

## Staged Design

### Stage 1: v0.6 Canonical Catalog

Ship all 41 controls and 23 canonical data classes in shared SDK assets. Keep the 39 common controls active by default and activate the 2 payment controls only from `DC-PAY` or `AGENT_PAYMENTS`/`X402` certification intent.

### Stage 2: Runtime Parity

Update Python and TypeScript activation constants, config schemas, result/evidence schemas, and import mappings so both SDKs agree on valid control IDs, `FLAG` results, framework metadata, and classification activation.

### Stage 3: Evaluator Alignment

Preserve existing evaluators but align their advertised control semantics with v0.6. Mark controls without runtime evaluators as catalog-backed/attestation-only rather than implying full enforcement.

### Stage 4: Adoption Surface

Add developer-facing ergonomics after the catalog is correct: Python facade parity with TypeScript, safer producer redaction defaults, platform connect wiring, and docs that reflect the actual package/runtime behavior.

## Non-Goals For The First Implementation Pass

- Do not claim full framework compliance for external frameworks.
- Do not hand-author new legal/regulatory mappings not present in the frozen source.
- Do not fabricate runtime evaluators for controls that only have attestation evidence today.
- Do not change public package names or distribution layout.

## Acceptance Criteria

- Shared controls contain exactly 41 AKSI v0.6 IDs.
- Shared taxonomy contains exactly the 23 canonical v0.6 classes from `aksi_class.schema.json`.
- `ActivationResolver` defaults to the 39 common controls and adds `PAY-01`/`PAY-02` only for payment activation.
- Python and TypeScript tests verify the same catalog counts and payment activation behavior.
- Schemas accept all v0.6 control IDs and `FLAG` outcomes where the engine already emits them.
- Documentation states attestation-only coverage honestly.
