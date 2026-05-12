# AKSI v0.6 SDK to Platform Coordination Contract

Date: 2026-05-11
SDK build: `aksi-v06-sdk-full-support`
Frozen framework SHA: `aeda1839054090a8384f3d9d2700a656fab519a2`
Frozen framework branch: `ancilis-one-shot/codex/aksi-production-grade-framework`
Frozen framework path: `docs/framework/aksi-framework-master.md`

This is an interface contract for the platform-side work required to ingest and reason over AKSI v0.6 SDK evidence. It is not an SDK implementation plan. The SDK build can continue against the frozen framework SHA above, but the SDK is complete-but-not-shippable until the platform changes in this contract are deployed.

## Release Gate

The v0.6 SDK emits 41-control, framework-versioned evidence. The current platform has v0.6 framework assets on the frozen branch, but the evidence storage and API surfaces still treat `control_id` as unversioned. Because v0.6 renumbers several controls, the platform must not read old v0.5 `PR-01` evidence as v0.6 `PR-01` evidence.

Minimum release gate:

- `evidence_records.framework_version` exists and is preserved on ingest, list, export, integrity, and posture recomputation paths.
- `control_assessments.framework_version` exists and assessment uniqueness is version-aware.
- v0.5 records with NULL `framework_version` are queryable for historical reporting but are not used to satisfy v0.6 controls.
- The platform accepts SDK v0.6 evidence at `POST /api/evidence/batches` or the SDK client is intentionally migrated to a documented v1 endpoint before release.

## Platform Files Requiring Updates

Exact files in `<platform-repo>` that need platform-side changes:

- `platform/backend/app/models/evidence_record.py`
  Add nullable `framework_version: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)`. NULL represents v0.5 and earlier.

- `platform/backend/app/models/control_assessment.py`
  Add nullable `framework_version: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)`. Replace `uq_control_assessments_org_id_system_id_control_id` with a version-aware uniqueness rule using `COALESCE(framework_version, '0.5')`.

- `platform/backend/app/schemas/evidence.py`
  Add `framework_version: str | None = Field(default=None, max_length=16)` to `EvidenceIngestRequest`, `EvidenceResponse`, `EvidenceFilterParams`, and `EvidenceListQuery`. Direct v0.6 SDK evidence sends `"0.6"`; omitted/NULL is legacy v0.5.

- `platform/backend/app/api/v1/evidence.py`
  Update `POST /v1/evidence/ingest`, `POST /v1/evidence/import`, `GET /v1/evidence`, `GET /v1/evidence/export`, `GET /v1/evidence/{evidence_id}/integrity`, `GET /v1/evidence/batches/{batch_id}/integrity`, and `GET /v1/evidence/chain/verify` to read, persist, serialize, filter, and hash `framework_version`.

- `platform/backend/app/api/v1/otel_ingest.py`
  Ensure `POST /v1/ingest/otlp/v1/traces` translated evidence items carry a framework version. OTEL-origin evidence without SDK v0.6 fields should remain NULL/v0.5 unless the adapter can prove v0.6 semantics.

- `platform/backend/app/api/v1/webhook_ingest.py`
  Ensure `POST /v1/ingest/openai/events`, `POST /v1/ingest/anthropic/events`, and `POST /v1/ingest/bedrock/events` preserve `framework_version` from translated items. If provider events do not contain SDK v0.6 metadata, store NULL.

- `platform/backend/app/services/evidence_pipeline.py`
  Add `resolve_framework_version(item)` alongside `resolve_control_id(item)`. Persist the resolved version. When recomputing posture from created records, pass both control IDs and framework version.

- `platform/backend/app/services/evidence_integrity.py`
  Include `framework_version` in canonical evidence hashes and batch verification responses. Add a legacy compatibility branch for records where `framework_version IS NULL`, because existing hashes were computed without that field.

- `platform/backend/app/engine/control_catalog.py`
  Confirm the runtime catalog loads exactly the frozen 41 v0.6 controls and exposes `framework_version="0.6"` with every control definition.

- `platform/backend/app/engine/evaluator.py`
  Scope evidence lookups and control assessment upserts by framework version. `evaluate_system_posture` and `evaluate_affected_controls` must query v0.6 evidence only when evaluating v0.6 controls. v0.5 evidence must not satisfy v0.6 assessments.

- `platform/backend/app/engine/overlays.py`
  Confirm the platform loads the 35 frozen v0.6 overlays and normalizes any `AKSI-` product-facing IDs to SDK/platform internal IDs before matching. Overlay readiness should carry `framework_version="0.6"` in derived metadata.

- `platform/backend/app/classification/service.py`
  Preserve `framework_version` through classification findings where evidence context is copied. New v0.6 data classes must remain limited to the frozen 23-class taxonomy.

- `platform/backend/app/seed/run.py`
  Seed v0.6 control catalog metadata, v0.6 overlays, and version-aware demo/control assessment rows. Do not backfill old evidence as v0.6.

- `platform/backend/app/api/v1/assessments.py`
  Return and filter control assessments by framework version. If a request does not specify a framework version, existing behavior should return NULL/v0.5 until the UI/API contract is explicitly moved to v0.6.

- `platform/backend/app/api/v1/posture.py`
  Include framework version in posture summaries, timeline evidence counts, and readiness cards so v0.5 and v0.6 are not blended.

- `platform/backend/app/api/v1/certifications.py`
  Ensure framework readiness/detail views use v0.6 overlay control IDs and v0.6 assessment rows.

- `platform/backend/app/schemas/assessments.py`, `platform/backend/app/schemas/posture.py`, `platform/backend/app/schemas/export.py`, `platform/backend/app/schemas/external.py`
  Add `framework_version` fields wherever evidence/control-assessment payloads are serialized or filtered.

- `platform/backend/app/api/v1/external.py`
  `GET /v1/external/readiness` must either accept an explicit `framework_version` query parameter or clearly return only one version. For v0.6 launch, prefer `framework_version=0.6` support with legacy default behavior preserved.

- `platform/backend/app/adapters/base.py` and provider adapters under `platform/backend/app/adapters/`
  Add `framework_version` to `TranslatedEvidenceItem` or its context payload path. Provider adapters that cannot prove v0.6 semantics must emit NULL, not `"0.6"`.

- `platform/backend/app/adapters/sdk_chain_verifier.py`
  Add `framework_version` to the SDK canonical payload verifier for v0.6 records, with a legacy verifier path for records where the field is absent.

- `platform/backend/migrations/`
  Add an Alembic migration for the schema changes and index/constraint replacement below.

- `platform/backend/tests/`
  Add mixed-version ingestion, lookup, posture, export, and integrity tests. At minimum update `tests/test_engine.py`, `tests/test_assessments_api.py`, `tests/test_certifications_api.py`, `tests/test_classification_service.py`, `tests/test_external_api.py`, `tests/test_evidence_import_cyclonedx.py`, `tests/test_hipaa_overlay.py`, `tests/test_posture_api.py`, and `tests/test_seed.py`.

## Database Migration Contract

Required migration:

```sql
ALTER TABLE evidence_records
  ADD COLUMN framework_version VARCHAR(16) DEFAULT NULL;

ALTER TABLE control_assessments
  ADD COLUMN framework_version VARCHAR(16) DEFAULT NULL;

CREATE INDEX ix_evidence_records_org_framework_timestamp
  ON evidence_records (org_id, framework_version, timestamp);

CREATE INDEX ix_evidence_records_system_framework_control
  ON evidence_records (system_id, framework_version, control_id);

ALTER TABLE control_assessments
  DROP CONSTRAINT uq_control_assessments_org_id_system_id_control_id;

CREATE UNIQUE INDEX uq_control_assessments_org_system_control_fw
  ON control_assessments (
    org_id,
    system_id,
    control_id,
    COALESCE(framework_version, '0.5')
  );
```

Migration rules:

- Do not backfill old rows to `"0.6"`.
- NULL means legacy v0.5 or earlier.
- New v0.6 SDK rows must store `"0.6"`.
- New platform-generated v0.6 assessment rows must store `"0.6"`.
- Version-aware queries should treat requested `"0.5"` as `framework_version IS NULL`; requested `"0.6"` as `framework_version = '0.6'`.

## v0.6 Evidence Shape

The SDK v0.6 canonical local evidence record should include these fields. Python uses snake_case; TypeScript exposes camelCase in memory but serializes to this JSON shape for platform sync.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `framework_version` | string | yes for v0.6 | Must be `"0.6"` for this SDK build. Absence/NULL is v0.5 legacy only. |
| `record_id` | string UUID | yes | SDK local evidence record ID. |
| `evaluation_id` | string UUID | yes | Evaluation run ID. |
| `record_hash` | string | yes | SHA-256 hash of canonical v0.6 payload. |
| `previous_hash` | string | yes | Previous SDK evidence-chain hash. |
| `agent_id` | string | yes | SDK agent ID. |
| `source_type` | string | yes | Examples: `agent`, `cli`, `tool`, `http`, `mcp`, `runtime`, `llm`, `bedrock`. |
| `producer_type` | string | yes | Producer surface, such as `cli`, `mcp`, `tool`, `http`, `runtime`, `llm`, `langchain`, `crewai`, `autogen`, `semantic_kernel`, `bedrock`, `auto`. |
| `producer_version` | string | yes | SDK producer version. |
| `tool_name` | string | yes | Tool or operation name. |
| `decision` | string enum | yes | `ALLOW`, `BLOCK`, or `FLAG`. |
| `mode` | string enum | yes | `audit` or `enforce`. |
| `timestamp` | string datetime | yes | ISO 8601. |
| `controls` | array | yes | Per-control evaluator results. |
| `overlays` | string array | yes | Active overlay IDs. |
| `classifications` | string array | yes | Detected/declared v0.6 data classes from the frozen 23-class taxonomy. |
| `certifications` | string array | yes | Active certification targets. |
| `session` | string or null | yes | Runtime session ID if known. |
| `tenant` | string or null | yes | Tenant ID if configured. |
| `sdk_version` | string or null | yes | SDK package version. |
| `classification_context` | object | yes | Context for data classification and overlay activation. |
| `action_context` | object | yes | v0.6 action context fields used by controls. |
| `detected_data_types` | string array | yes | Runtime detected data types. |
| `total_duration_ms` | number | yes | Evaluation duration. |
| `output_summary` | string or null | yes | Optional output summary. |

Per-control item shape:

```json
{
  "control_id": "AKSI-PR-12",
  "internal_control_id": "PR-12",
  "control_name": "Network Egress Policy",
  "result": "FAIL",
  "detail": "HTTP call attempted to an external host outside the approved egress allowlist.",
  "evidence_data": {
    "framework_version": "0.6",
    "tool_name": "http.request",
    "destination_host": "api.example-vendor.com",
    "egress_policy_id": "egress-prod-default",
    "egress_allowed": false,
    "trust_zone": "prod",
    "purpose": "customer-support-workflow"
  },
  "duration_ms": 3.7
}
```

Action context shape required for v0.6 evaluators:

```json
{
  "session_id": "sess_20260511_001",
  "parent_action_id": null,
  "data_classifications": ["customer_data", "financial_data"],
  "active_overlays": ["soc2", "pci_dss"],
  "sandbox_class": "network-restricted",
  "trust_zone": "prod",
  "purpose": "customer-support-workflow",
  "approval_id": "appr_01HW6K4J5N7YQG2S9T1A2B3C4D",
  "payment": {
    "amount": "25.00",
    "currency": "USD",
    "merchant_id": "m_123",
    "processor": "stripe",
    "idempotency_key": "pay_20260511_001"
  },
  "detected_data_types": ["email", "cardholder_data"],
  "runtime": {
    "tool_origin": "mcp",
    "network_destination": "api.example-vendor.com",
    "filesystem_scope": "workspace",
    "code_execution": false
  }
}
```

Full SDK batch example for `POST /api/evidence/batches`:

```json
{
  "records": [
    {
      "framework_version": "0.6",
      "record_id": "8f5dfb32-7b42-46f0-9c5f-e8cf53826f55",
      "evaluation_id": "2f4c0e0e-31e7-4fd3-8fd1-b4f3f767f773",
      "record_hash": "d3c615d5b7e7e1387f4e0fa6d7e2e9a3b82f2d88fa8c9159db8ef6a20b69af5d",
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "agent_id": "agent-prod-support",
      "source_type": "agent",
      "producer_type": "http",
      "producer_version": "0.6.0",
      "tool_name": "http.request",
      "decision": "FLAG",
      "mode": "audit",
      "timestamp": "2026-05-11T19:45:10.122Z",
      "controls": [
        {
          "control_id": "AKSI-PR-12",
          "internal_control_id": "PR-12",
          "control_name": "Network Egress Policy",
          "result": "FAIL",
          "detail": "Destination host was outside the approved allowlist.",
          "evidence_data": {
            "framework_version": "0.6",
            "destination_host": "api.example-vendor.com",
            "egress_allowed": false,
            "egress_policy_id": "egress-prod-default",
            "trust_zone": "prod",
            "purpose": "customer-support-workflow"
          },
          "duration_ms": 3.7
        }
      ],
      "overlays": ["soc2", "pci_dss"],
      "classifications": ["customer_data", "financial_data"],
      "certifications": ["SOC2", "PCI_DSS"],
      "session": "sess_20260511_001",
      "tenant": "tenant_acme",
      "sdk_version": "0.6.0",
      "classification_context": {
        "declared_data_classes": ["customer_data"],
        "detected_data_types": ["email", "cardholder_data"],
        "llm_provider": "openai"
      },
      "action_context": {
        "sandbox_class": "network-restricted",
        "trust_zone": "prod",
        "purpose": "customer-support-workflow",
        "approval_id": null,
        "payment": null,
        "detected_data_types": ["email", "cardholder_data"]
      },
      "detected_data_types": ["email", "cardholder_data"],
      "total_duration_ms": 19.4,
      "output_summary": "HTTP egress call flagged by PR-12."
    }
  ]
}
```

Full direct-ingest example for `POST /v1/evidence/ingest`:

```json
{
  "source_id": "11111111-1111-4111-8111-111111111111",
  "system_id": "22222222-2222-4222-8222-222222222222",
  "agent_id": "33333333-3333-4333-8333-333333333333",
  "framework_version": "0.6",
  "control_id": "PR-12",
  "timestamp": "2026-05-11T19:45:10.122Z",
  "result": "FAIL",
  "summary": "HTTP egress call blocked by PR-12.",
  "payload": {
    "sdk_record_id": "8f5dfb32-7b42-46f0-9c5f-e8cf53826f55",
    "sdk_evaluation_id": "2f4c0e0e-31e7-4fd3-8fd1-b4f3f767f773",
    "control_result": {
      "control_id": "PR-12",
      "product_control_id": "AKSI-PR-12",
      "control_name": "Network Egress Policy",
      "result": "FAIL",
      "evidence_data": {
        "framework_version": "0.6",
        "destination_host": "api.example-vendor.com",
        "egress_allowed": false,
        "egress_policy_id": "egress-prod-default"
      }
    },
    "active_overlays": ["soc2", "pci_dss"],
    "classification_context": {
      "declared_data_classes": ["customer_data"],
      "detected_data_types": ["email", "cardholder_data"]
    }
  },
  "context": {
    "framework_version": "0.6",
    "producer_type": "http",
    "producer_version": "0.6.0",
    "session_id": "sess_20260511_001",
    "trust_zone": "prod",
    "purpose": "customer-support-workflow",
    "sandbox_class": "network-restricted",
    "detected_data_types": ["email", "cardholder_data"]
  },
  "provenance": {
    "source": "ancilis-sdk",
    "sdk_version": "0.6.0",
    "record_hash": "d3c615d5b7e7e1387f4e0fa6d7e2e9a3b82f2d88fa8c9159db8ef6a20b69af5d",
    "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

Full PAY-01/PAY-02 payment example:

```json
{
  "framework_version": "0.6",
  "record_id": "0f5231e1-8363-4891-8f0d-37de15a672f9",
  "evaluation_id": "8620b870-4b8e-41b5-97a5-f8fbcdbb4bb8",
  "record_hash": "913de52cf47fbf7a65228b3b7bc91753da2f7a4ce61c7122d99d98d3105f7833",
  "previous_hash": "d3c615d5b7e7e1387f4e0fa6d7e2e9a3b82f2d88fa8c9159db8ef6a20b69af5d",
  "agent_id": "agent-payment-ops",
  "source_type": "agent",
  "producer_type": "tool",
  "producer_version": "0.6.0",
  "tool_name": "payments.capture",
  "decision": "BLOCK",
  "mode": "enforce",
  "timestamp": "2026-05-11T20:04:42.500Z",
  "controls": [
    {
      "control_id": "AKSI-PAY-01",
      "internal_control_id": "PAY-01",
      "control_name": "Payment Authorization Boundary",
      "result": "FAIL",
      "detail": "Payment action lacked a valid approval ID.",
      "evidence_data": {
        "framework_version": "0.6",
        "approval_id": null,
        "amount": "1499.00",
        "currency": "USD",
        "merchant_id": "m_enterprise"
      },
      "duration_ms": 2.1
    },
    {
      "control_id": "AKSI-PAY-02",
      "internal_control_id": "PAY-02",
      "control_name": "Payment Idempotency and Reconciliation",
      "result": "PASS",
      "detail": "Payment carried an idempotency key and reconciliation reference.",
      "evidence_data": {
        "framework_version": "0.6",
        "idempotency_key": "pay_20260511_001",
        "reconciliation_reference": "recon_20260511_batch_9"
      },
      "duration_ms": 1.6
    }
  ],
  "overlays": ["agent_payments", "soc2"],
  "classifications": ["financial_data"],
  "certifications": ["SOC2"],
  "session": "sess_payment_001",
  "tenant": "tenant_acme",
  "sdk_version": "0.6.0",
  "classification_context": {
    "declared_data_classes": ["financial_data"],
    "detected_data_types": ["payment_amount", "merchant_id"]
  },
  "action_context": {
    "sandbox_class": null,
    "trust_zone": "prod",
    "purpose": "payment-capture",
    "approval_id": null,
    "payment": {
      "amount": "1499.00",
      "currency": "USD",
      "merchant_id": "m_enterprise",
      "processor": "stripe",
      "idempotency_key": "pay_20260511_001",
      "reconciliation_reference": "recon_20260511_batch_9"
    },
    "detected_data_types": ["payment_amount", "merchant_id"]
  },
  "detected_data_types": ["payment_amount", "merchant_id"],
  "total_duration_ms": 15.2,
  "output_summary": "Payment capture blocked because approval evidence was absent."
}
```

## API Endpoint Contract

Existing platform endpoints that need version-aware behavior:

- `POST /v1/evidence/ingest`
  Accept `framework_version` in body. Persist it on `EvidenceRecord`. Reject `"0.6"` records whose `control_id` is not one of the 41 frozen v0.6 control IDs.

- `POST /v1/evidence/import`
  Imported SBOM/SARIF evidence remains NULL/v0.5 unless the importer is explicitly upgraded to v0.6 mappings. Once upgraded, imported v0.6 evidence must carry `framework_version="0.6"`.

- `GET /v1/evidence`
  Add optional query parameter `framework_version`. `"0.6"` returns only v0.6 rows. `"0.5"` returns only NULL rows. No parameter preserves existing behavior for legacy UI, unless the product/API owner explicitly changes the default.

- `GET /v1/evidence/export`
  Add optional query parameter `framework_version`. Export output must include each record's framework version.

- `GET /v1/evidence/{evidence_id}/integrity`
  Include `framework_version` in the response and use the v0.6 canonical hash when present.

- `GET /v1/evidence/batches/{batch_id}/integrity`
  Include mixed-version detection. A single batch should not contain both NULL/v0.5 and `"0.6"` records unless explicitly marked as a migration batch.

- `GET /v1/evidence/chain/verify`
  Keep chain verification across all records by default, but add `framework_version` filtering for v0.6-only verification.

- `POST /v1/ingest/otlp/v1/traces`
  Preserve v0.6 framework metadata if present in span attributes. Otherwise store NULL/v0.5.

- `POST /v1/ingest/openai/events`, `POST /v1/ingest/anthropic/events`, `POST /v1/ingest/bedrock/events`
  Preserve v0.6 framework metadata if provider event payloads contain SDK v0.6 context. Otherwise store NULL/v0.5.

- `GET /v1/external/readiness`
  Add optional `framework_version` query parameter or document that it returns only current production version. For v0.6 SDK release, readiness must be able to report v0.6 separately from v0.5.

SDK endpoint mismatch to resolve:

- Current SDK `python/src/ancilis/platform/client.py` posts to `POST /api/evidence/batches`.
- The frozen platform branch does not expose a matching route in `platform/backend/app/api/v1/`.
- Before release, either implement `POST /api/evidence/batches` as a compatibility endpoint for SDK batch sync, or update SDK sync to post to a new documented `POST /v1/evidence/batches` endpoint and implement that endpoint on the platform.
- The batch endpoint must accept the full SDK batch example above and return:

```json
{
  "results": [
    {
      "record_id": "8f5dfb32-7b42-46f0-9c5f-e8cf53826f55",
      "status_code": 201,
      "remote_evidence_id": "44444444-4444-4444-8444-444444444444",
      "error": null
    }
  ]
}
```

## Mixed v0.5 and v0.6 Migration Strategy

- Treat NULL `framework_version` as v0.5 for display and historical export only.
- Do not infer v0.6 from SDK version, timestamp, branch name, or control ID alone.
- Do not backfill v0.5 evidence to v0.6.
- Do not join v0.5 and v0.6 evidence into the same control assessment row.
- When evaluating v0.6, use only `EvidenceRecord.framework_version = '0.6'`.
- When evaluating v0.5 legacy posture, use only `EvidenceRecord.framework_version IS NULL`.
- If an API caller requests `control_id=PR-01&framework_version=0.6` and only NULL/v0.5 `PR-01` rows exist, return an empty list.
- If an API caller requests `control_id=PR-01` without a framework version, preserve the current legacy behavior until the product/API owner changes the default.
- Dashboards should show the selected framework version in the response body to avoid accidental screenshots with ambiguous control semantics.

## AKSI_GRAPH.json Decision

The SDK should not read `AKSI_GRAPH.json` from the platform repo at runtime. The SDK needs deterministic, package-local assets for offline agents, CI, and customer environments that do not have the platform repository mounted.

Decision:

- `AKSI_GRAPH.json` remains a platform artifact for platform graph/readiness experiences.
- The SDK ships `shared/aksi_version.json`, `shared/controls/*`, `shared/classifications/*`, and `shared/overlays/*` as its canonical package-local surface.
- If the SDK later needs graph traversal, generate a package-local graph artifact from the same frozen framework SHA during the SDK build. Do not load directly from a sibling platform checkout at runtime.

Reasoning:

- Runtime reads from the platform worktree would make installed SDK behavior depend on developer filesystem state.
- The freeze file already pins the source SHA and checksum.
- Package-local shared assets make Python and TypeScript parity testable in CI.

## Minimum Platform Changes Before SDK v0.6 Ship

The following are non-negotiable before the SDK can ship without breaking platform evidence ingestion:

1. Add `framework_version` to `evidence_records`, `control_assessments`, schemas, serializers, filters, and exports.
2. Make posture evaluation and assessment upserts version-aware.
3. Add or align the SDK batch ingest endpoint.
4. Accept and persist full SDK v0.6 evidence payloads with `framework_version="0.6"`.
5. Reject invalid v0.6 control IDs rather than silently storing them.
6. Preserve NULL/v0.5 evidence for historical reporting without using it for v0.6 controls.
7. Add mixed-version tests proving v0.5 `PR-01` does not satisfy v0.6 `PR-01`.
8. Update readiness/export APIs so customer-facing reports clearly identify framework version.

## Natural SDK Pause Points

These are planning checkpoints only. Option B still requires full v0.6 support before launch.

1. Platform-readable v0.6 framework slice
   Shared controls, classifications, overlays, and freeze metadata exist in the SDK. The platform can read the same frozen framework semantics, but evaluators may not be wired. Demonstrable: catalog parity and overlay/taxonomy assets. Not shippable.

2. End-to-end v0.6 evidence slice
   One producer emits `framework_version="0.6"` evidence through one v0.6 evaluator into DuckDB and through the platform ingest contract. Demonstrable: the integration works, including version isolation. Not shippable because most controls may still be stubs.

3. Full 41-control evaluator coverage slice
   Python and TypeScript both have all 41 evaluator factories wired, every evaluator exposes matching control IDs, and no evaluator returns "No evaluator implemented for this control" for applicable controls. Demonstrable: evaluator parity and full meaningful enforcement. This is the first SDK slice that can support the option-B release, assuming docs/examples and platform release gates are also complete.
