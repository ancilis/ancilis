# AKSI v0.6 SDK Full Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Python and TypeScript SDKs into full day-one support for the AKSI v0.6 framework: 39 common controls for every governed agent, plus 2 payment-extension controls activated by `DC-PAY` or payment certification targets.

**Architecture:** Treat the framework worktree as the AKSI v0.6 source material, but make the SDK's `shared/` package assets the runtime source of truth. Use shared JSON controls, shared taxonomy, shared overlay profiles, cross-language golden fixtures, and mirrored Python/TypeScript evaluator registries so both SDKs evaluate the same applicable controls with the same semantics. Preserve honest support boundaries by distinguishing inline-enforceable, observable, and attestation/external-evidence controls rather than returning blanket `SKIP`.

**Tech Stack:** Shared JSON assets and JSON Schema, Python Pydantic SDK, TypeScript Zod SDK, DuckDB evidence store, pytest, vitest, Node parity scripts.

---

## Review Snapshot

Reviewed framework worktree:

`<platform-repo-worktree>`

Reviewed current SDK branch:

`<sdk-repo>`

Graph MCP tools were not exposed in this session, so discovery fell back to local source inspection. Relevant source artifacts:

- Framework master: `docs/framework/aksi-framework-master.md`
- Framework graph: `AKSI_GRAPH.json`
- Framework backend catalog: `platform/backend/app/engine/control_catalog.py`
- Current SDK controls: `shared/controls/*.json`
- Current SDK taxonomy: `shared/classifications/taxonomy.json`
- Current Python engine: `python/src/ancilis/engine/engine.py`
- Current TypeScript engine: `typescript/src/ancilis/engine/engine.ts`
- Synced SDK branch for this build: `feat/aksi-v06-sdk-task-0-freeze`, created from `origin/main` because local `main` is checked out by another worktree.
- Synced producer surface: 14 Python producer files and 13 TypeScript producer files.
- LLM producer discovery: `python/src/ancilis/producers/llm.py` and `typescript/src/ancilis/producers/llm.ts` both exist. They expose a base LLM producer plus provider-specific producers for Anthropic, OpenAI, Gemini, Mistral, Cohere, xAI, Groq, Together, Fireworks, and DeepSeek. Treat Task 8 as a full LLM enrichment task, not a five-producer task.

Build estimate after producer sync:

- Original rough estimate: 24-34 days.
- Corrected rough estimate: 27-38 days.
- Task 8 alone: 7-10 days, because it covers action producers, framework producers, LLM provider producers, Bedrock, auto-detection, and TypeScript parity.

Current gap:

- Framework worktree defines 41 controls: 39 common + `PAY-01`, `PAY-02`.
- Current SDK has 26 shared control definitions.
- Missing shared SDK controls: `GOV-05`, `GOV-06`, `GOV-07`, `PR-09`, `PR-10`, `PR-11`, `PR-12`, `DE-05`, `DE-06`, `RS-04`, `RS-05`, `RS-06`, `RC-03`, `PAY-01`, `PAY-02`.
- Current SDK taxonomy has 16 canonical classes; AKSI v0.6 schema has 23 canonical classes.
- Missing canonical SDK classes: `DC-SAD`, `DC-NPI`, `DC-PAY`, `DC-EDU`, `DC-CJI`, `DC-EAR`, `DC-MEDDEV`.
- Legacy labels such as `DC-Code-Execution` and `DC-External-API` must not become canonical classes; they should resolve to control-detection findings such as `PR-09`, `ID-02`, or `PR-03`.
- Python runtime currently wires 12 control evaluators: `PR-01` through `PR-08`, `DE-01`, `DE-02`, `DE-04`, `GOV-02`.
- TypeScript runtime currently wires 11 control evaluators: `PR-01` through `PR-08`, `DE-01`, `DE-02`, `DE-04`.
- Some Python/TypeScript evaluators exist but are not wired into the engine, such as `GOV-01`, `GOV-03`, and `ID-01`.

Major semantic drift:

| ID | Current SDK meaning | AKSI v0.6 meaning | Plan |
| --- | --- | --- | --- |
| `GOV-01` | Agent Governance Policy | Agent Identity & Authentication | Move old `PR-01` identity semantics to `GOV-01`; keep governance policy as part of `GOV-03`/`GOV-05`/`GOV-06`. |
| `PR-01` | Agent Identity & Authentication | Action Authorization | Implement new authorization evaluator; do not keep old semantics under this ID. |
| `PR-05` | Comprehensive Audit Trail | Context & Tenant Isolation | Rename old `PR-05` audit support to `PR-06`; implement new isolation evaluator for `PR-05`. |
| `PR-06` | Configuration Integrity Baseline | Audit Trail Completeness | Move current audit-trail checks here; move config drift/baseline support under `DE-03`. |
| `DE-02` | Configuration Drift Monitoring | Classification Drift & Boundary Validation | Replace with declared-vs-observed data-classification drift logic. |
| `DE-03` | Compliance Posture Assessment | Configuration/Dependency Drift Monitoring | Use current config-baseline and drift code here. |
| `RS-02` | Human Escalation Workflow | Containment, Quarantine & Kill Switch | Implement containment semantics; move escalation to `RS-03`. |
| `RS-03` | Incident Evidence Preservation | Human Escalation & Incident Reporting | Implement human escalation/reporting semantics and preserve incident evidence via shared response evidence fields. |

## File Structure

Shared assets:

- Modify: `shared/controls/*.json`
- Modify: `shared/classifications/taxonomy.json`
- Modify: `shared/schemas/action.schema.json`
- Modify: `shared/schemas/config.schema.json`
- Modify: `shared/schemas/evaluation-result.schema.json`
- Modify: `shared/overlays/*.json`
- Create: `shared/fixtures/aksi-v06/control-evaluation-vectors.json`
- Create: `scripts/check_aksi_v06_parity.mjs`

Python SDK:

- Modify: `python/src/ancilis/config.py`
- Modify: `python/src/ancilis/activation/loader.py`
- Modify: `python/src/ancilis/activation/resolver.py`
- Modify: `python/src/ancilis/engine/action.py`
- Modify: `python/src/ancilis/engine/result.py`
- Modify: `python/src/ancilis/engine/engine.py`
- Modify: `python/src/ancilis/engine/evaluators/__init__.py`
- Create: `python/src/ancilis/engine/context.py`
- Create or modify evaluator modules under `python/src/ancilis/engine/evaluators/`
- Move/rename current `python/src/ancilis/controls/pr05_audit.py` and `python/src/ancilis/controls/de01_baseline.py` into the canonical evaluator package or re-export them from compatibility modules.
- Modify: `python/tests/test_aksi_importability.py`
- Create: `python/tests/test_aksi_v06_parity.py`
- Create: `python/tests/test_aksi_v06_semantic_migration.py`
- Create: `python/tests/test_aksi_v06_evaluators.py`
- Create: `python/tests/test_aksi_v06_activation.py`

TypeScript SDK:

- Modify: `typescript/src/ancilis/config/index.ts`
- Modify: `typescript/src/ancilis/activation/loader.ts`
- Modify: `typescript/src/ancilis/activation/resolver.ts`
- Modify: `typescript/src/ancilis/engine/action.ts`
- Modify: `typescript/src/ancilis/engine/result.ts`
- Modify: `typescript/src/ancilis/engine/engine.ts`
- Modify: `typescript/src/ancilis/engine/evaluators/index.ts`
- Create: `typescript/src/ancilis/engine/context.ts`
- Create or modify evaluator modules under `typescript/src/ancilis/engine/evaluators/`
- Move/rename current `typescript/src/ancilis/controls/pr05Audit.ts` and `typescript/src/ancilis/controls/de01Baseline.ts` into the canonical evaluator package or re-export them from compatibility modules.
- Modify: `typescript/tests/import.integration.test.ts`
- Create: `typescript/tests/aksi-v06-parity.test.ts`
- Create: `typescript/tests/aksi-v06-semantic-migration.test.ts`
- Create: `typescript/tests/aksi-v06-evaluators.test.ts`
- Create: `typescript/tests/aksi-v06-activation.test.ts`

Docs and examples:

- Modify: `docs/controls-reference.md`
- Modify: `docs/sdk/python.mdx`
- Modify: `docs/sdk/typescript.mdx`
- Modify: `examples/demo/ancilis.yaml`
- Create: `examples/aksi-v06/payment-agent/ancilis.yaml`
- Create: `examples/aksi-v06/code-execution-agent/ancilis.yaml`
- Create: `examples/aksi-v06/regulated-data-agent/ancilis.yaml`

## Task 0: Freeze v0.6 And Define Platform Contract

**Files:**

- Create: `shared/aksi_version.json`
- Create: `docs/superpowers/plans/2026-05-11-aksi-v06-platform-coordination.md`
- Modify: `docs/superpowers/plans/2026-05-11-aksi-v06-sdk-full-support.md`
- Create: `python/tests/test_aksi_v06_freeze.py`
- Create: `typescript/tests/aksi-v06-freeze.test.ts`

- [x] **Step 1: Verify platform framework master**

Run:

```bash
test -f <platform-repo-worktree>/docs/framework/aksi-framework-master.md
rg -n "41-control|41 controls|23 closed data classes|23 classes" <platform-repo-worktree>/docs/framework/aksi-framework-master.md
```

Expected: file exists and the master lists 41 controls and 23 data classes.

- [x] **Step 2: Verify platform overlay count**

Run:

```bash
find <platform-repo-worktree>/platform/backend/overlays -maxdepth 1 -name '*.json' | wc -l
```

Expected: `35`.

- [x] **Step 3: Verify PR-12 recalibration in four overlays**

Check `pci_dss.json`, `cmmc_l2.json`, `dora.json`, and `eu_ai_act.json` in the platform worktree. For each file:

- PR-12 appears with `coverage_level: "partial"`.
- The PR-12 rationale is framework-specific.
- The PR-12 rationale is not templated boilerplate such as "is partial because AKSI can provide runtime enforcement or evidence for the agent-owned portion".

If any check fails, stop and report to Kevin. Do not continue SDK work.

- [x] **Step 4: Wait for committed platform SHA**

After Step 1-3 pass, Kevin must commit the platform worktree changes to a branch. Capture:

```bash
git -C <platform-repo-worktree> branch --show-current
git -C <platform-repo-worktree> rev-parse HEAD
git -C <platform-repo-worktree> status --short
```

Expected: branch name and SHA are available. The platform framework files used for v0.6 are committed. If the relevant files are still uncommitted, stop and ask Kevin for the committed SHA.

- [x] **Step 5: Create `shared/aksi_version.json`**

Write:

```json
{
  "framework_version": "0.6",
  "framework_commit_sha": "<sha>",
  "framework_repo": "ancilis-one-shot",
  "framework_branch": "<branch name>",
  "framework_path": "docs/framework/aksi-framework-master.md",
  "framework_master_sha256": "<sha256 of master file at the frozen commit>",
  "frozen_at": "<ISO 8601>",
  "frozen_for_sdk_build": "aksi-v06-sdk-full-support"
}
```

- [x] **Step 6: Add freeze tests**

Add tests that fail if:

- `shared/aksi_version.json` is missing.
- `framework_commit_sha` does not exist in the optional local checkout identified by `ANCILIS_PLATFORM_REPO`.
- `framework_path` at that commit cannot be read.
- The committed master file checksum differs from `framework_master_sha256`.
- `framework_version` is not `"0.6"`.

- [x] **Step 7: Create platform coordination interface contract**

Create `docs/superpowers/plans/2026-05-11-aksi-v06-platform-coordination.md`. This is a concrete interface contract, not an implementation plan. It must include:

- Exact platform files needing updates: `platform/backend/app/engine/control_catalog.py`, `platform/backend/app/engine/evaluator.py`, `platform/backend/app/engine/overlays.py`, `platform/backend/app/classification/service.py`, relevant `platform/backend/app/models/`, relevant `platform/backend/app/schemas/`, `platform/backend/app/seed/run.py`, and Alembic migrations.
- Concrete full JSON examples of v0.6 evidence records emitted by the SDK.
- Exact field names and types in v0.6 evidence.
- Exact API endpoints that must accept v0.6 evidence.
- Mixed v0.5/v0.6 evidence migration strategy.
- Minimum platform changes required before SDK v0.6 can ship without breaking evidence ingestion.
- Required DB migration: add nullable `framework_version` to `evidence_records` and `control_assessments`, where NULL represents v0.5.
- Decision on `AKSI_GRAPH.json`: SDK should not read live platform files at runtime. SDK should ship versioned shared assets and freeze metadata; platform may retain `AKSI_GRAPH.json` as its graph artifact. If the SDK later needs graph traversal, add a generated SDK artifact from the frozen commit in a separate PR.
- Release gate: SDK build can complete before platform work, but SDK v0.6 cannot launch until the platform contract is implemented and deployed.

- [x] **Step 8: Document pause points**

Record the three natural pause points in this plan:

1. **Readable v0.6 framework slice:** after shared registry, taxonomy, overlay loader, identifier utilities, and freeze metadata exist. The platform can read SDK v0.6 assets, but evaluator coverage is incomplete. Not shippable.
2. **End-to-end evidence slice:** after one producer emits `framework_version: "0.6"` evidence through one v0.6 evaluator and stores versioned evidence without v0.5 reinterpretation. Demonstrable integration, still not shippable.
3. **Full evaluator coverage slice:** after all 41 controls have Python and TypeScript factories, green evaluator parity, and meaningful support-level behavior. Functionally close, but still gated by producers, docs, examples, platform contract, and final verification.

- [x] **Step 9: Run Task 0 tests**

Run:

```bash
python3 -m pytest python/tests/test_aksi_v06_freeze.py -q
npm test -- typescript/tests/aksi-v06-freeze.test.ts
```

Expected: PASS once the platform SHA is available and `shared/aksi_version.json` has been written.

## Task 1: Add Parity Guardrails First

**Files:**

- Create: `scripts/check_aksi_v06_parity.mjs`
- Create: `python/tests/test_aksi_v06_parity.py`
- Create: `typescript/tests/aksi-v06-parity.test.ts`

- [ ] **Step 1: Write the parity script**

Create `scripts/check_aksi_v06_parity.mjs` to validate SDK assets without importing either SDK runtime:

```js
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const controlsDir = join(root, "shared", "controls");
const taxonomyPath = join(root, "shared", "classifications", "taxonomy.json");
const overlaysDir = join(root, "shared", "overlays");

const expectedControls = [
  "GOV-01", "GOV-02", "GOV-03", "GOV-04", "GOV-05", "GOV-06", "GOV-07",
  "ID-01", "ID-02", "ID-03", "ID-04", "ID-05",
  "PR-01", "PR-02", "PR-03", "PR-04", "PR-05", "PR-06", "PR-07", "PR-08", "PR-09", "PR-10", "PR-11", "PR-12",
  "DE-01", "DE-02", "DE-03", "DE-04", "DE-05", "DE-06",
  "RS-01", "RS-02", "RS-03", "RS-04", "RS-05", "RS-06",
  "RC-01", "RC-02", "RC-03",
  "PAY-01", "PAY-02",
];

const expectedClasses = [
  "DC-PHI", "DC-CHD", "DC-SAD", "DC-CUI", "DC-FCI", "DC-MNPI", "DC-PII", "DC-FIN", "DC-NPI", "DC-GOV",
  "DC-AI", "DC-GEN", "DC-ITAR", "DC-CRIT", "DC-MINOR", "DC-BIO", "DC-LEGAL", "DC-IP", "DC-PAY", "DC-EDU",
  "DC-CJI", "DC-EAR", "DC-MEDDEV",
];

const controls = readdirSync(controlsDir)
  .filter(file => file.endsWith(".json"))
  .map(file => JSON.parse(readFileSync(join(controlsDir, file), "utf8")));

const controlIds = controls.map(control => control.id).sort();
assertSameSet("controls", controlIds, expectedControls);

const taxonomy = JSON.parse(readFileSync(taxonomyPath, "utf8"));
assertSameSet("taxonomy classes", taxonomy.classifications.map(entry => entry.code).sort(), expectedClasses);

for (const file of readdirSync(overlaysDir).filter(file => file.endsWith(".json"))) {
  const overlay = JSON.parse(readFileSync(join(overlaysDir, file), "utf8"));
  const ids = new Set(expectedControls);
  for (const controlId of Object.keys(overlay.controls ?? {})) {
    const normalized = controlId.replace(/^AKSI-/, "");
    if (!ids.has(normalized)) {
      throw new Error(`${file} references unknown control ${controlId}`);
    }
  }
}

function assertSameSet(label, actual, expected) {
  const missing = expected.filter(item => !actual.includes(item));
  const extra = actual.filter(item => !expected.includes(item));
  if (missing.length || extra.length) {
    throw new Error(`${label} mismatch. Missing: ${missing.join(", ") || "none"}; extra: ${extra.join(", ") || "none"}`);
  }
}
```

- [ ] **Step 2: Add Python wrapper test**

```python
import subprocess

def test_aksi_v06_shared_assets_are_internally_consistent() -> None:
    result = subprocess.run(
        ["node", "scripts/check_aksi_v06_parity.mjs"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
```

- [ ] **Step 3: Add TypeScript wrapper test**

```ts
import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";

describe("AKSI v0.6 parity", () => {
  it("shared assets are internally consistent", () => {
    const result = spawnSync("node", ["scripts/check_aksi_v06_parity.mjs"], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
  });
});
```

- [ ] **Step 4: Run failing tests**

Run:

```bash
python3 -m pytest python/tests/test_aksi_v06_parity.py -q
npm test -- typescript/tests/aksi-v06-parity.test.ts
```

Expected: FAIL because the SDK still has 26 controls and 16 canonical classes.

- [ ] **Step 5: Add evaluator parity script**

Create a second parity command, `scripts/check_aksi_v06_evaluator_parity.mjs`, that is allowed to import Python and TypeScript SDK modules after Task 6 starts. It must assert:

- Python `EVALUATOR_FACTORIES` has exactly 41 keys.
- TypeScript `EVALUATOR_FACTORIES` has exactly 41 keys.
- Both key sets exactly equal the IDs in `shared/controls/*.json`.
- Each evaluator class exposes a `control_id` / `controlId` matching its registry key.
- No applicable control can produce a result detail containing `"No evaluator implemented for this control"`.

This script is a green gate for each evaluator. A new evaluator is not complete until its factory entry exists and this parity test passes for the incremental addition.

## Task 1a: Centralize AKSI Identifier Boundaries

**Files:**

- Create: `python/src/ancilis/aksi/__init__.py`
- Create: `python/src/ancilis/aksi/identifiers.py`
- Create: `typescript/src/ancilis/aksi/identifiers.ts`
- Create: `python/tests/test_aksi_identifiers.py`
- Create: `typescript/tests/aksi-identifiers.test.ts`
- Create: `scripts/check_aksi_prefix_discipline.mjs`

- [x] **Step 1: Add identifier utilities**

Python:

```python
AKSI_PREFIX = "AKSI-"

def is_prefixed(control_id: str) -> bool:
    return control_id.startswith(AKSI_PREFIX) or control_id.startswith("AKSI_")

def unprefix(control_id: str) -> str:
    normalized = control_id.replace("AKSI_", AKSI_PREFIX, 1)
    return normalized.removeprefix(AKSI_PREFIX)

def prefix(control_id: str) -> str:
    return f"{AKSI_PREFIX}{unprefix(control_id)}"
```

Mirror in TypeScript.

- [x] **Step 2: Add unit tests**

Assert:

- `prefix("PR-04") == "AKSI-PR-04"`
- `prefix("AKSI-PR-04") == "AKSI-PR-04"`
- `unprefix("AKSI-PR-04") == "PR-04"`
- `unprefix("AKSI_PR-04") == "PR-04"`
- `is_prefixed("AKSI-PR-04") is True`
- `is_prefixed("PR-04") is False`

- [x] **Step 3: Add prefix discipline grep**

Create a script that fails on raw `AKSI-` or `AKSI_` prefix manipulation outside the identifier modules and static JSON/Markdown assets. Code may contain literal prefixed IDs in test fixtures only when the test is explicitly exercising the identifier boundary.

- [ ] **Step 4: Apply boundary rules**

Later tasks must use these utilities:

- Overlay loading goes through `unprefix()` at load time.
- Internal lookups use unprefixed IDs.
- Evidence emission goes through `prefix()` at write time.
- Report generation uses `prefix()` for display.
- No ad hoc `.replace(/^AKSI-/...)`, `.removeprefix("AKSI-")`, string slicing, or `"AKSI_"` replacement outside the identifier modules.

## Task 2: Promote AKSI v0.6 Registry Into Shared SDK Assets

**Files:**

- Modify/create: `shared/controls/*.json`
- Modify: `python/src/ancilis/config.py`
- Modify: `typescript/src/ancilis/config/index.ts`
- Modify: `shared/schemas/config.schema.json`
- Create: `python/tests/test_aksi_v06_semantic_migration.py`
- Create: `typescript/tests/aksi-v06-semantic-migration.test.ts`

- [ ] **Step 1: Generate or hand-port 41 shared controls**

Port the 41 controls from the framework worktree into `shared/controls/*.json`. Use unprefixed IDs in the SDK (`PR-04`), and include a `product_control_id` field for prefixed display/storage compatibility (`AKSI-PR-04`).

Each control JSON must include:

```json
{
  "id": "PR-09",
  "product_control_id": "AKSI-PR-09",
  "framework_version": "0.6",
  "name": "Controlled Code Execution & Sandbox Enforcement",
  "function": "PROTECT",
  "description": "Generated code, shell commands, and dynamic execution artifacts run only inside approved sandbox execution classes.",
  "default_enabled": true,
  "baseline": true,
  "common": true,
  "trigger_classifications": [],
  "trigger_certification_targets": [],
  "evidence_sources": ["sdk_direct", "aws_cloudtrail", "github", "otel", "attestation", "sarif_import"],
  "evidence_keywords": ["sandbox", "code", "command", "execution"],
  "support_level": "inline_enforceable",
  "legacy_aliases": ["DC-Code-Execution"],
  "display_name": "Controlled code execution",
  "display_detail": "Checks whether code execution and shell activity are confined to approved sandbox classes.",
  "remediation_hint_template": "Route code execution through an approved sandbox or disable the tool for this agent."
}
```

Use `common: false`, `trigger_classifications: ["DC-PAY"]`, and `trigger_certification_targets: ["AGENT_PAYMENTS", "X402"]` for `PAY-01` and `PAY-02`.

- [ ] **Step 2: Add semantic migration tests**

Assert the renumbering explicitly so future work cannot silently restore old meanings:

```python
def test_v06_control_semantics_are_not_old_sdk_semantics() -> None:
    controls = load_control_definitions()
    assert controls["GOV-01"]["name"] == "Agent Identity & Authentication"
    assert controls["PR-01"]["name"] == "Action Authorization"
    assert controls["PR-05"]["name"] == "Context & Tenant Isolation"
    assert controls["PR-06"]["name"] == "Audit Trail Completeness"
    assert controls["DE-02"]["name"] == "Classification Drift & Boundary Validation"
    assert controls["DE-03"]["name"] == "Configuration/Dependency Drift Monitoring"
```

Mirror this in TypeScript using `loadControlDefinitions`.

- [ ] **Step 3: Remove Python hard-coded control IDs**

Replace the hard-coded `VALID_CONTROL_IDS` in `python/src/ancilis/config.py` with a lazy set derived from `load_control_definitions()`.

```python
def valid_control_ids() -> set[str]:
    return set(load_control_definitions())
```

Use it in validation:

```python
elif key not in valid_control_ids():
    raise config_invalid(f"Unknown control ID in security.controls: '{key}'")
```

- [ ] **Step 4: Update schema control pattern**

In `shared/schemas/config.schema.json`, replace the old `^(PR-0[1-5]|DE-01)$` pattern with a complete v0.6 pattern:

```json
"^(GOV-0[1-7]|ID-0[1-5]|PR-(0[1-9]|1[0-2])|DE-0[1-6]|RS-0[1-6]|RC-0[1-3]|PAY-0[1-2])$"
```

- [ ] **Step 5: Run registry tests**

Run:

```bash
node scripts/check_aksi_v06_parity.mjs
python3 -m pytest python/tests/test_aksi_v06_parity.py python/tests/test_aksi_v06_semantic_migration.py -q
npm test -- typescript/tests/aksi-v06-parity.test.ts typescript/tests/aksi-v06-semantic-migration.test.ts
```

Expected: PASS after shared controls and schema are updated.

## Task 3: Update Taxonomy And Activation

**Files:**

- Modify: `shared/classifications/taxonomy.json`
- Modify: `python/src/ancilis/config.py`
- Modify: `typescript/src/ancilis/config/index.ts`
- Modify: `python/src/ancilis/activation/resolver.py`
- Modify: `typescript/src/ancilis/activation/resolver.ts`
- Create: `python/tests/test_aksi_v06_activation.py`
- Create: `typescript/tests/aksi-v06-activation.test.ts`

- [ ] **Step 1: Port the 23 canonical classes**

Update `shared/classifications/taxonomy.json` to include exactly:

`DC-PHI`, `DC-CHD`, `DC-SAD`, `DC-CUI`, `DC-FCI`, `DC-MNPI`, `DC-PII`, `DC-FIN`, `DC-NPI`, `DC-GOV`, `DC-AI`, `DC-GEN`, `DC-ITAR`, `DC-CRIT`, `DC-MINOR`, `DC-BIO`, `DC-LEGAL`, `DC-IP`, `DC-PAY`, `DC-EDU`, `DC-CJI`, `DC-EAR`, `DC-MEDDEV`.

- [ ] **Step 2: Add alias metadata**

Add an alias block to taxonomy:

```json
"aliases": {
  "DC-Customer-Data": ["DC-PII"],
  "DC-Consumer-Data": ["DC-PII"],
  "DC-Payment-Card": ["DC-CHD"],
  "DC-Sensitive-Authentication-Data": ["DC-SAD"],
  "DC-Financial": ["DC-FIN"],
  "DC-Student-Data": ["DC-EDU"],
  "DC-Education-Records": ["DC-EDU"],
  "DC-Criminal-Justice-Information": ["DC-CJI"],
  "DC-Dual-Use-Tech": ["DC-EAR"],
  "DC-Medical-Device": ["DC-MEDDEV"],
  "DC-GOV-CUI": ["DC-CUI", "DC-GOV"]
},
"control_detection_aliases": {
  "DC-Credentials": ["PR-04"],
  "DC-Code-Execution": ["PR-09"],
  "DC-External-API": ["ID-02", "PR-03"]
}
```

- [ ] **Step 3: Expand developer mappings**

Add developer-facing `my_agent_handles` aliases for payment, education, CJI, EAR, medical-device, sensitive-authentication, and NPI use cases.

Examples:

```json
"payment_authorization": ["DC-PAY", "DC-FIN"],
"payment_credentials": ["DC-PAY", "DC-SAD"],
"education_records": ["DC-EDU", "DC-PII"],
"criminal_justice_information": ["DC-CJI"],
"dual_use_export_controlled": ["DC-EAR"],
"medical_device_data": ["DC-MEDDEV", "DC-PHI"],
"nonpublic_financial_information": ["DC-NPI", "DC-FIN"]
```

- [ ] **Step 4: Activate extension controls from classifications**

Update Python and TypeScript config resolution so controls with `common: false` activate only when their `trigger_classifications` or `trigger_certification_targets` match current scope.

Expected evaluation counts:

- Minimal agent: 39 enabled common controls; `PAY-01` and `PAY-02` are not applicable.
- `my_agent_handles: ["payment_authorization"]`: 41 applicable controls.
- `certification_targets: ["AGENT_PAYMENTS"]`: 41 applicable controls.

- [ ] **Step 5: Add activation tests**

```python
def test_payment_controls_activate_only_for_payment_scope() -> None:
    baseline = load_config(raw={"agent": {"name": "plain"}})
    assert "PAY-01" not in [cid for cid, cs in baseline.controls.items() if cs.enabled]

    payment = load_config(raw={
        "agent": {"name": "pay"},
        "my_agent_handles": ["payment_authorization"],
    })
    assert payment.controls["PAY-01"].enabled is True
    assert payment.controls["PAY-02"].enabled is True
```

Mirror in TypeScript.

- [ ] **Step 6: Run activation tests**

Run:

```bash
python3 -m pytest python/tests/test_aksi_v06_activation.py -q
npm test -- typescript/tests/aksi-v06-activation.test.ts
```

Expected: PASS.

## Task 4: Import Framework Overlay Semantics Into SDK Loader

**Files:**

- Modify: `shared/overlays/*.json`
- Modify: `python/src/ancilis/activation/loader.py`
- Modify: `typescript/src/ancilis/activation/loader.ts`
- Create: `python/tests/test_aksi_v06_overlays.py`
- Create: `typescript/tests/aksi-v06-overlays.test.ts`

- [ ] **Step 1: Choose adapter shape**

Prefer extending SDK overlay loaders to accept both current SDK overlay shape and framework v0.6 overlay shape:

Framework v0.6 fields:

```json
{
  "framework_id": "gdpr",
  "framework_name": "EU General Data Protection Regulation",
  "trigger_classifications": ["DC-PII", "DC-MINOR", "DC-BIO"],
  "trigger_certification_targets": ["GDPR"],
  "direct_control_ids": ["AKSI-GOV-05"],
  "partial_control_ids": ["AKSI-ID-03"],
  "aspirational_control_ids": ["AKSI-DE-05"],
  "controls": [
    {
      "control_id": "AKSI-GOV-01",
      "framework_reference": "GDPR Art. 5(2), 24",
      "coverage_level": "partial",
      "evidence_threshold": {"required_fields": ["control_owner"]}
    }
  ]
}
```

Normalize it at load time to the existing runtime profile shape:

```json
{
  "id": "gdpr",
  "name": "EU General Data Protection Regulation",
  "trigger_type": "data_classification",
  "triggered_by": ["DC-PII", "DC-MINOR", "DC-BIO"],
  "triggered_by_classifications": ["DC-PII", "DC-MINOR", "DC-BIO"],
  "triggered_by_certification_targets": ["GDPR"],
  "controls": {
    "GOV-01": {
      "framework_reference": "GDPR Art. 5(2), 24",
      "coverage_level": "partial",
      "evidence_requirements": ["control_owner"]
    }
  }
}
```

- [ ] **Step 2: Port overlay files**

Port the framework worktree overlays from `platform/backend/overlays/*.json` into `shared/overlays/*.json`, preserving:

- `framework_reference`
- `requirement_text`
- `rationale`
- `agent_responsibility`
- `coverage_level`
- `evidence_threshold.required_fields`
- `no_coverage_obligations`
- direct/partial/aspirational control arrays

Normalize file names and IDs to SDK slugs. Avoid duplicate underscore/hyphen variants.

- [ ] **Step 3: Add overlay consistency tests**

Assert:

- Every overlay ID loads.
- Every overlay control ID exists after stripping `AKSI-`.
- Coverage levels are one of `direct`, `partial`, `aspirational`.
- `PAY-01` and `PAY-02` appear only in payment-relevant overlays.
- `no_coverage_obligations` survive load for reporting.

- [ ] **Step 4: Run overlay tests**

Run:

```bash
python3 -m pytest python/tests/test_aksi_v06_overlays.py -q
npm test -- typescript/tests/aksi-v06-overlays.test.ts
```

Expected: PASS.

## Task 5: Add Evaluation Context And Support Modes

**Files:**

- Modify: `python/src/ancilis/engine/action.py`
- Modify: `typescript/src/ancilis/engine/action.ts`
- Modify: `python/src/ancilis/evidence/store.py`
- Modify: `python/src/ancilis/evidence/record.py`
- Modify: `typescript/src/ancilis/evidence/store.ts`
- Modify: `typescript/src/ancilis/evidence/record.ts`
- Create: `python/src/ancilis/engine/context.py`
- Create: `typescript/src/ancilis/engine/context.ts`
- Modify: `python/src/ancilis/engine/evaluators/base.py`
- Modify: `typescript/src/ancilis/engine/evaluators/base.ts`
- Modify: `shared/schemas/action.schema.json`
- Modify: `shared/schemas/evaluation-result.schema.json`

- [ ] **Step 1: Require framework version on v0.6 Actions**

`framework_version` is required on every v0.6 `Action`. It must be `"0.6"` for this build. Producer code may derive it from `shared/aksi_version.json`, but the final emitted Action field is not optional and not silently defaulted at evidence write time.

- [ ] **Step 2: Extend Action with v0.6 evidence fields**

Keep contextual enrichment fields optional for backward compatibility, but not `framework_version`:

```python
@dataclass
class Action:
    framework_version: str
    ...

@dataclass
class ActionContext:
    session_id: str | None = None
    parent_action_id: str | None = None
    tenant_id: str | None = None
    trust_zone: str | None = None
    data_classifications: list[str] = field(default_factory=list)
    detected_data_types: list[str] = field(default_factory=list)
    active_overlays: list[str] = field(default_factory=list)
    destination: str | None = None
    purpose: str | None = None
    approval_id: str | None = None
    sandbox_class: str | None = None
    memory_store: str | None = None
    memory_operation: str | None = None
    payment: dict[str, Any] = field(default_factory=dict)
    incident: dict[str, Any] = field(default_factory=dict)
```

Mirror in TypeScript.

- [ ] **Step 3: Introduce EvaluationContext**

```python
@dataclass
class EvaluationContext:
    action: Action
    config: ResolvedConfig
    registry: ToolRegistry
    evidence_store: EvidenceIntegrityStore | None = None
    now: Callable[[], datetime] = datetime.now
```

Do not force every evaluator to take the richer object in the same PR. Add an adapter so old evaluators keep working while new evaluators can opt into context.

- [ ] **Step 4: Add framework version and support metadata to results**

Add optional fields:

```python
support_level: str = "inline_enforceable"  # inline_enforceable | observable | attestation | not_applicable
coverage_level: str = "direct"            # direct | partial | aspirational
```

`EvaluationResult.framework_version` is required and must match the source `Action.framework_version`. Update schemas and TypeScript interfaces.

- [ ] **Step 5: Add DuckDB framework version migration**

Add nullable `framework_version` to DuckDB evidence records. Existing v0.5 records have NULL and are treated as `"0.5"` only for historical reporting. Every v0.6 SDK write stores `"0.6"`.

- [ ] **Step 6: Prevent v0.5 evidence reinterpretation**

Any lookup/query path for control evidence must include framework version. If a consumer asks for `PR-01` under v0.6 and the database only contains NULL/v0.5 `PR-01` identity records, return empty results. Do not reinterpret v0.5 control IDs under v0.6 semantics.

- [ ] **Step 7: Add version isolation tests**

Manually insert a v0.5 evidence record with `control_id: "PR-01"` and NULL `framework_version`. Then emit/query v0.6 evidence and assert:

- v0.6 `PR-01` queries do not return the v0.5 record.
- historical v0.5 reporting can still read the record as v0.5.
- hash-chain verification still works across old rows after migration.

- [ ] **Step 8: Update decision logic**

Only `FAIL`/`ERROR` from `inline_enforceable` controls should block by default in enforce mode. Observable and attestation controls should produce `FLAG` for missing evidence unless strict policy says otherwise.

- [ ] **Step 9: Add compatibility tests**

Existing actions without new context fields must still evaluate without errors.

Run:

```bash
python3 -m pytest python/tests/test_engine.py python/tests/test_aksi_importability.py -q
npm test -- typescript/tests/engine.test.ts typescript/tests/import.integration.test.ts
```

Expected: PASS.

## Task 6: Fix Existing Evaluator Semantics Before Adding New Controls

**Files:**

- Modify: `python/src/ancilis/engine/engine.py`
- Modify: `typescript/src/ancilis/engine/engine.ts`
- Modify/create evaluator modules under both SDKs.
- Create: `shared/fixtures/aksi-v06/control-evaluation-vectors.json`
- Create: `python/tests/test_aksi_v06_evaluators.py`
- Create: `typescript/tests/aksi-v06-evaluators.test.ts`

- [ ] **Step 1: Create golden vectors**

Add cross-language fixtures for the semantic migrations:

```json
[
  {
    "name": "identity belongs to GOV-01",
    "config": {"agent": {"name": "agent-a", "owner": "owner@example.com"}},
    "action": {"agent_id": "wrong-agent", "action_type": "tool_call", "tool": {"name": "read"}, "parameters": {"raw": {}}},
    "expected": {"GOV-01": "FAIL", "PR-01": "PASS"}
  },
  {
    "name": "audit trail belongs to PR-06",
    "config": {"agent": {"name": "agent-a"}, "compliance": {"evidence": {"retention_days": 365}}},
    "action": {"agent_id": "agent-a", "action_type": "tool_call", "tool": {"name": "read"}, "parameters": {"raw": {}}},
    "expected": {"PR-06": "PASS"}
  }
]
```

- [ ] **Step 2: Wire canonical v0.6 evaluator registry**

Both engines should build the evaluator map from a single explicit registry so tests can compare keys. Use concrete construction in the current SDK style for this build; do not add dependency-injection lambdas yet. Refactor to a factory-plus-dependencies pattern later, after all 41 evaluator dependencies are visible.

```python
EVALUATOR_FACTORIES: dict[str, type[ControlEvaluator]] = {
    "GOV-01": GOV01IdentityEvaluator,
    "GOV-02": GOV02OwnershipEvaluator,
    "GOV-03": GOV03RiskToleranceEvaluator,
    "GOV-04": GOV04HumanOversightEvaluator,
    "PR-01": PR01ActionAuthorizationEvaluator,
    "PR-02": PR02ScopeEvaluator,
    "PR-03": PR03ProvenanceEvaluator,
    "PR-04": PR04ExposureEvaluator,
    "PR-05": PR05IsolationEvaluator,
    "PR-06": PR06AuditTrailEvaluator,
    "DE-02": DE02ClassificationDriftEvaluator,
    "DE-03": DE03ConfigDriftEvaluator,
    "DE-04": DE04IntegrityEvaluator,
}
```

Mirror in TypeScript.

- [ ] **Step 3: Rename or wrap migrated evaluators**

Required mappings:

- Old `PR01IdentityEvaluator` -> new `GOV01IdentityEvaluator`
- Old `PR05AuditEvaluator` -> new `PR06AuditTrailEvaluator`
- Old `PR06ConfigBaselineEvaluator` + old `DE02ConfigDriftEvaluator` -> new `DE03ConfigDriftEvaluator`
- Old `DE02ConfigDriftEvaluator` ID must not remain `DE-02`

Drop compatibility exports entirely. There are no external users to preserve for this material schema migration. Old class names are removed so v0.5/v0.6 ambiguity cannot leak through imports.

- [ ] **Step 4: Implement missing same-era controls**

Before the 15 missing controls, fill the 26 existing IDs with correct v0.6 semantics:

- `GOV-04`: human oversight configuration.
- `ID-01`: agent inventory, wired in both engines.
- `ID-02`: tool/model/integration registry, not only `PR-03` provenance.
- `ID-03`: data flow and classification.
- `ID-04`: supply chain and dependency risk using SARIF/CycloneDX/dependency scan evidence.
- `ID-05`: risk profiling and purpose scoping.
- `RS-01`: automated compliance response.
- `RS-02`: containment/quarantine/kill switch.
- `RS-03`: human escalation and incident reporting.
- `RC-01`: rollback/recovery plan.
- `RC-02`: post-incident review.

- [ ] **Step 5: Run migrated evaluator tests**

Run:

```bash
python3 -m pytest python/tests/test_aksi_v06_evaluators.py python/tests/test_aksi_importability.py -q
npm test -- typescript/tests/aksi-v06-evaluators.test.ts typescript/tests/import.integration.test.ts
```

Expected: PASS.

## Task 7: Implement The 15 Missing AKSI v0.6 Controls

**Files:**

- Create evaluator modules under `python/src/ancilis/engine/evaluators/`
- Create evaluator modules under `typescript/src/ancilis/engine/evaluators/`
- Modify: `python/src/ancilis/engine/engine.py`
- Modify: `typescript/src/ancilis/engine/engine.ts`
- Modify: `shared/fixtures/aksi-v06/control-evaluation-vectors.json`
- Modify: `python/tests/test_aksi_v06_evaluators.py`
- Modify: `typescript/tests/aksi-v06-evaluators.test.ts`

- [ ] **Step 1: Add governance controls**

| Control | Day-one SDK support |
| --- | --- |
| `GOV-05` | Validate action/data use against configured `agent.purpose`, declared data classes, legal-basis/use-restriction metadata, and prohibited-use rules. |
| `GOV-06` | Validate active overlays/certification targets have obligation metadata and posture reporting destination or owner route. |
| `GOV-07` | Validate instruction version, transparency/disclosure metadata, feedback or intervention route, and affected-party channel where configured overlays require it. |

- [ ] **Step 2: Add protect controls**

| Control | Day-one SDK support |
| --- | --- |
| `PR-09` | Detect shell/code execution tool names, command parameters, dynamic eval/exec signals, and require approved `context.sandbox_class`. Fail in enforce mode if unsafe. |
| `PR-10` | Check retrieved context/memory operations for source hash, trust label, quarantine status, and cross-session contamination. |
| `PR-11` | Check retention/deletion policy for action data, memory stores, and evidence; verify deletion or eviction requests are evidenced. |
| `PR-12` | Scan parameters and context for secrets, API keys, wallet keys, payment credentials, and require vault/key policy metadata for allowed uses. |

- [ ] **Step 3: Add detect controls**

| Control | Day-one SDK support |
| --- | --- |
| `DE-05` | Ingest output-evaluation evidence from SDK response scanners or adapters; flag missing evals for high-risk/high-impact AI actions. |
| `DE-06` | Ingest SARIF, CycloneDX, dependency scanner, red-team, adversarial test, and third-party evaluation evidence; flag stale or missing assurance evidence. |

- [ ] **Step 4: Add respond/recover controls**

| Control | Day-one SDK support |
| --- | --- |
| `RS-04` | Detect parent/child action chains, trust zones, and cascade suppression metadata; flag missing circuit breaker for multi-agent/downstream workflows. |
| `RS-05` | When incident evidence includes regulated data classes, compute notification-clock evidence fields and route to authority/customer owner metadata. |
| `RS-06` | Ingest vulnerability disclosure/security-update evidence and route advisories or support-period tasks to owners. |
| `RC-03` | Validate recovery drill, rollback test, failover, continuity exercise, or agent-disablement evidence within configured recency window. |

- [ ] **Step 5: Add payment extension controls**

| Control | Day-one SDK support |
| --- | --- |
| `PAY-01` | For `DC-PAY`, validate spend limit, approval ID, recipient trust status, sanctions-screen result, wallet policy ID, and payment intent before payment execution. |
| `PAY-02` | Validate settlement receipt, transaction hash, reconciliation status, irreversibility acknowledgement, and reversal/escalation route after payment execution. |

- [ ] **Step 6: Add one pass/fail/flag vector per control**

Each control needs at least:

- a PASS vector,
- a FAIL or FLAG vector,
- a not-applicable vector where activation rules require it.

- [ ] **Step 7: Run full evaluator tests**

Run:

```bash
node scripts/check_aksi_v06_evaluator_parity.mjs
python3 -m pytest python/tests/test_aksi_v06_evaluators.py -q
npm test -- typescript/tests/aksi-v06-evaluators.test.ts
```

Expected: PASS and no applicable control returns `"No evaluator implemented for this control."`. Each evaluator must pass this parity check when added, not just at the end of Task 7.

## Task 8: Update Producers To Populate v0.6 Evidence

**Files:**

- Modify: `docs/sdk/producer-enrichment-v06.md`
- Modify: `python/src/ancilis/producers/tool.py`
- Modify: `python/src/ancilis/producers/mcp.py`
- Modify: `python/src/ancilis/producers/cli.py`
- Modify: `python/src/ancilis/producers/http.py`
- Modify: `python/src/ancilis/producers/runtime.py`
- Modify: `python/src/ancilis/producers/llm.py`
- Modify: `python/src/ancilis/producers/langchain.py`
- Modify: `python/src/ancilis/producers/crewai.py`
- Modify: `python/src/ancilis/producers/autogen.py`
- Modify: `python/src/ancilis/producers/semantic_kernel.py`
- Modify: `python/src/ancilis/producers/bedrock.py`
- Modify: `python/src/ancilis/producers/auto.py`
- Modify: `typescript/src/ancilis/producers/*.ts`
- Modify: `typescript/src/ancilis/middleware/action-builder.ts`
- Modify: `typescript/src/ancilis/middleware/response-scanner.ts`

- [ ] **Step 1: Document the producer enrichment matrix**

Create `docs/sdk/producer-enrichment-v06.md` with a table for each producer surface:

- Python action producers: `cli`, `mcp`, `tool`, `http`, `runtime`.
- Python LLM producer surface: `llm.py`, including Anthropic, OpenAI, Gemini, Mistral, Cohere, xAI, Groq, Together, Fireworks, and DeepSeek plus the shared base behavior.
- Python framework producers: `langchain`, `crewai`, `autogen`, `semantic_kernel`.
- Python platform/provider producers: `bedrock`, `auto`.
- TypeScript parity producers under `typescript/src/ancilis/producers/`.

For each producer, document:

- Fields populated automatically with no config.
- Fields requiring explicit `ancilis.yaml` configuration.
- Fields requiring platform-side or downstream-system data.
- Which v0.6 controls become meaningful from those fields.
- Which fields may remain null in v0.6 and what that means for enforcement.

Honest enforcement rule: do not claim `PR-09` sandbox enforcement is meaningful unless the action has a real approved sandbox class. Null `sandbox_class` can produce a fail/flag, but it is not evidence of sandbox confinement.

- [ ] **Step 2: Add shared producer context helpers**

Add helper functions in Python and TypeScript so producers do not each hand-roll context enrichment. The helper should derive:

- `destination` from URL/tool target.
- `tenant_id` from config, invocation metadata, or environment.
- `trust_zone` from config or producer options.
- `purpose` from config or invocation metadata.
- `approval_id` from explicit parameters.
- `sandbox_class` for CLI/shell/code execution producers.
- `payment` object for x402/payment tools.
- `detected_data_types` from runtime scanners.

- [ ] **Step 3: Enrich action producers**

Update `cli`, `mcp`, `tool`, `http`, and `runtime` in both languages. Minimum expectations:

- CLI/runtime: can populate `sandbox_class` only from explicit config or invocation metadata.
- HTTP/MCP/tool: can populate `destination` and declared classifications automatically where present.
- All five: carry `framework_version`, `purpose`, `trust_zone`, `tenant_id`, active overlays, and declared classifications when configured.

- [ ] **Step 4: Enrich LLM producers**

Update Python `llm.py` and TypeScript `llm.ts`. Minimum expectations:

- Every provider class inherits base enrichment.
- `purpose`, `trust_zone`, `tenant_id`, declared classifications, active overlays, model/provider, tool schema metadata, and detected data types flow into `ActionContext`.
- Response-scanning output can feed `detected_data_types` and `DE-05`/`PR-04` evidence.
- Provider-specific extractors do not drop enrichment metadata.

- [ ] **Step 5: Enrich framework producers**

Update Python and TypeScript `langchain`, `crewai`, `autogen`, and `semantic_kernel` producers. Minimum expectations:

- Agent/team/task identifiers feed `tenant_id`, `trust_zone`, or `parent_action_id` where available.
- Tool/action destinations flow to `destination`.
- Multi-agent orchestration data feeds `parent_action_id` and cascade context for `RS-04`.
- Memory/retrieval hooks feed `memory_store` and `memory_operation` when exposed by the framework.

- [ ] **Step 6: Enrich Bedrock and auto producers**

Update Bedrock and auto-detection producers. Minimum expectations:

- Bedrock populates provider/model metadata, destination/provider endpoint, declared classifications, and detected data types where available.
- Auto producer preserves enrichment from the selected underlying producer instead of flattening it away.

- [ ] **Step 7: Add producer tests**

For each producer, add tests that at least one v0.6-only evaluator receives useful context. Prioritize `PR-09`, `PR-11`, `PR-12`, `PAY-01`, and `PAY-02`.

Test cases must prove field flow from producer to evaluator for:

- `PR-09`: code/shell action with configured sandbox class and without it.
- `PR-10`: memory/retrieval context where the producer can supply it.
- `PR-11`: retention/deletion metadata from config or invocation.
- `PR-12`: secret/payment credential scanning in parameters or messages.
- `PAY-01`: payment authorization metadata.
- `PAY-02`: settlement/reconciliation metadata.

- [ ] **Step 8: Run producer tests**

Run:

```bash
python3 -m pytest python/tests/test_producers.py python/tests/test_cli_shell.py -q
npm test -- typescript/tests/producers.test.ts typescript/tests/middleware.test.ts
```

Expected: PASS.

Estimated effort: 7-10 days. This is one of the longest tasks in the build because it covers 12 distinct Python producer surfaces plus TypeScript parity.

## Task 9a: Controls Reference Rewrite

**Files:**

- Modify: `docs/controls-reference.md`

- [ ] **Step 1: Rewrite the controls reference**

Rewrite the document rather than patching it. Every one of the 41 controls gets a consistent entry:

- description,
- activation rules,
- support level,
- evidence sources,
- what failure looks like,
- how to fix,
- worked example.

Estimated effort: 1.5-2 days.

## Task 9b: SDK API Docs

**Files:**

- Modify: `docs/sdk/python.mdx`
- Modify: `docs/sdk/typescript.mdx`

- [ ] **Step 1: Update Python SDK examples**

Every Python example must use v0.6 control IDs and semantics.

- [ ] **Step 2: Update TypeScript SDK examples**

Every TypeScript example must use v0.6 control IDs and semantics.

Estimated effort: 1-2 days.

## Task 9c: Working Examples

**Files:**

- Modify: `python/src/ancilis/report/*`
- Modify: `typescript/src/ancilis/report/*`
- Create: `examples/aksi-v06/payment-agent/ancilis.yaml`
- Create: `examples/aksi-v06/payment-agent/run.py`
- Create: `examples/aksi-v06/payment-agent/expected-output.md`
- Create: `examples/aksi-v06/code-execution-agent/ancilis.yaml`
- Create: `examples/aksi-v06/code-execution-agent/run.py`
- Create: `examples/aksi-v06/code-execution-agent/expected-output.md`
- Create: `examples/aksi-v06/regulated-data-agent/ancilis.yaml`
- Create: `examples/aksi-v06/regulated-data-agent/run.py`
- Create: `examples/aksi-v06/regulated-data-agent/expected-output.md`

- [ ] **Step 1: Update reports**

Reports should group controls by:

- `PASS`/`FAIL`/`FLAG`/`SKIP`
- support level
- coverage level
- missing evidence fields
- active overlays and activated payment controls

- [ ] **Step 2: Add runnable examples**

Add examples proving:

- A minimal agent evaluates 39 applicable controls.
- A payment agent evaluates 41 applicable controls.
- Code execution without sandbox fails `PR-09`.
- A regulated data agent activates privacy/security overlays from data classification alone.

Estimated effort: 1-1.5 days.

## Task 9d: Stale Claim Sweep

**Files:**

- Modify: `docs/**/*.md`
- Modify: `docs/**/*.mdx`
- Modify: `README.md`
- Modify: `examples/**`
- Modify: `python/src/**`
- Modify: `typescript/src/**`

- [ ] **Step 1: Run stale claim grep**

Run:

```bash
rg -n "26 controls|31 controls|9 controls|6 evaluators|No evaluator implemented|Runtime evaluator: Roadmap|v0\\.2|v0\\.5|26 of 41|29 of 41|16 classifications|20 overlays" docs README.md examples python/src typescript/src
```

Expected: every hit is either updated or explicitly annotated as historical context.

Estimated effort: 0.5 day.

Total Task 9 estimate: 4-6 days.

## Task 10: Final Verification

**Files:**

- All touched files.

- [ ] **Step 1: Run parity**

```bash
node scripts/check_aksi_v06_parity.mjs
```

Expected: PASS.

- [ ] **Step 2: Run Python tests**

```bash
python3 -m pytest python/tests/test_aksi_v06_parity.py python/tests/test_aksi_v06_activation.py python/tests/test_aksi_v06_evaluators.py python/tests/test_aksi_importability.py python/tests/test_engine.py -q
```

Expected: PASS.

- [ ] **Step 3: Run TypeScript tests**

```bash
npm test -- typescript/tests/aksi-v06-parity.test.ts typescript/tests/aksi-v06-activation.test.ts typescript/tests/aksi-v06-evaluators.test.ts typescript/tests/import.integration.test.ts typescript/tests/engine.test.ts
```

Expected: PASS.

- [ ] **Step 4: Run full suite if the focused tests pass**

```bash
python3 -m pytest
npm test
npm run typecheck
```

Expected: PASS.

- [ ] **Step 5: Run package smoke**

```bash
npm run pack:smoke
```

Expected: PASS.

## Suggested PR Slices

1. **Task 0 Freeze PR:** platform verification, platform coordination contract, pause points, freeze metadata, and freeze tests.
2. **Identifier Discipline PR:** centralized `AKSI-` prefix utilities and raw-prefix grep tests.
3. **Registry and activation PR:** shared 41-control registry, 23-class taxonomy, control-ID semantic migration tests, parity script, activation of `PAY-01`/`PAY-02`.
4. **Overlay PR:** import/normalize framework v0.6 overlays into SDK loader, preserve coverage levels and no-coverage obligations.
5. **Evidence Versioning PR:** required v0.6 framework version on emitted evidence, DuckDB migration, and v0.5/v0.6 lookup isolation.
6. **Evaluator migration PR:** fix semantic drift for existing controls and wire concrete `EVALUATOR_FACTORIES`.
7. **Missing controls PR:** implement the remaining v0.6 controls with Python/TypeScript parity vectors and per-evaluator parity gates.
8. **Producer evidence PR:** enrich Action context across all producer surfaces and TypeScript parity.
9. **Docs/reporting/examples PR:** controls reference rewrite, SDK docs, examples, reports, and stale-claim checks.

## Definition Of Done

- `shared/controls` contains exactly 41 AKSI v0.6 controls.
- `shared/classifications/taxonomy.json` contains exactly 23 canonical data classes.
- Minimal config evaluates 39 applicable common controls in both SDKs.
- Payment config evaluates 41 applicable controls in both SDKs.
- No applicable control returns `"No evaluator implemented for this control."`.
- `PAY-01` and `PAY-02` are not applicable for non-payment agents and active for `DC-PAY` / `AGENT_PAYMENTS` / `X402`.
- Python and TypeScript evaluator registries expose the same applicable AKSI IDs.
- Overlay loaders accept framework v0.6 overlay shape and all overlay control IDs resolve to SDK controls.
- Existing evidence is not silently reinterpreted across old/new control semantics; v0.6 results carry `framework_version: "0.6"` or equivalent metadata.
- Docs and reports say 41 controls and identify support mode per control.
- `shared/aksi_version.json` exists with a verified framework commit SHA and checksum.
- `docs/superpowers/plans/2026-05-11-aksi-v06-platform-coordination.md` exists as a concrete interface contract, not an outline.
- Evaluator parity test passes for all 41 controls in both languages.
- Identifier discipline test passes, with no raw `AKSI-` or `AKSI_` prefix manipulation outside identifier modules.
- Version-isolation test passes: v0.5 evidence is not returned for v0.6 control queries.
- Per-producer enrichment table exists and documents what is automatic, configured, platform-supplied, meaningful, or null.
- Three working example agents run successfully against a local SDK.
