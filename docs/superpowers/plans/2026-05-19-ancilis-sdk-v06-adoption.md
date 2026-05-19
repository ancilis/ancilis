# Ancilis SDK v0.6 Adoption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the SDK shared catalog, schemas, and activation behavior up to AKSI Framework v0.6.

**Architecture:** Treat the frozen platform framework artifacts as the source of truth. Generate/reconcile shared JSON catalog assets from `AKSI_GRAPH.json` and `control_catalog.py`, then make Python and TypeScript load those assets consistently.

**Tech Stack:** Python package under `python/src/ancilis`, TypeScript package under `typescript/src/ancilis`, shared JSON assets under `shared/`, pytest, Vitest.

---

### Task 1: v0.6 Catalog Parity Tests

**Files:**
- Create: `python/tests/test_aksi_v06_catalog.py`
- Create: `typescript/tests/aksi-v06-catalog.test.ts`

- [x] **Step 1: Write failing Python catalog test**

```python
from ancilis.activation.loader import load_control_definitions, load_taxonomy
from ancilis.activation.resolver import ActivationResolver

V06_COMMON_CONTROLS = {...39 common IDs...}
V06_EXTENSION_CONTROLS = {"PAY-01", "PAY-02"}
V06_CLASSES = {...23 canonical class IDs...}

def test_catalog_contains_exact_v06_control_set():
    assert set(load_control_definitions()) == V06_COMMON_CONTROLS | V06_EXTENSION_CONTROLS

def test_activation_defaults_to_common_controls_only():
    assert set(ActivationResolver().resolve().active_controls) == V06_COMMON_CONTROLS

def test_payment_controls_activate_for_payment_classification():
    spec = ActivationResolver().resolve(my_agent_handles=["agent_payments"])
    assert set(spec.active_controls) == V06_COMMON_CONTROLS | V06_EXTENSION_CONTROLS
    assert "DC-PAY" in spec.data_classifications

def test_taxonomy_contains_exact_v06_class_set():
    taxonomy = load_taxonomy()
    assert {entry["code"] for entry in taxonomy["classifications"]} == V06_CLASSES
```

- [x] **Step 2: Run Python test and verify it fails on 26 controls**

Run: `../../.venv/bin/python -m pytest python/tests/test_aksi_v06_catalog.py -v`
Expected: FAIL showing the catalog still has 26 controls and 16 classes.

- [x] **Step 3: Write failing TypeScript catalog test**

```typescript
import { describe, expect, it } from "vitest";
import { loadControlDefinitions, loadTaxonomy } from "../src/ancilis/activation/loader.js";
import { ActivationResolver } from "../src/ancilis/activation/resolver.js";

const V06_COMMON_CONTROLS = new Set([...39 common IDs...]);
const V06_EXTENSION_CONTROLS = new Set(["PAY-01", "PAY-02"]);
const V06_CLASSES = new Set([...23 canonical class IDs...]);

describe("AKSI v0.6 catalog", () => {
  it("contains the exact v0.6 controls", () => {
    expect(new Set(loadControlDefinitions().keys())).toEqual(new Set([...V06_COMMON_CONTROLS, ...V06_EXTENSION_CONTROLS]));
  });

  it("activates payment controls only for payment scope", () => {
    expect(new Set(new ActivationResolver().resolve().activeControls)).toEqual(V06_COMMON_CONTROLS);
    expect(new Set(new ActivationResolver().resolve({ dataHandling: ["agent_payments"] }).activeControls)).toEqual(new Set([...V06_COMMON_CONTROLS, ...V06_EXTENSION_CONTROLS]));
  });

  it("contains the exact v0.6 data classes", () => {
    const taxonomy = loadTaxonomy() as { classifications: Array<{ code: string }> };
    expect(new Set(taxonomy.classifications.map((entry) => entry.code))).toEqual(V06_CLASSES);
  });
});
```

- [x] **Step 4: Run TypeScript test and verify it fails on 26 controls**

Run: `../../node_modules/.bin/vitest run typescript/tests/aksi-v06-catalog.test.ts`
Expected: FAIL showing the catalog still has 26 controls and 16 classes.

### Task 2: Generate Shared v0.6 Assets

**Files:**
- Modify: `shared/controls/*.json`
- Modify: `shared/classifications/taxonomy.json`
- Modify: `shared/schemas/config.schema.json`
- Modify: `shared/schemas/evaluation-result.schema.json`
- Modify: `shared/schemas/evidence-record.schema.json`
- Modify: `shared/mappings/sarif-aksi-controls.json`

- [x] **Step 1: Generate controls from frozen source**

Use `/private/tmp/aksi-v06-src/AKSI_GRAPH.json` and `/private/tmp/aksi-v06-src/platform/backend/app/engine/control_catalog.py`.
Each control JSON must include `id`, `product_control_id`, `name`, `function`, `description`, `effort_level`, `common`, `trigger_classifications`, `trigger_certification_targets`, `evidence_sources`, `evidence_keywords`, `default_enabled`, `baseline`, `display_name`, `display_detail`, and `remediation_hint_template`.

- [x] **Step 2: Generate taxonomy from frozen schema and graph**

Use `/private/tmp/aksi-v06-src/shared/classifications/schema/aksi_class.schema.json` for the 23 canonical IDs. Use `/private/tmp/aksi-v06-src/AKSI_GRAPH.json` only for overlay activation, excluding `DC-External-API` and `DC-Code-Execution` from data classes because the framework says they are control-detection signals.

- [x] **Step 3: Update schemas and SARIF mapping**

Add all 41 IDs to config/evidence/result schemas, allow `FLAG` in evaluation results, and include the frozen SARIF mapping entry for `PR-09`.

- [x] **Step 4: Run catalog tests**

Run Python and TypeScript catalog tests from Task 1. Expected: PASS.

### Task 3: Runtime Activation Parity

**Files:**
- Modify: `python/src/ancilis/activation/resolver.py`
- Modify: `typescript/src/ancilis/activation/resolver.ts`
- Modify: docs/tests that still assert 26 controls where appropriate.

- [x] **Step 1: Replace hard-coded 26-control constants**

Derive or set `COMMON_AKSI_CONTROLS` to the 39 common IDs and `EXTENSION_CONTROLS` to `{"PAY-01", "PAY-02"}` in both languages.

- [x] **Step 2: Activate extension controls from classification/certification**

When resolved data classes include `DC-PAY` or certification targets include `AGENT_PAYMENTS`/`X402`, add `PAY-01` and `PAY-02` with activation sources that identify the trigger.

- [x] **Step 3: Run activation tests**

Run: `../../.venv/bin/python -m pytest python/tests/test_aksi_v06_catalog.py python/tests/test_aksi_registry.py -v`
Run: `../../node_modules/.bin/vitest run typescript/tests/aksi-v06-catalog.test.ts typescript/tests/activation.test.ts`
Expected: PASS or only existing tests needing factual 26-to-39/41 assertion updates.

### Task 4: Focused Verification

**Files:**
- No new production files unless tests expose regressions.

- [x] **Step 1: Run focused Python suite**

Run: `../../.venv/bin/python -m pytest python/tests/test_aksi_v06_catalog.py python/tests/test_aksi_v06_freeze.py python/tests/test_aksi_registry.py python/tests/test_config.py -v`

- [x] **Step 2: Run focused TypeScript suite**

Run: `../../node_modules/.bin/vitest run typescript/tests/aksi-v06-catalog.test.ts typescript/tests/aksi-v06-freeze.test.ts typescript/tests/config.test.ts typescript/tests/activation.test.ts`

- [ ] **Step 3: Commit**

Commit after tests pass: `git add ... && git commit -m "feat: align SDK catalog with AKSI v0.6"`
