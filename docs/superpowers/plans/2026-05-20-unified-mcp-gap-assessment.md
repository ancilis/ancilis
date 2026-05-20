# Unified MCP Gap Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ancilis-cover` the official unified local MCP server and add deterministic business-phrase gap assessment.

**Architecture:** Extract runtime and Cover tool registration into composable helpers, then make `ancilis-cover` compose onboarding, gap assessment, and runtime posture tools. Keep `ancilis serve` as a compatibility path that registers the same unified tool set. Add gap assessment as focused Cover modules: normalization maps business phrases to Ancilis targets, assessment compares targets with config/project/evidence state, and server wiring exposes the result read-only.

**Tech Stack:** Python 3.10+, FastMCP, Click, Pydantic v2, existing Ancilis config/activation/evidence APIs, pytest, existing MCP stdio client integration tests.

---

## File Structure

- Modify `python/src/ancilis/mcp_server/__init__.py`
  - Add `build_mcp_context`.
  - Add `register_runtime_tools`.
  - Keep `create_mcp_server` as compatibility factory, now registering runtime and Cover tools.
- Modify `python/src/ancilis/mcp_server/cover/server.py`
  - Add `register_cover_tools`.
  - Add optional runtime context/config handling for `create_cover_mcp_server`.
  - Add Click options to `ancilis-cover`.
  - Register `ancilis_assess_gap`.
- Modify `python/src/ancilis/mcp_server/cover/models.py`
  - Add structured gap target, normalization, config gap, instrumentation gap, evidence gap, and assessment response models.
- Create `python/src/ancilis/mcp_server/cover/normalization.py`
  - Deterministic phrase-to-target normalization.
- Create `python/src/ancilis/mcp_server/cover/gap_assessment.py`
  - Project/config/instrumentation/evidence gap computation.
- Modify `python/tests/test_mcp_server.py`
  - Verify legacy `create_mcp_server` exposes unified tools.
- Modify `python/tests/mcp_server/cover/test_server.py`
  - Verify `create_cover_mcp_server` exposes unified tools and accepts config context.
- Create `python/tests/mcp_server/cover/test_normalization.py`
  - Unit tests for deterministic business phrase normalization.
- Create `python/tests/mcp_server/cover/test_gap_assessment.py`
  - Unit tests for setup and evidence gap outputs.
- Modify `python/tests/mcp_server/cover/test_integration.py`
  - Verify stdio `ancilis-cover` lists runtime, onboarding, and gap tools.
- Modify docs:
  - `docs/cli/cover.mdx`
  - `docs/cli-reference.md`
  - `docs/cli/serve.mdx` only if present.

---

### Task 1: Lock Unified Tool Expectations

**Files:**
- Modify: `python/tests/test_mcp_server.py`
- Modify: `python/tests/mcp_server/cover/test_server.py`
- Modify: `python/tests/mcp_server/cover/test_integration.py`

- [ ] **Step 1: Update test tool name constants**

In `python/tests/test_mcp_server.py`, replace the existing `EXPECTED_TOOL_NAMES` with:

```python
EXPECTED_TOOL_NAMES = {
    "ancilis_check_posture",
    "ancilis_evaluate_action",
    "ancilis_get_evidence",
    "ancilis_report",
    "ancilis_list_overlays",
    "ancilis_inspect_project",
    "ancilis_classify_project",
    "ancilis_recommend_setup",
    "ancilis_review_code",
    "ancilis_onboarding_report",
    "ancilis_assess_gap",
}
```

In `python/tests/mcp_server/cover/test_server.py`, replace `EXPECTED_TOOL_NAMES` with the same set.

- [ ] **Step 2: Add Cover server config smoke test**

Append this test to `python/tests/mcp_server/cover/test_server.py`:

```python
def test_create_cover_mcp_server_accepts_config_path(tmp_path: Path) -> None:
    config_path = tmp_path / "ancilis.yaml"
    config_path.write_text(
        "agent:\n  name: cover-runtime\nsecurity:\n  mode: audit\n",
        encoding="utf-8",
    )

    server = create_cover_mcp_server(config_path=str(config_path))

    assert server.name == "ancilis-cover"
    tools = asyncio.run(server.list_tools())
    tool_names = {tool.name for tool in tools}
    assert EXPECTED_TOOL_NAMES.issubset(tool_names)
```

- [ ] **Step 3: Update stdio integration expectations**

In `python/tests/mcp_server/cover/test_integration.py`, extend the assertions after `tool_names` is computed:

```python
    assert "ancilis_check_posture" in tool_names
    assert "ancilis_assess_gap" in tool_names
```

- [ ] **Step 4: Run tests to verify they fail for missing unified registration**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/test_mcp_server.py::test_create_mcp_server_registers_tools python/tests/mcp_server/cover/test_server.py::test_create_cover_mcp_server_registers_tools python/tests/mcp_server/cover/test_server.py::test_create_cover_mcp_server_accepts_config_path -q
```

Expected: fail because runtime tools are not registered on Cover, Cover tools are not registered on `create_mcp_server`, and `ancilis_assess_gap` is not registered.

- [ ] **Step 5: Commit failing tool-surface tests**

```bash
git add python/tests/test_mcp_server.py python/tests/mcp_server/cover/test_server.py python/tests/mcp_server/cover/test_integration.py
git commit -m "test: define unified cover mcp tool surface"
```

---

### Task 2: Extract Runtime Tool Registration

**Files:**
- Modify: `python/src/ancilis/mcp_server/__init__.py`
- Test: `python/tests/test_mcp_server.py`

- [ ] **Step 1: Add reusable context builder**

In `python/src/ancilis/mcp_server/__init__.py`, add this function above `create_mcp_server`:

```python
def build_mcp_context(
    config_path: str | None = None,
    context: MCPServerContext | None = None,
    *,
    default_raw_config: dict[str, Any] | None = None,
) -> MCPServerContext:
    """Build a runtime MCP context, optionally falling back to a default config."""
    if context is not None:
        return context

    try:
        config = load_config(path=config_path) if config_path is not None else load_config()
    except FileNotFoundError:
        if default_raw_config is None:
            raise
        config = load_config(raw=default_raw_config)

    evidence_store = EvidenceStore(config)
    engine = Engine(config, evidence_store=evidence_store)
    action_producer = ToolActionProducer(
        config,
        engine,
        registry=engine.registry,
        evidence_store=evidence_store,
    )
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=evidence_store,
        action_producer=action_producer,
    )
```

- [ ] **Step 2: Extract runtime decorators into registration helper**

Replace the decorator block inside `create_mcp_server` with a new helper above it:

```python
def register_runtime_tools(server: FastMCP, context: MCPServerContext) -> None:
    """Register runtime posture and evidence MCP tools on an existing server."""

    @server.tool(name="ancilis_check_posture")
    async def ancilis_check_posture() -> dict[str, Any]:
        """Return current session posture, active control status, and overlays."""
        return _json_response(_build_posture_response(context))

    @server.tool(name="ancilis_evaluate_action")
    async def ancilis_evaluate_action(
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate a proposed tool action without writing evidence."""
        return _evaluate_action(
            context,
            tool_name=tool_name,
            parameters=parameters,
            description=description,
        )

    @server.tool(name="ancilis_get_evidence")
    async def ancilis_get_evidence(
        limit: int = 50,
        control_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Return recent evidence records for the selected or latest session."""
        return _json_response(
            _build_evidence_response(
                context,
                limit=limit,
                control_id=control_id,
                session_id=session_id,
            )
        )

    @server.tool(name="ancilis_report")
    async def ancilis_report(
        session_id: str | None = None,
        format: str = "markdown",
    ) -> dict[str, Any]:
        """Generate a posture report for the selected or latest session."""
        return _build_report_response(
            context,
            session_id=session_id,
            report_format=format,
        )

    @server.tool(name="ancilis_list_overlays")
    async def ancilis_list_overlays() -> dict[str, Any]:
        """List active overlays and evidence coverage percentages."""
        return _json_response(_build_overlay_list_response(context))
```

- [ ] **Step 3: Make legacy factory compose runtime and Cover tools**

Replace `create_mcp_server` with:

```python
def create_mcp_server(
    config_path: str | None = None,
    context: MCPServerContext | None = None,
) -> FastMCP:
    """Create the legacy Ancilis MCP server with the unified tool set."""
    resolved_context = build_mcp_context(config_path=config_path, context=context)
    server = FastMCP(name="ancilis")
    register_runtime_tools(server, resolved_context)

    from ancilis.mcp_server.cover.server import register_cover_tools

    register_cover_tools(server, runtime_context=resolved_context)
    return server
```

- [ ] **Step 4: Run runtime server tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/test_mcp_server.py -q
```

Expected: runtime tests pass except failures tied to the absent `ancilis_assess_gap` tool.

- [ ] **Step 5: Commit runtime registration extraction**

```bash
git add python/src/ancilis/mcp_server/__init__.py
git commit -m "refactor: extract runtime mcp tool registration"
```

---

### Task 3: Make Cover Compose Runtime Tools

**Files:**
- Modify: `python/src/ancilis/mcp_server/cover/server.py`
- Test: `python/tests/mcp_server/cover/test_server.py`

- [ ] **Step 1: Add imports for Click and runtime registration**

At the top of `python/src/ancilis/mcp_server/cover/server.py`, add:

```python
import click

from ancilis.mcp_server import MCPServerContext, build_mcp_context, register_runtime_tools
```

- [ ] **Step 2: Extract existing Cover decorators**

Change `create_cover_mcp_server` so the existing onboarding decorators live in:

```python
def register_cover_tools(
    server: FastMCP,
    *,
    runtime_context: MCPServerContext | None = None,
) -> None:
    """Register deterministic Cover onboarding and gap tools on an existing server."""
```

Move the existing `ancilis_inspect_project`, `ancilis_classify_project`, `ancilis_recommend_setup`, `ancilis_review_code`, and `ancilis_onboarding_report` decorators into that function. Leave their bodies unchanged in this task.

- [ ] **Step 3: Add default runtime config for Cover**

Add this helper to `server.py`:

```python
def _default_cover_config() -> dict[str, Any]:
    return {
        "agent": {"name": "ancilis-cover-preview"},
        "security": {"mode": "audit"},
    }
```

- [ ] **Step 4: Update Cover factory**

Replace `create_cover_mcp_server` with:

```python
def create_cover_mcp_server(
    config_path: str | None = None,
    context: MCPServerContext | None = None,
) -> FastMCP:
    """Create the official Ancilis Cover local MCP server."""
    runtime_context = build_mcp_context(
        config_path=config_path,
        context=context,
        default_raw_config=_default_cover_config(),
    )
    server = FastMCP(name="ancilis-cover")
    register_cover_tools(server, runtime_context=runtime_context)
    register_runtime_tools(server, runtime_context)
    return server
```

- [ ] **Step 5: Update Cover CLI entry point**

Replace `main` with a Click command:

```python
@click.command()
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(dir_okay=False, path_type=str),
    default=None,
    help="Path to ancilis.yaml. Defaults to auto-discovery, then a read-only preview config.",
)
@click.option(
    "--transport",
    type=click.Choice(["stdio"]),
    default="stdio",
    show_default=True,
    help="MCP transport to run.",
)
def main(config_path: str | None, transport: str) -> None:
    """Run the Ancilis Cover MCP server over stdio."""
    create_cover_mcp_server(config_path=config_path).run(transport=transport)
```

- [ ] **Step 6: Run Cover server tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_server.py -q
```

Expected: Cover registration tests pass except failures tied to the absent `ancilis_assess_gap` tool.

- [ ] **Step 7: Commit Cover composition**

```bash
git add python/src/ancilis/mcp_server/cover/server.py
git commit -m "feat: make cover mcp compose runtime tools"
```

---

### Task 4: Add Gap Assessment Models

**Files:**
- Modify: `python/src/ancilis/mcp_server/cover/models.py`
- Create: `python/tests/mcp_server/cover/test_normalization.py`

- [ ] **Step 1: Add model tests for normalization result shape**

Create `python/tests/mcp_server/cover/test_normalization.py`:

```python
"""Tests for deterministic Cover gap target normalization."""

from __future__ import annotations

from ancilis.mcp_server.cover.models import GapTarget, NormalizationSignal


def test_gap_target_defaults_are_empty_lists() -> None:
    target = GapTarget()

    assert target.my_agent_handles == []
    assert target.active_overlays == []
    assert target.certification_targets == []


def test_normalization_signal_serializes() -> None:
    signal = NormalizationSignal(
        source="business_context",
        phrase="patient records",
        mapped_to="health_records",
        target_type="my_agent_handles",
        confidence="high",
    )

    assert signal.model_dump(mode="json")["mapped_to"] == "health_records"
```

- [ ] **Step 2: Run model tests and verify they fail**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_normalization.py -q
```

Expected: fail because `GapTarget` and `NormalizationSignal` do not exist.

- [ ] **Step 3: Add gap models**

Append these models to `python/src/ancilis/mcp_server/cover/models.py`:

```python
class NormalizationSignal(BaseModel):
    """A deterministic mapping from user language to an Ancilis target."""

    source: str
    phrase: str
    mapped_to: str
    target_type: str
    confidence: str


class GapReviewItem(BaseModel):
    """A low-confidence or unsupported target phrase requiring user review."""

    source: str
    value: str
    reason: str


class GapTarget(BaseModel):
    """Normalized target state for a gap assessment."""

    my_agent_handles: list[str] = Field(default_factory=list)
    active_overlays: list[str] = Field(default_factory=list)
    certification_targets: list[str] = Field(default_factory=list)


class ConfigGap(BaseModel):
    """Delta between requested target and current Ancilis config."""

    missing_my_agent_handles: list[str] = Field(default_factory=list)
    present_my_agent_handles: list[str] = Field(default_factory=list)
    missing_overlays: list[str] = Field(default_factory=list)
    present_overlays: list[str] = Field(default_factory=list)
    missing_certification_targets: list[str] = Field(default_factory=list)
    present_certification_targets: list[str] = Field(default_factory=list)


class InstrumentationGap(BaseModel):
    """Producer instrumentation recommendations for the requested target."""

    recommended_producers: list[str] = Field(default_factory=list)
    present_producers: list[str] = Field(default_factory=list)
    missing_producers: list[str] = Field(default_factory=list)
    review_items: list[GapReviewItem] = Field(default_factory=list)


class EvidenceGap(BaseModel):
    """Evidence coverage for requested overlays and certifications."""

    session_id: str | None = None
    requested_overlays: list[str] = Field(default_factory=list)
    controls_total: int = 0
    controls_with_evidence: int = 0
    missing_controls: list[str] = Field(default_factory=list)
    evidenced_controls: list[str] = Field(default_factory=list)


class GapAssessmentResult(BaseModel):
    """Structured deterministic gap assessment response."""

    mode: str
    target: GapTarget
    normalization_signals: list[NormalizationSignal] = Field(default_factory=list)
    review_items: list[GapReviewItem] = Field(default_factory=list)
    project: dict[str, object] = Field(default_factory=dict)
    config_gap: ConfigGap
    instrumentation_gap: InstrumentationGap
    evidence_gap: EvidenceGap
    next_steps: list[str] = Field(default_factory=list)
    confidence: str = "low"
    assumptions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Run model tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_normalization.py -q
```

Expected: pass.

- [ ] **Step 5: Commit models**

```bash
git add python/src/ancilis/mcp_server/cover/models.py python/tests/mcp_server/cover/test_normalization.py
git commit -m "feat: add cover gap assessment models"
```

---

### Task 5: Implement Business Phrase Normalization

**Files:**
- Create: `python/src/ancilis/mcp_server/cover/normalization.py`
- Modify: `python/tests/mcp_server/cover/test_normalization.py`

- [ ] **Step 1: Add normalization behavior tests**

Append to `python/tests/mcp_server/cover/test_normalization.py`:

```python
from ancilis.mcp_server.cover.normalization import normalize_gap_target


def test_normalize_patient_records_and_hipaa() -> None:
    result = normalize_gap_target(
        business_context="We handle patient records and need HIPAA."
    )

    assert result.target.my_agent_handles == ["health_records"]
    assert result.target.active_overlays == ["hipaa"]
    assert result.review_items == []
    assert result.confidence == "high"
    assert {signal.mapped_to for signal in result.signals} == {"health_records", "hipaa"}


def test_normalize_checkout_and_pci() -> None:
    result = normalize_gap_target(
        business_context="Checkout agent accepts cards and needs PCI."
    )

    assert result.target.my_agent_handles == ["credit_cards"]
    assert result.target.active_overlays == ["pci-dss-v4"]


def test_explicit_targets_merge_with_business_context() -> None:
    result = normalize_gap_target(
        business_context="Customer support bot stores emails.",
        target_data_types=["health_records"],
        target_overlays=["hipaa"],
        target_certifications=["aiuc-1"],
    )

    assert result.target.my_agent_handles == ["health_records", "personal_info"]
    assert result.target.active_overlays == ["gdpr", "hipaa"]
    assert result.target.certification_targets == ["aiuc-1"]
    assert any(signal.source == "explicit_input" for signal in result.signals)


def test_unknown_compliance_phrase_becomes_review_item() -> None:
    result = normalize_gap_target(
        business_context="We need banana compliance for this assistant."
    )

    assert result.target.my_agent_handles == []
    assert result.target.active_overlays == []
    assert result.review_items[0].value == "banana compliance"
    assert result.confidence == "low"
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_normalization.py -q
```

Expected: fail because `normalization.py` does not exist.

- [ ] **Step 3: Add normalization module**

Create `python/src/ancilis/mcp_server/cover/normalization.py`:

```python
"""Deterministic business-context normalization for Cover gap assessment."""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import BaseModel, Field

from ancilis.activation.loader import load_overlay_profiles
from ancilis.config import _load_valid_certification_targets, load_taxonomy
from ancilis.mcp_server.cover.models import GapReviewItem, GapTarget, NormalizationSignal


_UNKNOWN_COMPLIANCE_PATTERN = re.compile(r"\b([a-z][a-z0-9 -]{1,40}\s+compliance)\b", re.I)


@dataclass(frozen=True)
class _PhraseRule:
    phrases: tuple[str, ...]
    mapped_to: str
    target_type: str
    confidence: str = "high"


class GapNormalizationResult(BaseModel):
    """Normalized target plus evidence for how normalization happened."""

    target: GapTarget
    signals: list[NormalizationSignal] = Field(default_factory=list)
    review_items: list[GapReviewItem] = Field(default_factory=list)
    confidence: str = "low"


_RULES: tuple[_PhraseRule, ...] = (
    _PhraseRule(("patient records", "patient record", "medical records", "medical record", "clinic", "therapy", "therapist", "mrn", "ehr", "phi"), "health_records", "my_agent_handles"),
    _PhraseRule(("hipaa", "health insurance portability"), "hipaa", "active_overlays"),
    _PhraseRule(("credit card", "credit cards", "cardholder data", "checkout", "stripe", "payment", "payments", "billing"), "credit_cards", "my_agent_handles"),
    _PhraseRule(("pci dss", "pci-dss", "pci"), "pci-dss-v4", "active_overlays"),
    _PhraseRule(("customer profile", "customer", "user", "email", "emails", "address", "profile", "account"), "personal_info", "my_agent_handles", "medium"),
    _PhraseRule(("gdpr", "eu user", "european user", "data subject"), "gdpr", "active_overlays"),
    _PhraseRule(("soc 2", "soc2", "trust services"), "soc2", "active_overlays"),
    _PhraseRule(("bank", "kyc", "loan", "trading", "portfolio", "invoice"), "financial_records", "my_agent_handles"),
    _PhraseRule(("biometric", "face", "fingerprint", "voiceprint"), "biometric_data", "my_agent_handles"),
)


def _accepted_data_types() -> set[str]:
    taxonomy = load_taxonomy()
    return set(taxonomy["developer_type_mapping"])


def _accepted_overlays() -> set[str]:
    return set(load_overlay_profiles())


def _accepted_certifications() -> set[str]:
    return set(_load_valid_certification_targets())


def _contains_phrase(text: str, phrase: str) -> bool:
    pattern = r"(?<![a-z0-9])" + re.escape(phrase.lower()) + r"(?![a-z0-9])"
    return re.search(pattern, text) is not None


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _add_target(target: GapTarget, target_type: str, value: str) -> None:
    if target_type == "my_agent_handles":
        _append_unique(target.my_agent_handles, value)
    elif target_type == "active_overlays":
        _append_unique(target.active_overlays, value)
    elif target_type == "certification_targets":
        _append_unique(target.certification_targets, value)


def _confidence(signals: list[NormalizationSignal], review_items: list[GapReviewItem]) -> str:
    if any(signal.confidence == "high" for signal in signals):
        return "high"
    if signals:
        return "medium"
    if review_items:
        return "low"
    return "low"


def normalize_gap_target(
    *,
    business_context: str | None = None,
    target_data_types: list[str] | None = None,
    target_overlays: list[str] | None = None,
    target_certifications: list[str] | None = None,
) -> GapNormalizationResult:
    """Normalize business language and explicit inputs into Ancilis targets."""
    target = GapTarget()
    signals: list[NormalizationSignal] = []
    review_items: list[GapReviewItem] = []
    text = (business_context or "").lower()

    for rule in _RULES:
        for phrase in rule.phrases:
            if not _contains_phrase(text, phrase):
                continue
            _add_target(target, rule.target_type, rule.mapped_to)
            signals.append(
                NormalizationSignal(
                    source="business_context",
                    phrase=phrase,
                    mapped_to=rule.mapped_to,
                    target_type=rule.target_type,
                    confidence=rule.confidence,
                )
            )
            break

    accepted_data_types = _accepted_data_types()
    for value in target_data_types or []:
        if value in accepted_data_types:
            _add_target(target, "my_agent_handles", value)
            signals.append(NormalizationSignal(source="explicit_input", phrase=value, mapped_to=value, target_type="my_agent_handles", confidence="high"))
        else:
            review_items.append(GapReviewItem(source="explicit_input", value=value, reason="unsupported_target"))

    accepted_overlays = _accepted_overlays()
    for value in target_overlays or []:
        if value in accepted_overlays:
            _add_target(target, "active_overlays", value)
            signals.append(NormalizationSignal(source="explicit_input", phrase=value, mapped_to=value, target_type="active_overlays", confidence="high"))
        else:
            review_items.append(GapReviewItem(source="explicit_input", value=value, reason="unsupported_target"))

    accepted_certifications = _accepted_certifications()
    for value in target_certifications or []:
        if value in accepted_certifications:
            _add_target(target, "certification_targets", value)
            signals.append(NormalizationSignal(source="explicit_input", phrase=value, mapped_to=value, target_type="certification_targets", confidence="high"))
        else:
            review_items.append(GapReviewItem(source="explicit_input", value=value, reason="unsupported_target"))

    mapped_phrases = {signal.phrase for signal in signals if signal.source == "business_context"}
    for match in _UNKNOWN_COMPLIANCE_PATTERN.findall(text):
        if match not in mapped_phrases:
            review_items.append(GapReviewItem(source="business_context", value=match, reason="unmapped_compliance_phrase"))

    target.my_agent_handles = sorted(target.my_agent_handles)
    target.active_overlays = sorted(target.active_overlays)
    target.certification_targets = sorted(target.certification_targets)
    return GapNormalizationResult(
        target=target,
        signals=signals,
        review_items=review_items,
        confidence=_confidence(signals, review_items),
    )
```

- [ ] **Step 4: Run normalization tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_normalization.py -q
```

Expected: pass.

- [ ] **Step 5: Commit normalization**

```bash
git add python/src/ancilis/mcp_server/cover/normalization.py python/tests/mcp_server/cover/test_normalization.py
git commit -m "feat: normalize business context for cover gaps"
```

---

### Task 6: Implement Setup Gap Assessment

**Files:**
- Create: `python/src/ancilis/mcp_server/cover/gap_assessment.py`
- Create: `python/tests/mcp_server/cover/test_gap_assessment.py`

- [ ] **Step 1: Add setup gap tests**

Create `python/tests/mcp_server/cover/test_gap_assessment.py`:

```python
"""Tests for deterministic Cover gap assessment."""

from __future__ import annotations

from pathlib import Path

from ancilis.config import load_config
from ancilis.engine.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.mcp_server import MCPServerContext
from ancilis.mcp_server.cover.gap_assessment import assess_gap
from ancilis.producers.tool import ToolActionProducer


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _context(raw: dict) -> MCPServerContext:
    config = load_config(raw=raw)
    store = EvidenceStore(config, in_memory=True)
    engine = Engine(config, evidence_store=store)
    return MCPServerContext(
        config=config,
        engine=engine,
        evidence_store=store,
        action_producer=ToolActionProducer(config, engine, registry=engine.registry, evidence_store=store),
    )


def test_assess_gap_reports_setup_gap_without_config(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", "[project]\ndependencies = ['openai']\n")

    result = assess_gap(
        root=tmp_path,
        business_context="We handle patient records and need HIPAA.",
    )

    assert result.mode == "setup_gap"
    assert result.target.my_agent_handles == ["health_records"]
    assert result.target.active_overlays == ["hipaa"]
    assert result.config_gap.missing_my_agent_handles == ["health_records"]
    assert result.config_gap.missing_overlays == ["hipaa"]
    assert "openai" in result.instrumentation_gap.missing_producers
    assert result.evidence_gap.session_id is None
    assert result.next_steps[0].startswith("Create ancilis.yaml")


def test_assess_gap_reports_present_config_items(tmp_path: Path) -> None:
    _write(
        tmp_path / "ancilis.yaml",
        "agent:\n  name: therapy\nmy_agent_handles:\n  - health_records\ncompliance:\n  overlays:\n    - hipaa\n",
    )

    result = assess_gap(
        root=tmp_path,
        business_context="Patient records and HIPAA.",
    )

    assert result.config_gap.present_my_agent_handles == ["health_records"]
    assert result.config_gap.missing_my_agent_handles == []
    assert result.config_gap.present_overlays == ["hipaa"]
    assert result.config_gap.missing_overlays == []
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_gap_assessment.py -q
```

Expected: fail because `gap_assessment.py` does not exist.

- [ ] **Step 3: Add setup gap implementation**

Create `python/src/ancilis/mcp_server/cover/gap_assessment.py` with:

```python
"""Deterministic gap assessment for Ancilis Cover."""

from __future__ import annotations

from pathlib import Path

from ancilis.config import ResolvedConfig, load_config
from ancilis.mcp_server import MCPServerContext
from ancilis.mcp_server.cover.code_review import review_code
from ancilis.mcp_server.cover.models import (
    ConfigGap,
    EvidenceGap,
    GapAssessmentResult,
    GapReviewItem,
    InstrumentationGap,
)
from ancilis.mcp_server.cover.normalization import normalize_gap_target
from ancilis.mcp_server.cover.project import inspect_project


def _load_project_config(config_path: str | None) -> tuple[ResolvedConfig | None, list[str]]:
    if config_path is None:
        return None, []
    try:
        return load_config(path=config_path), []
    except Exception as exc:
        return None, [f"config_unavailable:{exc}"]


def _config_gap(target_handles: list[str], target_overlays: list[str], target_certs: list[str], config: ResolvedConfig | None) -> ConfigGap:
    present_handles = sorted(set(config.data_classifications) & set(target_handles)) if config is not None else []
    present_overlays = sorted(set(config.active_overlays) & set(target_overlays)) if config is not None else []
    present_certs = sorted(set(config.active_certifications) & set(target_certs)) if config is not None else []
    return ConfigGap(
        missing_my_agent_handles=sorted(set(target_handles) - set(present_handles)),
        present_my_agent_handles=present_handles,
        missing_overlays=sorted(set(target_overlays) - set(present_overlays)),
        present_overlays=present_overlays,
        missing_certification_targets=sorted(set(target_certs) - set(present_certs)),
        present_certification_targets=present_certs,
    )


def _instrumentation_gap(
    recommended_producers: list[str],
    review_items: list[GapReviewItem],
) -> InstrumentationGap:
    producers = sorted(set(recommended_producers))
    return InstrumentationGap(
        recommended_producers=producers,
        present_producers=[],
        missing_producers=producers,
        review_items=review_items,
    )


def _next_steps(config_gap: ConfigGap, instrumentation_gap: InstrumentationGap, has_evidence: bool) -> list[str]:
    steps: list[str] = []
    if config_gap.missing_my_agent_handles or config_gap.missing_overlays or config_gap.missing_certification_targets:
        steps.append("Create or update ancilis.yaml with the requested data handles, overlays, and certification targets.")
    if instrumentation_gap.missing_producers:
        first = instrumentation_gap.missing_producers[0]
        steps.append(f"Wrap the {first} producer surface first.")
    if has_evidence:
        steps.append("Review missing evidence controls and run targeted agent flows.")
    else:
        steps.append("Run ancilis doctor and ancilis scan after integration.")
    return steps


def assess_gap(
    root: str | Path | None = None,
    *,
    business_context: str | None = None,
    target_data_types: list[str] | None = None,
    target_overlays: list[str] | None = None,
    target_certifications: list[str] | None = None,
    session_id: str | None = None,
    include_code_review: bool = False,
    paths: list[str] | None = None,
    runtime_context: MCPServerContext | None = None,
) -> GapAssessmentResult:
    """Assess setup and evidence gaps against a deterministic target."""
    root_path = Path.cwd() if root is None else Path(root)
    inspection = inspect_project(root_path)
    normalization = normalize_gap_target(
        business_context=business_context,
        target_data_types=target_data_types,
        target_overlays=target_overlays,
        target_certifications=target_certifications,
    )
    project_config, warnings = _load_project_config(inspection.config_path)
    config = project_config or (runtime_context.config if runtime_context is not None else None)
    config_gap = _config_gap(
        normalization.target.my_agent_handles,
        normalization.target.active_overlays,
        normalization.target.certification_targets,
        config,
    )
    review = review_code(root_path, paths=paths) if include_code_review else None
    review_items = list(normalization.review_items)
    if review is not None:
        review_items.extend(
            GapReviewItem(source="code_review", value=finding.category, reason=finding.message)
            for finding in review.findings
        )
    instrumentation_gap = _instrumentation_gap(inspection.recommended_producers, review_items)
    evidence_gap = EvidenceGap(session_id=session_id)
    mode = "evidence_gap" if evidence_gap.session_id else "setup_gap"
    return GapAssessmentResult(
        mode=mode,
        target=normalization.target,
        normalization_signals=normalization.signals,
        review_items=review_items,
        project={
            "ancilis_present": inspection.ancilis_present,
            "recommended_producers": inspection.recommended_producers,
            "languages": inspection.languages,
        },
        config_gap=config_gap,
        instrumentation_gap=instrumentation_gap,
        evidence_gap=evidence_gap,
        next_steps=_next_steps(config_gap, instrumentation_gap, has_evidence=False),
        confidence=normalization.confidence,
        assumptions=[],
        warnings=[*inspection.warnings, *warnings],
    )
```

- [ ] **Step 4: Run setup gap tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_gap_assessment.py -q
```

Expected: pass for setup gap tests.

- [ ] **Step 5: Commit setup gap assessment**

```bash
git add python/src/ancilis/mcp_server/cover/gap_assessment.py python/tests/mcp_server/cover/test_gap_assessment.py
git commit -m "feat: assess cover setup gaps"
```

---

### Task 7: Add Evidence Gap Coverage

**Files:**
- Modify: `python/src/ancilis/mcp_server/cover/gap_assessment.py`
- Modify: `python/tests/mcp_server/cover/test_gap_assessment.py`

- [ ] **Step 1: Add evidence gap test**

Append to `python/tests/mcp_server/cover/test_gap_assessment.py`:

```python
from ancilis.engine.result import ControlResult, EvaluationResult


def test_assess_gap_reports_evidence_gap_from_runtime_context(tmp_path: Path) -> None:
    context = _context(
        {
            "agent": {"name": "therapy"},
            "my_agent_handles": ["health_records"],
            "compliance": {"overlays": ["hipaa"]},
        }
    )
    evaluation = EvaluationResult(
        evaluation_id="eval-1",
        action_id="action-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="agent-1",
        source_type="tool",
        mode="audit",
        control_results=[ControlResult("PR-01", "Tool Identity & Allowlist", "PASS", "ok")],
        decision="ALLOW",
        decision_reason="test",
        active_overlays=["hipaa"],
        data_classifications=["DC-PHI"],
        total_duration_ms=1.0,
        session_id="session-1",
    )
    context.evidence_store.store(evaluation, tool_name="agent")

    result = assess_gap(
        root=tmp_path,
        business_context="Patient records need HIPAA.",
        runtime_context=context,
    )

    assert result.mode == "evidence_gap"
    assert result.evidence_gap.session_id == "session-1"
    assert result.evidence_gap.controls_total > 0
    assert "PR-01" in result.evidence_gap.evidenced_controls
    assert "PR-01" not in result.evidence_gap.missing_controls
```

- [ ] **Step 2: Run evidence test and verify it fails**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_gap_assessment.py::test_assess_gap_reports_evidence_gap_from_runtime_context -q
```

Expected: fail because evidence coverage is not implemented.

- [ ] **Step 3: Implement evidence coverage helpers**

In `gap_assessment.py`, import overlay profiles:

```python
from ancilis.activation.loader import load_overlay_profiles
```

Add helpers:

```python
def _overlay_controls(overlays: list[str]) -> list[str]:
    profiles = load_overlay_profiles()
    controls: set[str] = set()
    for overlay in overlays:
        profile = profiles.get(overlay)
        if profile is None:
            continue
        for control_id, control_data in profile.get("controls", {}).items():
            if control_data.get("applicable", True):
                controls.add(control_id)
        if not controls:
            controls.update(profile.get("control_adjustments", {}).keys())
            controls.update(profile.get("evidence_requirements", {}).keys())
    return sorted(controls)


def _evidence_gap(
    context: MCPServerContext | None,
    *,
    requested_overlays: list[str],
    session_id: str | None,
) -> EvidenceGap:
    controls = _overlay_controls(requested_overlays)
    if context is None:
        return EvidenceGap(
            session_id=session_id,
            requested_overlays=requested_overlays,
            controls_total=len(controls),
            missing_controls=controls,
        )

    selected_session = session_id or context.evidence_store.latest_session_id()
    if selected_session is None:
        return EvidenceGap(
            session_id=None,
            requested_overlays=requested_overlays,
            controls_total=len(controls),
            missing_controls=controls,
        )

    records = context.evidence_store.get_records(session_id=selected_session, limit=None)
    evidenced: set[str] = set()
    for record in records:
        for raw_result in record.control_results:
            control_id = raw_result.get("control_id")
            status = str(raw_result.get("result", "SKIP")).upper()
            if isinstance(control_id, str) and status != "SKIP":
                evidenced.add(control_id)

    missing = sorted(set(controls) - evidenced)
    return EvidenceGap(
        session_id=selected_session,
        requested_overlays=requested_overlays,
        controls_total=len(controls),
        controls_with_evidence=len(set(controls) & evidenced),
        missing_controls=missing,
        evidenced_controls=sorted(set(controls) & evidenced),
    )
```

- [ ] **Step 4: Wire evidence coverage into `assess_gap`**

Replace:

```python
    evidence_gap = EvidenceGap(session_id=session_id)
    mode = "evidence_gap" if evidence_gap.session_id else "setup_gap"
```

with:

```python
    evidence_gap = _evidence_gap(
        runtime_context,
        requested_overlays=normalization.target.active_overlays,
        session_id=session_id,
    )
    mode = "evidence_gap" if evidence_gap.session_id else "setup_gap"
```

Replace the `next_steps` call with:

```python
        next_steps=_next_steps(config_gap, instrumentation_gap, has_evidence=evidence_gap.session_id is not None),
```

- [ ] **Step 5: Run gap assessment tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/mcp_server/cover/test_gap_assessment.py -q
```

Expected: pass.

- [ ] **Step 6: Commit evidence gaps**

```bash
git add python/src/ancilis/mcp_server/cover/gap_assessment.py python/tests/mcp_server/cover/test_gap_assessment.py
git commit -m "feat: assess cover evidence gaps"
```

---

### Task 8: Register `ancilis_assess_gap`

**Files:**
- Modify: `python/src/ancilis/mcp_server/cover/server.py`
- Modify: `python/tests/mcp_server/cover/test_server.py`
- Modify: `python/tests/test_mcp_server.py`
- Modify: `python/tests/mcp_server/cover/test_integration.py`

- [ ] **Step 1: Add server structured call test**

Append to `python/tests/mcp_server/cover/test_server.py`:

```python
def test_assess_gap_tool_returns_structured_content(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = ['openai']\n",
        encoding="utf-8",
    )
    server = create_cover_mcp_server()

    gap = _call_tool_structured(
        server,
        "ancilis_assess_gap",
        {
            "root": str(tmp_path),
            "business_context": "We handle patient records and need HIPAA.",
        },
    )

    assert gap["mode"] == "setup_gap"
    assert gap["target"]["my_agent_handles"] == ["health_records"]
    assert gap["target"]["active_overlays"] == ["hipaa"]
```

- [ ] **Step 2: Update stdio integration to call gap tool**

In `python/tests/mcp_server/cover/test_integration.py`, call `ancilis_assess_gap` after the inspect call:

```python
        gap_result = await session.call_tool(
            "ancilis_assess_gap",
            {
                "root": str(tmp_path),
                "business_context": "Customer agent handles email and needs SOC 2.",
            },
        )
```

Then assert:

```python
    gap = _structured(gap_result)
    assert gap["target"]["my_agent_handles"] == ["personal_info"]
    assert gap["target"]["active_overlays"] == ["soc2"]
```

- [ ] **Step 3: Run registration tests and verify they fail**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/test_mcp_server.py::test_create_mcp_server_registers_tools python/tests/mcp_server/cover/test_server.py::test_assess_gap_tool_returns_structured_content -q
```

Expected: fail until the tool is registered.

- [ ] **Step 4: Register the gap tool**

In `python/src/ancilis/mcp_server/cover/server.py`, import:

```python
from ancilis.mcp_server.cover.gap_assessment import assess_gap
```

Inside `register_cover_tools`, add:

```python
    @server.tool(name="ancilis_assess_gap")
    async def ancilis_assess_gap(
        root: str | None = None,
        business_context: str | None = None,
        target_data_types: list[str] | None = None,
        target_overlays: list[str] | None = None,
        target_certifications: list[str] | None = None,
        session_id: str | None = None,
        include_code_review: bool = False,
        paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Assess setup and evidence gaps for a business compliance target."""
        return _json_response(
            assess_gap(
                root,
                business_context=business_context,
                target_data_types=target_data_types,
                target_overlays=target_overlays,
                target_certifications=target_certifications,
                session_id=session_id,
                include_code_review=include_code_review,
                paths=paths,
                runtime_context=runtime_context,
            )
        )
```

- [ ] **Step 5: Run server and integration tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/test_mcp_server.py python/tests/mcp_server/cover -q
```

Expected: pass.

- [ ] **Step 6: Commit tool registration**

```bash
git add python/src/ancilis/mcp_server/cover/server.py python/tests/test_mcp_server.py python/tests/mcp_server/cover/test_server.py python/tests/mcp_server/cover/test_integration.py
git commit -m "feat: register cover gap assessment mcp tool"
```

---

### Task 9: Update Docs for Cover-First MCP

**Files:**
- Modify: `docs/cli/cover.mdx`
- Modify: `docs/cli-reference.md`
- Modify: `docs/cli/serve.mdx` if present

- [ ] **Step 1: Update Cover docs**

In `docs/cli/cover.mdx`, replace the opening description and host config with:

````md
Ancilis Cover is the official local stdio MCP server for AI coding assistants. It combines onboarding, gap assessment, and runtime posture tools in one read-only local server.

Configure your MCP host to launch `ancilis-cover` locally:

```json
{
  "mcpServers": {
    "ancilis-cover": {
      "command": "ancilis-cover",
      "args": []
    }
  }
}
```
````

Add `ancilis_assess_gap` to the tools table:

```md
| `ancilis_assess_gap` | Convert business context such as "patient records and HIPAA" into Ancilis targets, then report setup, instrumentation, and evidence gaps. |
```

Add a gap assessment example:

````md
## Gap Assessment

Call `ancilis_assess_gap` with business context:

```json
{
  "root": "/path/to/project",
  "business_context": "We handle patient records and need HIPAA."
}
```

The response includes normalized Ancilis targets, missing config, missing producer instrumentation, evidence coverage when available, and next steps.
````

- [ ] **Step 2: Update CLI reference**

In `docs/cli-reference.md`, update the `ancilis-cover` entry to mention:

```md
`ancilis-cover` starts the official unified local MCP server for Cover onboarding, gap assessment, and runtime posture tools.
```

Update the `ancilis serve` entry to mention:

```md
`ancilis serve` remains available as a compatibility MCP entry point for one release. New MCP host configs should prefer `ancilis-cover`.
```

- [ ] **Step 3: Update serve docs when present**

If `docs/cli/serve.mdx` exists, add this note near the top:

```md
> Compatibility: `ancilis serve` remains available for existing MCP host configs. New local MCP configurations should use `ancilis-cover`.
```

- [ ] **Step 4: Run docs grep**

Run:

```bash
rg -n "ancilis serve|ancilis-cover|ancilis_assess_gap" docs/cli docs/cli-reference.md
```

Expected: Cover docs position `ancilis-cover` as official; serve docs mention compatibility.

- [ ] **Step 5: Commit docs**

```bash
git add docs/cli/cover.mdx docs/cli-reference.md docs/cli/serve.mdx
git commit -m "docs: document cover-first unified mcp"
```

If `docs/cli/serve.mdx` does not exist, omit it from `git add`.

---

### Task 10: Final Verification

**Files:**
- All modified files

- [ ] **Step 1: Run focused MCP tests**

Run:

```bash
PYTHONPATH=python/src python -m pytest python/tests/test_mcp_server.py python/tests/test_mcp_server_integration.py python/tests/mcp_server/cover -q
```

Expected: all tests pass.

- [ ] **Step 2: Run type checking**

Run:

```bash
PYTHONPATH=python/src python -m mypy python/src/ancilis --ignore-missing-imports
```

Expected: success.

- [ ] **Step 3: Run lint on touched Python paths**

Run:

```bash
PYTHONPATH=python/src python -m ruff check python/src/ancilis/mcp_server python/tests/mcp_server python/tests/test_mcp_server.py python/tests/test_mcp_server_integration.py
```

Expected: success.

- [ ] **Step 4: Run TypeScript typecheck**

Run:

```bash
npm run typecheck
```

Expected: success.

- [ ] **Step 5: Check whitespace**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 6: Commit final verification fixes when needed**

If verification requires code or docs changes:

```bash
git add <changed-files>
git commit -m "fix: stabilize unified cover mcp"
```

Expected: no commit is created when verification is already clean.
