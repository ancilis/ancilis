# Ancilis Cover Onboarding MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic first iteration of the local `ancilis-cover` MCP onboarding server.

**Architecture:** Keep Cover separate from the existing `ancilis serve` posture server. Implement small modules under `python/src/ancilis/mcp_server/cover/`, each with one responsibility: models, project inspection, classification, setup recommendations, code review, report rendering, and MCP server wiring.

**Tech Stack:** Python 3.10+, FastMCP from `mcp.server.fastmcp`, Pydantic v2, Click console scripts through `pyproject.toml`, existing Ancilis taxonomy/config/pattern scanner, pytest.

---

## File Structure

- Create `python/src/ancilis/mcp_server/cover/models.py`: Pydantic models shared by tools.
- Create `python/src/ancilis/mcp_server/cover/project.py`: bounded local project inspection.
- Create `python/src/ancilis/mcp_server/cover/classification.py`: deterministic signal to data type and overlay inference.
- Create `python/src/ancilis/mcp_server/cover/recommendations.py`: install commands, config YAML, snippets, validation commands.
- Create `python/src/ancilis/mcp_server/cover/code_review.py`: explicit file/snippet review with path boundaries and redaction.
- Create `python/src/ancilis/mcp_server/cover/report.py`: concise Markdown onboarding report.
- Create `python/src/ancilis/mcp_server/cover/server.py`: FastMCP server factory and `main()`.
- Modify `pyproject.toml`: add `ancilis-cover` console script.
- Create `python/tests/mcp_server/cover/test_project.py`: project inspection tests.
- Create `python/tests/mcp_server/cover/test_classification.py`: classification and setup recommendation tests.
- Create `python/tests/mcp_server/cover/test_code_review.py`: path boundary and finding tests.
- Create `python/tests/mcp_server/cover/test_server.py`: MCP tool registration and direct tool-call tests.
- Create `python/tests/mcp_server/cover/test_integration.py`: stdio server integration test.
- Create `docs/cli/cover.mdx`: minimal user docs and host config.

## Task 1: Project Inspection

**Files:**
- Create: `python/tests/mcp_server/cover/test_project.py`
- Create: `python/src/ancilis/mcp_server/cover/models.py`
- Create: `python/src/ancilis/mcp_server/cover/project.py`

- [ ] **Step 1: Write failing project inspection tests**

Add tests that create a temporary project with `pyproject.toml`, `package.json`, `ancilis.yaml`, and sample Python files. Assert that inspection detects Python, TypeScript, MCP, LangChain, OpenAI, existing Ancilis config, recommended producers, and bounded file counts.

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_project.py -q
```

Expected: fail with `ModuleNotFoundError` for missing Cover implementation modules.

- [ ] **Step 2: Implement models and project inspection**

Implement Pydantic models for signals and project inspection output. Implement `inspect_project(root, max_files=200, include_hidden=False)` using only local reads, manifest parsing, extension counting, known dependency names, and existing `ancilis.yaml` detection.

- [ ] **Step 3: Verify project inspection**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_project.py -q
```

Expected: all tests in `test_project.py` pass.

## Task 2: Classification and Setup Recommendations

**Files:**
- Create: `python/tests/mcp_server/cover/test_classification.py`
- Create: `python/src/ancilis/mcp_server/cover/classification.py`
- Create: `python/src/ancilis/mcp_server/cover/recommendations.py`

- [ ] **Step 1: Write failing classification and recommendation tests**

Add tests for deterministic mappings:

- `stripe`, `checkout`, and `card` signals produce `credit_cards` and PCI-related overlays.
- `patient`, `clinic`, `mrn`, and `therapist` signals produce `health_records` and HIPAA-related overlays.
- weak single keywords become `review_items` when confidence is low.
- setup recommendations include install commands, `ancilis.yaml`, integration snippets, and validation commands.

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_classification.py -q
```

Expected: fail because classification and recommendation modules do not exist.

- [ ] **Step 2: Implement deterministic classification**

Implement rule tables with stable `rule_id` values. Resolve overlays by passing proposed `my_agent_handles` and any certification targets through existing Ancilis config/activation behavior where practical. Every recommendation must include the signal evidence that caused it.

- [ ] **Step 3: Implement setup recommendations**

Generate deterministic install commands, minimal `ancilis.yaml`, Python and TypeScript integration snippets, and validation commands. Do not write any files.

- [ ] **Step 4: Verify classification and recommendations**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_classification.py -q
```

Expected: all tests in `test_classification.py` pass.

## Task 3: Code Review and Onboarding Report

**Files:**
- Create: `python/tests/mcp_server/cover/test_code_review.py`
- Create: `python/src/ancilis/mcp_server/cover/code_review.py`
- Create: `python/src/ancilis/mcp_server/cover/report.py`

- [ ] **Step 1: Write failing code review tests**

Add tests for:

- rejecting paths outside `root`
- skipping files larger than `max_bytes_per_file`
- redacting samples from `scan_for_patterns`
- detecting subprocess/shell usage
- detecting outbound HTTP destinations
- accepting named snippets

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_code_review.py -q
```

Expected: fail because code review module does not exist.

- [ ] **Step 2: Implement bounded code review**

Use `Path.resolve()` root checks, byte limits, `scan_for_patterns`, deterministic regex/keyword heuristics, and structured skip warnings. Return findings and producer recommendations without writing files.

- [ ] **Step 3: Implement report rendering**

Render a concise Markdown report from inspection, classification, setup, and optional review findings.

- [ ] **Step 4: Verify code review**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_code_review.py -q
```

Expected: all tests in `test_code_review.py` pass.

## Task 4: MCP Server and CLI Entrypoint

**Files:**
- Create: `python/tests/mcp_server/cover/test_server.py`
- Create: `python/tests/mcp_server/cover/test_integration.py`
- Create: `python/src/ancilis/mcp_server/cover/server.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Write failing MCP server tests**

Add tests that:

- `create_cover_mcp_server()` registers all five tools
- each tool returns structured content through `server.call_tool`
- `main` exists through `ancilis.mcp_server.cover`
- stdio integration starts with `python -m ancilis.mcp_server.cover.server`

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_server.py python/tests/mcp_server/cover/test_integration.py -q
```

Expected: fail because `server.py` and console script wiring are missing.

- [ ] **Step 2: Implement FastMCP server**

Register tools:

- `ancilis_inspect_project`
- `ancilis_classify_project`
- `ancilis_recommend_setup`
- `ancilis_review_code`
- `ancilis_onboarding_report`

Expose `create_cover_mcp_server()` and `main()`.

- [ ] **Step 3: Add console script**

Add this script to `pyproject.toml`:

```toml
ancilis-cover = "ancilis.mcp_server.cover.server:main"
```

- [ ] **Step 4: Verify MCP server**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover/test_server.py python/tests/mcp_server/cover/test_integration.py -q
```

Expected: all tests in `test_server.py` and `test_integration.py` pass.

## Task 5: Docs and Final Verification

**Files:**
- Create: `docs/cli/cover.mdx`
- Modify as needed: `README.md` or `docs/cli-reference.md`

- [ ] **Step 1: Add user documentation**

Document local stdio usage, host configuration, tool list, read-only/privacy guarantees, and first setup workflow.

- [ ] **Step 2: Run focused Cover tests**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/mcp_server/cover -q
```

Expected: all Cover tests pass.

- [ ] **Step 3: Run existing MCP regression tests**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m pytest python/tests/test_mcp_server.py python/tests/test_mcp_server_integration.py -q
```

Expected: all existing MCP server tests pass.

- [ ] **Step 4: Run static checks**

Run:

```bash
/Users/hellohelloalbus/projects/ancilis/.venv/bin/python -m ruff check python/src/ancilis/mcp_server/cover python/tests/mcp_server/cover
git diff --check
```

Expected: no ruff errors and no whitespace errors.

- [ ] **Step 5: Commit implementation**

Run:

```bash
git add pyproject.toml python/src/ancilis/mcp_server/cover python/tests/mcp_server/cover docs/cli/cover.mdx docs/superpowers/plans/2026-05-20-ancilis-cover-onboarding-mcp.md
git commit -m "feat: add deterministic ancilis cover onboarding mcp"
```
