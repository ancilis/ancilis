# README Adoption and Trust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the root README so it demonstrates Ancilis value quickly, gives developers a clear adoption path, and uses concrete trust and compliance language.

**Architecture:** This is a documentation-only rewrite of `README.md`. The new structure keeps the existing factual content but changes the editorial flow from release-append order to adoption-first order: hook, proof, integration paths, compliance/trust, operation, limitations, links.

**Tech Stack:** Markdown, local shell verification with `rg`, `sed`, `git diff`, and optional markdown linting if available.

---

### Task 1: Establish The README Outline

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Capture the current heading order**

Run:

```bash
rg -n "^#{1,6} " README.md
```

Expected: output shows the current scattered order, including `Install`, `30-second setup`, multiple integration sections, compliance, architecture, CLI, TypeScript, limitations, and links.

- [ ] **Step 2: Replace the README section order with the adoption-first outline**

Edit `README.md` so the top-level heading order is exactly:

```markdown
# Ancilis
## See Value In 30 Seconds
## Choose Your Integration Path
## Compliance And Trust
## How It Works
## Configuration Levels
## CLI Reference
## TypeScript Preview
## What's Honest
## Links
```

Keep badge links and all existing important facts. Move details into the new sections instead of deleting them.

- [ ] **Step 3: Verify the new outline**

Run:

```bash
rg -n "^#{1,6} " README.md
```

Expected: output matches the section order from Step 2, with lower-level headings only inside the relevant sections.

### Task 2: Rewrite The Adoption Hook And First Demo

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite the opening paragraph and proof points**

Replace the current short description with copy that says:

```markdown
Runtime security decisions and audit-ready evidence for AI agents.

AI agents do real work now: they call tools, run shell commands, invoke MCP servers, and send requests to LLM providers. Ancilis gives those actions a policy decision before they become invisible operational risk. It evaluates each action against deterministic AKSI controls, records the result in a local tamper-evident evidence store, and turns the same evidence into compliance posture reports.

Use it when you need to answer:

- What did this agent do?
- Was the action allowed by policy?
- Which controls passed, failed, or need attestation?
- What evidence can we show for SOC 2, HIPAA, PCI-DSS, EU AI Act, and other readiness work?

Ancilis runs locally. Core evaluation does not require a hosted service, network calls, or sending agent payloads to Ancilis.
```

- [ ] **Step 2: Add a concrete trust proof list**

Add this list directly after the opening:

```markdown
What you get:

- **Policy decisions at runtime**: audit mode observes every action; enforce mode blocks violations before execution.
- **Tamper-evident evidence**: each record is written to DuckDB with a SHA-256 hash chain.
- **Compliance posture from the same data**: data declarations and certification targets activate framework overlays without manual crosswalking.
- **Honest coverage**: direct evaluators, attestation-backed controls, and current TypeScript preview limits are called out below.
```

- [ ] **Step 3: Rewrite the first demo section**

Keep the existing install command, minimal `ancilis.yaml`, tool wrapper example, and `ancilis status` example. Introduce the section with:

```markdown
## See Value In 30 Seconds

Install Ancilis, name your agent, allow the tools it should use, and wrap the first callable surface. The first call creates an evaluated Action and a local evidence record.
```

Use the existing code examples unless they are structurally tied to the old section order.

### Task 3: Group Integration Paths

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Create the integration section**

Create `## Choose Your Integration Path` after the quick demo.

- [ ] **Step 2: Move existing integration content under focused subheadings**

Use these subheadings:

```markdown
### Plain Python Tools
### MCP Agents
### Cover MCP Server
### CLI And Subprocess Agents
### LLM SDKs And Agent Frameworks
```

Move the current MCP, Cover MCP, CLI, and LLM/framework sections under those headings. Keep examples and producer table. Add a short `Plain Python Tools` paragraph that points back to the 30-second wrapper example.

- [ ] **Step 3: Verify required integration terms remain present**

Run:

```bash
rg -n "MCP|ancilis-cover|CLIActionProducer|auto_register|AnthropicActionProducer|LangChainCallbackHandler|Semantic Kernel|HTTP" README.md
```

Expected: each major integration path appears at least once.

### Task 4: Strengthen Compliance And Trust Without Overclaiming

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace `Add compliance` and `Data types → compliance overlays` with one compliance section**

Create `## Compliance And Trust`. Include:

```markdown
Compliance work starts with what your agent handles. Declare the data classes and certification targets that apply; Ancilis activates the matching overlays and reports posture from the evidence your runtime already produced.
```

Keep the existing config example with `certification_targets` and `my_agent_handles`.

- [ ] **Step 2: Keep the overlay table**

Keep the current data type to overlay table and the note that 23 canonical data classes and 19 overlay profiles are supported. Preserve the roadmap note, but make clear that automatic classification is not the current behavior.

- [ ] **Step 3: Add bounded compliance wording**

Ensure this section uses `readiness`, `posture`, and `evidence` language. Do not claim Ancilis makes a user compliant or certified.

- [ ] **Step 4: Verify overclaiming terms**

Run:

```bash
rg -n "\\bcompliant\\b|guarantee|certified|certifies|magic|automatic classification" README.md
```

Expected: no unbounded compliance claims. `automatic classification` may appear only in the roadmap note explaining it is future work.

### Task 5: Preserve Operations, Limits, And Links

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Move operating details into stable sections**

Keep and tighten:

```markdown
## How It Works
## Configuration Levels
## CLI Reference
## TypeScript Preview
## What's Honest
## Links
```

Use the existing flow diagram, configuration table, CLI command list, TypeScript sample, limitations bullets, and links.

- [ ] **Step 2: Verify core factual claims remain**

Run:

```bash
rg -n "41 AKSI|39 common|PAY-01|PAY-02|18 direct runtime evaluators|23 attestation-backed|19 overlay profiles|DuckDB|SHA-256|pandoc|xelatex" README.md
```

Expected: each current honesty/detail item remains represented.

- [ ] **Step 3: Review the full diff**

Run:

```bash
git diff -- README.md
```

Expected: the diff is a README rewrite only; no unrelated files are modified by this task.

### Task 6: Final Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Check Markdown structure**

Run:

```bash
rg -n "^#{1,6} " README.md
```

Expected: section order is coherent and no code comments are accidentally parsed as headings.

- [ ] **Step 2: Check for leftover planning language**

Run:

```bash
rg -n "TBD|TODO|placeholder|fill in|similar to|magic" README.md
```

Expected: no matches.

- [ ] **Step 3: Inspect rendered-adjacent content**

Run:

```bash
sed -n '1,220p' README.md
sed -n '220,420p' README.md
```

Expected: the README reads in adoption-first order and all fenced code blocks are closed.
