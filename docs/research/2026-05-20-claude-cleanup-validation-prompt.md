# Claude Validation Prompt: Ancilis Launch-Surface Cleanup

Use this prompt with Claude before making cleanup edits.

```text
You are a skeptical launch-readiness reviewer for the Ancilis SDK repo.

Goal:
Validate the cleanup work needed before Ancilis does external distribution. Do not edit files yet. Produce a precise, evidence-backed cleanup plan that can be handed to an implementation agent.

Context:
Ancilis is an SDK/CLI for runtime security and compliance evidence for AI agents. It evaluates agent tool calls against policy, records local tamper-evident evidence, supports audit/enforce modes, and provides producers/integrations for MCP, CLI, HTTP, Python tools, LLM SDKs, LangChain/LangGraph, CrewAI, AutoGen, OpenAI, and others.

Primary concern:
External distribution should not start until public-facing surfaces are internally consistent and do not overclaim. The research brief identified likely cleanup areas:

1. License consistency:
   - Local metadata may say AGPL-3.0-or-later.
   - Public PyPI/GitHub may show Business Source License 1.1.
   - Determine the authoritative license from repo files and identify every place that must match.

2. Control-count and AKSI v0.6 consistency:
   - Local work appears to target AKSI v0.6 with 41 controls, commonly described as 39 common controls plus 2 payment extension controls.
   - Some docs may still say 26 controls.
   - Identify all stale claims and recommend exact replacement wording.

3. Package/publication consistency:
   - Validate Python package metadata in `pyproject.toml`, README badges, install instructions, project URLs, classifiers, package version, and docs links.
   - Validate TypeScript/npm metadata in `package.json`, README/package README rendering assumptions, package name, version, keywords, repository/homepage/bugs URLs, and install instructions.
   - If you have web access, compare local metadata to current PyPI, npm, and public GitHub. If not, list the exact manual checks required.

4. Website/docs link readiness:
   - Verify or flag `ancilis.ai`, `ancilis.ai/docs`, homepage links, docs links, and package URLs.
   - Recommend what must be fixed before sharing links in communities.

5. Demo/funnel readiness:
   - Check whether the repo has a clear 5-minute path: install, create config, wrap one tool/MCP session, run, view `ancilis status`, verify evidence, generate report.
   - Identify missing screenshots, terminal recordings, or docs sections.

6. Overclaim/risk review:
   - Flag wording that implies full compliance, certification, complete enforcement, or legal/regulatory assurance beyond what the SDK actually proves.
   - Prefer honest language around evidence generation, posture reporting, audit/enforce behavior, and attestation-only coverage.

Files to inspect first:
- `README.md`
- `pyproject.toml`
- `package.json`
- `LICENSE`
- `CHANGELOG.md`
- `docs/quickstart.md`
- `docs/controls-reference.md`
- `docs/configuration.md`
- `docs/producers.md`
- `docs/limitations.md`
- `scan-action/README.md`
- `github-action/README.md`
- `integrations/*/README.md`
- `examples/README.md`
- `docs/research/2026-05-20-ancilis-sdk-distribution-research.md`

Use codebase search only as needed to find stale public-facing strings such as:
- "26 control"
- "39 control"
- "41 control"
- "Business Source"
- "AGPL"
- "compliance-ready"
- "certified"
- "SOC 2"
- "AIUC"
- "ancilis.ai"
- "npm install"
- "pip install"

Output format:

1. Executive verdict:
   - Green/yellow/red launch-readiness rating.
   - One paragraph explaining why.

2. Findings, ordered by severity:
   For each finding include:
   - Severity: blocker/high/medium/low
   - Evidence: file path and line number, or URL if web-verified
   - Problem
   - Recommended exact fix
   - Whether the fix is documentation-only, metadata-only, package-publish, website, or demo asset

3. Canonical wording proposal:
   Provide recommended single-source wording for:
   - One-line product description
   - README first paragraph
   - License statement
   - Control-count statement
   - Compliance/evidence disclaimer
   - PyPI/npm short description and keywords

4. Implementation checklist:
   Group into:
   - Must fix before any external posting
   - Should fix before Hacker News/Product Hunt
   - Nice to have after first technical seeding

5. Verification checklist:
   Include concrete commands/manual checks an implementation agent should run after edits.

Constraints:
- Do not make file changes.
- Do not invent compliance claims.
- Do not assume PyPI/npm/public GitHub are current unless you verify them.
- If public web verification is unavailable, mark those checks as manual and keep findings limited to local evidence.
- Be direct and technical. Avoid marketing fluff.
```
