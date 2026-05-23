# README Adoption and Trust Rewrite Design

## Goal

Rewrite the root README so it demonstrates Ancilis value quickly, gives developers a clear adoption path, and makes trust and compliance claims concrete rather than generic.

The README should answer three questions in order:

1. Why would I install this?
2. How quickly can I see it work?
3. Can I trust the evidence and compliance story?

## Audience

Primary audience: developers and technical security leads evaluating Ancilis for tool-using AI agents.

Secondary audience: compliance and trust stakeholders who need to understand what evidence Ancilis produces, how controls activate, and what limitations remain.

## Editorial Approach

Use an adoption-first narrative:

- Lead with the operational risk: AI agents are making tool calls, shell calls, MCP calls, and model calls that need policy decisions and audit evidence.
- Show the payoff immediately: wrap a tool, run a status/report command, and get evaluated actions plus hash-chained local evidence.
- Then expand into integration paths, compliance overlays, reporting, and operating modes.

Avoid a feature catalog opening. The README should make the product feel usable before listing every supported producer.

## Proposed README Structure

1. `# Ancilis`
2. Short value proposition focused on runtime security decisions and audit-ready evidence.
3. Trust/compliance proof points:
   - deterministic policy evaluation,
   - local DuckDB evidence store,
   - SHA-256 hash chain,
   - audit and enforce modes,
   - data-driven compliance overlay activation,
   - no hosted service or network dependency for core evaluation.
4. 30-second value demo:
   - install,
   - minimal `ancilis.yaml`,
   - wrap one tool,
   - run `ancilis status`,
   - explain the outcome.
5. Integration paths:
   - plain Python tools,
   - MCP middleware,
   - CLI/subprocess agents,
   - LLM SDK and agent framework producers,
   - Cover MCP for onboarding and gap assessment.
6. Compliance and trust:
   - data classifications trigger overlays,
   - certification targets can be declared,
   - reports include per-control posture and evidence chain verification,
   - current coverage is stated honestly.
7. How it works:
   - producers create Actions,
   - engine evaluates AKSI controls,
   - evidence is written locally,
   - CLI reads posture and reporting data.
8. Configuration levels.
9. CLI reference.
10. TypeScript preview.
11. Honest limitations.
12. Links.

## Trust and Compliance Language

The rewrite should use concrete language such as:

- "audit-ready evidence" only when paired with the mechanism that creates it.
- "tamper-evident" for the SHA-256 hash chain, while noting that database replacement is outside the protection boundary.
- "deterministic controls" for policy evaluation, avoiding claims that Ancilis magically certifies an organization.
- "compliance posture" and "readiness" instead of "compliant" unless backed by an explicit report scope.
- "data declarations activate overlays" rather than implying runtime data classification is already automatic.

## Non-Goals

- Do not change package installation commands or public APIs unless the current README is already wrong.
- Do not invent compliance guarantees, certifications, or legal conclusions.
- Do not remove the "What's honest" limitations section; tighten it if needed.
- Do not rewrite linked docs or examples as part of this pass.
- Do not claim TypeScript is the primary path; keep it clearly marked as preview.

## Acceptance Criteria

- The README starts with a clear adoption hook and value proof before detailed integration catalogs.
- A new reader can find install, minimal setup, and first status/report command in the first half of the file.
- Trust and compliance claims are specific, bounded, and supported by mechanisms described in the README.
- The integration sections are grouped by adoption path instead of scattered across the document.
- Existing important facts remain present: MCP, Cover MCP, CLI producer, LLM/framework producers, compliance overlays, CLI commands, TypeScript preview, limitations, and links.
- The README no longer feels like sections were appended in release order.
