# Ancilis SDK Distribution Research

Date: 2026-05-20

## Executive Recommendation

Ancilis should lead with a developer-authentic wedge, not a broad "AI tool" launch.

The strongest adoption path is:

1. Fix the public package/repo/docs surface so the first impression is consistent.
2. Seed technical proof in the communities where agent builders already discuss tool calls, MCP, LangChain, CrewAI, OpenAI Agents, and runtime security.
3. Convert attention into a narrow install path: install, wrap one tool call, run `ancilis status`, generate an evidence/report artifact.
4. Use the early feedback and proof points to launch more broadly on Hacker News, Product Hunt, newsletters, and security communities.

The core positioning should be:

> Ancilis turns AI-agent tool calls into deterministic policy decisions and tamper-evident evidence. Start in audit mode, switch to enforce mode, and map what the agent handles to compliance controls without sending data to a SaaS service.

The channels with the highest near-term leverage are:

1. GitHub and package registry surfaces
2. LangChain, CrewAI, OpenAI Agents, and MCP communities
3. Reddit communities: `r/LLMDevs`, `r/mcp`, `r/AI_Agents`, `r/LangChain`, selective security subreddits
4. Hacker News `Show HN` after the demo/docs surface is ready
5. GitHub awesome lists and topic SEO
6. OWASP GenAI and MLSecOps as credibility channels, not launch channels
7. Product Hunt and AI newsletters after there is a clean conversion funnel

## Product Context

Based on the local repo, Ancilis is an SDK and CLI for runtime security and compliance evidence for AI agents. The current local README describes:

- Policy evaluation for every tool call
- Tamper-evident evidence records with SHA-256 hash chaining
- Local DuckDB evidence store, no external service required
- Audit and enforce modes
- MCP, CLI, HTTP, Python tool wrapper, LLM SDK, and agent framework producers
- Integrations for LangChain/LangGraph, CrewAI, AutoGen, OpenAI, Bedrock, Anthropic, Gemini, Mistral, Cohere, xAI, Groq, Together, Fireworks, DeepSeek, Semantic Kernel
- Compliance overlays for SOC 2, HIPAA, PCI-DSS, EU AI Act, and others

This is not just "guardrails." The useful wedge is "runtime evidence for tool-using agents." That matters because agent builders already understand tool calls, but security/compliance buyers care about proof after the fact.

## Public Surface Gaps To Fix First

Do these before meaningful distribution. Otherwise the channels will send qualified users into contradictory public surfaces.

- PyPI shows `ancilis 0.1.0`, released March 23, 2026, and describes the package as "Python-first runtime evaluation and policy enforcement for AI agent tool calls." It also says the license is Business Source License 1.1, while the local repo metadata currently says AGPL-3.0-or-later. Resolve the license and publish consistent metadata before launch. Source: https://pypi.org/project/ancilis/
- The public GitHub repo currently shows 2 stars and 0 forks. Its README still includes 26-control messaging in multiple places, while local repo work appears to be moving toward AKSI v0.6 / 41-control messaging. Do not launch until public README, local README, PyPI, npm, and docs agree. Source: https://github.com/ancilis/ancilis
- The local package metadata says TypeScript `ancilis` exists, but npm search did not reliably surface the package. Verify npm publication, README rendering, keywords, provenance, and install instructions.
- Verify `ancilis.ai`, `ancilis.ai/docs`, and package homepage links resolve cleanly. The package and repo point people there, so broken docs would waste the launch.
- Add one high-trust demo path: a short screen recording or terminal GIF showing install -> wrap one tool -> run -> evidence -> report. Communities should be able to try the result without a sales call.

## Priority Channels

### 1. GitHub, PyPI, npm, And Docs

This is the highest ROI channel because every other channel points here.

Actions:

- Update GitHub repo topics to cover both discovery and buyer intent: `ai-agents`, `agent-security`, `ai-security`, `mcp`, `mcp-security`, `model-context-protocol`, `langchain`, `langgraph`, `crewai`, `openai-agents`, `runtime-security`, `policy-as-code`, `compliance-automation`, `audit-logs`, `evidence-generation`.
- Make the README first screen answer: what it does, who it is for, 30-second install, local/no-SaaS posture, honest limitations.
- Add a "Run the minimal demo" block with a copy-paste command.
- Add screenshots or terminal output for `ancilis status`, `evidence verify`, and `report --format markdown`.
- Add framework-specific docs pages with names people search for:
  - "Secure LangChain tool calls with tamper-evident evidence"
  - "Audit MCP tool calls in Python"
  - "AI agent compliance evidence for SOC 2"
  - "Runtime policy enforcement for OpenAI Agents"
- Keep limitations visible. This increases trust with HN/security audiences.

Why this matters:

- GitHub topics for `mcp-security` currently show a live competitive surface with 165 public repos and many projects positioning around MCP security, AI security, runtime security, and agent governance. Ancilis needs to be present in those search paths. Source: https://github.com/topics/mcp-security
- Awesome lists are still meaningful for developer discovery. `e2b-dev/awesome-ai-agents` shows 27.9k stars and hundreds of pull requests, and LLM-security lists already include agent security and MCP scanner tools. Sources: https://github.com/e2b-dev/awesome-ai-agents and https://github.com/beyefendi/awesome-llm-security

### 2. LangChain And LangGraph Ecosystem

This is a strong audience because Ancilis already has a LangChain/LangGraph callback handler story.

Best entry point:

- Do not post a generic launch in the LangChain Forum. The forum guidelines explicitly say promotional content or solicitation can result in an immediate ban. Source: https://forum.langchain.com/guidelines
- Use the LangChain Slack/community for broader conversation and showcase, and use the forum only for specific technical help or a concrete integration question. LangChain's community page points builders to the forum, LangChain Academy discussions, and Community Slack. Source: https://www.langchain.com/community

Recommended post angle:

> I built a LangChain callback handler that records hash-chained evidence for LLM/tool/chain/retriever events without storing document content. Looking for feedback from people running regulated LangGraph agents.

Assets to link:

- Minimal LangChain example
- Evidence output screenshot
- "What is captured / what is not captured" table
- Limitations and privacy details

Goal:

- Feedback from people already using LangChain in production
- Maintainer visibility
- A possible docs/examples PR into related ecosystem resources later

### 3. CrewAI Community

CrewAI is attractive because the official community has a specific `Showcase` category and active support categories. The CrewAI forum currently exposes categories for General, Community Support, Showcase, Crews, LLMs, and more. Source: https://community.crewai.com/

Recommended post angle:

> Showcase: tamper-evident evidence for CrewAI `kickoff()` runs and tool usage, with no captured output content.

Keep it concrete:

- One simple CrewAI research crew
- Before/after of adding `@ancilis_crew`
- Evidence fields captured
- "What should this capture for real deployments?" as the feedback question

Goal:

- Early framework-specific users
- Specific friction feedback around decorators, callbacks, and evidence semantics

### 4. MCP Communities And Registries

MCP is one of the most important awareness surfaces, but the registry path only works if Ancilis exposes a server, gateway, or package that fits the registry model.

Current situation:

- The official MCP Registry is a metadata repository for publicly accessible MCP servers. It supports namespace verification, server metadata, REST discovery, and public installation metadata. Source: https://modelcontextprotocol.io/registry/about
- Docker's MCP Catalog is a curated collection of verified MCP servers packaged as Docker images. Source: https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/
- Ancilis currently reads like MCP client middleware, not a standalone MCP server. That is still valuable, but it means registry/catalog submissions may not fit unless Ancilis packages a gateway/proxy/server mode.

Best near-term channel:

- `r/mcp`
- `r/modelcontextprotocol`
- MCP GitHub discussions, if a specific technical proposal or issue exists
- Docs/tutorial posts: "Audit MCP tool calls before they hit the server"

Recommended post angle:

> I built client-side MCP middleware that evaluates every `call_tool` against policy and writes hash-chained evidence locally. Does this belong in the client, a proxy, or an MCP gateway?

Why this works:

- Existing `r/mcp` posts show clear interest in runtime security proxies, inspection, policy enforcement, exfiltration detection, and audit trails. Source: https://www.reddit.com/r/mcp/comments/1sb0o26/i_built_a_runtime_security_proxy_for_ai_agents/
- This audience will challenge architecture choices. That is useful early.

Longer-term:

- Consider an `ancilis-mcp-gateway` or `ancilis-mcp-server` package if registry/catalog discovery becomes strategic.
- If built, submit to the official MCP Registry, Docker MCP Catalog, Glama, Smithery, and other MCP directories.

### 5. Reddit: Technical Communities

Reddit is probably the fastest feedback and first-user channel, but posts must be useful without requiring a click.

High-priority communities:

- `r/LLMDevs`: Good fit for agent builders discussing runtime security. Recent discussions explicitly distinguish prompt safety from runtime enforcement and mention least privilege, RBAC, sandboxing, and SDK friction. Source: https://www.reddit.com/r/LLMDevs/comments/1s2f7df/how_are_you_guys_handling_agent_security/
- `r/mcp`: Good fit for the MCP middleware story. Use architecture/feedback framing.
- `r/AI_Agents`: Broad reach. A third-party listing reports roughly 309k members, making it a meaningful but noisier channel. Source: https://thehiveindex.com/communities/r-ai-agents/
- `r/LangChain`: Good fit only with a LangChain-specific post. Existing posts about tamper-evident audit evidence got relevant discussion around regulated pipelines and signed evidence. Source: https://www.reddit.com/r/LangChain/comments/1rbbz2r/i_scanned_30_popular_ai_projects_for/
- `r/cybersecurity`, `r/devsecops`, `r/netsec`: Use research/checklist content, not a launch.
- `r/MachineLearning`: Use the recurring self-promotion thread, not a standalone product post, unless there is a research-grade benchmark or paper. Source: https://www.reddit.com/r/MachineLearning/comments/1t1d2m0/d_selfpromotion_thread/

Post formats:

- Feedback post: "How are you handling evidence for AI-agent tool calls in production?"
- Architecture post: "Client middleware vs proxy vs gateway for MCP runtime policy enforcement"
- Case study post: "I wrapped a LangChain agent and generated a SOC 2-ready evidence report from tool calls"
- Checklist post: "A practical AI-agent security review before go-live"

Rules of thumb:

- Put the substance in the post body.
- Include code snippets and screenshots.
- Ask for specific feedback.
- Do not cross-post the same text everywhere.
- Do not lead with "we launched."
- Use a founder account that participates outside launch posts.

### 6. Hacker News

Hacker News can work well for open-source developer infrastructure, but only if the launch is technically credible and immediately tryable.

Relevant HN rules:

- Do not use HN primarily for promotion.
- Submit the original source.
- Do not solicit upvotes, comments, or submissions.
- Do not use hype in titles.
- Do not post generated or AI-edited comments. Source: https://news.ycombinator.com/newsguidelines.html

Use `Show HN` only after:

- The repo is public and coherent.
- The README is consistent.
- A user can run the demo in under 5 minutes.
- The founder can spend several hours answering comments.
- The docs honestly explain limitations.

Potential title:

> Show HN: Ancilis - runtime security and hash-chained evidence for AI agents

Backup title:

> Show HN: I built a local evidence layer for AI-agent tool calls

Avoid:

- "Compliance-ready AI agents in 30 seconds"
- "The best security SDK for AI agents"
- "SOC 2 for AI agents"

HN readers will punish overclaims. They may reward a narrow, honest, technical artifact.

### 7. Product Hunt

Product Hunt is useful for broad awareness, backlinks, and social proof, but it is not the first launch for a developer SDK. Product Hunt itself frames launches around community submissions, upvotes, comments, and homepage ranking. Source: https://www.producthunt.com/launch/

Launch after:

- There is a polished landing page and demo GIF.
- GitHub/PyPI/npm/docs are fixed.
- There are 2-3 testimonials or early user quotes.
- There is an email capture path.
- There is a clear "try without talking to sales" flow.

Positioning:

> Runtime security and compliance evidence for AI agents.

Use Product Hunt for:

- Awareness
- Newsletter pickups
- Founder/investor visibility
- Backlinks

Do not expect it to be the primary developer adoption source.

### 8. OWASP GenAI, MLSecOps, And Security Communities

These are credibility and relationship channels, not quick-growth channels.

Why they matter:

- OWASP GenAI has initiatives around Agentic AI threats, LLM/data security, transparency, and AI red teaming. Source: https://genai.owasp.org/initiatives/
- MLSecOps describes itself as a hub for building security into AI and ML lifecycles. Source: https://community.mlsecops.com/

Recommended contribution formats:

- "AI-agent runtime evidence: what to log without leaking sensitive content"
- "Mapping tool-call evidence to OWASP LLM/Agentic AI risks"
- "A local-first reference implementation for tamper-evident agent evidence"
- "Ancilis as an example implementation, not the headline"

Actions:

- Join the communities.
- Share educational material first.
- Offer to contribute examples, checklists, or mappings.
- Ask for review of evidence schemas or control mappings.

This path supports enterprise trust more than immediate installs.

### 9. OpenAI Developer Community And Agents SDK

OpenAI's developer surfaces matter because Ancilis has an OpenAI SDK wrapper and can potentially cover OpenAI Agents SDK use cases. The OpenAI developer site links to a developer forum and Agents SDK resources. Source: https://developers.openai.com/

Recommended post angle:

> How should runtime evidence work for OpenAI Agents tool calls without storing prompts or outputs?

Good content:

- Minimal OpenAI tool-call wrapper
- Evidence fields captured
- Privacy stance
- How this complements, not replaces, OpenAI tracing/guardrails

Avoid:

- Generic "try our SDK" posts.
- Claims that Ancilis certifies compliance by itself.

### 10. Newsletters And Directories

Use after there is public traction or a clean launch asset.

Targets:

- TLDR AI / TLDR Dev sponsorship or submission. TLDR's sponsorship page claims large technical audiences across newsletters, including TLDR AI and TLDR Dev. Source: https://advertise.tldr.tech/
- Ben's Bites, which allows product/news submissions and community voting. Source: https://bensbites.co/
- The Rundown AI tool submission path. Source: https://www.rundown.ai/submit
- Curated AI/devtool newsletters that accept open-source tools.

Best pitch:

> Open-source/local SDK for AI-agent runtime security: evaluate every tool call, keep tamper-evident evidence locally, and generate compliance posture reports.

Newsletter audiences need a one-sentence "why now":

> Agents are moving from chat to real actions; teams need evidence of what the agent did and which policy was applied.

## Adoption Funnel

### Awareness

Channels:

- Reddit technical posts
- LangChain/CrewAI/OpenAI/MCP community threads
- GitHub topics and awesome-list PRs
- HN Show HN
- Product Hunt/newsletters later

Message:

> Your agent's tool calls are the control point. Ancilis evaluates them, records local evidence, and gives you reports.

### Activation

Required path:

1. `pip install ancilis`
2. Create `ancilis.yaml`
3. Wrap one tool or MCP session
4. Run one action
5. Run `ancilis status`
6. Run `ancilis evidence verify`
7. Generate a Markdown report

Measure:

- PyPI/npm installs
- GitHub stars
- Demo repo clones
- Docs page views
- Issues/discussions
- Completed example runs, if telemetry is intentionally added later and made opt-in

### Retention

Add reasons to return:

- Framework examples
- "Control of the week" posts
- Security/compliance checklist templates
- Example evidence reports for SOC 2, HIPAA, PCI-DSS, EU AI Act
- CI/GitHub Action posture checks

### Conversion

Near-term conversion is not payment. It is:

- GitHub star
- `pip install`
- Run demo
- Open issue/discussion
- Join mailing list
- Ask about production use

Commercial conversion can come later around:

- Hosted dashboard
- Team evidence storage
- Enterprise policy packs
- Compliance report export workflows
- Managed mappings
- Support contracts

## 30-Day Distribution Plan

### Days 1-3: Launch Readiness

- Align license, controls count, and positioning across local README, public GitHub, PyPI, npm, docs, and website.
- Publish or verify a fresh package release if the local SDK is ahead of public package pages.
- Add a demo GIF or short terminal recording.
- Add one minimal example for MCP and one for LangChain.
- Add a "What Ancilis does not do" section.

### Days 4-7: Technical Seeding

- Post one LangChain-specific integration question/showcase in the right LangChain community surface.
- Post one CrewAI Showcase thread.
- Post one `r/LLMDevs` discussion about runtime evidence and policy enforcement.
- Post one `r/mcp` architecture feedback thread.
- Reply deeply to every comment.

### Days 8-14: Open-Source Discovery

- Submit PRs to relevant awesome lists:
  - `awesome-ai-agents`
  - `awesome-llm-security`
  - MCP/security lists, if fit is accepted
- Add GitHub topics and improve README SEO.
- Publish a technical blog post: "Auditing MCP tool calls locally with hash-chained evidence."
- Share the blog post to `r/mcp`, `r/AI_Agents`, and relevant LinkedIn/X threads with different summaries.

### Days 15-21: Launch Moment

- Run Hacker News `Show HN` once the demo is ready.
- Post a founder technical thread on LinkedIn and X.
- Submit to Ben's Bites / Rundown / TLDR or start paid newsletter testing if budget exists.
- Collect and publish early feedback.

### Days 22-30: Security Credibility

- Join OWASP GenAI and MLSecOps.
- Share an educational checklist or evidence-schema post, not a product launch.
- Reach out to maintainers of LangChain/CrewAI/MCP examples with a small docs/example PR if appropriate.
- Publish "AI-agent compliance evidence: what to capture without storing content."

## Concrete Post Ideas

### r/LLMDevs

Title:

> How are you recording evidence for AI-agent tool calls in production?

Body outline:

- Agents are now calling tools that touch real systems.
- Prompt-only safety does not prove what happened.
- I built Ancilis to evaluate each tool call against policy and write local hash-chained evidence.
- Here is the minimal code.
- What would you require before using this in production?
- Specific asks: evidence schema, redaction model, MCP architecture, framework integration.

### r/mcp

Title:

> Client middleware vs proxy vs gateway for MCP runtime policy enforcement?

Body outline:

- Explain Ancilis wraps the MCP client session.
- It evaluates `call_tool` before forwarding and records evidence locally.
- Ask whether this should remain client-side or become a gateway/server.
- Include code and failure-mode tradeoffs.

### CrewAI Community

Title:

> Showcase: local evidence capture for CrewAI runs without storing output content

Body outline:

- Show `@ancilis_crew`.
- Show captured event fields.
- Ask what CrewAI production users need: task-level attribution, tool-level attribution, delegation evidence, redaction.

### LangChain

Title:

> LangChain callback handler for hash-chained tool-call evidence - feedback on event model?

Body outline:

- Do not make it promotional.
- Focus on technical event mapping and privacy.
- Ask whether callback coverage is enough for LangGraph production flows.

### HN

Title:

> Show HN: Ancilis - runtime security and hash-chained evidence for AI agents

Body/comment:

- "I built this because agent security reviews kept collapsing into screenshots and best-effort logs."
- "It is local-first: DuckDB evidence store, no service required."
- "It is alpha. Here is what works and what does not."
- "I am especially interested in feedback on the evidence model and MCP boundary."

## Positioning Guidance

Lead with:

- Tool-call boundary
- Deterministic policy evaluation
- Local tamper-evident evidence
- Audit mode first, enforce later
- Compliance reports as a byproduct
- No prompt/output content stored by default for framework integrations

Avoid leading with:

- "SOC 2 for AI agents" unless the claim is carefully scoped
- "Fully compliant"
- "AI safety"
- "Agent firewall" unless the feature actually behaves like a firewall
- "MCP registry" unless Ancilis ships a registry-eligible server/gateway

Differentiation:

- Many current projects describe MCP security proxies, sandboxes, scanners, or firewalls.
- Ancilis should occupy "policy-to-evidence for tool calls across frameworks."
- The evidence/compliance layer is more distinctive than generic runtime blocking.

## Metrics To Track

Awareness:

- GitHub stars/watchers/forks
- README views, if GitHub traffic is available
- Docs page views
- HN/Product Hunt/Reddit comments

Activation:

- PyPI downloads
- npm downloads
- Demo repo clones
- `ancilis` CLI issue reports
- Example-specific questions

Engagement:

- GitHub issues/discussions
- Community replies from production users
- Requests for framework support
- PRs or example contributions

Conversion:

- Email list signups
- Calls requested
- Security/compliance buyer questions
- Requests for hosted dashboard or team evidence store

## Source Links

- Ancilis PyPI package: https://pypi.org/project/ancilis/
- Ancilis GitHub repo: https://github.com/ancilis/ancilis
- GitHub `mcp-security` topic: https://github.com/topics/mcp-security
- LangChain community: https://www.langchain.com/community
- LangChain forum guidelines: https://forum.langchain.com/guidelines
- CrewAI community: https://community.crewai.com/
- MCP Registry: https://modelcontextprotocol.io/registry/about
- Docker MCP Catalog: https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/
- Hacker News guidelines: https://news.ycombinator.com/newsguidelines.html
- Product Hunt launch guide: https://www.producthunt.com/launch/
- OWASP GenAI initiatives: https://genai.owasp.org/initiatives/
- MLSecOps community: https://community.mlsecops.com/
- Awesome AI Agents: https://github.com/e2b-dev/awesome-ai-agents
- Awesome LLM Security: https://github.com/beyefendi/awesome-llm-security
- r/LLMDevs agent security discussion: https://www.reddit.com/r/LLMDevs/comments/1s2f7df/how_are_you_guys_handling_agent_security/
- r/mcp runtime security proxy discussion: https://www.reddit.com/r/mcp/comments/1sb0o26/i_built_a_runtime_security_proxy_for_ai_agents/
- r/LangChain tamper-evident audit discussion: https://www.reddit.com/r/LangChain/comments/1rbbz2r/i_scanned_30_popular_ai_projects_for/
- r/MachineLearning self-promotion thread: https://www.reddit.com/r/MachineLearning/comments/1t1d2m0/d_selfpromotion_thread/
- r/AI_Agents community listing: https://thehiveindex.com/communities/r-ai-agents/
- TLDR sponsorship: https://advertise.tldr.tech/
- Ben's Bites: https://bensbites.co/
- The Rundown AI tool submission: https://www.rundown.ai/submit
