# Ancilis Cover Onboarding MCP Design

## Goal

Build the first production slice of Ancilis Cover: a local, deterministic MCP server that helps AI coding assistants convert an uninstrumented AI application into an Ancilis-ready project.

The server should answer:

- What kind of AI project is this?
- Does it likely handle regulated or sensitive data?
- Which Ancilis data declarations, overlays, and producer integrations fit?
- What exact setup should the coding assistant apply next?

This slice optimizes for adoption and onboarding, not ongoing runtime operations. The existing `ancilis serve` posture server remains unchanged for now.

## Background

PR #73 introduced the package scaffold for `ancilis.mcp_server.cover`, but it did not implement the planned server. The merged code only added package markers and a lazy `main` import that points at a missing `cover.server`.

The current repository also contains a working MCP posture server behind `ancilis serve`. That server exposes runtime inspection tools for instrumented projects:

- `ancilis_check_posture`
- `ancilis_evaluate_action`
- `ancilis_get_evidence`
- `ancilis_report`
- `ancilis_list_overlays`

Those tools are valuable after Ancilis is installed and evidence exists. Cover fills the earlier funnel step: helping a developer discover why they need Ancilis and how to add it.

## Product Positioning

Ancilis Cover is an AI-native onboarding copilot for local development.

It should be distributed as a local stdio MCP server. Developers should not need hosted infrastructure to use it. Their MCP host, such as Claude Code, Cursor, Cline, Continue, or another coding assistant, launches the server as a subprocess.

Example host configuration:

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

The v1 server reads bounded local project metadata and returns structured recommendations. It does not modify files.

## Non-Goals

- No LLM calls.
- No MCP sampling.
- No hosted service dependency.
- No network calls.
- No automatic file writes.
- No code rewriting.
- No replacement for `ancilis serve`.
- No consolidation between Cover and `ancilis serve` in this slice.

A future experimental mode can use an LLM-assisted workflow, possibly named `compliance-party`, but v1 must have no runtime path to host LLM inference.

## Architecture

Add the production Cover implementation under:

```text
python/src/ancilis/mcp_server/cover/
```

Modules:

- `server.py`: FastMCP server factory, tool registration, and `main()`.
- `models.py`: Pydantic request and response models for tool outputs.
- `project.py`: deterministic project inspection from manifests, known config files, directory names, and file names.
- `classification.py`: deterministic signal to data-type, classification, and overlay inference.
- `recommendations.py`: install commands, `ancilis.yaml` generation, producer selection, and integration guidance.
- `code_review.py`: bounded file and snippet review using existing pattern scanners plus deterministic framework and risk heuristics.
- `report.py`: Markdown onboarding report renderer.

Keep Cover separate from `python/src/ancilis/mcp_server/__init__.py` so the current posture server stays stable.

## Command Shape

Add a console script:

```toml
[project.scripts]
ancilis-cover = "ancilis.mcp_server.cover.server:main"
```

The command starts the Cover MCP server over stdio. No additional CLI arguments are required for v1. Optional arguments can be added later for explicit root directory or debug logging.

## MCP Tools

### `ancilis_inspect_project`

Purpose: identify the local project shape and Ancilis readiness.

Inputs:

- `root`: optional string path. Defaults to current working directory.
- `max_files`: integer, default 200.
- `include_hidden`: boolean, default false.

Behavior:

- Read directory names and file names up to a bounded limit.
- Read supported manifests when present:
  - `pyproject.toml`
  - `requirements.txt`
  - `package.json`
  - `pnpm-lock.yaml`
  - `yarn.lock`
  - `package-lock.json`
  - `Dockerfile`
  - `ancilis.yaml`
- Detect languages from manifests and file extensions.
- Detect AI frameworks and SDKs from dependency names and known imports where cheap and bounded.
- Detect whether Ancilis is already configured.
- Detect likely producer paths such as `tool`, `mcp`, `cli`, `http`, `openai`, `anthropic`, `langchain`, `crewai`, and `autogen`.

Output:

- `root`
- `languages`
- `frameworks`
- `dependencies`
- `ancilis_present`
- `config_path`
- `recommended_producers`
- `signals`
- `warnings`

### `ancilis_classify_project`

Purpose: map deterministic project signals to Ancilis data declarations and overlays.

Inputs:

- `root`: optional string path.
- `description`: optional natural language project description supplied by the MCP host or user.
- `signals`: optional signals returned by `ancilis_inspect_project`.

Behavior:

- Use only deterministic keyword, filename, dependency, and manifest rules.
- Map signals to `my_agent_handles` values.
- Resolve classifications and overlays through existing Ancilis taxonomy and activation logic where possible.
- Include confidence as `high`, `medium`, or `low`.
- Include evidence for every recommendation.
- Phrase low confidence results as review items rather than detections.

Example mappings:

- `stripe`, `checkout`, `card`, `payment` -> `credit_cards` -> PCI-DSS v4.
- `patient`, `clinic`, `medical`, `mrn`, `ehr`, `therapist` -> `health_records` -> HIPAA, GDPR, SOC 2.
- `invoice`, `bank`, `portfolio`, `trading`, `kyc` -> `financial_records` -> GLBA or securities overlays where applicable.
- `email`, `profile`, `address`, `user`, `account` -> `personal_info` -> GDPR, CCPA, SOC 2.
- `biometric`, `face`, `voiceprint`, `fingerprint` -> `biometric_data` -> EU AI Act.

Output:

- `my_agent_handles`
- `data_classifications`
- `active_overlays`
- `certification_targets`
- `confidence`
- `signals`
- `review_items`

### `ancilis_recommend_setup`

Purpose: provide the exact next setup steps for the project.

Inputs:

- `root`: optional string path.
- `project`: optional output from `ancilis_inspect_project`.
- `classification`: optional output from `ancilis_classify_project`.
- `language`: optional override, one of `python`, `typescript`, or `auto`.

Behavior:

- Recommend install command.
- Generate minimal `ancilis.yaml` text.
- Recommend producer integration pattern.
- Provide a short code snippet for the best-fit integration.
- Provide validation commands.
- Do not write files.

Output:

- `install_commands`
- `config_yaml`
- `integration_summary`
- `integration_snippets`
- `validation_commands`
- `next_steps`

### `ancilis_review_code`

Purpose: review explicit files or snippets for onboarding-relevant risks.

Inputs:

- `root`: optional string path.
- `paths`: list of relative or absolute file paths, default empty.
- `snippets`: list of named snippets, default empty.
- `max_bytes_per_file`: integer, default 60000.

Behavior:

- Read only requested files.
- Reject paths outside `root`.
- Limit file bytes.
- Scan for existing sensitive data patterns with `ancilis.engine.patterns.scan_for_patterns`.
- Add deterministic heuristics for:
  - raw API keys or secrets
  - unwrapped tool/function calls
  - outbound HTTP destinations
  - database/query surfaces
  - MCP client or server usage
  - shell/subprocess usage
  - likely LLM SDK invocation surfaces
- Return findings with severity and suggested Ancilis producer.

Output:

- `findings`
- `producer_recommendations`
- `suggested_config_changes`
- `reviewed_files`
- `skipped_files`

### `ancilis_onboarding_report`

Purpose: produce a concise Markdown report for an AI coding assistant to act on.

Inputs:

- `root`: optional string path.
- `description`: optional project description.
- `include_code_review`: boolean, default false.
- `paths`: optional paths for code review if enabled.

Behavior:

- Compose inspection, classification, setup recommendation, and optional code review.
- Keep the report short and action oriented.
- Include deterministic evidence behind each recommendation.

Output:

- `report_markdown`
- `summary`
- `next_steps`
- `confidence`

## Deterministic Rule System

Rules should be simple, inspectable, and testable. Each emitted signal should include:

- `source`: where the signal came from, such as dependency, filename, manifest, description, or snippet.
- `value`: the matched text or normalized dependency.
- `rule_id`: stable identifier for the rule.
- `confidence`: high, medium, or low.
- `recommendation`: the resulting data type, overlay, producer, or risk.

Rule results should be merged by confidence:

- `high`: two or more independent signals, or one strong dependency signal.
- `medium`: one strong keyword or framework signal.
- `low`: weak keyword only. This becomes a review item unless supported by another signal.

## Privacy and Safety

The v1 server is local-first and read-only.

Required guarantees:

- No network calls.
- No host LLM calls.
- No MCP sampling.
- No file writes.
- No reads outside the requested project root.
- Bounded directory traversal.
- Bounded file reads.
- Redacted samples for sensitive data findings.
- Structured warnings when files are skipped.

## Error Handling

Return structured errors instead of raising raw exceptions through MCP when possible.

Examples:

- `path_outside_root`
- `file_too_large`
- `unsupported_manifest`
- `invalid_root`
- `manifest_parse_error`

The server should continue with partial results when a non-critical file cannot be parsed.

## Testing Strategy

Unit tests:

- Project inspection detects Python, TypeScript, MCP, LangChain, OpenAI, Anthropic, CLI, and HTTP surfaces from manifests.
- Classification maps deterministic signals to expected `my_agent_handles` and overlays.
- Low confidence findings remain review items.
- Setup recommendation emits valid YAML and expected snippets.
- Code review redacts sensitive samples and rejects paths outside root.
- Report rendering includes the core sections and next steps.

MCP integration tests:

- `ancilis-cover` starts over stdio.
- The server lists all five tools.
- Each tool returns structured content.

Privacy tests:

- No writes occur during tool calls.
- Path traversal is rejected.
- File reads are bounded.
- No sampling or network path is imported or invoked.

Regression tests:

- Existing `ancilis serve` MCP tests remain unchanged and passing.

## Documentation

Add docs that explain:

- Cover is local stdio MCP, not hosted.
- How to configure it in common MCP hosts.
- What each tool does.
- What data it reads.
- Why deterministic v1 does not use LLM inference.
- How to move from recommendation to actual SDK setup.

## Future Work

- Consolidate Cover and `ancilis serve` under a single MCP server with modes.
- Optional hosted policy packs for teams.
- Optional code-writing installer after trust is established.
- Experimental LLM-assisted mode, such as `compliance-party`, explicitly gated and separate from deterministic v1.
