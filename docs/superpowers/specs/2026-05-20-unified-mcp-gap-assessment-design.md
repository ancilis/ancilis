# Unified MCP and Gap Assessment Design

## Summary

Consolidate Ancilis MCP onboarding and runtime posture on Cover as the official local MCP server while preserving `ancilis serve` as a compatibility entry point for one release. Add a deterministic `ancilis_assess_gap` tool that lets a developer describe their business context in plain language, such as "we handle patient records and need HIPAA", and receive an Ancilis-specific setup and evidence gap assessment.

This phase turns the MCP experience from "help me install Ancilis" into "tell me exactly what I need to add or prove for this compliance target." The tool remains local, read-only, deterministic, and suitable for coding assistants without introducing LLM inference, MCP sampling, hosted infrastructure, or file mutation.

## Goals

- Make `ancilis-cover` the official MCP entry point for both onboarding tools and existing posture tools.
- Keep `ancilis serve` working for one release as a compatibility path for existing MCP host configs.
- Move documentation and examples away from `ancilis serve` and toward Cover.
- Add `ancilis_assess_gap` as a first-class MCP tool for conversion and onboarding.
- Let users provide low-friction business phrases, then deterministically normalize those phrases into Ancilis data handles, overlays, and certification targets.
- Support both fresh projects with no evidence and instrumented projects with existing evidence sessions.
- Produce a concise, structured gap assessment that a coding assistant can act on.

## Non-Goals

- Do not add LLM-based interpretation, MCP sampling, or network-backed classification.
- Do not write `ancilis.yaml`, edit source files, run installers, or mutate evidence stores from MCP tools.
- Do not remove `ancilis serve` in this release.
- Do not print deprecation warnings to stdout while running stdio MCP, because stdout is the protocol stream.
- Do not implement hosted MCP infrastructure; the server remains a local stdio process launched by an MCP host.
- Do not add experimental "dangerous-compliance" behavior in this phase.

## Current State

There are now two local MCP server entry points:

- `ancilis serve` creates the existing runtime/posture server from `ancilis.mcp_server.create_mcp_server`.
- `ancilis-cover` creates the onboarding server from `ancilis.mcp_server.cover.server.create_cover_mcp_server`.

The current `ancilis serve` tools are:

- `ancilis_check_posture`
- `ancilis_evaluate_action`
- `ancilis_get_evidence`
- `ancilis_report`
- `ancilis_list_overlays`

The current `ancilis-cover` tools are:

- `ancilis_inspect_project`
- `ancilis_classify_project`
- `ancilis_recommend_setup`
- `ancilis_review_code`
- `ancilis_onboarding_report`

The next phase should compose these capabilities instead of maintaining two separate product stories.

## Proposed Command Surface

### Official Path

`ancilis-cover` becomes the official command for MCP hosts. The server name remains `ancilis-cover`, and the tool list includes both onboarding and runtime posture tools.

`ancilis-cover` should accept the same config selection needed by runtime posture tools:

- `--config PATH`: optional path to `ancilis.yaml`.
- `--transport stdio`: accepted for symmetry with `ancilis serve`; only stdio is supported in this phase.

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

### Compatibility Path

`ancilis serve --transport stdio` continues to launch an MCP server for one release, but it becomes the legacy compatibility path. It should expose the same unified tool set as Cover while docs steer new users to `ancilis-cover`.

Do not emit a runtime deprecation warning over stdout in stdio mode. If a warning is added later, it must go to stderr before transport startup or appear only in docs/help text.

## Unified Tool Surface

`ancilis-cover` should expose the Cover onboarding tools, the existing runtime tools, and the new gap assessment tool:

- `ancilis_check_posture`
- `ancilis_evaluate_action`
- `ancilis_get_evidence`
- `ancilis_report`
- `ancilis_list_overlays`
- `ancilis_inspect_project`
- `ancilis_classify_project`
- `ancilis_recommend_setup`
- `ancilis_review_code`
- `ancilis_onboarding_report`
- `ancilis_assess_gap`

The implementation should avoid a large mixed server file. Runtime tools and Cover tools should each have a focused registration function that accepts a `FastMCP` instance and any required context. The Cover server factory composes both registration functions; the legacy `ancilis serve` factory reuses the same registration functions for compatibility.

## `ancilis_assess_gap`

### Purpose

Assess the gap between a user-declared compliance target and the current project state. The target can be expressed in business language first, with Ancilis-specific terms as optional overrides.

### Inputs

- `root: str | None = None`
  - Project root to inspect. Defaults to the MCP process working directory.
- `business_context: str | None = None`
  - Plain-language target description. Examples:
    - `"We handle patient records and need HIPAA."`
    - `"Checkout agent accepts cards and needs PCI."`
    - `"Customer support bot stores email addresses and needs SOC 2."`
- `target_data_types: list[str] | None = None`
  - Optional explicit Ancilis data handles such as `health_records`, `credit_cards`, `personal_info`, `financial_records`, or `biometric_data`.
- `target_overlays: list[str] | None = None`
  - Optional explicit overlays such as `hipaa`, `pci-dss-v4`, `soc2`, or `gdpr`.
- `target_certifications: list[str] | None = None`
  - Optional explicit certification targets when the repo distinguishes them from overlays.
- `session_id: str | None = None`
  - Optional evidence session to assess. If omitted, the tool uses the latest session when evidence exists.
- `include_code_review: bool = false`
  - Optional bounded review of explicit files if `paths` is provided.
- `paths: list[str] | None = None`
  - Explicit files for the optional code review. The tool never scans arbitrary source files through this parameter.

### Output

The tool returns structured JSON:

```json
{
  "mode": "setup_gap",
  "target": {
    "my_agent_handles": ["health_records"],
    "active_overlays": ["hipaa"],
    "certification_targets": []
  },
  "normalization_signals": [
    {
      "source": "business_context",
      "phrase": "patient records",
      "mapped_to": "health_records",
      "target_type": "my_agent_handles",
      "confidence": "high"
    }
  ],
  "project": {
    "ancilis_present": false,
    "recommended_producers": ["openai"],
    "languages": ["python"]
  },
  "config_gap": {
    "missing_my_agent_handles": ["health_records"],
    "missing_overlays": ["hipaa"],
    "missing_certification_targets": []
  },
  "instrumentation_gap": {
    "missing_producers": ["openai"],
    "review_items": []
  },
  "evidence_gap": {
    "session_id": null,
    "controls_total": 0,
    "controls_with_evidence": 0,
    "missing_controls": []
  },
  "next_steps": [
    "Create ancilis.yaml with health_records and hipaa enabled.",
    "Wrap the OpenAI producer surface first.",
    "Run ancilis doctor and ancilis scan after integration."
  ],
  "confidence": "high",
  "assumptions": []
}
```

### Modes

The tool chooses a mode automatically:

- `setup_gap`: no usable evidence session exists. The output focuses on missing config, missing producer instrumentation, and setup next steps.
- `evidence_gap`: a usable evidence session exists. The output includes setup gaps and overlay/control evidence coverage from the selected or latest session.

If a project has evidence but the requested target adds overlays or data handles not present in the current config, the tool still reports both setup and evidence gaps. `mode` should be `evidence_gap` because evidence was available, but the response must still include config and instrumentation gaps.

## Business Phrase Normalization

Normalization should be deterministic and inspectable. The implementation uses a local phrase map rather than an LLM.

### Target Mappings

Initial mappings should cover high-value conversion phrases:

| Business Phrase Examples | Normalized Target |
| --- | --- |
| patient, patient record, medical record, clinic, therapy, therapist, mrn, ehr, phi | `my_agent_handles: health_records` |
| hipaa, health insurance portability | `active_overlays: hipaa` |
| card, credit card, checkout, stripe, payment, billing | `my_agent_handles: credit_cards` |
| pci, pci dss, pci-dss, cardholder data | `active_overlays: pci-dss-v4` |
| customer, user, email, address, profile, account | `my_agent_handles: personal_info` |
| gdpr, eu user, european user, data subject | `active_overlays: gdpr` |
| soc 2, soc2, trust services | `active_overlays: soc2` |
| bank, kyc, loan, trading, portfolio, invoice | `my_agent_handles: financial_records` |
| biometric, face, fingerprint, voiceprint | `my_agent_handles: biometric_data` |

Explicit `target_data_types`, `target_overlays`, and `target_certifications` are merged into the normalized target and marked with source `explicit_input`.

Unknown phrases should not be guessed. They should become review items when they look compliance-related but do not map to a known target.

### Confidence Rules

- `high`: explicit Ancilis target input, direct overlay acronym, or unambiguous domain phrase such as `patient records`.
- `medium`: one non-explicit phrase with a clear but broader meaning, such as `customer profile`.
- `low`: phrase that looks relevant but cannot be mapped deterministically.

Low-confidence normalization does not activate targets. It appears in `review_items` and `assumptions`.

## Gap Computation

### Config Gap

Compare normalized targets against the currently loaded Ancilis config when `ancilis.yaml` exists. Report:

- `missing_my_agent_handles`
- `present_my_agent_handles`
- `missing_overlays`
- `present_overlays`
- `missing_certification_targets`
- `present_certification_targets`

When no config exists, all normalized targets are missing.

### Instrumentation Gap

Use `inspect_project` and optional `review_code` results to infer recommended producers. Report:

- `recommended_producers`
- `present_producers` when they can be detected through Ancilis config or project signals
- `missing_producers`
- `review_items`

For v1, producer presence can be conservative. If there is no reliable Ancilis instrumentation signal, recommend wrapping the highest-risk detected producer rather than claiming it is present.

### Evidence Gap

When evidence exists, reuse the same active overlay/control logic used by `ancilis_list_overlays` and `ancilis_check_posture`. Report:

- selected `session_id`
- requested overlays
- controls total for those overlays
- controls with evidence
- controls missing evidence
- latest result status by evidenced control when available

If the requested overlay is not active in the current config, report its controls as missing evidence and add a config gap item first.

## Error Handling

- Invalid root returns a structured `invalid_root` error.
- Unsupported explicit target values return `unsupported_target` with the accepted values.
- Malformed config should not crash the MCP server; return config parse details in `warnings` and continue with project inspection when possible.
- Evidence store read failures should return `evidence_unavailable` in `warnings` and continue with setup gap output.
- Code review path escapes are reported through the existing `skipped_files` mechanism.

## Privacy and Safety

All tools in this phase remain read-only:

- No network calls.
- No file writes.
- No subprocess execution beyond the MCP host launching the server.
- No LLM calls.
- No MCP sampling.
- Path inputs are resolved and constrained to the requested root.
- File reads remain bounded.
- Sensitive samples remain redacted.

## Documentation

Update docs to position `ancilis-cover` as the primary MCP entry point and `ancilis serve` as a legacy compatibility path. Add a gap assessment section with business-context examples and sample outputs.

Required docs updates:

- `docs/cli/cover.mdx` to show the official unified Cover MCP host configuration.
- `docs/cli/serve.mdx` or equivalent MCP server docs if present, marking `ancilis serve` as compatibility-only.
- `docs/cli-reference.md` for the unified Cover tools and the `ancilis serve` compatibility path.

## Testing

Add focused tests for:

- `ancilis-cover` registering both onboarding and runtime tools.
- `ancilis serve` continuing to register the unified tool set for compatibility.
- `ancilis_assess_gap` normalizing business phrases into targets.
- Explicit targets merging with business-context targets.
- Unknown phrases becoming review items instead of activated targets.
- Setup gap output for a project with no `ancilis.yaml`.
- Evidence gap output for a project with stored evidence.
- Path boundary behavior when `include_code_review` uses explicit paths.
- CLI smoke tests for `ancilis-cover --config` and `ancilis serve --config` server factories without starting long-running transports.

Baseline checks from the feature worktree:

- `PYTHONPATH=python/src python -m pytest python/tests/test_mcp_server.py python/tests/mcp_server/cover -q`
- `npm run typecheck`

## Migration Plan

1. Extract existing runtime tool registration from `ancilis.mcp_server.create_mcp_server` into a reusable registration helper.
2. Extract Cover onboarding tool registration into a reusable registration helper.
3. Make `create_cover_mcp_server` compose Cover onboarding tools and runtime posture tools, with optional config loading for runtime context.
4. Keep `create_mcp_server` and `ancilis serve` as a compatibility path that composes the same unified tool set.
5. Implement deterministic target normalization and gap assessment modules under `python/src/ancilis/mcp_server/cover/`.
6. Register `ancilis_assess_gap` in both the official Cover server and the legacy `ancilis serve` server.
7. Update docs to favor `ancilis-cover`.
8. Keep `ancilis serve` available and documented as compatibility-only for one release.

## Deferred Decision

This phase intentionally makes Cover the official MCP surface and keeps `ancilis serve` as a compatibility path. `ancilis serve` removal is outside this phase; after one release, decide whether to remove it, keep it as a stable alias, or add a deprecation warning based on usage data and support feedback.
