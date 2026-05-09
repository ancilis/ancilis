# Changelog

All notable changes to this project will be documented in this file.

The project follows a conservative pre-1.0 release posture:

- `0.1.x`: first honest public release line for the Python SDK.
- Minor releases may still include breaking changes when required for correctness.
- Patch releases should stay backward-conscious and focus on regressions, packaging, or security fixes.

## [Unreleased]

### Added
- **15 net-new SDK producers** covering the highest-leverage day-one runtime evidence gaps for the 2026 AI agent ecosystem:
  - **Direct LLM provider SDKs (10):** `AnthropicActionProducer`, `OpenAIActionProducer` (chat completions + responses APIs), `GeminiActionProducer` (google-genai), `MistralActionProducer`, `CohereActionProducer` (folds `message`/`chat_history`/`preamble` into unified messages), `XAIActionProducer`, plus four OpenAI-compatible serverless inference subclasses: `GroqActionProducer`, `TogetherActionProducer`, `FireworksActionProducer`, `DeepSeekActionProducer`.
  - **Cloud LLM gateway (1):** `BedrockActionProducer` for AWS Bedrock — Python parity with the existing TypeScript `BedrockActionProducer`, closing the cross-language drift. Covers `InvokeModel` and `InvokeModelWithResponseStream` with model-family detection, inference-profile ARN handling, and basic token-usage extraction.
  - **2026 top-5 agent frameworks (4):** `LangChainCallbackHandler` (drop-in `BaseCallbackHandler` for any Runnable/Chain/LLM; covers LangGraph via the shared callback bus), `CrewAIActionProducer` (step/task/crew callback factories), `AutoGenActionProducer` (`process_message_before_send` + `process_last_received_message` hooks with `attach()` helper that auto-wires against `ConversableAgent`-shaped objects), `SemanticKernelActionProducer` (filters for `function_invocation`, `prompt_rendering`, `auto_function_invocation`).
- **`ancilis.producers.auto`** convenience layer:
  - `auto_register(config, engine)` instantiates one producer per upstream SDK detected in the environment via `importlib.util.find_spec` (no actual imports, no side effects). Supports `include=` / `exclude=` filters.
  - `detect_installed_sdks()` returns `{provider: present?}` for diagnostics.
  - `installed_provider_slugs()` returns just the present provider slugs.
- All new producers are duck-typed against their upstream SDKs — installation is not required for the producer module to load. Producer type is `FRAMEWORK` for all new producers, matching the existing TypeScript `BedrockActionProducer` precedent.
- Tool-name convention extends consistently: `llm:{provider}:{model}` for direct LLM SDKs, `aws-bedrock:{operation}` for Bedrock, `{framework}:{kind}:{name}` for framework producers. Allowlists in `ancilis.yaml` reference these names directly.
- 137 new tests across 7 test modules. Full Python suite at 1584 tests passing.
- **TypeScript parity** for every new Python producer (closes the cross-language drift):
  - `LLMActionProducer` base class plus all 10 LLM provider subclasses (`AnthropicActionProducer`, `OpenAIActionProducer`, `GeminiActionProducer`, `MistralActionProducer`, `CohereActionProducer`, `XAIActionProducer`, `GroqActionProducer`, `TogetherActionProducer`, `FireworksActionProducer`, `DeepSeekActionProducer`).
  - `LangChainActionProducer` + `LangChainCallbackHandler` matching the LangChain.js `BaseCallbackHandler` shape (drop-in via `callbacks=[handler]`).
  - `CrewAIActionProducer` (step/task/crew callback factories), `AutoGenActionProducer` (send/receive hooks + `attach()` helper), `SemanticKernelActionProducer` (three filter factories).
  - `ancilis.producers.auto` for TypeScript: `autoRegister`, `detectInstalledSdks`, `installedProviderSlugs`. Uses `createRequire(import.meta.url).resolve()` instead of `importlib.find_spec`. Detector table covers `@anthropic-ai/sdk`, `openai`, `@google/genai` / `@google/generative-ai`, `@mistralai/mistralai`, `cohere-ai`, `groq-sdk`, `together-ai`, `fireworks-ai`, `@aws-sdk/client-bedrock-runtime` / `aws-sdk`, `@langchain/core` / `langchain`, `crewai`, `autogen`, `@semantic-kernel/typescript` / `@microsoft/semantic-kernel`.
- 68 new TypeScript tests (34 LLM/LangChain + 34 frameworks/auto). Full TS suite at 1012/1013 passing (1 pre-existing eslint env-only failure unrelated to these changes).

### Documentation
- README: new "LLM SDKs and agent frameworks" section with auto-register example, explicit-wiring example, LangChain handler example, and supported-producers reference table. TypeScript section updated to mention LLM/framework producer parity.
- `docs/producers.md`: reference table extended to 16 producers; new sections for LLM SDK producers, agent framework producers (LangChain / CrewAI / AutoGen / Semantic Kernel), and auto-detection.
- `docs/sdk/typescript.mdx`: new sections for TS LLM producers, agent framework producers, and auto-detection (`autoRegister`, `detectInstalledSdks`, `installedProviderSlugs`).

## [0.1.0] - 2026-04-02

### Added
- Four runnable examples: certification-driven, data-classification, mcp-middleware, cli-agent.
- Full documentation: quickstart, configuration reference, producers guide, evidence/reporting, limitations.
- README rewrite with accurate quick start, architecture overview, and honest limitations section.
- Artifact-based Python install verification for wheel and sdist builds.
- Release-check automation for Python artifacts and preview TypeScript package smoke checks.
- `source_type` propagation across Python action, evaluation, evidence, and schema layers.
- Additional CLI, evidence, packaging, and regression coverage.
- **Overlay activation (Build Unit 5):** Expanded GDPR and HIPAA overlay control catalogs; wired `overlay_requirements` so `data_handling` codes activate the correct overlay controls at runtime.
- **Advisory reporting:** `ancilis report --format aiuc1-readiness` generates a human-readable AIUC-1 readiness report; advisory module surfaces control gaps as recommendations without blocking enforcement.
- **PDF report fallback:** `ancilis report --format pdf` gracefully falls back to terminal output when WeasyPrint is unavailable, with an explicit notice rather than a crash.
- **`output_summary` evidence field:** Captures a structured summary of tool output in each evidence record for richer audit trails.
- **Cert declaration and output disclosure (Retrofit):** `ancilis.yaml` accepts an explicit `cert_declaration` field; tool output disclosure tracking added to evidence pipeline so PR-04 (Exposure) evaluations have accurate output-disclosure context.

### Changed
- CLI `approve-tool` and `doctor` output uses plain language instead of control IDs.
- CLI `status` empty-store message is more actionable.
- CLI `doctor` shows next steps on first run.
- Fixed author email in pyproject.toml and package.json (kevin@ancilis.ai).
- Removed public roadmap file.
- README data type → overlay table corrected to match actual implementation.
- Hardened Python packaging metadata and shared-asset inclusion.
- Kept the TypeScript package explicitly preview in package metadata and release workflow posture.
- Strengthened release workflows and dependency audit coverage.

### Security
- Clarified disclosure process and technical trust boundaries.
- Surfaced evidence-chain integrity failures more explicitly in release verification and reporting.
- Bumped `cryptography` to 46.0.6, `pygments` to 2.20.0, `path-to-regexp` to 8.4.0 (dependency security maintenance).
