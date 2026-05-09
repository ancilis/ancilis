/**
 * Auto-detection of installed LLM/framework SDKs (TypeScript parity with
 * `ancilis.producers.auto`).
 *
 * Detects which upstream npm packages are installed in the current
 * environment and instantiates one producer per detected SDK. Uses
 * `createRequire(import.meta.url).resolve(...)` — never actually imports
 * the upstream package, so detection has no side effects.
 *
 * Typical wiring:
 *
 *   import { loadConfig } from "ancilis";
 *   import { Engine } from "ancilis";
 *   import { autoRegister } from "ancilis";
 *
 *   const config = loadConfig({ raw: { agent: { name: "my-agent" } } });
 *   const engine = new Engine(config);
 *   const producers = autoRegister(config, engine);
 *   // producers == { anthropic: AnthropicActionProducer, openai: ..., ... }
 */

import { createRequire } from "node:module";
import type { ResolvedConfig } from "../config/index.js";
import { Engine } from "../engine/engine.js";
import { ToolRegistry } from "../engine/registry.js";
import { EvidenceStore } from "../evidence/store.js";
import {
  AnthropicActionProducer,
  CohereActionProducer,
  DeepSeekActionProducer,
  FireworksActionProducer,
  GeminiActionProducer,
  GroqActionProducer,
  type LLMActionProducer,
  MistralActionProducer,
  OpenAIActionProducer,
  TogetherActionProducer,
  XAIActionProducer,
} from "./llm.js";
import { BedrockActionProducer } from "./bedrock.js";
import { LangChainActionProducer } from "./langchain.js";
import { CrewAIActionProducer } from "./crewai.js";
import { AutoGenActionProducer } from "./autogen.js";
import { SemanticKernelActionProducer } from "./semantic_kernel.js";

const require_ = createRequire(import.meta.url);

type ProducerCtor = new (
  config: ResolvedConfig,
  engine: Engine,
  registry?: ToolRegistry,
  evidenceStore?: EvidenceStore,
) =>
  | LLMActionProducer
  | BedrockActionProducer
  | LangChainActionProducer
  | CrewAIActionProducer
  | AutoGenActionProducer
  | SemanticKernelActionProducer;

interface Detector {
  /** Slug used as the dict key in the result. */
  provider: string;
  /** Producer class to instantiate when this SDK is detected. */
  cls: ProducerCtor;
  /** Any-of: SDK is "available" if any candidate npm package is resolvable. */
  modules: readonly string[];
}

// SDK → producer mapping. Aliases cover renames (e.g. @google/genai vs
// @google/generative-ai). Empty modules tuple = no dedicated SDK; user
// must wire explicitly. Bedrock keys off the AWS SDK v3 runtime client.
const DETECTORS: readonly Detector[] = [
  { provider: "anthropic", cls: AnthropicActionProducer, modules: ["@anthropic-ai/sdk"] },
  { provider: "openai", cls: OpenAIActionProducer, modules: ["openai"] },
  {
    provider: "gemini",
    cls: GeminiActionProducer,
    modules: ["@google/genai", "@google/generative-ai"],
  },
  { provider: "mistral", cls: MistralActionProducer, modules: ["@mistralai/mistralai"] },
  { provider: "cohere", cls: CohereActionProducer, modules: ["cohere-ai"] },
  { provider: "groq", cls: GroqActionProducer, modules: ["groq-sdk"] },
  { provider: "together", cls: TogetherActionProducer, modules: ["together-ai"] },
  { provider: "fireworks", cls: FireworksActionProducer, modules: ["fireworks-ai"] },
  { provider: "deepseek", cls: DeepSeekActionProducer, modules: [] },
  { provider: "xai", cls: XAIActionProducer, modules: [] },
  {
    provider: "aws-bedrock",
    cls: BedrockActionProducer,
    modules: ["@aws-sdk/client-bedrock-runtime", "aws-sdk"],
  },
  {
    provider: "langchain",
    cls: LangChainActionProducer,
    modules: ["@langchain/core", "langchain"],
  },
  { provider: "crewai", cls: CrewAIActionProducer, modules: ["crewai"] },
  { provider: "autogen", cls: AutoGenActionProducer, modules: ["autogen"] },
  {
    provider: "semantic-kernel",
    cls: SemanticKernelActionProducer,
    modules: ["@semantic-kernel/typescript", "@microsoft/semantic-kernel"],
  },
];

/** Internal: returns true iff any candidate module name resolves. */
export function _modulePresent(modules: readonly string[]): boolean {
  for (const name of modules) {
    try {
      require_.resolve(name);
      return true;
    } catch {
      // not installed; continue
    }
  }
  return false;
}

export interface AutoRegisterOptions {
  registry?: ToolRegistry;
  evidenceStore?: EvidenceStore;
  /** Only consider these provider slugs (still must be installed). */
  include?: readonly string[];
  /** Skip these provider slugs even if installed. */
  exclude?: readonly string[];
}

/** Side-effect-free detection: returns a flat `{provider: present?}` map. */
export function detectInstalledSdks(): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const d of DETECTORS) {
    out[d.provider] = d.modules.length > 0 ? _modulePresent(d.modules) : false;
  }
  return out;
}

/** Slugs whose upstream SDK is detected as installed. */
export function installedProviderSlugs(): string[] {
  const detected = detectInstalledSdks();
  return Object.keys(detected).filter((p) => detected[p] === true);
}

/**
 * Instantiate one producer per detected upstream SDK. Returns a record
 * keyed by provider slug.
 */
export function autoRegister(
  config: ResolvedConfig,
  engine: Engine,
  options: AutoRegisterOptions = {},
): Record<
  string,
  | LLMActionProducer
  | BedrockActionProducer
  | LangChainActionProducer
  | CrewAIActionProducer
  | AutoGenActionProducer
  | SemanticKernelActionProducer
> {
  const include = options.include ? new Set(options.include) : null;
  const exclude = new Set(options.exclude ?? []);
  const out: Record<string, LLMActionProducer | BedrockActionProducer | LangChainActionProducer | CrewAIActionProducer | AutoGenActionProducer | SemanticKernelActionProducer> = {};
  for (const d of DETECTORS) {
    if (d.modules.length === 0) continue;
    if (!_modulePresent(d.modules)) continue;
    if (include !== null && !include.has(d.provider)) continue;
    if (exclude.has(d.provider)) continue;
    out[d.provider] = new d.cls(config, engine, options.registry, options.evidenceStore);
  }
  return out;
}

// Test-only export for the detector table integrity check.
export { DETECTORS as _DETECTORS };
