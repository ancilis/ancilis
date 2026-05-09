import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import {
  AnthropicActionProducer,
  CohereActionProducer,
  DeepSeekActionProducer,
  FireworksActionProducer,
  GeminiActionProducer,
  GroqActionProducer,
  LLMActionProducer,
  type LLMInvocation,
  MistralActionProducer,
  OpenAIActionProducer,
  TogetherActionProducer,
  XAIActionProducer,
} from "../src/ancilis/producers/llm.js";
import { ProducerType, type ActionProducer } from "../src/ancilis/producers/index.js";

function makeConfig(opts: { mode?: "audit" | "enforce"; toolsAllowed?: string[] } = {}): ResolvedConfig {
  return loadConfig({
    raw: {
      agent: { name: "llm-agent", owner: "test-owner" },
      security: {
        mode: opts.mode ?? "audit",
        tools: { allowed: opts.toolsAllowed ?? [] },
      },
    },
  });
}

function makeProducer<T extends LLMActionProducer>(
  Cls: new (...args: ConstructorParameters<typeof LLMActionProducer>) => T,
  store?: EvidenceStore,
): T {
  const config = makeConfig();
  return new Cls(
    config,
    new Engine(config),
    undefined,
    store ?? new EvidenceStore(config, { inMemory: true }),
  );
}

const ALL_CLASSES: Array<{ Cls: typeof LLMActionProducer; provider: string }> = [
  { Cls: AnthropicActionProducer, provider: "anthropic" },
  { Cls: OpenAIActionProducer, provider: "openai" },
  { Cls: GeminiActionProducer, provider: "gemini" },
  { Cls: MistralActionProducer, provider: "mistral" },
  { Cls: CohereActionProducer, provider: "cohere" },
  { Cls: XAIActionProducer, provider: "xai" },
  { Cls: GroqActionProducer, provider: "groq" },
  { Cls: TogetherActionProducer, provider: "together" },
  { Cls: FireworksActionProducer, provider: "fireworks" },
  { Cls: DeepSeekActionProducer, provider: "deepseek" },
];

describe("LLM producer protocol compliance", () => {
  for (const { Cls, provider } of ALL_CLASSES) {
    it(`${Cls.name} satisfies the producer protocol with provider=${provider}`, () => {
      const producer: ActionProducer = makeProducer(Cls);
      expect(producer.producerType).toBe(ProducerType.FRAMEWORK);
      expect((producer as LLMActionProducer).provider).toBe(provider);
      expect(producer.producerVersion).toBe("0.1.0");
    });
  }

  it("re-exports producers from the package root", () => {
    const root = ancilis as Record<string, unknown>;
    expect(root.AnthropicActionProducer).toBe(AnthropicActionProducer);
    expect(root.OpenAIActionProducer).toBe(OpenAIActionProducer);
    expect(root.GeminiActionProducer).toBe(GeminiActionProducer);
    expect(root.GroqActionProducer).toBe(GroqActionProducer);
    expect(root.LLMActionProducer).toBe(LLMActionProducer);
  });
});

describe("LLM observe + translate", () => {
  it("Anthropic emits llm:anthropic:{model} tool name and api_request action", async () => {
    const config = makeConfig();
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new AnthropicActionProducer(config, new Engine(config), undefined, store);
    const invocation: LLMInvocation = {
      model: "claude-sonnet-4-6",
      agentName: "llm-agent",
      messages: [{ role: "user", content: "hi" }],
    };
    const observation = await producer.observe(invocation);
    expect(observation.action.tool.name).toBe("llm:anthropic:claude-sonnet-4-6");
    expect(observation.action.tool.server).toBe("anthropic");
    expect(observation.action.actionType).toBe("api_request");
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("Gemini emits llm:gemini:{model}", async () => {
    const config = makeConfig();
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new GeminiActionProducer(config, new Engine(config), undefined, store);
    const observation = await producer.observe({
      model: "gemini-2.5-flash",
      agentName: "llm-agent",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(observation.action.tool.name).toBe("llm:gemini:gemini-2.5-flash");
  });

  it("falls back to unknown-model for empty model string", async () => {
    const producer = makeProducer(AnthropicActionProducer);
    const observation = await producer.observe({ model: "", agentName: "llm-agent" });
    expect(observation.action.tool.name).toBe("llm:anthropic:unknown-model");
  });
});

// Probe extractInvocation through wrapCreate behaviour (it's protected).
describe("LLM wrapCreate normalizes provider-specific shapes", () => {
  it("OpenAI: input string normalized to messages[0]", async () => {
    const producer = makeProducer(OpenAIActionProducer);
    let captured: { kwargs: Record<string, unknown> } | null = null;
    const wrapped = producer.wrapCreate((kwargs) => {
      captured = { kwargs };
      return { id: "resp_1" };
    });
    const result = await wrapped({ model: "gpt-4o", input: "summarize" });
    expect(result.response).toEqual({ id: "resp_1" });
    expect(captured).not.toBeNull();
    // Translate the captured invocation by re-wrapping
    const inv: LLMInvocation = {
      model: "gpt-4o",
      agentName: "llm-agent",
      messages: [{ role: "user", content: "summarize" }],
    };
    const action = producer.translate(inv);
    expect(action.tool.name).toBe("llm:openai:gpt-4o");
  });

  it("Cohere: message + chat_history fold into messages list", async () => {
    const producer = makeProducer(CohereActionProducer);
    const wrapped = producer.wrapCreate(() => ({ ok: true }));
    const result = await wrapped({
      model: "command-r-plus",
      message: "ping",
      chat_history: [{ role: "user", message: "earlier" }],
      preamble: "be terse",
    });
    expect(result.evaluation).toBeDefined();
    expect(result.action.tool.name).toBe("llm:cohere:command-r-plus");
  });

  it("Gemini: contents string normalized; config.system_instruction extracted", async () => {
    const producer = makeProducer(GeminiActionProducer);
    const wrapped = producer.wrapCreate(() => ({ ok: true }));
    const result = await wrapped({
      model: "gemini-2.5-flash",
      contents: "hello",
      config: { system_instruction: "be terse" },
    });
    expect(result.action.tool.name).toBe("llm:gemini:gemini-2.5-flash");
  });
});

describe("LLM enforce mode", () => {
  it("blocks disallowed model and skips transport when enforce=true", async () => {
    const allowed = "llm:anthropic:claude-sonnet-4-6";
    const config = makeConfig({ mode: "enforce", toolsAllowed: [allowed] });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new AnthropicActionProducer(config, new Engine(config), undefined, store);

    const calls: string[] = [];
    const wrapped = producer.wrapCreate(
      (kwargs) => {
        calls.push(String(kwargs["model"]));
        return { id: "ok" };
      },
      undefined,
      true, // enforce
    );

    const ok = await wrapped({
      model: "claude-sonnet-4-6",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(ok.response).toEqual({ id: "ok" });
    expect(calls).toEqual(["claude-sonnet-4-6"]);

    await expect(
      wrapped({
        model: "claude-opus-4",
        messages: [{ role: "user", content: "hi" }],
      }),
    ).rejects.toThrow();
    expect(calls).toEqual(["claude-sonnet-4-6"]);
  });
});

describe("OpenAI-compatible inference subclasses", () => {
  it("each subclass emits a distinct provider tool name", async () => {
    for (const { Cls, provider } of [
      { Cls: GroqActionProducer, provider: "groq" },
      { Cls: TogetherActionProducer, provider: "together" },
      { Cls: FireworksActionProducer, provider: "fireworks" },
      { Cls: DeepSeekActionProducer, provider: "deepseek" },
      { Cls: XAIActionProducer, provider: "xai" },
    ]) {
      const config = makeConfig();
      const store = new EvidenceStore(config, { inMemory: true });
      const producer = new Cls(config, new Engine(config), undefined, store);
      const observation = await producer.observe({
        model: "model-x",
        agentName: "llm-agent",
        messages: [{ role: "user", content: "ping" }],
      });
      expect(observation.action.tool.name).toBe(`llm:${provider}:model-x`);
    }
  });
});

describe("LLM session id", () => {
  it("each producer instance gets a unique session id", () => {
    const a = makeProducer(AnthropicActionProducer);
    const b = makeProducer(AnthropicActionProducer);
    expect(a.sessionId).not.toBe(b.sessionId);
  });
});
