import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import {
  LangChainActionProducer,
  LangChainCallbackHandler,
  type LangChainEvent,
  _nameFromSerialized,
} from "../src/ancilis/producers/langchain.js";
import { ProducerType, type ActionProducer } from "../src/ancilis/producers/index.js";

function makeConfig(): ResolvedConfig {
  return loadConfig({
    raw: { agent: { name: "lc-agent", owner: "test-owner" }, security: { mode: "audit" } },
  });
}

function makeProducer(): { producer: LangChainActionProducer; store: EvidenceStore } {
  const config = makeConfig();
  const store = new EvidenceStore(config, { inMemory: true });
  return {
    producer: new LangChainActionProducer(config, new Engine(config), undefined, store),
    store,
  };
}

function makeHandler(): { handler: LangChainCallbackHandler; store: EvidenceStore } {
  const { producer, store } = makeProducer();
  return { handler: new LangChainCallbackHandler(producer, "lc-agent"), store };
}

describe("nameFromSerialized", () => {
  it("uses name field when present", () => {
    expect(_nameFromSerialized({ name: "MyChain" }, "fb")).toBe("MyChain");
  });

  it("uses last id segment when no name", () => {
    expect(_nameFromSerialized({ id: ["langchain", "chains", "LLMChain"] }, "fb")).toBe(
      "LLMChain",
    );
  });

  it("falls back when serialized empty", () => {
    expect(_nameFromSerialized(undefined, "fallback")).toBe("fallback");
    expect(_nameFromSerialized({}, "fallback")).toBe("fallback");
  });
});

describe("LangChainActionProducer protocol", () => {
  it("satisfies the protocol", () => {
    const { producer } = makeProducer();
    const ap: ActionProducer = producer;
    expect(ap.producerType).toBe(ProducerType.FRAMEWORK);
    expect(ap.producerVersion).toBe("0.1.0");
  });

  it("translate(tool event) emits action_type=tool_call", () => {
    const { producer } = makeProducer();
    const event: LangChainEvent = {
      kind: "tool",
      name: "search",
      agentName: "lc-agent",
      inputs: { input: "weather" },
      serialized: { name: "search" },
    };
    const action = producer.translate(event);
    expect(action.actionType).toBe("tool_call");
    expect(action.tool.name).toBe("langchain:tool:search");
  });

  it("translate(llm event) emits api_request", () => {
    const { producer } = makeProducer();
    const action = producer.translate({
      kind: "llm",
      name: "ChatAnthropic",
      agentName: "lc-agent",
    });
    expect(action.actionType).toBe("api_request");
  });

  it("re-exports from package root", () => {
    const root = ancilis as Record<string, unknown>;
    expect(root.LangChainActionProducer).toBe(LangChainActionProducer);
    expect(root.LangChainCallbackHandler).toBe(LangChainCallbackHandler);
  });
});

describe("LangChainCallbackHandler", () => {
  it("has the LangChain.js BaseCallbackHandler shape", () => {
    const { handler } = makeHandler();
    expect(handler.name).toBe("ancilis-langchain-callback-handler");
    expect(handler.raiseError).toBe(false);
    expect(handler.ignoreLLM).toBe(false);
    expect(handler.ignoreChain).toBe(false);
    expect(handler.ignoreAgent).toBe(false);
    expect(handler.ignoreRetriever).toBe(false);
  });

  it("handleLLMStart records evidence", async () => {
    const { handler, store } = makeHandler();
    await handler.handleLLMStart({ name: "OpenAI" }, ["What is 2+2?"]);
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("handleChatModelStart records evidence", async () => {
    const { handler, store } = makeHandler();
    await handler.handleChatModelStart(
      { id: ["langchain", "chat_models", "ChatAnthropic"] },
      [["HumanMessage(content='hi')"]],
    );
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("handleToolStart records evidence", async () => {
    const { handler, store } = makeHandler();
    await handler.handleToolStart({ name: "search" }, "weather in NYC");
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("handleChainStart records evidence", async () => {
    const { handler, store } = makeHandler();
    await handler.handleChainStart({ name: "RunnableSequence" }, { question: "ping" });
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("multiple callbacks accumulate evidence", async () => {
    const { handler, store } = makeHandler();
    await handler.handleChainStart({ name: "Top" }, { q: "x" });
    await handler.handleLLMStart({ name: "OpenAI" }, ["x"]);
    await handler.handleToolStart({ name: "calc" }, "1+1");
    expect((await store.getSummary()).totalEvaluations).toBe(3);
  });

  it("noop handlers don't record evidence", async () => {
    const { handler, store } = makeHandler();
    await handler.handleLLMEnd();
    await handler.handleLLMNewToken("token");
    await handler.handleLLMError(new Error("x"));
    await handler.handleChainEnd();
    await handler.handleChainError(new Error("x"));
    await handler.handleToolEnd("output");
    await handler.handleToolError(new Error("x"));
    await handler.handleText("text");
    await handler.handleAgentAction();
    await handler.handleAgentEnd();
    await handler.handleRetrieverStart();
    await handler.handleRetrieverEnd();
    await handler.handleRetrieverError();
    expect((await store.getSummary()).totalEvaluations).toBe(0);
  });
});
