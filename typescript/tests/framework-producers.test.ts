import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import {
  CrewAIActionProducer,
  type CrewAIEvent,
  _stepName,
  _taskName,
  _crewName,
  _serializable,
} from "../src/ancilis/producers/crewai.js";
import {
  AutoGenActionProducer,
  type AutoGenEvent,
  _agentName,
  _serializableMessage,
} from "../src/ancilis/producers/autogen.js";
import {
  SemanticKernelActionProducer,
  type SemanticKernelEvent,
  _functionMetadata,
  _argumentsValue,
} from "../src/ancilis/producers/semantic_kernel.js";
import {
  autoRegister,
  detectInstalledSdks,
  installedProviderSlugs,
  _DETECTORS,
  _modulePresent,
} from "../src/ancilis/producers/auto.js";
import { ProducerType, type ActionProducer } from "../src/ancilis/producers/index.js";

function makeConfig(): ResolvedConfig {
  return loadConfig({
    raw: { agent: { name: "fw-agent", owner: "test-owner" }, security: { mode: "audit" } },
  });
}

function makeStore(config: ResolvedConfig): EvidenceStore {
  return new EvidenceStore(config, { inMemory: true });
}

// ---- CrewAI ----

describe("CrewAI helper functions", () => {
  it("_stepName prefers tool, falls back to agent_role, then dict, then fallback", () => {
    expect(_stepName({ tool: "search" }, "fb")).toBe("search");
    expect(_stepName({ agent_role: "researcher" }, "fb")).toBe("researcher");
    expect(_stepName({ name: "" }, "fb")).toBe("fb");
    expect(_stepName(null, "fallback")).toBe("fallback");
  });

  it("_taskName uses description / task_id / name", () => {
    expect(_taskName({ description: "research" }, "fb")).toBe("research");
    expect(_taskName({}, "fb")).toBe("fb");
  });

  it("_crewName uses name / id / crew_id", () => {
    expect(_crewName({ name: "market" }, "fb")).toBe("market");
  });

  it("_serializable handles primitives, arrays, dicts, model_dump", () => {
    expect(_serializable("a")).toBe("a");
    expect(_serializable(42)).toBe(42);
    expect(_serializable([1, 2])).toEqual([1, 2]);
    expect(_serializable({ k: 1 })).toEqual({ k: 1 });
    const obj = { name: "x", model_dump: () => ({ name: "x" }) };
    expect(_serializable(obj)).toEqual({ name: "x" });
  });
});

describe("CrewAIActionProducer", () => {
  function make(): { producer: CrewAIActionProducer; store: EvidenceStore } {
    const config = makeConfig();
    const store = makeStore(config);
    return {
      producer: new CrewAIActionProducer(config, new Engine(config), undefined, store),
      store,
    };
  }

  it("satisfies the producer protocol", () => {
    const { producer } = make();
    const ap: ActionProducer = producer;
    expect(ap.producerType).toBe(ProducerType.FRAMEWORK);
    expect(ap.producerVersion).toBe("0.1.0");
  });

  it("translate(step) emits action_type=tool_call", () => {
    const { producer } = make();
    const event: CrewAIEvent = { kind: "step", name: "search", agentName: "fw-agent" };
    const action = producer.translate(event);
    expect(action.actionType).toBe("tool_call");
    expect(action.tool.name).toBe("crewai:step:search");
  });

  it("translate(task) emits api_request", () => {
    const { producer } = make();
    const action = producer.translate({ kind: "task", name: "research", agentName: "fw-agent" });
    expect(action.actionType).toBe("api_request");
    expect(action.tool.name).toBe("crewai:task:research");
  });

  it("stepCallback records evidence", async () => {
    const { producer, store } = make();
    const cb = producer.stepCallback("researcher");
    await cb({ tool: "search" });
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("taskCallback + crewCallback chain produces 2 evaluations", async () => {
    const { producer, store } = make();
    await producer.taskCallback()({ description: "research" });
    await producer.crewCallback()({ name: "market" });
    expect((await store.getSummary()).totalEvaluations).toBe(2);
  });
});

// ---- AutoGen ----

describe("AutoGen helper functions", () => {
  it("_agentName prefers .name attribute", () => {
    expect(_agentName({ name: "alice" }, "fb")).toBe("alice");
    expect(_agentName(null, "fb")).toBe("fb");
  });

  it("_serializableMessage recurses into dicts and arrays", () => {
    expect(_serializableMessage("x")).toBe("x");
    expect(_serializableMessage({ a: 1, b: { c: 2 } })).toEqual({ a: 1, b: { c: 2 } });
    expect(_serializableMessage([{ k: 1 }, { k: 2 }])).toEqual([{ k: 1 }, { k: 2 }]);
  });
});

describe("AutoGenActionProducer", () => {
  function make(): { producer: AutoGenActionProducer; store: EvidenceStore } {
    const config = makeConfig();
    const store = makeStore(config);
    return {
      producer: new AutoGenActionProducer(config, new Engine(config), undefined, store),
      store,
    };
  }

  it("translate(send) builds autogen:send:from->to tool name", () => {
    const { producer } = make();
    const event: AutoGenEvent = {
      kind: "send",
      sender: "alice",
      recipient: "bob",
      message: { role: "user", content: "hi" },
    };
    const action = producer.translate(event);
    expect(action.tool.name).toBe("autogen:send:alice->bob");
    expect(action.actionType).toBe("api_request");
    expect(action.agentId).toBe("alice");
  });

  it("sendHook records and returns the message unchanged", async () => {
    const { producer, store } = make();
    const hook = producer.sendHook("alice");
    const result = await hook({ name: "alice" }, "hello", { name: "bob" }, false);
    expect(result).toBe("hello");
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("receiveHook extracts last-message sender and returns messages unchanged", async () => {
    const { producer, store } = make();
    const hook = producer.receiveHook("bob");
    const messages = [
      { role: "user", name: "alice", content: "hi" },
      { role: "assistant", name: "bob", content: "hello back" },
    ];
    const result = await hook(messages);
    expect(result).toBe(messages);
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("receiveHook handles empty/null messages", async () => {
    const { producer } = make();
    const hook = producer.receiveHook("bob");
    await hook([]);
    await hook(null);
  });

  it("attach uses register_hook when present", async () => {
    const { producer, store } = make();
    const calls: Array<[string, unknown]> = [];
    const agent = {
      name: "alice",
      register_hook: (name: string, fn: unknown) => { calls.push([name, fn]); },
    };
    const registered = producer.attach(agent);
    expect(Object.keys(registered)).toEqual(["process_message_before_send", "process_last_received_message"]);
    expect(calls.length).toBe(2);
    expect(calls[0][0]).toBe("process_message_before_send");
    // Trigger
    await (registered.process_message_before_send as (...args: unknown[]) => Promise<unknown>)(
      { name: "alice" },
      "hi",
      { name: "bob" },
      false,
    );
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("attach falls back to hook_lists dict", async () => {
    const { producer, store } = make();
    const hookLists: Record<string, unknown[]> = {};
    const agent = { name: "alice", hook_lists: hookLists };
    producer.attach(agent);
    expect(Array.isArray(hookLists["process_message_before_send"])).toBe(true);
    const fn = hookLists["process_message_before_send"][0] as (...args: unknown[]) => Promise<unknown>;
    await fn({ name: "alice" }, "hi", { name: "bob" }, false);
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("attach falls back to direct attribute assignment", async () => {
    const { producer, store } = make();
    const agent: Record<string, unknown> = { name: "alice" };
    producer.attach(agent);
    expect(typeof agent["process_message_before_send"]).toBe("function");
    await (agent["process_message_before_send"] as (...args: unknown[]) => Promise<unknown>)(
      { name: "alice" },
      "hi",
      { name: "bob" },
      false,
    );
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });
});

// ---- Semantic Kernel ----

describe("Semantic Kernel helper functions", () => {
  it("_functionMetadata extracts via .function or direct attrs", () => {
    expect(
      _functionMetadata({ function: { name: "search", plugin_name: "WebPlugin" } }),
    ).toEqual({ functionName: "search", pluginName: "WebPlugin" });
    expect(_functionMetadata({ function_name: "x", plugin_name: "p" })).toEqual({
      functionName: "x",
      pluginName: "p",
    });
    expect(_functionMetadata({})).toEqual({
      functionName: "unknown-function",
      pluginName: "default",
    });
  });

  it("_argumentsValue passes through dict, falls back to model_dump", () => {
    expect(_argumentsValue({ arguments: { q: "weather" } })).toEqual({ q: "weather" });
    expect(_argumentsValue({})).toBeNull();
    const args = { model_dump: () => ({ k: 1 }) };
    expect(_argumentsValue({ arguments: args })).toEqual({ k: 1 });
  });
});

describe("SemanticKernelActionProducer", () => {
  function make(): { producer: SemanticKernelActionProducer; store: EvidenceStore } {
    const config = makeConfig();
    const store = makeStore(config);
    return {
      producer: new SemanticKernelActionProducer(config, new Engine(config), undefined, store),
      store,
    };
  }

  it("satisfies the producer protocol", () => {
    const { producer } = make();
    const ap: ActionProducer = producer;
    expect(ap.producerType).toBe(ProducerType.FRAMEWORK);
  });

  it("translate(function_invocation) emits tool_call with plugin.function tool name", () => {
    const { producer } = make();
    const event: SemanticKernelEvent = {
      kind: "function_invocation",
      functionName: "search",
      pluginName: "WebPlugin",
      agentName: "fw-agent",
    };
    const action = producer.translate(event);
    expect(action.actionType).toBe("tool_call");
    expect(action.tool.name).toBe("semantic-kernel:function_invocation:WebPlugin.search");
  });

  it("translate(prompt_rendering) emits api_request", () => {
    const { producer } = make();
    const action = producer.translate({
      kind: "prompt_rendering",
      functionName: "ChatPrompt",
      pluginName: "default",
      agentName: "fw-agent",
    });
    expect(action.actionType).toBe("api_request");
  });

  it("functionInvocationFilter observes and calls next", async () => {
    const { producer, store } = make();
    const filter = producer.functionInvocationFilter();
    const ctx = { function: { name: "search", plugin_name: "WebPlugin" }, arguments: { q: "x" } };
    let nextCalled = 0;
    let receivedCtx: unknown = null;
    const result = await filter(ctx, async (c) => {
      nextCalled += 1;
      receivedCtx = c;
      return "result";
    });
    expect(result).toBe("result");
    expect(nextCalled).toBe(1);
    expect(receivedCtx).toBe(ctx);
    expect((await store.getSummary()).totalEvaluations).toBe(1);
  });

  it("filter chain records one event per call", async () => {
    const { producer, store } = make();
    const filter = producer.functionInvocationFilter();
    const ctx = { function_name: "x", plugin_name: "p" };
    const next = async (_: unknown) => null;
    await filter(ctx, next);
    await filter(ctx, next);
    await filter(ctx, next);
    expect((await store.getSummary()).totalEvaluations).toBe(3);
  });
});

// ---- Auto-detection ----

describe("auto-detection: _modulePresent", () => {
  it("returns true for installed Node built-in", () => {
    expect(_modulePresent(["node:os"])).toBe(true);
  });

  it("returns true for any-of alias resolution", () => {
    expect(_modulePresent(["ancilis-not-installed-xyz", "node:fs"])).toBe(true);
  });

  it("returns false when nothing resolves", () => {
    expect(_modulePresent(["ancilis-definitely-not-installed-xyz"])).toBe(false);
  });

  it("returns false for empty list", () => {
    expect(_modulePresent([])).toBe(false);
  });
});

describe("detectInstalledSdks + installedProviderSlugs", () => {
  it("returns boolean per detector slug", () => {
    const result = detectInstalledSdks();
    const expected = new Set(_DETECTORS.map((d) => d.provider));
    expect(new Set(Object.keys(result))).toEqual(expected);
    for (const v of Object.values(result)) {
      expect(typeof v).toBe("boolean");
    }
  });

  it("installedProviderSlugs is a subset of detectInstalledSdks=true entries", () => {
    const detected = detectInstalledSdks();
    for (const slug of installedProviderSlugs()) {
      expect(detected[slug]).toBe(true);
    }
  });
});

describe("autoRegister", () => {
  it("returns empty when no module present (modules: [] entries skipped)", () => {
    // xai/deepseek have no dedicated SDK so they should never be returned
    // by autoRegister even though they're in the detector table.
    const config = makeConfig();
    const producers = autoRegister(config, new Engine(config));
    expect("xai" in producers).toBe(false);
    expect("deepseek" in producers).toBe(false);
  });

  it("dispatch table covers each detector's class with a real constructor", () => {
    for (const d of _DETECTORS) {
      // Each ctor should be a function (a class constructor).
      expect(typeof d.cls).toBe("function");
    }
  });

  it("re-exports auto helpers from package root", () => {
    const root = ancilis as Record<string, unknown>;
    expect(root.autoRegister).toBe(autoRegister);
    expect(root.detectInstalledSdks).toBe(detectInstalledSdks);
    expect(root.installedProviderSlugs).toBe(installedProviderSlugs);
  });
});
