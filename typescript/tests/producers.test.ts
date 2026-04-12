/**
 * Tests for protocol-agnostic producers.
 */

import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import type { ActionProducer } from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import { CLIActionProducer } from "../src/ancilis/producers/cli.js";
import { HTTPActionProducer } from "../src/ancilis/producers/http.js";
import { MCPActionProducer } from "../src/ancilis/producers/mcp.js";
import { ToolActionProducer } from "../src/ancilis/producers/tool.js";
import { ToolRegistry, ToolStatus } from "../src/ancilis/engine/registry.js";

function makeConfig(options: {
  mode?: "audit" | "enforce";
  toolsAllowed?: string[];
  toolsBlocked?: string[];
} = {}): ResolvedConfig {
  return loadConfig({
    raw: {
      agent: { name: "runtime-agent" },
      security: {
        mode: options.mode ?? "audit",
        tools: {
          allowed: options.toolsAllowed ?? [],
          blocked: options.toolsBlocked ?? [],
        },
      },
    },
  });
}

describe("package exports", () => {
  it("exports the producer APIs from the TypeScript package root", () => {
    const root = ancilis as Record<string, unknown>;
    expect(ancilis.CLIActionProducer).toBeDefined();
    expect(ancilis.HTTPActionProducer).toBeDefined();
    expect(ancilis.MCPActionProducer).toBeDefined();
    expect(ancilis.ToolActionProducer).toBeDefined();
    expect(ancilis.BlockedActionError).toBeDefined();
    expect(root.ProducerType).toBeDefined();
    expect(root.wrapTool).toBeDefined();
    expect(root.tool).toBeDefined();
    expect(root.evaluateAndExecute).toBeDefined();
  });

  it("exposes sessionId on all non-MCP producers for Python parity", () => {
    const config = makeConfig({ mode: "audit" });
    const store = new EvidenceStore(config, { inMemory: true });
    const cli = new CLIActionProducer(config, new Engine(config), undefined, store);
    const http = new HTTPActionProducer(config, new Engine(config), undefined, store);
    const tool = new ToolActionProducer(config, new Engine(config), undefined, store);

    // Each producer gets a unique session id
    expect(cli.sessionId).toHaveLength(36);
    expect(http.sessionId).toHaveLength(36);
    expect(tool.sessionId).toHaveLength(36);
    expect(cli.sessionId).not.toBe(http.sessionId);
    expect(cli.sessionId).not.toBe(tool.sessionId);

    // Session id is stable across calls
    expect(cli.sessionId).toBe(cli.sessionId);
  });

  it("exposes a shared producer protocol surface", () => {
    const config = makeConfig({ mode: "audit" });
    const evidenceStore = new EvidenceStore(config, { inMemory: true });
    const producers: ActionProducer[] = [
      new CLIActionProducer(config, new Engine(config), undefined, evidenceStore),
      new HTTPActionProducer(config, new Engine(config), undefined, evidenceStore),
      new ToolActionProducer(config, new Engine(config), undefined, evidenceStore),
    ];

    expect(producers.map((producer) => producer.producerType)).toEqual([
      ancilis.ProducerType.CLI,
      ancilis.ProducerType.HTTP,
      ancilis.ProducerType.FRAMEWORK,
    ]);
  });
});

describe("CLIActionProducer", () => {
  it("treats a bare allowlist entry as approval for the prefixed CLI tool", async () => {
    const config = makeConfig({ mode: "enforce", toolsAllowed: ["echo"] });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const result = await producer.execute(["echo", "hello"], "runtime-agent");

    expect(result.blocked).toBe(false);
    expect(result.action.producerType).toBe("cli");
    expect(result.action.producerVersion).toBe("0.1.0");
    expect(result.stdout?.trim()).toBe("hello");
  });

  it("treats an already-prefixed allowlist entry as approval without double-prefixing", async () => {
    const config = makeConfig({ mode: "enforce", toolsAllowed: ["cli:echo"] });
    const registry = new ToolRegistry();
    const engine = new Engine(config, { registry });
    const producer = new CLIActionProducer(
      config,
      engine,
      registry,
      new EvidenceStore(config, { inMemory: true }),
    );

    const registered = producer.registerTools(registry);
    const result = await producer.execute(["echo", "hello"], "runtime-agent");

    expect(registered).toEqual(["cli:echo"]);
    expect(registry.lookup("cli:cli:echo")).toBeUndefined();
    expect(result.blocked).toBe(false);
    expect(result.stdout?.trim()).toBe("hello");
  });

  it("auto-registers unknown CLI tools as observed and preserves firstSeen", async () => {
    const config = makeConfig({ mode: "audit" });
    const engine = new Engine(config);
    const registry = engine.registry;
    const producer = new CLIActionProducer(
      config,
      engine,
      registry,
      new EvidenceStore(config, { inMemory: true }),
    );

    await producer.execute(["echo", "first"], "runtime-agent");
    const firstEntry = registry.lookup("cli:echo");

    await producer.execute(["echo", "second"], "runtime-agent");
    const secondEntry = registry.lookup("cli:echo");

    expect(firstEntry?.status).toBe(ToolStatus.OBSERVED);
    expect(secondEntry?.status).toBe(ToolStatus.OBSERVED);
    expect(secondEntry?.firstSeen).toBe(firstEntry?.firstSeen);
  });

  it("registers allowlisted CLI tools as approved with stable hashes", () => {
    const config = makeConfig({ mode: "audit", toolsAllowed: ["echo", "cat"] });
    const registry = new ToolRegistry();
    const producer = new CLIActionProducer(
      config,
      new Engine(config, { registry }),
      registry,
      new EvidenceStore(config, { inMemory: true }),
    );

    const registered = producer.registerTools(registry);

    expect(registered).toEqual(["cli:echo", "cli:cat"]);
    expect(registry.lookup("cli:echo")?.status).toBe(ToolStatus.APPROVED);
    expect(registry.lookup("cli:echo")?.approvedBy).toBe("config");
    expect(registry.lookup("cli:echo")?.descriptionHash).toHaveLength(64);
  });

  it("includes the resolved binary path in computeToolHash for Python parity", () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );
    const baseDir = mkdtempSync(join(tmpdir(), "ancilis-cli-hash-"));
    const dirA = join(baseDir, "bin-a");
    const dirB = join(baseDir, "bin-b");
    const toolName = "ancilis-demo-tool";
    const script = "#!/bin/sh\necho demo-version\n";
    mkdirSync(dirA, { recursive: true });
    mkdirSync(dirB, { recursive: true });
    writeFileSync(join(dirA, toolName), script);
    writeFileSync(join(dirB, toolName), script);
    chmodSync(join(dirA, toolName), 0o755);
    chmodSync(join(dirB, toolName), 0o755);
    const originalPath = process.env.PATH ?? "";

    try {
      process.env.PATH = `${dirA}:${originalPath}`;
      const first = producer.computeToolHash(toolName);

      process.env.PATH = `${dirB}:${originalPath}`;
      const second = producer.computeToolHash(toolName);

      expect(first).not.toBe(second);
    } finally {
      process.env.PATH = originalPath;
    }
  });

  it("does not leak version-probe stderr while hashing CLI tools", () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );
    const writes: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: unknown, ...args: unknown[]) => {
      writes.push(String(chunk));
      return originalWrite(chunk as never, ...(args as never[]));
    }) as typeof process.stderr.write;

    try {
      producer.computeToolHash("cat");
    } finally {
      process.stderr.write = originalWrite;
    }

    expect(writes).toEqual([]);
  });

  it("captures stderr for successful commands to match Python producer behavior", async () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const result = await producer.execute(
      ["node", "-e", "process.stderr.write('warn\\\\n')"],
      "runtime-agent",
    );

    expect(result.blocked).toBe(false);
    expect(result.returnCode).toBe(0);
    expect(result.stderr).toContain("warn");
  });

  it("does not register anything when the CLI allowlist is empty", () => {
    const config = makeConfig({ mode: "audit" });
    const registry = new ToolRegistry();
    const producer = new CLIActionProducer(
      config,
      new Engine(config, { registry }),
      registry,
      new EvidenceStore(config, { inMemory: true }),
    );

    expect(producer.registerTools(registry)).toEqual([]);
  });

  it("treats a bare blocked entry as a block for the prefixed CLI tool", async () => {
    const config = makeConfig({ mode: "enforce", toolsBlocked: ["echo"] });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const result = await producer.execute(["echo", "blocked"], "runtime-agent");

    expect(result.blocked).toBe(true);
    expect(result.stdout).toBeUndefined();
    expect(result.returnCode).toBeUndefined();
  });

  it("flags sensitive stdout patterns for Python parity", async () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const result = await producer.execute(["echo", "SSN: 123-45-6789"], "runtime-agent");

    expect(result.blocked).toBe(false);
    expect(result.scanResult?.patterns.map((pattern) => pattern.patternType)).toContain("ssn");
  });

  it("does not scan blocked CLI output for Python parity", async () => {
    const config = makeConfig({ mode: "enforce" });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const result = await producer.execute(["echo", "SSN: 123-45-6789"], "runtime-agent");

    expect(result.blocked).toBe(true);
    expect(result.scanResult).toBeUndefined();
  });

  it("persists CLI evidence records and preserves chain integrity for Python parity", async () => {
    const config = makeConfig({ mode: "audit" });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );

    await producer.execute(["echo", "first"], "runtime-agent");
    await producer.execute(["echo", "second"], "runtime-agent");

    expect(await store.count()).toBe(2);
    expect((await store.getRecords())[0]?.toolName).toBe("cli:echo");
    expect(await store.verifyChain()).toEqual({ valid: true, errors: [] });
  });

  it("stores blocked CLI evaluations in evidence for Python parity", async () => {
    const config = makeConfig({ mode: "enforce", toolsBlocked: ["echo"] });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new CLIActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );

    const result = await producer.execute(["echo", "blocked"], "runtime-agent");

    expect(result.blocked).toBe(true);
    expect(await store.count()).toBe(1);
    expect((await store.getRecords())[0]?.decision).toBe("BLOCK");
  });
});

describe("ToolActionProducer", () => {
  it("uses function source in computeToolHash so same-named tools with different bodies drift", () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );
    const first = Function("return function demo() { return 'one'; }")() as () => string;
    const second = Function("return function demo() { return 'two'; }")() as () => string;

    expect(first.name).toBe("demo");
    expect(second.name).toBe("demo");
    expect(producer.computeToolHash(first)).not.toBe(producer.computeToolHash(second));
  });

  it("returns the current registry contents from registerTools for Python parity", async () => {
    const config = makeConfig({ mode: "audit" });
    const registry = new ToolRegistry();
    const producer = new ToolActionProducer(
      config,
      new Engine(config, { registry }),
      registry,
      new EvidenceStore(config, { inMemory: true }),
    );

    const refund = (paymentId: string): string => `refunded:${paymentId}`;
    await producer.execute(
      refund,
      "runtime-agent",
      ["pay_123"],
      undefined,
      "tool:payments.refund",
    );

    expect(producer.registerTools(registry)).toEqual(["tool:payments.refund"]);
  });

  it("propagates sessionId into action context for Python parity", () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const action = producer.translate({
      fn: (x: unknown) => x,
      agentName: "runtime-agent",
      toolName: "tool:demo",
    });

    expect(action.context?.sessionId).toBe(producer.sessionId);
  });

  it("treats a bare allowlist entry as approval for an explicitly named tool", async () => {
    const config = makeConfig({ mode: "enforce", toolsAllowed: ["payments.refund"] });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const refund = (paymentId: string): string => `refunded:${paymentId}`;
    const result = await producer.execute(
      refund,
      "runtime-agent",
      ["pay_123"],
      undefined,
      "tool:payments.refund",
    );

    expect(result.blocked).toBe(false);
    expect(result.action.producerType).toBe("framework");
    expect(result.action.producerVersion).toBe("0.1.0");
    expect(result.returnValue).toBe("refunded:pay_123");
  });

  it("forwards kwargs payloads into execution for Python parity", async () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const inspectPayload = (payload?: { flag?: boolean }): boolean => payload?.flag === true;
    const result = await producer.execute(
      inspectPayload,
      "runtime-agent",
      [],
      { flag: true },
      "tool:demo.kwargs",
    );

    expect(result.blocked).toBe(false);
    expect(result.action.parameters.raw.kwargs).toEqual({ flag: true });
    expect(result.returnValue).toBe(true);
  });

  it("includes nested kwargs values in parameterHash for Python parity", () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );
    const inspectPayload = (payload?: { flag?: boolean; nested?: { value?: string } }): boolean =>
      payload?.flag === true;

    const first = producer.translate({
      fn: inspectPayload,
      agentName: "runtime-agent",
      kwargs: { flag: true, nested: { value: "alpha" } },
      toolName: "tool:demo.kwargs",
    });
    const second = producer.translate({
      fn: inspectPayload,
      agentName: "runtime-agent",
      kwargs: { flag: true, nested: { value: "beta" } },
      toolName: "tool:demo.kwargs",
    });

    expect(first.parameters.parameterHash).not.toBe(second.parameters.parameterHash);
  });

  it("exposes a wrapTool helper from the package root", async () => {
    const config = makeConfig({ mode: "enforce", toolsAllowed: ["payments.refund"] });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const api = ancilis as Record<string, unknown>;
    const wrapTool = api.wrapTool as (
      fn: (paymentId: string) => string,
      options: { producer: ToolActionProducer; agentName: string; toolName: string },
    ) => (paymentId: string) => Promise<string>;

    const refund = (paymentId: string): string => `refunded:${paymentId}`;
    const wrapped = wrapTool(refund, {
      producer,
      agentName: "runtime-agent",
      toolName: "tool:payments.refund",
    });

    await expect(wrapped("pay_123")).resolves.toBe("refunded:pay_123");
  });

  it("records evidence for evaluated tool calls", async () => {
    const config = makeConfig({ mode: "audit" });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );

    await producer.evaluate(
      (paymentId: string): string => `refunded:${paymentId}`,
      "runtime-agent",
      ["pay_123"],
      undefined,
      "tool:payments.refund",
    );

    expect(await store.count()).toBe(1);
    expect((await store.getRecords())[0]?.toolName).toBe("tool:payments.refund");
  });

  it("awaits async tool return values before returning execution results", async () => {
    const config = makeConfig({ mode: "audit" });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );

    const result = await producer.execute(
      async (paymentId: string): Promise<string> => `refunded:${paymentId}`,
      "runtime-agent",
      ["pay_123"],
      undefined,
      "tool:payments.refund_async",
    );

    expect(result.returnValue).toBe("refunded:pay_123");
    expect(await store.count()).toBe(1);
  });

  it("stores evidence before throwing for blocked tool execution", async () => {
    const config = makeConfig({ mode: "enforce", toolsBlocked: ["payments.refund"] });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new ToolActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );

    await expect(
      producer.execute(
        (paymentId: string): string => `refunded:${paymentId}`,
        "runtime-agent",
        ["pay_123"],
        undefined,
        "tool:payments.refund",
      ),
    ).rejects.toThrow(ancilis.BlockedActionError);
    expect(await store.count()).toBe(1);
    expect((await store.getRecords())[0]?.decision).toBe("BLOCK");
  });
});

describe("HTTPActionProducer", () => {
  it("returns the current registry contents from registerTools for Python parity", async () => {
    const config = makeConfig({ mode: "audit" });
    const registry = new ToolRegistry();
    const producer = new HTTPActionProducer(
      config,
      new Engine(config, { registry }),
      registry,
      new EvidenceStore(config, { inMemory: true }),
    );

    await producer.observe({
      method: "GET",
      url: "https://allowed.example.com/healthz",
      agentName: "runtime-agent",
    });

    expect(producer.registerTools(registry)).toEqual(["http:GET:allowed.example.com"]);
  });

  it("matches the Python prefix-trimmed allowlist semantics for wrapped HTTP calls", async () => {
    const config = makeConfig({ mode: "enforce", toolsAllowed: ["GET:allowed.example.com"] });
    const producer = new HTTPActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const fakeRequest = (method: string, url: string): { method: string; url: string } => ({ method, url });
    const wrapped = producer.wrapTransport(fakeRequest, "runtime-agent", undefined, true);
    const result = await wrapped("GET", "https://allowed.example.com/healthz");

    expect(result.blocked).toBe(false);
    expect(result.action.producerType).toBe("http");
    expect(result.action.producerVersion).toBe("0.1.0");
    expect(result.response).toEqual({
      method: "GET",
      url: "https://allowed.example.com/healthz",
    });
  });

  it("records evidence and preserves chain integrity across observations", async () => {
    const config = makeConfig({ mode: "audit" });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new HTTPActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );

    await producer.observe({
      method: "GET",
      url: "https://allowed.example.com/healthz",
      agentName: "runtime-agent",
    });
    await producer.observe({
      method: "POST",
      url: "https://allowed.example.com/events",
      agentName: "runtime-agent",
      body: { hello: "world" },
    });

    expect(await store.count()).toBe(2);
    expect((await store.getRecords())[0]?.toolName).toBe("http:GET:allowed.example.com");
    expect(await store.verifyChain()).toEqual({ valid: true, errors: [] });
  });

  it("includes nested HTTP payload values in parameterHash for Python parity", () => {
    const config = makeConfig({ mode: "audit" });
    const producer = new HTTPActionProducer(
      config,
      new Engine(config),
      undefined,
      new EvidenceStore(config, { inMemory: true }),
    );

    const first = producer.translate({
      method: "POST",
      url: "https://allowed.example.com/events",
      agentName: "runtime-agent",
      headers: { "x-trace-id": "trace-1" },
      body: { nested: { status: "alpha" } },
      metadata: { audit: { reason: "first" } },
    });
    const second = producer.translate({
      method: "POST",
      url: "https://allowed.example.com/events",
      agentName: "runtime-agent",
      headers: { "x-trace-id": "trace-2" },
      body: { nested: { status: "beta" } },
      metadata: { audit: { reason: "second" } },
    });

    expect(first.parameters.parameterHash).not.toBe(second.parameters.parameterHash);
  });

  it("stores evidence and skips transport when enforce mode blocks an HTTP call", async () => {
    const config = makeConfig({ mode: "enforce", toolsBlocked: ["GET:blocked.example.com"] });
    const store = new EvidenceStore(config, { inMemory: true });
    const producer = new HTTPActionProducer(
      config,
      new Engine(config),
      undefined,
      store,
    );
    let transportRan = false;

    await expect(
      producer.execute(
        {
          method: "GET",
          url: "https://blocked.example.com/healthz",
          agentName: "runtime-agent",
        },
        () => {
          transportRan = true;
          return { ok: true };
        },
        true,
      ),
    ).rejects.toThrow(ancilis.BlockedActionError);
    expect(transportRan).toBe(false);
    expect(await store.count()).toBe(1);
    expect((await store.getRecords())[0]?.decision).toBe("BLOCK");
  });
});

describe("MCPActionProducer", () => {
  it("exposes the MCP producer from the package root", () => {
    const root = ancilis as Record<string, unknown>;

    expect(root.MCPActionProducer).toBeDefined();
  });

  it("matches the Python producer metadata and translation shape", () => {
    const config = makeConfig({ mode: "audit" });
    const registry = new ToolRegistry();
    registry.register({
      name: "read_file",
      descriptionHash: "desc-hash",
      status: ToolStatus.APPROVED,
      approvedBy: "config",
      firstSeen: "2026-04-04T00:00:00Z",
      statusChanged: "2026-04-04T00:00:00Z",
    });
    const producer = new MCPActionProducer(config, registry);

    const action = producer.translate({
      name: "read_file",
      arguments: { path: "/tmp/example.txt" },
    });

    expect(producer.producerType).toBe(ancilis.ProducerType.MCP);
    expect(producer.producerVersion).toBe("0.1.0");
    expect(action.sourceType).toBe("mcp");
    expect(action.producerType).toBe("mcp");
    expect(action.producerVersion).toBe("0.1.0");
    expect(action.agentId).toBe("runtime-agent");
    expect(action.tool).toEqual({
      name: "read_file",
      version: null,
      descriptionHash: "desc-hash",
    });
    expect(action.parameters.raw).toEqual({ path: "/tmp/example.txt" });
  });

  it("registers tools from listTools-style responses via the existing discovery logic", () => {
    const config = makeConfig({ mode: "audit", toolsAllowed: ["approved.tool"] });
    const registry = new ToolRegistry();
    const producer = new MCPActionProducer(config, registry);

    const drift = producer.registerToolsFromResponse(
      [
        { name: "approved.tool", description: "approved description" },
        { name: "observed.tool", description: "observed description" },
      ],
      registry,
      config.toolsAllowed,
    );

    expect(drift).toEqual([]);
    expect(registry.lookup("approved.tool")?.status).toBe(ToolStatus.APPROVED);
    expect(registry.lookup("observed.tool")?.status).toBe(ToolStatus.OBSERVED);
    expect(producer.registerTools(registry)).toEqual(["approved.tool", "observed.tool"]);
    expect(producer.computeToolHash("demo")).toBe(producer.computeToolHash("demo"));
  });
});
