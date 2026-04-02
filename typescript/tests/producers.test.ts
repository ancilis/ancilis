/**
 * Tests for protocol-agnostic producers.
 */

import { describe, expect, it } from "vitest";
import * as ancilis from "../src/ancilis/index.js";
import { loadConfig } from "../src/ancilis/config/index.js";
import type { ResolvedConfig } from "../src/ancilis/config/index.js";
import { Engine } from "../src/ancilis/engine/engine.js";
import { EvidenceStore } from "../src/ancilis/evidence/store.js";
import { CLIActionProducer } from "../src/ancilis/producers/cli.js";
import { HTTPActionProducer } from "../src/ancilis/producers/http.js";
import { ToolActionProducer } from "../src/ancilis/producers/tool.js";

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
    expect(ancilis.CLIActionProducer).toBeDefined();
    expect(ancilis.HTTPActionProducer).toBeDefined();
    expect(ancilis.ToolActionProducer).toBeDefined();
    expect(ancilis.BlockedActionError).toBeDefined();
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
    expect(result.stdout?.trim()).toBe("hello");
  });
});

describe("ToolActionProducer", () => {
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
});

describe("HTTPActionProducer", () => {
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
    expect(result.response).toEqual({
      method: "GET",
      url: "https://allowed.example.com/healthz",
    });
  });
});
