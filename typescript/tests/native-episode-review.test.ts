import { expect, it } from "vitest";
import { Ancilis } from "../src/ancilis/index.js";

const surface = { surface: "tool" as const, operation: "EXECUTE" as const };

it("attaches a frozen MCP client while preserving method receivers", () => {
  const sdk = Ancilis.open({ tenant: "tenant", source: "source" });
  const client = Object.freeze({
    value: 42,
    callTool(_request: { name: string }) { return this.value; },
    listTools() { return [this.value]; },
  });
  const adapter = sdk.attachMcp(client, { surfaces: { read: surface } });
  sdk.episode("one", { expectedSurfaces: ["tool"] }, (episode) => {
    expect(adapter.callTool({ name: "read" })).toBe(42);
    expect(adapter.callTool({ name: "unmapped" })).toBe(42);
    expect(adapter.listTools()).toEqual([42]);
    expect(episode.inspect().observations).toHaveLength(2);
  });
  expect(Object.isFrozen(client)).toBe(true);
});

it.each([
  [{ maxAttachments: 3 }, 3],
  [{ maxDiagnosticKeys: 2 }, 2],
] as const)("keeps MCP cap refusal atomic with %j", (caps, count) => {
  const sdk = Ancilis.open({ tenant: "tenant", source: "source", ...caps });
  sdk.attachTool(() => 42, { name: "existing", ...surface });
  const before = sdk.diagnostics().attachments;
  const surfaces = Object.fromEntries(Array.from({ length: count }, (_, i) => [String(i), surface]));
  expect(() => sdk.attachMcp({ callTool: () => 42 }, { surfaces })).toThrow("ATTACHMENT_CAP");
  expect(sdk.diagnostics().attachments).toEqual(before);
});

it.each([
  { "z\n": surface },
  { z: { surface: "invalid", operation: "EXECUTE" } },
  { z: { surface: "tool", operation: "invalid" } },
])("keeps invalid later MCP mappings atomic", (invalid) => {
  const sdk = Ancilis.open({ tenant: "tenant", source: "source" });
  expect(() => sdk.attachMcp({ callTool: () => 42 }, {
    surfaces: { a: surface, ...invalid } as any,
  })).toThrow("INVALID_OBSERVATION");
  expect(sdk.diagnostics().attachments).toEqual([]);
});

it("forwards mutable MCP properties and private-field method receivers", () => {
  class Client {
    #secret = 7;
    value = 42;
    callTool() { return this.value + this.#secret; }
  }
  const client = new Client();
  const sdk = Ancilis.open({ tenant: "tenant", source: "source" });
  const adapter = sdk.attachMcp(client, { surfaces: {} });
  adapter.value = 1;
  expect(client.value).toBe(1);
  expect(adapter.callTool()).toBe(8);
});
