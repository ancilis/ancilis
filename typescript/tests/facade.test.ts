import { describe, expect, it } from "vitest";
import { Ancilis, BlockedActionError } from "../src/ancilis/index.js";

describe("Ancilis facade", () => {
  it("is exported from the package root with a load helper", () => {
    expect(Ancilis).toBeDefined();
    expect(Ancilis.load).toBeTypeOf("function");
  });

  it("runs allowed tool calls through run.call", async () => {
    const anc = Ancilis.load({
      raw: {
        agent: { name: "runtime-agent" },
        security: {
          mode: "enforce",
          tools: { allowed: ["payments.refund"] },
        },
      },
      evidence: { inMemory: true },
    });
    const refund = (paymentId: string): string => `refunded:${paymentId}`;
    const run = anc.tool(refund, { toolName: "tool:payments.refund" });

    await expect(run.call("pay_123")).resolves.toBe("refunded:pay_123");
    expect(anc.registry.lookup("tool:payments.refund")?.approvedBy).toBe("config");
  });

  it("blocks disallowed tool calls without executing the function", async () => {
    const anc = Ancilis.load({
      raw: {
        agent: { name: "runtime-agent" },
        security: { mode: "enforce" },
      },
      evidence: { inMemory: true },
    });
    let executed = false;
    const refund = (paymentId: string): string => {
      executed = true;
      return `refunded:${paymentId}`;
    };
    const run = anc.tool(refund, { toolName: "tool:payments.refund" });

    await expect(run.call("pay_123")).rejects.toThrow(BlockedActionError);
    expect(executed).toBe(false);
  });
});
