/**
 * Ancilis TypeScript SDK — Quickstart
 *
 * In a real project after `npm install ancilis`:
 *   import { loadConfig, Engine, EvidenceStore, ToolActionProducer, BlockedActionError } from "ancilis";
 *
 * Run from the repo root (after `npm run build`):
 *   node examples/typescript/quickstart.mjs
 */
import {
  loadConfig,
  Engine,
  EvidenceStore,
  ToolActionProducer,
  BlockedActionError,
} from "../../dist/ancilis/index.js";

// 1. Define your policy inline (or load from ancilis.yaml)
const config = loadConfig({
  raw: {
    agent: { name: "payment-agent" },
    security: {
      mode: "enforce",
      tools: {
        allowed: ["payments.read"],
        blocked: ["payments.delete"],
      },
    },
  },
});

// 2. Wire up the evidence store and producer
const store = new EvidenceStore(config, { inMemory: true });
const producer = new ToolActionProducer(config, new Engine(config), undefined, store);

// 3. Define tools as plain functions
const readPayment = (id) => ({ id, amount: 42.0, status: "settled" });
const deletePayment = (_id) => { throw new Error("unreachable"); };

// 4. Execute tools — policy is enforced automatically
console.log("=== Ancilis Quickstart (enforce mode) ===\n");

// Allowed tool
const allowed = await producer.execute(
  readPayment, "payment-agent", ["pay_123"], undefined, "payments.read",
);
console.log(`✓  payments.read  -> ALLOW`);
console.log(`   result: ${JSON.stringify(allowed.returnValue)}\n`);

// Blocked tool
try {
  await producer.execute(
    deletePayment, "payment-agent", ["pay_123"], undefined, "payments.delete",
  );
} catch (e) {
  if (e instanceof BlockedActionError) {
    console.log(`✗  payments.delete -> BLOCK (enforce mode)\n`);
  }
}

// 5. Inspect evidence
const records = await store.getRecords();
console.log(`Evidence: ${records.length} record(s) generated`);
for (const r of records) {
  console.log(`  [${r.decision}] ${r.toolName}`);
}

const { valid } = await store.verifyChain();
console.log(`\nHash-chain integrity: ${valid ? "valid ✓" : "BROKEN ✗"}`);
