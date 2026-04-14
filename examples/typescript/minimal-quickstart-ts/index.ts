/**
 * Minimal Quickstart - fastest path to first Ancilis scan.
 *
 * Demonstrates:
 *   1. Loading config from ancilis.yaml
 *   2. Wrapping plain TypeScript functions with ToolActionProducer
 *   3. Evidence recorded on every tool call
 *   4. Hash-chain integrity verification
 *
 * Run from this directory:
 *   npx tsx index.ts
 *   npx ancilis scan
 */

import { loadConfig, Engine, EvidenceStore, ToolActionProducer } from "ancilis";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const config = loadConfig({ path: join(__dirname, "ancilis.yaml") });
const engine = new Engine(config);
const evidence = new EvidenceStore(config);
const producer = new ToolActionProducer(config, engine, undefined, evidence);

// --- Tool definitions ---

function searchWeb(query: string): { results: string[] } {
  return {
    results: [
      "NIST AI RMF",
      "EU AI Act",
      "SOC 2 Type II",
    ],
  };
}

function sendReply(message: string): string {
  return `Sent: ${message}`;
}

// Wrap tools - each call is evaluated and evidence-recorded
const wrappedSearch = producer.wrapTool(searchWeb, undefined, "search_web");
const wrappedReply = producer.wrapTool(sendReply, undefined, "send_reply");

// --- Run the agent ---

console.log(`Agent: ${config.agentName}`);
console.log(`Mode:  ${config.mode}`);
console.log();

const searchResult = await wrappedSearch("AI compliance frameworks");
console.log(`search_web  -> ${JSON.stringify(searchResult)}`);

const replyResult = await wrappedReply("Here are the top compliance frameworks for AI agents.");
console.log(`send_reply  -> ${replyResult}`);

// --- Evidence summary ---

const summary = await evidence.getSummary();
console.log();
console.log(
  `Evidence: ${summary.totalEvaluations} records, ` +
  `chain ${summary.chainValid ? "intact" : "BROKEN"}`,
);
console.log();
console.log("Run `npx ancilis scan` to see your compliance posture.");

await evidence.close();
