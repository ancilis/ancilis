/**
 * LangChain.js Chatbot + Ancilis SOC 2 Compliance Monitoring.
 *
 * Demonstrates wrapping LangChain tool calls with Ancilis ToolActionProducer
 * to record compliance evidence for every tool execution.
 *
 * Run from this directory:
 *   npx tsx index.ts
 *
 * Prerequisites:
 *   npm install (or make setup)
 *   export OPENAI_API_KEY=sk-...  # optional - example simulates calls if absent
 */

import { loadConfig, Engine, EvidenceStore, ToolActionProducer } from "ancilis";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// --- Ancilis setup ---
const config = loadConfig({ path: join(__dirname, "ancilis.yaml") });
const engine = new Engine(config);
const evidence = new EvidenceStore(config);
const producer = new ToolActionProducer(config, engine, undefined, evidence);

console.log(`Agent: ${config.agentName}`);
console.log(`Mode:  ${config.mode}`);
console.log(`SOC 2 active: ${config.activeOverlays.has("soc2")}`);
console.log();

// --- Tool implementations ---

function searchWebImpl(query: string): { query: string; results: string[] } {
  /** Simulate web search - replace with real search tool in production. */
  return {
    query,
    results: [
      "SOC 2 Type II requires continuous monitoring of security controls",
      "AI agents accessing personal data must maintain audit logs",
      "NIST AI RMF recommends runtime policy enforcement",
    ],
  };
}

function calculatorImpl(expression: string): { expression: string; result?: number; error?: string } {
  /** Safe arithmetic evaluator. */
  const allowed = /^[0-9+\-*/.()\s]+$/;
  if (!allowed.test(expression)) {
    return { expression, error: "Expression contains disallowed characters" };
  }
  try {
    // eslint-disable-next-line no-eval
    const result = Function(`"use strict"; return (${expression})`)() as number;
    return { expression, result };
  } catch (e) {
    return { expression, error: String(e) };
  }
}

// Wrap with Ancilis - each call is evaluated and evidence-recorded
const searchWeb = producer.wrapTool(searchWebImpl, undefined, "search_web");
const calculator = producer.wrapTool(calculatorImpl, undefined, "calculator");

// --- Simulated LangChain agent conversation ---

const CONVERSATIONS = [
  {
    user: "What are the SOC 2 monitoring requirements for AI agents?",
    tool: "search_web" as const,
    toolInput: { query: "SOC 2 monitoring requirements AI agents" },
  },
  {
    user: "If we need 99.9% uptime, how many minutes of downtime per year is allowed?",
    tool: "calculator" as const,
    toolInput: { expression: "365 * 24 * 60 * (1 - 0.999)" },
  },
  {
    user: "What frameworks does NIST recommend for AI runtime policy?",
    tool: "search_web" as const,
    toolInput: { query: "NIST AI RMF runtime policy enforcement" },
  },
  {
    user: "How many hours is 525 minutes?",
    tool: "calculator" as const,
    toolInput: { expression: "525 / 60" },
  },
  {
    user: "What is required for SOC 2 audit log compliance?",
    tool: "search_web" as const,
    toolInput: { query: "SOC 2 audit log requirements AI personal data" },
  },
];

console.log("=== Simulated LangChain Agent Conversation ===");
console.log();

for (const [i, turn] of CONVERSATIONS.entries()) {
  console.log(`[Turn ${i + 1}] User: ${turn.user}`);

  if (turn.tool === "search_web") {
    const result = await searchWeb(turn.toolInput.query);
    console.log(`  -> search_web(${JSON.stringify(turn.toolInput.query)})`);
    if ("results" in result) {
      console.log(`    Found ${result.results.length} results`);
    }
  } else if (turn.tool === "calculator") {
    const result = await calculator(turn.toolInput.expression);
    console.log(`  -> calculator(${JSON.stringify(turn.toolInput.expression)})`);
    if ("result" in result && result.result !== undefined) {
      console.log(`    = ${result.result.toFixed(4)}`);
    }
  }

  console.log();
}

// --- Evidence summary ---

const summary = await evidence.getSummary();
console.log("=== Evidence Summary ===");
console.log(`  Records:    ${summary.totalEvaluations}`);
console.log(`  Decisions:  ${JSON.stringify(summary.decisions)}`);
console.log(`  Hash chain: ${summary.chainValid ? "intact" : "BROKEN"}`);
console.log(`  Tools:      ${summary.toolsEvaluated.join(", ")}`);
console.log();
console.log("Run `npx ancilis scan` to see SOC 2 posture.");

await evidence.close();
