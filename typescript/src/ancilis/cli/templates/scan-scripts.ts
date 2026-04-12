/** ancilis.cli.templates.scan-scripts — framework-specific TypeScript sample scripts. */

const LANGCHAIN = `/**
 * Sample Ancilis scan for a LangChain agent.
 *
 * Run: npx ts-node ancilis_scan.ts
 * Or:  ancilis scan
 */
import { Engine } from "ancilis";
import { loadConfig } from "ancilis/config";

const config = loadConfig();
const engine = new Engine(config);

// Your LangChain agent code here — Ancilis evaluates
// actions automatically via the callback producer.

const results = await engine.evaluate();
console.log(\`Posture score: \${results.score}\`);
console.log(\`Controls evaluated: \${results.total}\`);
console.log(\`Controls passed: \${results.passed}\`);
`;

const OPENAI = `/**
 * Sample Ancilis scan for an OpenAI agent.
 *
 * Run: npx ts-node ancilis_scan.ts
 * Or:  ancilis scan
 */
import { Engine } from "ancilis";
import { loadConfig } from "ancilis/config";

const config = loadConfig();
const engine = new Engine(config);

// Your OpenAI agent code here — Ancilis evaluates
// tool calls made by your assistants.

const results = await engine.evaluate();
console.log(\`Posture score: \${results.score}\`);
console.log(\`Controls evaluated: \${results.total}\`);
console.log(\`Controls passed: \${results.passed}\`);
`;

const ANTHROPIC = `/**
 * Sample Ancilis scan for an Anthropic (Claude) agent.
 *
 * Run: npx ts-node ancilis_scan.ts
 * Or:  ancilis scan
 */
import { Engine } from "ancilis";
import { loadConfig } from "ancilis/config";

const config = loadConfig();
const engine = new Engine(config);

// Your Claude/Anthropic agent code here — Ancilis monitors
// tool calls made in the conversation.

const results = await engine.evaluate();
console.log(\`Posture score: \${results.score}\`);
console.log(\`Controls evaluated: \${results.total}\`);
console.log(\`Controls passed: \${results.passed}\`);
`;

const MCP = `/**
 * Sample Ancilis scan for an MCP-enabled agent.
 *
 * Run: npx ts-node ancilis_scan.ts
 * Or:  ancilis scan
 */
import { Engine } from "ancilis";
import { loadConfig } from "ancilis/config";

const config = loadConfig();
const engine = new Engine(config);

// Your MCP agent code here — Ancilis intercepts
// tool calls via the MCP middleware.

const results = await engine.evaluate();
console.log(\`Posture score: \${results.score}\`);
console.log(\`Controls evaluated: \${results.total}\`);
console.log(\`Controls passed: \${results.passed}\`);
`;

const GENERIC = `/**
 * Sample Ancilis scan.
 *
 * Run: npx ts-node ancilis_scan.ts
 * Or:  ancilis scan
 */
import { Engine } from "ancilis";
import { loadConfig } from "ancilis/config";

const config = loadConfig();
const engine = new Engine(config);

// Your agent code here — Ancilis evaluates tool calls
// recorded by the middleware.

const results = await engine.evaluate();
console.log(\`Posture score: \${results.score}\`);
console.log(\`Controls evaluated: \${results.total}\`);
console.log(\`Controls passed: \${results.passed}\`);
`;

const SCRIPTS: Record<string, string> = {
  langchain: LANGCHAIN,
  openai: OPENAI,
  anthropic: ANTHROPIC,
  mcp: MCP,
  generic: GENERIC,
};

/** Return a TypeScript sample scan script for the given framework. */
export function getScanScript(framework: string): string {
  return SCRIPTS[framework] ?? SCRIPTS["generic"]!;
}
