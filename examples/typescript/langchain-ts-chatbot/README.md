# LangChain.js Chatbot + Ancilis SOC 2

Simulate a LangChain.js agent conversation with Ancilis compliance monitoring.
Every tool call is evaluated, evidence-recorded, and verifiable against SOC 2 controls.

## What this demonstrates

1. Wrapping LangChain tool functions with `ToolActionProducer`
2. SOC 2 overlay activated via `certification_targets: [soc2]`
3. Audit-mode evidence recorded across 5 conversation turns
4. Hash-chain integrity preserved across all calls
5. `ancilis scan` showing SOC 2 compliance posture

## Install from npm

```bash
npm install ancilis langchain @langchain/core @langchain/openai
```

## Run (from this directory in the repo)

```bash
make setup    # installs dependencies
make run      # runs the simulated chatbot
make scan     # runs chatbot + shows SOC 2 posture
```

`OPENAI_API_KEY` is optional - the example simulates API calls without it.
Set it to replace simulated results with real LangChain calls.

## Expected output

```
Agent: langchain-chatbot
Mode:  audit
SOC 2 active: true

=== Simulated LangChain Agent Conversation ===

[Turn 1] User: What are the SOC 2 monitoring requirements for AI agents?
  -> search_web("SOC 2 monitoring requirements AI agents")
    Found 3 results

...

=== Evidence Summary ===
  Records:    5
  Decisions:  {"ALLOW":5}
  Hash chain: intact
  Tools:      search_web, calculator
```

Followed by:

```
Ancilis scan - langchain-chatbot
  Mode:    audit
  Posture: non_compliant

  OK Identity verification - pass (5 evals)
  OK Scope enforcement - pass (5 evals)
  ...
```

## Connecting to real LangChain agents

```typescript
import { loadConfig, Engine, EvidenceStore, ToolActionProducer } from "ancilis";
import { tool } from "@langchain/core/tools";
import { z } from "zod";

const config = loadConfig({ path: "ancilis.yaml" });
const producer = new ToolActionProducer(
  config,
  new Engine(config),
  undefined,
  new EvidenceStore(config),
);

// Wrap any function before passing to LangChain
const searchFn = (query: string) => ({ results: [] });
const wrappedSearch = producer.wrapTool(searchFn, undefined, "search_web");

// Create LangChain tool with wrapped function
const searchTool = tool(
  async ({ query }) => JSON.stringify(await wrappedSearch(query)),
  {
    name: "search_web",
    description: "Search the web",
    schema: z.object({ query: z.string() }),
  },
);
```

## Config

```yaml
agent:
  name: langchain-chatbot
security:
  mode: audit
  tools:
    allowed:
      - search_web
      - calculator
my_agent_handles:
  - personal_info
certification_targets:
  - soc2
```

## Docs

- Full documentation: [docs.ancilis.ai](https://docs.ancilis.ai)
- TypeScript SDK reference: [docs.ancilis.ai/typescript-api-reference](https://docs.ancilis.ai/typescript-api-reference)
- LangChain.js integration guide: [docs.ancilis.ai/integrations/langchainjs](https://docs.ancilis.ai/integrations/langchainjs)
