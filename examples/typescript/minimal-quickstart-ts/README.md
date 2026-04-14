# Ancilis TypeScript Minimal Quickstart

Wrap plain TypeScript functions with runtime security evaluation and generate cryptographically chained evidence - in a single file.

## What this demonstrates

1. Loading policy config from `ancilis.yaml`
2. Wrapping plain TypeScript functions with `ToolActionProducer`
3. Evidence recorded automatically on every tool call
4. Hash-chain integrity verification
5. `ancilis scan` showing compliance posture

## Install from npm

```bash
npm install ancilis
```

## Run (from this directory in the repo)

```bash
make setup    # installs dependencies
make run      # runs the agent
make scan     # runs agent + shows compliance posture
```

## Expected output

```
Agent: quickstart-agent
Mode:  audit

search_web  -> {"results":["NIST AI RMF","EU AI Act","SOC 2 Type II"]}
send_reply  -> Sent: Here are the top compliance frameworks for AI agents.

Evidence: 5 records, chain intact

Run `npx ancilis scan` to see your compliance posture.
```

Followed by:

```
Ancilis scan - quickstart-agent
  Mode:    audit
  Posture: non_compliant

  OK Identity verification - pass (5 evals)
  OK Scope enforcement - pass (5 evals)
  ...
```

## Config

```yaml
agent:
  name: quickstart-agent
security:
  mode: audit
  tools:
    allowed:
      - search_web
      - send_reply
certification_targets:
  - soc2
my_agent_handles:
  - personal_info
```

## Use in your project

```typescript
import { loadConfig, Engine, EvidenceStore, ToolActionProducer } from "ancilis";

const config = loadConfig({ path: "ancilis.yaml" });
const engine = new Engine(config);
const evidence = new EvidenceStore(config);
const producer = new ToolActionProducer(config, engine, undefined, evidence);

const myTool = (input: string) => `processed: ${input}`;
const wrappedTool = producer.wrapTool(myTool, undefined, "my.tool");

const result = await wrappedTool("hello");
console.log(result); // processed: hello
```

## Docs

- Full documentation: [docs.ancilis.ai](https://docs.ancilis.ai)
- TypeScript SDK reference: [docs.ancilis.ai/typescript-api-reference](https://docs.ancilis.ai/typescript-api-reference)
