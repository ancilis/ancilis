# Ancilis TypeScript Quickstart

Evaluate tool calls against a security policy and generate cryptographically chained evidence — in a single file.

## What this demonstrates

1. Inline policy config (no YAML file needed)
2. `ToolActionProducer` wrapping plain TypeScript functions
3. Allowed tool executing normally with evidence recorded
4. Blocked tool intercepted before execution
5. Hash-chain integrity verification

## Install

```bash
npm install ancilis
```

## Run (from the repo after `npm run build`)

```bash
node examples/typescript/quickstart.mjs
```

## Expected output

```
=== Ancilis Quickstart (enforce mode) ===

✓  payments.read  -> ALLOW
   result: {"id":"pay_123","amount":42,"status":"settled"}

✗  payments.delete -> BLOCK (enforce mode)

Evidence: 2 record(s) generated
  [ALLOW] payments.read
  [BLOCK] payments.delete

Hash-chain integrity: valid ✓
```

## Config

```yaml
agent:
  name: payment-agent
security:
  mode: enforce
  tools:
    allowed:
      - payments.read
    blocked:
      - payments.delete
```

## Use in a real project

```typescript
import {
  loadConfig,
  Engine,
  EvidenceStore,
  ToolActionProducer,
  BlockedActionError,
} from "ancilis";

const config = loadConfig({ path: "ancilis.yaml" });
const store = new EvidenceStore(config);
const producer = new ToolActionProducer(config, new Engine(config), undefined, store);

const myTool = (input: string) => `processed: ${input}`;

const result = await producer.execute(myTool, config.agentName, ["hello"], undefined, "my.tool");
console.log(result.returnValue);
```
