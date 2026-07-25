# LangChain Chatbot + Ancilis SOC 2

A LangChain conversational agent with Ancilis SDK for SOC 2 compliance monitoring. Demonstrates wrapping LangChain tool calls to record compliance evidence for every tool execution.

## What this demonstrates

1. Wrap LangChain tool functions with `ToolActionProducer`
2. Run a multi-turn conversation — each tool call is evaluated and evidence-recorded
3. SOC 2 (plus GDPR and CCPA) overlays activate automatically from the `personal_info` data declaration
4. `ancilis scan` shows compliance posture from real tool-call evidence

When `ancilis-langchain` ships, the `producer.wrap_tool()` calls can be replaced with the native LangChain integration. The TODO markers in `main.py` show where to migrate.

## Prerequisites

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set OPENAI_API_KEY
```

Or:

```bash
make setup
```

## Run

```bash
make run    # executes main.py (simulated conversation, no API key needed)
make scan   # shows SOC 2 posture
```

The example uses simulated tool responses and does **not** require an OpenAI API key to run the compliance demonstration. Set `OPENAI_API_KEY` to connect a real LangChain agent.

## Config

```yaml
agent:
  name: langchain-chatbot
my_agent_handles:
  - personal_info
security:
  mode: audit
```

## Expected output

```
Agent: langchain-chatbot
Mode: audit
SOC 2 active: True

=== Simulated LangChain Agent Conversation ===

[Turn 1] User: What are the SOC 2 monitoring requirements for AI agents?
  → search_web('SOC 2 monitoring requirements AI agents')
    Found 3 results

...

=== Evidence Summary ===
  Records:    5
  Decisions:  {'ALLOW': 5}
  Hash chain: intact
  Tools:      ['calculator', 'search_web']

Run `ancilis scan` to see SOC 2 posture.
```

## Integration pattern

```python
from ancilis import ToolActionProducer, load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore

config = load_config()
engine = Engine(config)
evidence = EvidenceStore(config)
producer = ToolActionProducer(config=config, engine=engine, evidence_store=evidence)

# Wrap any callable — LangChain tool, plain function, or method
my_tool = producer.wrap_tool(my_tool_impl, tool_name="my_tool")

# TODO: use ancilis-langchain for native LangChain integration (ANC-568)
```

## Next steps

- See [crewai-research-crew](../crewai-research-crew/) for multi-agent compliance monitoring
- See [certification-driven](../certification-driven/) for AIUC-1 targeting
