# Ancilis Examples

Runnable examples showing how to integrate Ancilis SDK in common AI agent patterns.

| Example | Framework | Description | Difficulty |
|---------|-----------|-------------|------------|
| [minimal-quickstart](./minimal-quickstart/) | Python | Fastest path to first scan — 10 lines | Beginner |
| [certification-driven](./certification-driven/) | Python | One config line to AIUC-1 readiness | Beginner |
| [data-classification](./data-classification/) | Python | Declare data types, get HIPAA/GDPR/SOC 2 controls | Beginner |
| [auto-register](./auto-register/) | Any | `auto_register` — instantiate one producer per installed SDK | Beginner |
| [openai-assistant](./openai-assistant/) | OpenAI | Wrap `chat.completions.create` with `OpenAIActionProducer.wrap_create` | Intermediate |
| [langchain-chatbot](./langchain-chatbot/) | LangChain / LangGraph | Drop-in `LangChainCallbackHandler` for any Runnable, Chain, or LLM | Intermediate |
| [crewai-research-crew](./crewai-research-crew/) | CrewAI | `step_callback` / `task_callback` / `crew_callback` — per-agent attribution | Intermediate |
| [autogen-group-chat](./autogen-group-chat/) | AutoGen / AG2 | `producer.attach(agent)` — auto-wire send + receive hooks | Intermediate |
| [mcp-middleware](./mcp-middleware/) | MCP | Intercept MCP tool calls with Ancilis middleware | Intermediate |
| [cli-agent](./cli-agent/) | Python | CLI agent with HTTP producer | Intermediate |

## Quick start

```bash
pip install ancilis
cd examples/minimal-quickstart
python main.py
ancilis scan --config ancilis.yaml
```

## Prerequisites

All Python examples require:

```bash
pip install ancilis
```

## Framework examples

Framework examples (LangChain, CrewAI, AutoGen, OpenAI) drive the producers directly with framework-shape arguments, so they run without an API key or any of the framework SDKs installed — the producers are duck-typed. Once you wire a real Runnable/Crew/Agent/Client into the same producer instance, the same observations are produced for free.

Set `OPENAI_API_KEY` for the OpenAI example to swap the fake transport for a real `chat.completions.create` call.

## License

AGPL-3.0-or-later — see [LICENSE](../LICENSE).
