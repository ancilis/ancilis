# Ancilis Examples

Runnable examples showing how to integrate Ancilis SDK in common AI agent patterns.

| Example | Framework | Description | Difficulty |
|---------|-----------|-------------|------------|
| [minimal-quickstart](./minimal-quickstart/) | Python | Fastest path to first scan — 10 lines | Beginner |
| [certification-driven](./certification-driven/) | Python | One config line to AIUC-1 readiness | Beginner |
| [data-classification](./data-classification/) | Python | Declare data types, get HIPAA/GDPR/SOC 2 controls | Beginner |
| [langchain-chatbot](./langchain-chatbot/) | LangChain | SOC 2 monitoring for conversational agents | Intermediate |
| [crewai-research-crew](./crewai-research-crew/) | CrewAI | Multi-agent compliance with per-agent attribution | Intermediate |
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

Framework examples (LangChain, CrewAI) include simulated tools that run without an API key, so you can see the compliance monitoring in action immediately. To connect a real LLM, set `OPENAI_API_KEY` and the tools will use live responses.

## License

AGPL-3.0-or-later — see [LICENSE](../LICENSE).
