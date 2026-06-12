# Minimal Quickstart

The fastest path to your first Ancilis scan. Ten lines of Python, one config file.

## What this demonstrates

1. Load `ancilis.yaml` — declare the agent name and the data types it handles
2. Wrap Python tool functions with `ToolActionProducer`
3. Run your agent — every tool call is evaluated and evidence is recorded
4. Run `ancilis scan` to see compliance posture

The SOC 2, GDPR, and CCPA overlays activate automatically from the
`personal_info` data declaration (`soc2` is an overlay name, not a
`certification_targets` value).

## Prerequisites

```bash
pip install ancilis
```

Or use the Makefile:

```bash
make setup
```

## Run

```bash
make run    # executes main.py
make scan   # runs ancilis scan
```

Or without the Makefile:

```bash
python main.py
ancilis scan --config ancilis.yaml
```

## Config

```yaml
agent:
  name: quickstart-agent
my_agent_handles:
  - personal_info
```

Declaring the data your agent handles activates the matching overlays (SOC 2,
GDPR, CCPA) and data-classification monitoring.

## Expected output

```
Agent: quickstart-agent
Mode: audit

search_web -> {'results': ['NIST AI RMF', 'EU AI Act', 'SOC 2 Type II']}
send_reply -> Sent: Here are the top compliance frameworks for AI agents.

Evidence: 2 records this run, chain intact

Run `ancilis scan` to see your compliance posture.
```

## Next steps

- See [certification-driven](../certification-driven/) for AIUC-1 targeting
- See [data-classification](../data-classification/) for HIPAA/GDPR activation
- See [langchain-chatbot](../langchain-chatbot/) for a LangChain integration
