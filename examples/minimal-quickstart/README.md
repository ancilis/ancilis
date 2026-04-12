# Minimal Quickstart

The fastest path to your first Ancilis scan. Ten lines of Python, one config file.

## What this demonstrates

1. Load `ancilis.yaml` — declare agent name, certification target, and data types
2. Wrap Python tool functions with `ToolActionProducer`
3. Run your agent — every tool call is evaluated and evidence is recorded
4. Run `ancilis scan` to see compliance posture

SOC 2 controls activate automatically from `certification_targets: [soc2]`.

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
agent_name: quickstart-agent
certification_targets:
  - soc2
my_agent_handles:
  - personal_info
```

Three lines activate SOC 2 controls and data-classification monitoring.

## Expected output

```
Agent: quickstart-agent
Mode: audit

search_web -> {'results': ['NIST AI RMF', 'EU AI Act', 'SOC 2 Type II']}
send_reply -> Sent: Here are the top compliance frameworks for AI agents.

Evidence: 2 records, chain intact

Run `ancilis scan` to see your compliance posture.
```

## Next steps

- See [certification-driven](../certification-driven/) for AIUC-1 targeting
- See [data-classification](../data-classification/) for HIPAA/GDPR activation
- See [langchain-chatbot](../langchain-chatbot/) for a LangChain integration
