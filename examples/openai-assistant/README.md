# OpenAI Assistants API + Ancilis

HIPAA and SOC 2 compliance monitoring for the OpenAI Assistants API using
`HTTPActionProducer` — no framework or middleware layer required.

**Pattern:** Every Assistants API call (create thread, add message, run
assistant, retrieve messages) is recorded as a compliance event. `health_records`
in `my_agent_handles` automatically activates HIPAA and SOC 2 overlays.

## Quick Start

```bash
make setup
make run
make scan
```

No API key needed — the example runs in simulation mode by default and
exercises all Ancilis code paths identically to a live run.

## What This Shows

| Step | API Call                     | Evidence Captured  |
|------|------------------------------|--------------------|
| 1    | Create assistant             | 1 HTTP record      |
| 2    | Create thread                | 1 HTTP record      |
| 3    | Add user message             | 1 HTTP record      |
| 4    | Run assistant                | 1 HTTP record      |
| 5    | List response messages       | 1 HTTP record      |

All 5 API calls are recorded in DuckDB with SHA-256 hash chaining.
`make scan` evaluates HIPAA (§164.312 audit controls), SOC 2, GDPR, and
CCPA posture.

## Integration Pattern

```python
from ancilis import load_config
from ancilis.engine import Engine
from ancilis.evidence.store import EvidenceStore
from ancilis.producers.http import HTTPActionProducer

config = load_config()
engine = Engine(config)
evidence = EvidenceStore(config)
producer = HTTPActionProducer(
    config=config,
    engine=engine,
    evidence_store=evidence,
    server_url="https://api.openai.com",
)

# Record any HTTP interaction — works with any REST API
producer.observe(
    method="POST",
    url="https://api.openai.com/v1/threads",
    request_body={},
    response_body=thread_response,
    status_code=200,
)
```

## Live API Setup

```bash
cp .env.example .env
# Add your OPENAI_API_KEY to .env
make run
```

See [docs.ancilis.ai](https://docs.ancilis.ai) for the full integration guide.
