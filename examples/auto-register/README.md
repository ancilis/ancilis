# `auto_register` — wire what's installed

Use `ancilis.producers.auto_register(config, engine)` to skip per-SDK boilerplate. It detects every Ancilis-supported LLM/framework SDK that's installed in your Python environment via `importlib.util.find_spec` (no actual imports, no side effects) and instantiates one producer per detected SDK.

```bash
pip install -r requirements.txt
python main.py
```

The example prints a detection table for every supported SDK, then shows what `auto_register` returns. Try installing a few SDKs and re-running:

```bash
pip install anthropic openai
python main.py
```

You'll see `anthropic` and `openai` flip from blank to ✓, and the `Wired N producer(s)` count increase.

## What you get

```python
from ancilis.producers import auto_register

producers = auto_register(config, engine)
# producers["anthropic"]  → AnthropicActionProducer instance (if anthropic installed)
# producers["openai"]     → OpenAIActionProducer instance     (if openai installed)
# producers["langchain"]  → LangChainActionProducer instance  (if langchain installed)
# ... etc
```

Filters:

```python
auto_register(config, engine, include={"anthropic", "openai"})
auto_register(config, engine, exclude={"deepseek", "fireworks"})
```

## Detection table

| Provider slug | Upstream module(s) |
|---|---|
| `anthropic` | `anthropic` |
| `openai` | `openai` |
| `gemini` | `google.genai`, `google.generativeai` |
| `mistral` | `mistralai` |
| `cohere` | `cohere` |
| `groq` | `groq` |
| `together` | `together` |
| `fireworks` | `fireworks` |
| `aws-bedrock` | `boto3` |
| `langchain` | `langchain`, `langchain_core` |
| `crewai` | `crewai` |
| `autogen` | `autogen`, `autogen_agentchat`, `ag2` |
| `semantic-kernel` | `semantic_kernel` |

xAI and DeepSeek expose OpenAI-compatible APIs and have no dedicated Python SDK, so they don't appear in `auto_register` results — wire them explicitly with `XAIActionProducer` / `DeepSeekActionProducer` if you use them.

## See also

- [docs/producers.md](../../docs/producers.md) — full producer reference, including the `auto_register` API
- [README.md](../../README.md) — top-level overview with `auto_register` example
