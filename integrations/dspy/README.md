# ancilis-dspy

[DSPy](https://github.com/stanfordnlp/dspy) integration for [Ancilis](https://ancilis.ai) — automatic evidence capture for compound-AI / programmatic LLM systems.

DSPy is the leading "programming, not prompting" framework — declarative `Module` programs (Predict, ChainOfThought, ReAct, ProgramOfThought) that get auto-optimized by teleprompters (BootstrapFewShot, MIPROv2, SIMBA). Each Predict invocation, retriever call, evaluation iteration, and compile step is an evidence-relevant event. ancilis-dspy records every one as cryptographically chained evidence — without ever storing raw `dspy.Example` field values, raw `dspy.Prediction` outputs, or raw teleprompter training sets.

## Install

```bash
pip install ancilis-dspy
```

## Quickstart — wrap_lm

```python
import dspy
from ancilis_dspy import wrap_lm

lm = wrap_lm(dspy.LM("openai/gpt-4o"), agent_id="research-agent")
dspy.settings.configure(lm=lm)
program = dspy.ChainOfThought("question -> answer")
program(question="What is compound AI?")
```

## Quickstart — AncilisCallback (DSPy 2.5+ callbacks)

```python
import dspy
from ancilis_dspy import AncilisCallback

dspy.settings.configure(callbacks=[AncilisCallback(agent_id="my-agent")])
program = dspy.ReAct("question -> answer", tools=[...])
program(question="Who wrote Hamlet?")
```

## What gets captured

| DSPy event | action_type | Captured |
|------------|-------------|----------|
| `lm_call` (single Predict invocation) | `tool_call` | model, prompt length + sha256, completion length + sha256, token usage |
| `module_call` (custom `dspy.Module.__call__`) | `tool_call` | module name, input field names + sha256, output field names + sha256 |
| `retrieve` (RM call) | `data_access` | query length + sha256, result count |
| `evaluate` (Evaluate iteration) | `tool_call` | metric name, score, dataset size |
| `compile` (teleprompt step) | `tool_call` | optimizer name, training-set size + sha256, metric score |

## Privacy

**`dspy.Example` fields, `dspy.Prediction` fields, and teleprompter training sets are never stored raw.** DSPy programs frequently process structured user data with PII. Ancilis records only:

- The list of field *names* on every `Example` / `Prediction`
- A sha256 digest of the joined field *values* (for change-detection / chain-of-custody)
- Length + sha256 of every prompt and completion string
- Token usage (`prompt_tokens`, `completion_tokens`, `total_tokens`)
- Training-set *size* + sha256 — never the examples themselves
- Numeric optimization scores (these are useful for posture, not PII)

Raw example values, raw prediction outputs, and raw training data never enter the evidence store.

## Compatibility

- dspy: `>=2.5.0` (callbacks API; producer is duck-typed and never imports `dspy` at module load)
- Python: `>=3.10`
- Ancilis: `>=0.1.0`
