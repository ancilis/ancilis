"""Sample scan script templates per agent framework."""

from __future__ import annotations

_LANGCHAIN = '''\
"""Sample Ancilis scan for a LangChain agent.

Run: python ancilis_scan.py
Or:  ancilis scan
"""
from ancilis import Engine
from ancilis.config import load_config

config = load_config()
engine = Engine(config)

# Your LangChain agent code here — Ancilis evaluates
# actions automatically via the callback producer.

results = engine.evaluate()
print(f"Posture score: {results.score}")
print(f"Controls evaluated: {results.total}")
print(f"Controls passed: {results.passed}")
'''

_CREWAI = '''\
"""Sample Ancilis scan for a CrewAI agent.

Run: python ancilis_scan.py
Or:  ancilis scan
"""
from ancilis import Engine
from ancilis.config import load_config

config = load_config()
engine = Engine(config)

# Your CrewAI agent code here — Ancilis monitors
# tool calls made by your crew members.

results = engine.evaluate()
print(f"Posture score: {results.score}")
print(f"Controls evaluated: {results.total}")
print(f"Controls passed: {results.passed}")
'''

_AUTOGEN = '''\
"""Sample Ancilis scan for an AutoGen agent.

Run: python ancilis_scan.py
Or:  ancilis scan
"""
from ancilis import Engine
from ancilis.config import load_config

config = load_config()
engine = Engine(config)

# Your AutoGen agent code here — Ancilis intercepts
# tool calls in the conversation loop.

results = engine.evaluate()
print(f"Posture score: {results.score}")
print(f"Controls evaluated: {results.total}")
print(f"Controls passed: {results.passed}")
'''

_OPENAI = '''\
"""Sample Ancilis scan for an OpenAI agent.

Run: python ancilis_scan.py
Or:  ancilis scan
"""
from ancilis import Engine
from ancilis.config import load_config

config = load_config()
engine = Engine(config)

# Your OpenAI agent code here — Ancilis evaluates
# function call tool uses against your policy.

results = engine.evaluate()
print(f"Posture score: {results.score}")
print(f"Controls evaluated: {results.total}")
print(f"Controls passed: {results.passed}")
'''

_GENERIC = '''\
"""Sample Ancilis scan for a custom agent.

Run: python ancilis_scan.py
Or:  ancilis scan
"""
from ancilis import Engine
from ancilis.config import load_config

config = load_config()
engine = Engine(config)

# Register evidence manually for custom agents:
# engine.record_action({"tool": "my_tool", "params": {...}})

results = engine.evaluate()
print(f"Posture score: {results.score}")
print(f"Controls evaluated: {results.total}")
print(f"Controls passed: {results.passed}")
'''

_TEMPLATES: dict[str, str] = {
    "langchain": _LANGCHAIN,
    "crewai": _CREWAI,
    "autogen": _AUTOGEN,
    "openai": _OPENAI,
    "generic": _GENERIC,
}


def get_scan_script(framework: str) -> str:
    """Return the sample scan script for the given framework name."""
    return _TEMPLATES.get(framework, _GENERIC)
