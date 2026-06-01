"""ancilis-pydantic-ai — Pydantic-AI integration for Ancilis evidence capture."""

from ancilis_pydantic_ai._producer import PydanticAIProducer
from ancilis_pydantic_ai._version import __version__
from ancilis_pydantic_ai.wrapper import wrap_agent

__all__ = ["PydanticAIProducer", "wrap_agent", "__version__"]
