"""ancilis-crewai — CrewAI integration for Ancilis evidence capture."""

from ancilis_crewai._version import __version__
from ancilis_crewai.decorator import ancilis_crew
from ancilis_crewai.callbacks import _wrap_crew as wrap_crew_instance

__all__ = ["ancilis_crew", "wrap_crew_instance", "__version__"]
