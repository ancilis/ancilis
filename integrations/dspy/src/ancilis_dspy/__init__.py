"""ancilis-dspy — DSPy integration for Ancilis evidence capture.

DSPy is the "programming, not prompting" framework for compound AI systems —
declarative ``Module`` programs that get auto-optimized by teleprompters
(BootstrapFewShot, MIPROv2, SIMBA). ancilis-dspy records every Predict
invocation, custom-module call, retriever query, evaluation iteration, and
compile step as cryptographically chained evidence — without ever storing
raw ``dspy.Example`` field values, raw ``dspy.Prediction`` outputs, or raw
teleprompter training sets.
"""

from ancilis_dspy._producer import DSPyProducer
from ancilis_dspy._version import __version__
from ancilis_dspy.callback import AncilisCallback
from ancilis_dspy.wrapper import wrap_lm

__all__ = [
    "AncilisCallback",
    "DSPyProducer",
    "wrap_lm",
    "__version__",
]
