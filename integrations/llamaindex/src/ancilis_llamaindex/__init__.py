"""ancilis-llamaindex — LlamaIndex integration for Ancilis evidence capture."""

from ancilis_llamaindex._producer import LlamaIndexProducer
from ancilis_llamaindex._version import __version__
from ancilis_llamaindex.handler import AncilisEventHandler

__all__ = ["AncilisEventHandler", "LlamaIndexProducer", "__version__"]
