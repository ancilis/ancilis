from __future__ import annotations

import asyncio
import inspect
import os
import sys
from importlib.metadata import entry_points
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "python" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


_ancilis_pytest_entrypoint = any(
    ep.name == "ancilis" and ep.value == "ancilis.testing.plugin"
    for ep in entry_points(group="pytest11")
)
if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") or not _ancilis_pytest_entrypoint:
    pytest_plugins = ["ancilis.testing.plugin"]


def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: run async test functions with asyncio.run")


def pytest_pyfunc_call(pyfuncitem):
    testfunction = pyfuncitem.obj
    if not inspect.iscoroutinefunction(testfunction):
        return None

    kwargs = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    asyncio.run(testfunction(**kwargs))
    return True
