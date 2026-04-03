#!/usr/bin/env python3
"""Local release verification for Python and preview TypeScript packaging."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SANITIZED_NPM_ENV_KEYS = (
    "NODE_ENV",
    "NPM_CONFIG_PRODUCTION",
    "npm_config_production",
    "NPM_CONFIG_OMIT",
    "npm_config_omit",
)


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd or ROOT, env=env, check=True)


def build_python_artifacts(python: str) -> tuple[Path, Path]:
    if DIST.exists():
        shutil.rmtree(DIST)
    run([python, "-m", "pip", "install", "--upgrade", "build", "twine"])
    run([python, "-m", "build", "--sdist", "--wheel"])
    wheels = sorted(DIST.glob("ancilis-*.whl"))
    sdists = sorted(DIST.glob("ancilis-*.tar.gz"))
    if not wheels or not sdists:
        raise SystemExit("Expected both wheel and sdist artifacts in dist/.")
    run([python, "-m", "twine", "check", str(wheels[-1]), str(sdists[-1])])
    return wheels[-1], sdists[-1]


def smoke_install_from_artifact(python: str, artifact: Path, extra: str = "") -> None:
    with tempfile.TemporaryDirectory(prefix="ancilis-release-check-") as tmp:
        venv = Path(tmp) / "venv"
        run([python, "-m", "venv", str(venv)])
        bin_dir = venv / ("Scripts" if os.name == "nt" else "bin")
        vpy = str(bin_dir / "python")
        vpip = str(bin_dir / "pip")
        ancilis = str(bin_dir / "ancilis")
        run([vpy, "-m", "pip", "install", "--upgrade", "pip"])
        target = f"{artifact}{extra}" if extra else str(artifact)
        run([vpip, "install", target])

        smoke_config = Path(tmp) / "ancilis.yaml"
        smoke_config.write_text("agent:\n  name: release-check-agent\n")
        env = os.environ | {"PYTHONPATH": ""}

        run([vpy, "-c", "import ancilis; print(ancilis.__all__[0])"], env=env)
        run([ancilis, "doctor", "--config", str(smoke_config)], env=env)
        run([ancilis, "config", "validate", "--config", str(smoke_config)], env=env)
        run([ancilis, "status", "--config", str(smoke_config)], env=env)
        run([ancilis, "report", "--config", str(smoke_config), "--format", "terminal"], env=env)


def smoke_editable_installs(python: str) -> None:
    with tempfile.TemporaryDirectory(prefix="ancilis-install-check-") as tmp:
        venv = Path(tmp) / "venv"
        run([python, "-m", "venv", str(venv)])
        bin_dir = venv / ("Scripts" if os.name == "nt" else "bin")
        vpip = str(bin_dir / "pip")
        vpy = str(bin_dir / "python")
        run([vpy, "-m", "pip", "install", "--upgrade", "pip"])
        run([vpip, "install", "."])
        run([vpip, "install", ".[mcp]"])


def npm_smoke_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in SANITIZED_NPM_ENV_KEYS:
        env.pop(key, None)
    return env


def smoke_typescript() -> None:
    if shutil.which("npm") is None:
        raise SystemExit("npm is required for TypeScript smoke checks.")
    env = npm_smoke_env()
    run(["npm", "ci"], env=env)
    run(["npm", "run", "build"], env=env)
    run(["npm", "pack", "--dry-run"], env=env)
    run(["node", "scripts/ts_package_smoke.mjs"], env=env)


def main() -> None:
    python = sys.executable
    smoke_editable_installs(python)
    wheel, sdist = build_python_artifacts(python)
    smoke_install_from_artifact(python, wheel)
    smoke_install_from_artifact(python, sdist)
    smoke_typescript()


if __name__ == "__main__":
    main()
