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


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd or ROOT, env=env, check=True)


def build_python_artifacts(python: str) -> tuple[Path, Path]:
    if DIST.exists():
        shutil.rmtree(DIST)
    run([python, "-m", "pip", "install", "--upgrade", "build", "twine"])
    run([python, "-m", "build", "--sdist", "--wheel"])
    run([python, "-m", "twine", "check", "dist/*"])
    wheels = sorted(DIST.glob("ancilis-*.whl"))
    sdists = sorted(DIST.glob("ancilis-*.tar.gz"))
    if not wheels or not sdists:
        raise SystemExit("Expected both wheel and sdist artifacts in dist/.")
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


def smoke_typescript() -> None:
    if shutil.which("npm") is None:
        raise SystemExit("npm is required for TypeScript smoke checks.")
    run(["npm", "ci"])
    run(["npm", "run", "build"])
    run(["npm", "pack", "--dry-run"])
    run(["node", "scripts/ts_package_smoke.mjs"])


def main() -> None:
    python = sys.executable
    smoke_editable_installs(python)
    wheel, sdist = build_python_artifacts(python)
    smoke_install_from_artifact(python, wheel)
    smoke_install_from_artifact(python, sdist)
    smoke_typescript()


if __name__ == "__main__":
    main()
