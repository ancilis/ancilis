"""AKSI v0.6 freeze metadata validation."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
AKSI_VERSION_PATH = REPO_ROOT / "shared" / "aksi_version.json"
PLATFORM_REPO = Path("/Volumes/MiniAlbus/projects/ancilis-one-shot")


def _load_aksi_version() -> dict[str, Any]:
    assert AKSI_VERSION_PATH.exists(), "shared/aksi_version.json is missing"
    return json.loads(AKSI_VERSION_PATH.read_text())


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(PLATFORM_REPO), *args])


def test_aksi_v06_freeze_metadata_points_to_existing_platform_commit() -> None:
    metadata = _load_aksi_version()

    assert metadata["framework_version"] == "0.6"
    assert metadata["framework_repo"] == "ancilis-one-shot"
    assert metadata["framework_branch"] == "codex/aksi-production-grade-framework"
    assert metadata["framework_path"] == "docs/framework/aksi-framework-master.md"
    assert metadata["frozen_for_sdk_build"] == "aksi-v06-sdk-full-support"

    commit_sha = metadata["framework_commit_sha"]
    subprocess.check_call(
        ["git", "-C", str(PLATFORM_REPO), "cat-file", "-e", f"{commit_sha}^{{commit}}"]
    )


def test_aksi_v06_freeze_metadata_matches_framework_master_checksum() -> None:
    metadata = _load_aksi_version()
    commit_sha = metadata["framework_commit_sha"]
    framework_path = metadata["framework_path"]

    content = _git("show", f"{commit_sha}:{framework_path}")
    digest = hashlib.sha256(content).hexdigest()

    assert digest == metadata["framework_master_sha256"]
