"""AKSI v0.6 freeze metadata validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
AKSI_VERSION_PATH = REPO_ROOT / "shared" / "aksi_version.json"
PLATFORM_REPO_ENV = "ANCILIS_PLATFORM_REPO"


def _load_aksi_version() -> dict[str, Any]:
    assert AKSI_VERSION_PATH.exists(), "shared/aksi_version.json is missing"
    return json.loads(AKSI_VERSION_PATH.read_text())


def _platform_repo() -> Path:
    raw_path = os.environ.get(PLATFORM_REPO_ENV)
    if not raw_path:
        pytest.skip(f"Set {PLATFORM_REPO_ENV} to a local ancilis-one-shot checkout")
    return Path(raw_path).expanduser()


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def test_aksi_v06_freeze_metadata_has_stable_contract_fields() -> None:
    metadata = _load_aksi_version()

    assert metadata["framework_version"] == "0.6"
    assert metadata["framework_repo"] == "ancilis-one-shot"
    assert metadata["framework_branch"] == "codex/aksi-production-grade-framework"
    assert metadata["framework_path"] == "docs/framework/aksi-framework-master.md"
    assert metadata["frozen_for_sdk_build"] == "aksi-v06-sdk-full-support"
    assert re.fullmatch(r"[0-9a-f]{40}", metadata["framework_commit_sha"])
    assert re.fullmatch(r"[0-9a-f]{64}", metadata["framework_master_sha256"])


def test_aksi_v06_freeze_metadata_points_to_existing_platform_commit() -> None:
    metadata = _load_aksi_version()
    platform_repo = _platform_repo()

    commit_sha = metadata["framework_commit_sha"]
    subprocess.check_call(
        ["git", "-C", str(platform_repo), "cat-file", "-e", f"{commit_sha}^{{commit}}"]
    )


def test_aksi_v06_freeze_metadata_matches_framework_master_checksum() -> None:
    metadata = _load_aksi_version()
    platform_repo = _platform_repo()
    commit_sha = metadata["framework_commit_sha"]
    framework_path = metadata["framework_path"]

    content = _git(platform_repo, "show", f"{commit_sha}:{framework_path}")
    digest = hashlib.sha256(content).hexdigest()

    assert digest == metadata["framework_master_sha256"]
