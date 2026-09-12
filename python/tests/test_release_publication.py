"""Offline adversarial release gates; no registry writes or live API dependencies."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_manifest", ROOT / "scripts/release_manifest.py"
)
manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest)
SHA = "a" * 40
VERSION = "0.2.0"


def tar(path, files):
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            data = content.encode()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


@pytest.fixture
def package(tmp_path):
    root = tmp_path / "artifacts"
    root.mkdir()
    tar(
        root / "ancilis-0.2.0.tgz",
        {
            "package/package.json": json.dumps(
                {"name": "ancilis", "version": VERSION, "license": "AGPL-3.0-or-later"}
            ),
            "package/LICENSE": "fixture license",
            "package/shared/controls.json": "{}",
            "package/shared/schemas/example.json": "{}",
            "package/dist/index.js": "export {};",
        },
    )
    manifest.create_manifest(root, "npm", VERSION, SHA, {"node": "20.20.0"})
    digest = hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest()
    return root, digest


def test_exact_artifact_manifest_round_trip(package):
    root, digest = package
    result = manifest.verify_manifest(root, "npm", VERSION, SHA, digest)
    assert result["artifacts"][0]["files"]["package/LICENSE"]["role"] == "license"
    assert (
        result["artifacts"][0]["files"]["package/shared/schemas/example.json"]["role"] == "schema"
    )
    assert manifest.registry_state(result, root, None) == "absent"


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "missing",
        "changed",
        "symlink",
        "wrong_source",
        "wrong_version",
        "manifest_changed",
        "duplicate_key",
    ],
)
def test_manifest_refuses_substitution(package, change):
    root, digest = package
    version, source = VERSION, SHA
    artifact = root / "ancilis-0.2.0.tgz"
    if change == "extra":
        (root / "surprise.tgz").write_text("unexpected")
    if change == "missing":
        artifact.unlink()
    if change == "changed":
        artifact.write_bytes(artifact.read_bytes() + b"changed")
    if change == "symlink":
        target = root.parent / "other"
        artifact.rename(target)
        artifact.symlink_to(target)
    if change == "wrong_source":
        source = "b" * 40
    if change == "wrong_version":
        version = "0.2.1"
    if change == "manifest_changed":
        p = root / "release-manifest.json"
        data = json.loads(p.read_text())
        data["toolchain"]["node"] = "changed"
        p.write_text(json.dumps(data))
    if change == "duplicate_key":
        p = root / "release-manifest.json"
        p.write_text('{"schema":1,"schema":1}')
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
    with pytest.raises(manifest.ReleaseError):
        manifest.verify_manifest(root, "npm", version, source, digest)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "package/.release-private/secret"])
def test_manifest_rejects_unsafe_archive_names(tmp_path, name):
    tar(tmp_path / "ancilis-0.2.0.tgz", {name: "data"})
    with pytest.raises(manifest.ReleaseError):
        manifest.create_manifest(tmp_path, "npm", VERSION, SHA, {})


def test_manifest_rejects_archive_symlink(tmp_path):
    with tarfile.open(tmp_path / "ancilis-0.2.0.tgz", "w:gz") as archive:
        link = tarfile.TarInfo("package/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp/private"
        archive.addfile(link)
    with pytest.raises(manifest.ReleaseError):
        manifest.create_manifest(tmp_path, "npm", VERSION, SHA, {})


def test_python_manifest_requires_exact_wheel_and_sdist(tmp_path):
    metadata = f"Name: ancilis\nVersion: {VERSION}\n"
    with zipfile.ZipFile(tmp_path / "ancilis-0.2.0-py3-none-any.whl", "w") as wheel:
        for name, value in {
            "ancilis-0.2.0.dist-info/METADATA": metadata,
            "ancilis-0.2.0.dist-info/licenses/LICENSE": "license",
            "ancilis/shared/controls.json": "{}",
        }.items():
            wheel.writestr(name, value)
    tar(
        tmp_path / "ancilis-0.2.0.tar.gz",
        {
            "ancilis-0.2.0/PKG-INFO": metadata,
            "ancilis-0.2.0/LICENSE": "license",
            "ancilis-0.2.0/shared/controls.json": "{}",
        },
    )
    data = manifest.create_manifest(tmp_path, "python", VERSION, SHA, {"python": "3.12"})
    files = [
        {"filename": a["filename"], "digests": {"sha256": a["sha256"]}} for a in data["artifacts"]
    ]
    response = {"info": {"name": "ancilis", "version": VERSION}, "urls": files}
    assert manifest.registry_state(data, tmp_path, response) == "identical"
    with pytest.raises(manifest.ReleaseError):
        manifest.registry_state(data, tmp_path, response | {"urls": files[:1]})
    files[0]["digests"]["sha256"] = "0" * 64
    with pytest.raises(manifest.ReleaseError):
        manifest.registry_state(data, tmp_path, response)


def test_npm_repeated_publication_requires_exact_integrity(package):
    import base64

    root, digest = package
    data = manifest.verify_manifest(root, "npm", VERSION, SHA, digest)
    integrity = (
        "sha512-"
        + base64.b64encode(
            hashlib.sha512((root / "ancilis-0.2.0.tgz").read_bytes()).digest()
        ).decode()
    )
    response = {
        "name": "ancilis",
        "version": VERSION,
        "dist": {
            "integrity": integrity,
            "tarball": "https://registry.npmjs.org/ancilis/-/ancilis-0.2.0.tgz",
        },
    }
    assert manifest.registry_state(data, root, response) == "identical"
    response["dist"]["integrity"] += "changed"
    with pytest.raises(manifest.ReleaseError):
        manifest.registry_state(data, root, response)


def test_publish_routes_are_push_only_and_have_no_verification_secrets():
    for name, jobname in [
        ("release-python.yml", "publish_python"),
        ("release-typescript.yml", "publish_typescript"),
    ]:
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        job = workflow["jobs"][jobname]
        assert "github.event_name == 'push'" in job["if"]
        assert "release_gate" in job["needs"]
        assert workflow["concurrency"]["cancel-in-progress"] is False
        gate = workflow["jobs"]["release_gate"]
        assert all(v == "read" for v in gate["permissions"].values())
        for jname, j in workflow["jobs"].items():
            if jname != jobname:
                assert "NPM_TOKEN" not in json.dumps(j)
    alternate = json.dumps(
        yaml.safe_load((ROOT / ".github/workflows/ts-sdk-release.yml").read_text())
    )
    assert "npm publish" not in alternate and "NPM_TOKEN" not in alternate


@pytest.mark.parametrize("http_status", [401, 403, 429, 500])
def test_registry_api_errors_are_not_absence(monkeypatch, http_status):
    import urllib.error

    class Denied:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, http_status, "denied", {}, None)

    monkeypatch.setattr(manifest.urllib.request, "build_opener", lambda *_: Denied())
    with pytest.raises(manifest.ReleaseError):
        manifest.registry_read("npm", VERSION)


def test_registry_404_is_only_absence_case(monkeypatch):
    import urllib.error

    class Missing:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

    monkeypatch.setattr(manifest.urllib.request, "build_opener", lambda *_: Missing())
    assert manifest.registry_read("npm", VERSION) is None


def test_registry_redirect_is_refused():
    with pytest.raises(manifest.ReleaseError):
        manifest.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.example")


def test_wrong_metadata_version_is_rejected(tmp_path):
    tar(
        tmp_path / "ancilis-0.2.0.tgz",
        {
            "package/package.json": json.dumps({"name": "ancilis", "version": "0.1.0"}),
            "package/LICENSE": "license",
            "package/shared/controls.json": "{}",
        },
    )
    with pytest.raises(manifest.ReleaseError):
        manifest.create_manifest(tmp_path, "npm", VERSION, SHA, {})


def test_signed_digest_does_not_allow_malformed_manifest_fields(package):
    root, _ = package
    path = root / "release-manifest.json"
    data = json.loads(path.read_text())
    data["schema"] = True
    path.write_text(json.dumps(data))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(manifest.ReleaseError):
        manifest.verify_manifest(root, "npm", VERSION, SHA, digest)


def test_source_freeze_requires_exact_clean_commit(tmp_path):
    import subprocess

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()

    git("init", "-q")
    (tmp_path / ".gitignore").write_text("artifacts/\n")
    (tmp_path / "source.txt").write_text("reviewed source")
    git("add", ".")
    git(
        "-c",
        "user.name=Release fixture",
        "-c",
        "user.email=release-fixture@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    source = git("rev-parse", "HEAD")
    manifest.verify_checkout(tmp_path, source)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/package").write_text("generated")
    manifest.verify_checkout(tmp_path, source)
    with pytest.raises(manifest.ReleaseError):
        manifest.verify_checkout(tmp_path, "0" * 40)
    (tmp_path / "source.txt").write_text("unreviewed edit")
    with pytest.raises(manifest.ReleaseError):
        manifest.verify_checkout(tmp_path, source)
    (tmp_path / "source.txt").write_text("reviewed source")
    (tmp_path / "untracked.py").write_text("new uncommitted implementation")
    with pytest.raises(manifest.ReleaseError):
        manifest.verify_checkout(tmp_path, source)
