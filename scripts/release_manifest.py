#!/usr/bin/env python3
"""Closed release archives and immutable registry comparison; never publishes."""

from __future__ import annotations

import argparse
import base64
import email.parser
import hashlib
import importlib.metadata
import json
import io
import os
import platform
import re
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MANIFEST = "release-manifest.json"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_FILES = 10000


class ReleaseError(ValueError):
    """Release evidence is missing, ambiguous or different."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def parse(data):
    try:
        return json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError("Non-finite JSON")),
        )
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError("Invalid release JSON") from exc


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path):
    require(not path.is_symlink() and path.is_file(), "Expected a regular release file")
    require(path.stat().st_size <= MAX_ARCHIVE, "Release file too large")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Expected a regular release file")
        raw = stream.read(MAX_ARCHIVE + 1)
        require(len(raw) <= MAX_ARCHIVE, "Release file too large")
        return raw


def names(kind, version):
    require(
        re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version) is not None,
        "Expected stable version",
    )
    require(kind in ("python", "npm"), "Unknown package kind")
    return (
        [f"ancilis-{version}-py3-none-any.whl", f"ancilis-{version}.tar.gz"]
        if kind == "python"
        else [f"ancilis-{version}.tgz"]
    )


def role(name):
    if PurePosixPath(name).name == "LICENSE":
        return "license"
    if "/schemas/" in name:
        return "schema"
    if "/shared/" in name:
        return "asset"
    return "package"


def inventory(path, kind, version, raw=None):
    raw = read_regular(path) if raw is None else raw
    files, contents = {}, {}
    total = 0

    def add(name, data):
        nonlocal total
        parts = PurePosixPath(name).parts
        require(
            not name.startswith("/")
            and "\\" not in name
            and all(p not in ("..", ".", ".git", ".release-private", ".env") for p in parts),
            "Unsafe archive path",
        )
        require(
            str(PurePosixPath(name)) == name and name not in files,
            "Duplicate or noncanonical archive path",
        )
        require(len(files) < MAX_FILES and len(data) <= MAX_MEMBER, "Archive limit exceeded")
        total += len(data)
        require(total <= MAX_ARCHIVE, "Expanded archive limit exceeded")
        files[name] = {"size": len(data), "sha256": sha(data), "role": role(name)}
        if name.endswith(("/METADATA", "/PKG-INFO", "/package.json")):
            contents[name] = data

    try:
        if path.suffix == ".whl":
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for member in archive.infolist():
                    require(
                        not stat.S_ISLNK(member.external_attr >> 16), "Archive links are forbidden"
                    )
                    if member.is_dir():
                        continue
                    require(member.file_size <= MAX_MEMBER, "Archive member too large")
                    add(member.filename, archive.read(member))
            metadata_path = f"ancilis-{version}.dist-info/METADATA"
        else:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                for member in archive:
                    require(
                        member.isfile() or member.isdir(),
                        "Archive links and special files are forbidden",
                    )
                    if member.isdir():
                        continue
                    require(member.size <= MAX_MEMBER, "Archive member too large")
                    stream = archive.extractfile(member)
                    require(stream is not None, "Missing member body")
                    add(member.name, stream.read(MAX_MEMBER + 1))
            metadata_path = (
                "package/package.json" if kind == "npm" else f"ancilis-{version}/PKG-INFO"
            )
        require(metadata_path in contents, "Missing package metadata")
        if kind == "npm":
            metadata = parse(contents[metadata_path])
            require(
                metadata.get("name") == "ancilis" and metadata.get("version") == version,
                "Package metadata mismatch",
            )
        else:
            metadata = email.parser.BytesParser().parsebytes(contents[metadata_path])
            require(
                metadata.get_all("Name") == ["ancilis"]
                and metadata.get_all("Version") == [version],
                "Package metadata mismatch",
            )
        require(any(v["role"] == "license" for v in files.values()), "Missing LICENSE")
        require(
            any(v["role"] in ("asset", "schema") for v in files.values()), "Missing shared assets"
        )
        return dict(sorted(files.items()))
    except (
        OSError,
        EOFError,
        tarfile.TarError,
        zipfile.BadZipFile,
        KeyError,
        AttributeError,
    ) as exc:
        raise ReleaseError("Invalid release archive") from exc


def describe(directory, kind, version):
    expected = names(kind, version)
    require(
        {p.name for p in directory.iterdir()} - {MANIFEST} == set(expected),
        "Missing or extra release files",
    )
    result = []
    for name in expected:
        path = directory / name
        data = read_regular(path)
        result.append(
            {
                "filename": name,
                "size": len(data),
                "sha256": sha(data),
                "files": inventory(path, kind, version, data),
            }
        )
    return result


def create_manifest(directory, kind, version, source, toolchain):
    require(re.fullmatch("[0-9a-f]{40}", source) is not None, "Invalid source commit")
    require(
        isinstance(toolchain, dict)
        and all(
            isinstance(k, str) and isinstance(v, str) and len(v) <= 256
            for k, v in toolchain.items()
        ),
        "Invalid toolchain",
    )
    require(not (directory / MANIFEST).exists(), "Refusing to replace a frozen manifest")
    data = {
        "schema": 1,
        "kind": kind,
        "name": "ancilis",
        "version": version,
        "source": source,
        "toolchain": toolchain,
        "artifacts": describe(directory, kind, version),
    }
    (directory / MANIFEST).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def verify_manifest(directory, kind, version, source, expected_digest):
    require(
        re.fullmatch("[0-9a-f]{64}", expected_digest) is not None, "Missing build manifest digest"
    )
    raw = read_regular(directory / MANIFEST)
    require(sha(raw) == expected_digest, "Manifest differs from verified build")
    data = parse(raw)
    require(
        isinstance(data, dict)
        and set(data) == {"schema", "kind", "name", "version", "source", "toolchain", "artifacts"},
        "Malformed manifest",
    )
    require(
        type(data["schema"]) is int
        and data["schema"] == 1
        and data["kind"] == kind
        and data["name"] == "ancilis"
        and data["version"] == version
        and data["source"] == source,
        "Release identity mismatch",
    )
    require(re.fullmatch("[0-9a-f]{40}", source) is not None, "Invalid source commit")
    require(
        isinstance(data["toolchain"], dict)
        and all(
            isinstance(k, str) and isinstance(v, str) and len(v) <= 256
            for k, v in data["toolchain"].items()
        ),
        "Invalid toolchain",
    )
    require(
        json.dumps(data["artifacts"], sort_keys=True)
        == json.dumps(describe(directory, kind, version), sort_keys=True),
        "Release artifact contents changed",
    )
    return data


def registry_state(manifest, directory, response):
    if response is None:
        return "absent"
    try:
        version = manifest["version"]
        if manifest["kind"] == "python":
            require(
                response["info"]["name"] == "ancilis" and response["info"]["version"] == version,
                "Registry identity mismatch",
            )
            records = response["urls"]
            require(isinstance(records, list), "Invalid registry file list")
            actual = {r["filename"]: r["digests"]["sha256"] for r in records}
            require(len(actual) == len(records), "Duplicate registry file")
            require(
                actual == {a["filename"]: a["sha256"] for a in manifest["artifacts"]},
                "Existing PyPI release differs or is partial",
            )
        else:
            require(
                response["name"] == "ancilis" and response["version"] == version,
                "Registry identity mismatch",
            )
            name = names("npm", version)[0]
            expected = (
                "sha512-"
                + base64.b64encode(hashlib.sha512(read_regular(directory / name)).digest()).decode()
            )
            require(response["dist"]["integrity"] == expected, "Existing npm release differs")
            require(
                response["dist"]["tarball"] == f"https://registry.npmjs.org/ancilis/-/{name}",
                "Unexpected registry tarball origin",
            )
        return "identical"
    except (KeyError, TypeError) as exc:
        raise ReleaseError("Malformed registry response") from exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ReleaseError("Unexpected registry redirect")


def registry_read(kind, version):
    names(kind, version)
    url = (
        f"https://pypi.org/pypi/ancilis/{version}/json"
        if kind == "python"
        else f"https://registry.npmjs.org/ancilis/{version}"
    )
    try:
        request = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "ancilis-release-verifier"}
        )
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            require(response.status == 200, "Unexpected registry response")
            raw = response.read(MAX_ARCHIVE + 1)
            require(len(raw) <= MAX_ARCHIVE, "Registry response too large")
            return parse(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError(f"Registry read failed: HTTP {exc.code}") from None
    except (OSError, urllib.error.URLError) as exc:
        raise ReleaseError("Registry unavailable; publication refused") from exc


def verify_checkout(checkout, source):
    actual_source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
    ).strip()
    require(actual_source == source, "Manifest source is not the checked-out commit")
    require(
        subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--"], cwd=checkout, check=False
        ).returncode
        == 0,
        "Cannot freeze a release manifest from modified tracked source",
    )
    require(
        not subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard"], cwd=checkout
        ).strip(),
        "Cannot freeze a release manifest with untracked source",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["create", "verify", "registry"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--kind", choices=["python", "npm"], required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--digest")
    parser.add_argument("--require-identical", action="store_true")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "create":
            checkout = Path(__file__).resolve().parents[1]
            verify_checkout(checkout, args.source)
            toolchain = {"python": platform.python_version()}
            for distribution in ("pip", "build", "twine"):
                try:
                    toolchain[distribution] = importlib.metadata.version(distribution)
                except importlib.metadata.PackageNotFoundError:
                    toolchain[distribution] = "not-installed"
            compiler = checkout / "node_modules/typescript/package.json"
            if compiler.is_file():
                toolchain["typescript"] = parse(compiler.read_bytes())["version"]
            for executable in ("node", "npm"):
                toolchain[executable] = subprocess.check_output(
                    [executable, "--version"], text=True
                ).strip()
            create_manifest(args.directory, args.kind, args.version, args.source, toolchain)
            digest = sha(read_regular(args.directory / MANIFEST))
            print(digest)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                    output.write(f"manifest_sha256={digest}\n")
        else:
            data = verify_manifest(
                args.directory, args.kind, args.version, args.source, args.digest or ""
            )
            if args.operation == "registry":
                response = registry_read(args.kind, args.version)
                state = registry_state(data, args.directory, response)
                require(
                    not args.require_identical or state == "identical",
                    "Published artifact not found",
                )
                if args.evidence:
                    args.evidence.write_text(
                        json.dumps(
                            {
                                "state": state,
                                "manifest_sha256": args.digest,
                                "registry_response_sha256": sha(
                                    json.dumps(response, sort_keys=True).encode()
                                ),
                            },
                            indent=2,
                        )
                        + "\n"
                    )
                print(state)
                if os.environ.get("GITHUB_OUTPUT"):
                    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                        output.write(f"state={state}\n")
            else:
                print("Verified exact release archives and manifest")
    except ReleaseError as exc:
        parser.exit(1, f"Release verification failed: {exc}\n")


if __name__ == "__main__":
    main()
