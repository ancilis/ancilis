"""Regression tests for certification_targets consistency (audit finding F5).

The validator, docs, and examples must agree: every certification_targets value
taught in README/docs and shipped in example configs must be a real, validating
target (so it never emits the "unrecognized value" warning). soc2/hipaa/pci/gdpr
are overlay names, activated by data classes — not certification_targets values.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ancilis.config import _load_valid_certification_targets, validate_config

ROOT = Path(__file__).resolve().parents[2]


def _cert_targets_in_markdown(text: str) -> list[str]:
    values: list[str] = []
    # inline form: certification_targets: [aiuc-1, ...]
    for m in re.finditer(r"certification_targets:\s*\[([^\]]*)\]", text):
        values += [v.strip().strip("'\"") for v in m.group(1).split(",") if v.strip()]
    # block form: certification_targets:\n  - aiuc-1
    for m in re.finditer(r"certification_targets:\s*\n((?:\s*-\s*[^\n]+\n?)+)", text):
        for line in m.group(1).splitlines():
            item = line.strip()
            if item.startswith("-"):
                values.append(item[1:].strip().strip("'\""))
    return values


def test_valid_targets_are_the_expected_set() -> None:
    valid = _load_valid_certification_targets()
    # Derived from shared/overlays/certifications/*.json + non-common control
    # trigger_certification_targets (pay-01/pay-02 -> AGENT_PAYMENTS, X402).
    assert valid == {"aiuc-1", "gov-contractor", "AGENT_PAYMENTS", "X402"}, valid
    # Overlay names must NOT be certification targets.
    for not_a_target in ("soc2", "hipaa", "pci-dss-v4", "gdpr"):
        assert not_a_target not in valid


def _doc_surfaces() -> list[Path]:
    files = [ROOT / "README.md"]
    for pattern in ("docs/**/*.md", "docs/**/*.mdx", "examples/**/README.md"):
        files += [
            p
            for p in ROOT.glob(pattern)
            if ".venv" not in p.parts
            and ".worktrees" not in p.parts
            and "node_modules" not in p.parts
        ]
    return sorted(set(files))


def test_readme_and_docs_only_teach_valid_cert_targets() -> None:
    valid = _load_valid_certification_targets()
    offenders: list[str] = []
    for f in _doc_surfaces():
        for value in _cert_targets_in_markdown(f.read_text(encoding="utf-8")):
            if value and value not in valid:
                offenders.append(f"{f.relative_to(ROOT)}: certification_targets value {value!r}")
    assert not offenders, "Invalid certification_targets in docs:\n" + "\n".join(offenders)


def test_example_configs_emit_no_cert_target_warning() -> None:
    offenders: list[str] = []
    for cfg_path in sorted((ROOT / "examples").rglob("ancilis.yaml")):
        if ".venv" in cfg_path.parts:
            continue
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        _config, warnings = validate_config(raw)
        bad = [w for w in warnings if "certification_targets" in w]
        if bad:
            offenders.append(f"{cfg_path.relative_to(ROOT)}: {bad}")
    assert not offenders, "Example configs emit cert-target warnings:\n" + "\n".join(offenders)
