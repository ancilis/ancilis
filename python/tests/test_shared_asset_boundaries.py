"""A wheel must use its own assets, never a similarly named ancestor directory."""

from pathlib import Path

import pytest

from ancilis import _shared


def test_packaged_assets_take_precedence_over_ancestor(tmp_path, monkeypatch):
    package = tmp_path / "site-packages" / "ancilis"
    (package / "shared").mkdir(parents=True)
    (tmp_path / "shared").mkdir()
    monkeypatch.setattr(_shared, "files", lambda name: package)
    monkeypatch.setattr(_shared, "__file__", str(package / "_shared.py"))
    assert _shared.shared_root() == package / "shared"


def test_damaged_install_does_not_adopt_ancestor_assets(tmp_path, monkeypatch):
    package = tmp_path / "site-packages" / "ancilis"
    package.mkdir(parents=True)
    (package / "_shared.py").write_text("")
    (tmp_path / "shared").mkdir()
    monkeypatch.setattr(_shared, "files", lambda name: package)
    monkeypatch.setattr(_shared, "__file__", str(package / "_shared.py"))
    with pytest.raises(FileNotFoundError, match="shared"):
        _shared.shared_root()


def test_only_exact_source_checkout_can_use_repo_assets(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    package = root / "python" / "src" / "ancilis"
    package.mkdir(parents=True)
    module = package / "_shared.py"
    module.write_text("")
    (root / "shared").mkdir()
    monkeypatch.setattr(_shared, "files", lambda name: package)
    monkeypatch.setattr(_shared, "__file__", str(module))
    with pytest.raises(FileNotFoundError):
        _shared.shared_root()
    (root / "pyproject.toml").write_text("[project]\nname = 'ancilis'\n")
    assert _shared.shared_root() == root / "shared"


def test_all_importer_mapping_paths_select_canonical_assets():
    import importlib
    import pkgutil

    from ancilis import importers

    checked = 0
    for entry in pkgutil.iter_modules(importers.__path__):
        module = importlib.import_module(f"ancilis.importers.{entry.name}")
        mapping = getattr(module, "_MAPPING_PATH", None)
        if mapping is not None:
            checked += 1
            assert mapping == _shared.shared_path("mappings", Path(mapping).name), entry.name
            assert mapping.is_file(), entry.name
    assert checked >= 60
