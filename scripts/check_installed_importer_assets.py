"""Run with a wheel/sdist-installed interpreter outside the checkout."""

import importlib
import json
import pkgutil
from pathlib import Path

import ancilis
from ancilis import importers


def main() -> None:
    root = Path(ancilis.__file__).resolve().parent
    if "site-packages" not in root.parts:
        raise RuntimeError("Expected an installed package, not an editable checkout")
    checked = []
    for entry in pkgutil.iter_modules(importers.__path__):
        module = importlib.import_module(f"ancilis.importers.{entry.name}")
        mapping = getattr(module, "_MAPPING_PATH", None)
        if mapping is None:
            continue
        expected = root / "shared" / "mappings" / Path(mapping).name
        if Path(mapping).resolve() != expected.resolve() or not expected.is_file():
            raise RuntimeError(f"Importer does not use its installed mapping: {entry.name}")
        if not isinstance(json.loads(expected.read_text()), dict):
            raise RuntimeError(f"Malformed installed mapping: {entry.name}")
        checked.append(entry.name)
    if len(checked) < 60:
        raise RuntimeError("Importer asset check did not cover the expected modules")
    print(json.dumps({"package": str(root), "mapping_count": len(checked), "modules": checked}))


if __name__ == "__main__":
    main()
