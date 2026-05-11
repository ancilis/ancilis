from ancilis.aksi.identifiers import is_prefixed, prefix, unprefix


def test_prefix_adds_aksi_namespace() -> None:
    assert prefix("PR-04") == "AKSI-PR-04"


def test_prefix_is_idempotent_for_prefixed_ids() -> None:
    assert prefix("AKSI-PR-04") == "AKSI-PR-04"


def test_unprefix_removes_hyphenated_aksi_namespace() -> None:
    assert unprefix("AKSI-PR-04") == "PR-04"


def test_unprefix_accepts_legacy_underscore_namespace() -> None:
    assert unprefix("AKSI_PR-04") == "PR-04"


def test_is_prefixed_identifies_product_facing_ids() -> None:
    assert is_prefixed("AKSI-PR-04") is True
    assert is_prefixed("PR-04") is False
