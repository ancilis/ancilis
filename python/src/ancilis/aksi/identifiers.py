"""AKSI control identifier boundaries."""

AKSI_PREFIX = "AKSI-"
AKSI_LEGACY_PREFIX = "AKSI_"


def is_prefixed(control_id: str) -> bool:
    return control_id.startswith(AKSI_PREFIX) or control_id.startswith(AKSI_LEGACY_PREFIX)


def unprefix(control_id: str) -> str:
    if control_id.startswith(AKSI_LEGACY_PREFIX):
        return control_id[len(AKSI_LEGACY_PREFIX) :]
    return control_id.removeprefix(AKSI_PREFIX)


def prefix(control_id: str) -> str:
    return f"{AKSI_PREFIX}{unprefix(control_id)}"
