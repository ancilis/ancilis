"""AKSI v0.6 shared catalog and activation parity tests."""

from __future__ import annotations

from ancilis.activation.loader import load_control_definitions, load_taxonomy
from ancilis.activation.resolver import ActivationResolver


V06_COMMON_CONTROLS = {
    "GOV-01",
    "GOV-02",
    "GOV-03",
    "GOV-04",
    "GOV-05",
    "GOV-06",
    "GOV-07",
    "ID-01",
    "ID-02",
    "ID-03",
    "ID-04",
    "ID-05",
    "PR-01",
    "PR-02",
    "PR-03",
    "PR-04",
    "PR-05",
    "PR-06",
    "PR-07",
    "PR-08",
    "PR-09",
    "PR-10",
    "PR-11",
    "PR-12",
    "DE-01",
    "DE-02",
    "DE-03",
    "DE-04",
    "DE-05",
    "DE-06",
    "RS-01",
    "RS-02",
    "RS-03",
    "RS-04",
    "RS-05",
    "RS-06",
    "RC-01",
    "RC-02",
    "RC-03",
}

V06_EXTENSION_CONTROLS = {"PAY-01", "PAY-02"}

V06_DATA_CLASSES = {
    "DC-PHI",
    "DC-CHD",
    "DC-SAD",
    "DC-CUI",
    "DC-FCI",
    "DC-MNPI",
    "DC-PII",
    "DC-FIN",
    "DC-NPI",
    "DC-GOV",
    "DC-AI",
    "DC-GEN",
    "DC-ITAR",
    "DC-CRIT",
    "DC-MINOR",
    "DC-BIO",
    "DC-LEGAL",
    "DC-IP",
    "DC-PAY",
    "DC-EDU",
    "DC-CJI",
    "DC-EAR",
    "DC-MEDDEV",
}


def test_catalog_contains_exact_v06_control_set() -> None:
    controls = load_control_definitions()

    assert set(controls) == V06_COMMON_CONTROLS | V06_EXTENSION_CONTROLS
    assert len(controls) == 41


def test_catalog_marks_common_and_extension_controls() -> None:
    controls = load_control_definitions()

    common_ids = {cid for cid, control in controls.items() if control["common"] is True}
    extension_ids = {cid for cid, control in controls.items() if control["common"] is False}

    assert common_ids == V06_COMMON_CONTROLS
    assert extension_ids == V06_EXTENSION_CONTROLS
    assert controls["PAY-01"]["trigger_classifications"] == ["DC-PAY"]
    assert controls["PAY-02"]["trigger_certification_targets"] == ["AGENT_PAYMENTS", "X402"]


def test_activation_defaults_to_common_controls_only() -> None:
    spec = ActivationResolver().resolve()

    assert set(spec.active_controls) == V06_COMMON_CONTROLS
    assert not V06_EXTENSION_CONTROLS.intersection(spec.active_controls)


def test_payment_controls_activate_for_payment_classification() -> None:
    spec = ActivationResolver().resolve(my_agent_handles=["agent_payments"])

    assert set(spec.active_controls) == V06_COMMON_CONTROLS | V06_EXTENSION_CONTROLS
    assert "DC-PAY" in spec.data_classifications
    assert spec.activation_source["PAY-01"] == "classification:DC-PAY"
    assert spec.activation_source["PAY-02"] == "classification:DC-PAY"


def test_payment_controls_activate_for_payment_certification_target() -> None:
    spec = ActivationResolver().resolve(certification_targets=["X402"])

    assert set(spec.active_controls) == V06_COMMON_CONTROLS | V06_EXTENSION_CONTROLS
    assert spec.activation_source["PAY-01"] == "certification_targets:X402"
    assert spec.activation_source["PAY-02"] == "certification_targets:X402"


def test_taxonomy_contains_exact_v06_class_set() -> None:
    taxonomy = load_taxonomy()
    codes = {entry["code"] for entry in taxonomy["classifications"]}

    assert codes == V06_DATA_CLASSES
    assert len(codes) == 23
    assert "DC-Code-Execution" not in codes
    assert "DC-External-API" not in codes


def test_taxonomy_maps_payment_alias_to_dc_pay() -> None:
    taxonomy = load_taxonomy()

    assert taxonomy["developer_type_mapping"]["agent_payments"] == ["DC-PAY"]
