"""Tests for the shared custom control definition contract."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from ancilis.config import SHARED_DIR


SCHEMA_PATH = SHARED_DIR / "schemas" / "custom-control.schema.json"
FIXTURE_DIR = SHARED_DIR / "fixtures" / "custom-controls"


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text()))


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = _load_json(SCHEMA_PATH)
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


@pytest.fixture(scope="module")
def regex_fixture() -> dict[str, Any]:
    return _load_json(FIXTURE_DIR / "acme-siem-latency.json")


@pytest.fixture(scope="module")
def manual_fixture() -> dict[str, Any]:
    return _load_json(FIXTURE_DIR / "manual-vendor-review.json")


def _messages_for(validator: Draft7Validator, instance: dict[str, Any]) -> list[str]:
    return [error.message for error in validator.iter_errors(instance)]


def test_regex_custom_control_fixture_validates(
    validator: Draft7Validator, regex_fixture: dict[str, Any]
) -> None:
    assert _messages_for(validator, regex_fixture) == []


def test_manual_custom_control_fixture_validates(
    validator: Draft7Validator, manual_fixture: dict[str, Any]
) -> None:
    assert _messages_for(validator, manual_fixture) == []


def test_bad_custom_control_id_prefix_fails_validation(
    validator: Draft7Validator, regex_fixture: dict[str, Any]
) -> None:
    instance = copy.deepcopy(regex_fixture)
    instance["id"] = "ACME:siem-latency"

    messages = _messages_for(validator, instance)

    assert any("does not match" in message and "custom:" in message for message in messages)


def test_missing_regex_evaluator_config_fails_validation(
    validator: Draft7Validator, regex_fixture: dict[str, Any]
) -> None:
    instance = copy.deepcopy(regex_fixture)
    instance["evaluator"] = {}

    messages = _messages_for(validator, instance)

    assert any("'pattern' is a required property" in message for message in messages)


@pytest.mark.parametrize("reserved_type", ["script", "webhook"])
def test_reserved_evaluator_types_fail_validation(
    validator: Draft7Validator, regex_fixture: dict[str, Any], reserved_type: str
) -> None:
    instance = copy.deepcopy(regex_fixture)
    instance["evaluator_type"] = reserved_type

    messages = _messages_for(validator, instance)

    assert any("'regex', 'manual'" in message for message in messages)
