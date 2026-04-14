"""Custom control registry and safe local evaluators."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from jsonschema import Draft7Validator

from ancilis._shared import shared_path

if TYPE_CHECKING:
    from ancilis.config import ResolvedConfig
    from ancilis.engine.action import Action
    from ancilis.engine.result import ControlResult


SUPPORTED_EVALUATOR_TYPES = {"regex", "manual"}
RESERVED_EVALUATOR_TYPES = {"script", "webhook"}
MAX_REGEX_TARGET_CHARS = 32_768

_SCHEMA_PATH = shared_path("schemas", "custom-control.schema.json")
_VALIDATOR: Draft7Validator | None = None
_CUSTOM_CONTROLS: dict[str, CustomControlDefinition] = {}


@dataclass(frozen=True)
class CustomControlDefinition:
    """Validated custom control definition loaded from the shared schema shape."""

    id: str
    title: str
    description: str
    category: str
    severity: str
    evaluator_type: str
    evaluator: dict[str, Any]
    version: str | None = None
    owner: str | None = None
    framework_references: list[str] = field(default_factory=list)
    overlay_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    evidence_selectors: list[dict[str, Any]] = field(default_factory=list)
    remediation: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> CustomControlDefinition:
        return cls(
            id=str(data["id"]),
            title=str(data["title"]),
            description=str(data["description"]),
            category=str(data["category"]),
            severity=str(data["severity"]),
            evaluator_type=str(data["evaluator_type"]),
            evaluator=dict(data["evaluator"]),
            version=cast(str | None, data.get("version")),
            owner=cast(str | None, data.get("owner")),
            framework_references=list(data.get("framework_references", [])),
            overlay_ids=list(data.get("overlay_ids", [])),
            tags=list(data.get("tags", [])),
            evidence_selectors=list(data.get("evidence_selectors", [])),
            remediation=cast(str | None, data.get("remediation")),
            raw=dict(data),
        )


def _validator() -> Draft7Validator:
    global _VALIDATOR
    if _VALIDATOR is None:
        schema = json.loads(_SCHEMA_PATH.read_text())
        Draft7Validator.check_schema(schema)
        _VALIDATOR = Draft7Validator(schema)
    return _VALIDATOR


def _validate_definition(data: dict[str, Any]) -> None:
    evaluator_type = data.get("evaluator_type")
    if evaluator_type in RESERVED_EVALUATOR_TYPES:
        raise ValueError(
            f"unsupported evaluator_type '{evaluator_type}'; "
            "script and webhook evaluators are reserved and are not executed"
        )

    errors = sorted(_validator().iter_errors(data), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        control_id = data.get("id", "<unknown>")
        raise ValueError(f"invalid custom control {control_id}: {first.message}")


def register_control(
    custom_control: dict[str, Any] | CustomControlDefinition,
    *,
    replace: bool = False,
) -> CustomControlDefinition:
    """Register a schema-valid custom control in the process-local registry."""
    if isinstance(custom_control, CustomControlDefinition):
        data = _definition_to_mapping(custom_control)
    else:
        data = dict(custom_control)
    _validate_definition(data)
    definition = CustomControlDefinition.from_mapping(data)

    if definition.evaluator_type not in SUPPORTED_EVALUATOR_TYPES:
        raise ValueError(f"unsupported evaluator_type '{definition.evaluator_type}'")

    if definition.id in _CUSTOM_CONTROLS and not replace:
        raise ValueError(f"custom control '{definition.id}' is already registered")

    _CUSTOM_CONTROLS[definition.id] = definition
    return definition


def _definition_to_mapping(definition: CustomControlDefinition) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": definition.id,
        "title": definition.title,
        "description": definition.description,
        "category": definition.category,
        "severity": definition.severity,
        "evaluator_type": definition.evaluator_type,
        "evaluator": dict(definition.evaluator),
    }
    if definition.version is not None:
        data["version"] = definition.version
    if definition.owner is not None:
        data["owner"] = definition.owner
    if definition.framework_references:
        data["framework_references"] = list(definition.framework_references)
    if definition.overlay_ids:
        data["overlay_ids"] = list(definition.overlay_ids)
    if definition.tags:
        data["tags"] = list(definition.tags)
    if definition.evidence_selectors:
        data["evidence_selectors"] = list(definition.evidence_selectors)
    if definition.remediation is not None:
        data["remediation"] = definition.remediation
    return data


def list_custom_controls() -> dict[str, CustomControlDefinition]:
    """Return the currently registered process-local custom controls."""
    return dict(_CUSTOM_CONTROLS)


def clear_custom_controls() -> None:
    """Clear custom controls registered in this process.

    This is primarily intended for tests and long-lived development shells.
    """
    _CUSTOM_CONTROLS.clear()


def load_custom_controls_from_directory(
    directory: str | Path,
    *,
    replace: bool = True,
) -> list[str]:
    """Load JSON custom controls from a local `.ancilis/controls` directory."""
    control_dir = Path(directory)
    if not control_dir.exists():
        return []

    warnings: list[str] = []
    for path in sorted(control_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            if not isinstance(data, dict):
                raise ValueError("definition must be a JSON object")
            register_control(cast(dict[str, Any], data), replace=replace)
        except Exception as exc:  # noqa: BLE001 - invalid local controls should not break config loading
            warnings.append(f"Custom control {path.name} skipped: {exc}")
    return warnings


class CustomControlEvaluator:
    """Evaluate a registered custom control using local, non-executable logic."""

    def __init__(self, definition: CustomControlDefinition) -> None:
        self.definition = definition
        self.control_id = definition.id
        self.control_name = definition.title

    def evaluate(self, action: Action, config: ResolvedConfig) -> ControlResult:
        start = time.perf_counter()
        if self.definition.evaluator_type == "regex":
            result = self._evaluate_regex(action)
        elif self.definition.evaluator_type == "manual":
            result = self._evaluate_manual(action)
        else:
            from ancilis.engine.result import ControlResult

            result = ControlResult(
                control_id=self.control_id,
                control_name=self.control_name,
                result="SKIP",
                detail=(
                    f"Custom evaluator type '{self.definition.evaluator_type}' is unsupported."
                ),
                evidence_data={"evaluator_type": self.definition.evaluator_type},
            )
        result.duration_ms = (time.perf_counter() - start) * 1000
        return result

    def _evaluate_regex(self, action: Action) -> ControlResult:
        evaluator = self.definition.evaluator
        pattern = str(evaluator["pattern"])
        target = str(evaluator.get("target", "evidence"))
        pass_when = str(evaluator.get("pass_when", "matches"))
        flags = _compile_regex_flags(evaluator.get("flags", []))

        try:
            regex = re.compile(pattern, flags)
        except re.error as exc:
            return self._result(
                "ERROR",
                f"Invalid custom regex for {self.control_id}: {exc}",
                {"target": target, "evaluator_type": "regex", "error": str(exc)},
            )

        target_text = _target_text(action, target)
        truncated = len(target_text) > MAX_REGEX_TARGET_CHARS
        if truncated:
            target_text = target_text[:MAX_REGEX_TARGET_CHARS]
        matched = regex.search(target_text) is not None
        passed = matched if pass_when == "matches" else not matched
        return self._result(
            "PASS" if passed else "FAIL",
            (
                f"Custom regex control {self.control_id} "
                f"{'matched' if matched else 'did not match'} target '{target}'."
            ),
            {
                "evaluator_type": "regex",
                "target": target,
                "pass_when": pass_when,
                "matched": matched,
                "truncated": truncated,
            },
        )

    def _evaluate_manual(self, action: Action) -> ControlResult:
        evaluator = self.definition.evaluator
        attestation = _manual_attestation(action, self.control_id)
        evidence_data = {
            "evaluator_type": "manual",
            "instructions": evaluator.get("instructions", ""),
            "expected_evidence": list(evaluator.get("expected_evidence", [])),
            "attestation_present": attestation is not None,
        }
        if _attestation_passed(attestation):
            return self._result(
                "PASS",
                f"Manual attestation supplied for {self.control_id}.",
                evidence_data,
            )
        if attestation is not None:
            return self._result(
                "FAIL",
                f"Manual attestation did not pass for {self.control_id}.",
                evidence_data,
            )
        return self._result(
            "SKIP",
            f"Manual attestation required for {self.control_id}.",
            evidence_data,
        )

    def _result(
        self,
        result: str,
        detail: str,
        evidence_data: dict[str, Any],
    ) -> ControlResult:
        if self.definition.remediation:
            evidence_data["remediation"] = self.definition.remediation
        from ancilis.engine.result import ControlResult

        return ControlResult(
            control_id=self.control_id,
            control_name=self.control_name,
            result=result,
            detail=detail,
            evidence_data=evidence_data,
        )


def _compile_regex_flags(flag_names: Any) -> int:
    flag_map = {
        "IGNORECASE": re.IGNORECASE,
        "MULTILINE": re.MULTILINE,
        "DOTALL": re.DOTALL,
    }
    flags = 0
    for name in flag_names or []:
        flags |= flag_map[str(name)]
    return flags


def _target_text(action: Action, target: str) -> str:
    raw = action.parameters.raw
    if target == "tool_name":
        return action.tool.name
    if target == "input_summary":
        return _stringify(raw.get("input_summary", raw.get("input", raw)))
    if target == "output_summary":
        return _stringify(raw.get("output_summary", ""))
    if target == "metadata":
        return _stringify(raw.get("metadata", {}))
    return _stringify(
        {
            "tool_name": action.tool.name,
            "action_type": action.action_type,
            "source_type": action.source_type,
            "producer_type": action.producer_type,
            "parameters": raw,
            "context": {
                "session_id": action.context.session_id,
                "data_classifications": action.context.data_classifications,
                "active_overlays": action.context.active_overlays,
            },
        }
    )


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _manual_attestation(action: Action, control_id: str) -> Any:
    attestations = action.parameters.raw.get("manual_attestations")
    if isinstance(attestations, dict) and control_id in attestations:
        return attestations[control_id]
    return None


def _attestation_passed(attestation: Any) -> bool:
    if attestation is True:
        return True
    if isinstance(attestation, str):
        return attestation.strip().lower() in {"pass", "passed", "true", "attested", "approved"}
    if isinstance(attestation, dict):
        status = attestation.get("status", attestation.get("result"))
        return _attestation_passed(status)
    return False
