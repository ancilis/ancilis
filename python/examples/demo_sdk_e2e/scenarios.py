"""Synthetic sensitive-data scenarios for the SDK E2E demo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from toy_agent import AgentRun, DemoLangChainAgent


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    run: AgentRun
    expected_detected: tuple[str, ...]


class ScenarioMismatch(RuntimeError):
    """Raised when production classification output differs from this demo spec."""


def _assert_detected(
    *,
    scenario_name: str,
    result: ScenarioResult,
) -> None:
    actual = tuple(result.run.evidence_record.detected_data_types)
    expected = result.expected_detected
    if actual != expected:
        raise ScenarioMismatch(
            f"{scenario_name}: expected detected_data_types={list(expected)!r}, "
            f"got {list(actual)!r}"
        )


def scenario_benign(agent: DemoLangChainAgent) -> ScenarioResult:
    """Expected: tool call succeeds, evidence recorded, no classification fires."""
    run = agent.run(
        "benign",
        {"name": "John Smith", "account_id": "ACME-001"},
    )
    result = ScenarioResult("Benign Request", run, ())
    _assert_detected(scenario_name="scenario_benign", result=result)
    return result


def scenario_pii(agent: DemoLangChainAgent) -> ScenarioResult:
    """Expected: DC-PII classification fires and evidence records metadata."""
    run = agent.run(
        "pii",
        {"name": "Jane Doe", "ssn": "123-45-6789", "dob": "1985-03-15"},
    )
    result = ScenarioResult("PII Detected", run, ("DC-PII",))
    _assert_detected(scenario_name="scenario_pii", result=result)
    return result


def scenario_chd(agent: DemoLangChainAgent) -> ScenarioResult:
    """Expected: DC-CHD classification fires for PCI-DSS cardholder data scope."""
    run = agent.run(
        "chd",
        {"customer": "Acme Corp", "card": "4111-1111-1111-1111", "amount": 250.00},
    )
    result = ScenarioResult("Cardholder Data Detected", run, ("DC-CHD",))
    _assert_detected(scenario_name="scenario_chd", result=result)
    return result


def describe_result(result: ScenarioResult) -> list[str]:
    record = result.run.evidence_record
    detected = ", ".join(record.detected_data_types) or "none"
    declared = ", ".join(record.data_classifications) or "none"
    return [
        f"Tool summary: {result.run.summary}",
        f"Evidence ID: {record.record_id}",
        f"Decision: {record.decision}",
        f"Detected data types: {detected}",
        f"Declared data classifications: {declared}",
        f"Tool name: {record.tool_name}",
    ]


def blocker_payload(exc: Exception, *, records: list[dict[str, Any]] | None = None) -> str:
    lines = [
        "# Ancilis SDK E2E Demo Blockers",
        "",
        "The demo stopped because production SDK behavior did not match the scenario contract.",
        "",
        f"Error: {exc}",
    ]
    if records:
        lines.extend(["", "Observed evidence classifications:"])
        for record in records:
            lines.append(
                "- "
                f"{record.get('record_id')}: "
                f"detected_data_types={record.get('detected_data_types')} "
                f"data_classifications={record.get('data_classifications')}"
            )
    lines.append("")
    return "\n".join(lines)
