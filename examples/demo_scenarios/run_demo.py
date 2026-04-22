#!/usr/bin/env python3
"""Generate realistic multi-agent evidence for the acquirer demo."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ancilis.cli.export import export_records
from ancilis.config import load_config
from ancilis.demo_orchestration import build_demo_integration_payload
from ancilis.engine.action import Action, ActionContext, ActionParameters, ToolInfo
from ancilis.engine.engine import Engine
from ancilis.engine.registry import ToolEntry, ToolRegistry, ToolStatus
from ancilis.evidence.store import EvidenceStore

from scenarios import code_review, data_pipeline, hr_onboarding, patient_intake, payment_processor
from scenarios.common import DemoCall, DemoScenario

DEMO_START = datetime(2026, 4, 15, 9, 0, tzinfo=timezone.utc)
FULL_TIMELINE_SPAN = timedelta(hours=23, minutes=30)
DEFAULT_DB_PATH = Path.home() / ".ancilis" / "demo-scenarios" / "evidence.duckdb"
SCENARIO_FACTORIES = (
    patient_intake,
    payment_processor,
    code_review,
    hr_onboarding,
    data_pipeline,
)


@dataclass(frozen=True)
class DemoRunResult:
    db_path: Path
    ndjson_path: Path
    agent_count: int
    evidence_count: int
    decisions: dict[str, int]
    pushed: bool = False
    push_result: dict[str, Any] | None = None


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run realistic Ancilis demo scenarios.")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Path to the DuckDB evidence store.")
    parser.add_argument("--output", default=None, help="Path for NDJSON evidence export.")
    parser.add_argument("--fast", action="store_true", help="Run one tool call per agent for recording.")
    parser.add_argument("--push", action="store_true", help="Create/sync an SDK Direct source in the Platform API.")
    parser.add_argument("--keep", action="store_true", help="Append to the existing evidence store instead of resetting it.")
    return parser.parse_args(argv)


def _scenario_config(scenario: DemoScenario):
    return load_config(
        raw={
            "agent": {
                "name": scenario.agent_id,
                "description": f"{scenario.display_name} demo scenario",
                "owner": scenario.agent_owner,
                "llm_provider": scenario.llm_provider,
            },
            "security": {
                "mode": "enforce",
                "tools": {
                    "allowed": list(scenario.allowed_tools),
                    "blocked": list(scenario.blocked_tools),
                },
            },
            "my_agent_handles": list(scenario.handles),
            "certification_targets": list(scenario.certification_targets),
        }
    )


def _tool_hash(scenario: DemoScenario, call: DemoCall) -> str:
    source = f"{scenario.agent_id}:{scenario.architecture}:{call.tool_name}:{call.description}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _registry_for(scenario: DemoScenario, calls: Sequence[DemoCall]) -> ToolRegistry:
    registry = ToolRegistry()
    for call in calls:
        status = ToolStatus.BLOCKED if call.tool_name in scenario.blocked_tools else ToolStatus.APPROVED
        description_hash = None if call.outcome == "FLAG" else _tool_hash(scenario, call)
        registry.register(
            ToolEntry(
                name=call.tool_name,
                description_hash=description_hash,
                status=status,
                approved_by="demo-seed" if status == ToolStatus.APPROVED else None,
            )
        )
    return registry


def _parameter_hash(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(arguments, sort_keys=True, default=str).encode()).hexdigest()


def _action_for(
    scenario: DemoScenario,
    call: DemoCall,
    timestamp: datetime,
    session_id: str,
) -> Action:
    producer_type = scenario.architecture.lower()
    if producer_type == "bedrock":
        producer_type = "http"
    return Action(
        action_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{scenario.agent_id}:{call.tool_name}:{timestamp.isoformat()}")),
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        agent_id=scenario.agent_id,
        source_type=producer_type,
        action_type="tool_call" if producer_type != "http" else "api_request",
        tool=ToolInfo(
            name=call.tool_name,
            server=scenario.architecture,
            description_hash=_tool_hash(scenario, call) if call.outcome != "FLAG" else None,
        ),
        parameters=ActionParameters(raw=call.arguments, parameter_hash=_parameter_hash(call.arguments)),
        agent_owner=scenario.agent_owner,
        context=ActionContext(
            session_id=session_id,
            data_classifications=[],
            active_overlays=[],
        ),
        producer_type=producer_type,
        producer_version="0.1.0-demo",
    )


def _reset_db(db_path: Path) -> None:
    if db_path.parent.exists():
        for artifact in db_path.parent.glob(f"{db_path.name}*"):
            artifact.unlink(missing_ok=True)
    db_path.unlink(missing_ok=True)


def _selected_calls(scenario: DemoScenario, *, fast: bool) -> tuple[DemoCall, ...]:
    if not fast:
        return scenario.calls
    fast_call_indexes = {
        "patient_intake_agent": 2,
        "payment_processor": 3,
        "code_review_agent": 0,
        "hr_onboarding_bot": 1,
        "data_pipeline_agent": 3,
    }
    index = fast_call_indexes.get(scenario.agent_id, 0)
    return (scenario.calls[index],)


def _schedule(count: int, *, fast: bool) -> list[datetime]:
    if count <= 0:
        return []
    if fast:
        return [DEMO_START + timedelta(seconds=index) for index in range(count)]
    if count == 1:
        return [DEMO_START]
    step = FULL_TIMELINE_SPAN / (count - 1)
    return [DEMO_START + step * index for index in range(count)]


def _apply_demo_outcome(evaluation, call: DemoCall, timestamp: datetime) -> None:  # type: ignore[no-untyped-def]
    evaluation.timestamp = timestamp.isoformat().replace("+00:00", "Z")
    detected = set(evaluation.detected_data_types)
    detected.update(call.detected_data_types)
    evaluation.detected_data_types = sorted(detected)
    if call.outcome == "FLAG":
        evaluation.decision = "FLAG"
        evaluation.decision_reason = call.reason
    elif call.outcome == "BLOCK" and evaluation.decision != "BLOCK":
        evaluation.decision = "BLOCK"
        evaluation.decision_reason = call.reason


def _run_scenario(
    scenario: DemoScenario,
    calls: Sequence[DemoCall],
    timestamps: Sequence[datetime],
    store: EvidenceStore,
) -> dict[str, int]:
    config = _scenario_config(scenario)
    registry = _registry_for(scenario, calls)
    engine = Engine(config, registry=registry, evidence_store=store)
    session_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"ancilis-demo:{scenario.agent_id}"))
    decisions: dict[str, int] = {}

    for call, timestamp in zip(calls, timestamps, strict=True):
        action = _action_for(scenario, call, timestamp, session_id)
        action.context.data_classifications = [
            code
            for codes in config.data_classifications.values()
            for code in codes
        ]
        action.context.active_overlays = list(config.active_overlays.keys())
        evaluation = engine.evaluate(action)
        _apply_demo_outcome(evaluation, call, timestamp)
        store._config = config  # Store per-agent overlay/certification metadata in the same DB.
        store._certifications = list(config.active_certifications)
        store.store(evaluation, tool_name=call.tool_name, output_summary=call.response)
        decisions[evaluation.decision] = decisions.get(evaluation.decision, 0) + 1

    return decisions


def _build_push_request(url: str, token: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> urllib.request.Request:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    return urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )


def _read_json(request: urllib.request.Request) -> dict[str, Any]:
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _push_to_platform(db_path: Path) -> dict[str, Any]:
    api_url = os.environ.get("ANCILIS_PLATFORM_URL")
    token = os.environ.get("ANCILIS_API_KEY")
    if not api_url or not token:
        raise RuntimeError("Set ANCILIS_PLATFORM_URL and ANCILIS_API_KEY before using --push.")

    base = api_url.rstrip("/")
    payload = build_demo_integration_payload(db_path, name="Acquirer Demo SDK Scenarios")
    integrations = _read_json(_build_push_request(f"{base}/v1/integrations", token))
    integration_id = None
    for item in integrations.get("items", []):
        if item.get("name") == payload["name"] and item.get("source_type") == "sdk_direct":
            integration_id = item.get("id")
            break

    if integration_id is None:
        created = _read_json(_build_push_request(f"{base}/v1/integrations", token, method="POST", payload=payload))
        integration_id = created["id"]

    sync = _read_json(_build_push_request(f"{base}/v1/integrations/{integration_id}/sync", token, method="POST"))
    return {"integration_id": integration_id, "sync": sync}


def run_demo(*, db_path: Path, ndjson_path: Path, fast: bool, keep: bool, push: bool) -> DemoRunResult:
    scenarios = [factory() for factory in SCENARIO_FACTORIES]
    if not keep:
        _reset_db(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    all_calls: list[tuple[DemoScenario, DemoCall]] = [
        (scenario, call)
        for scenario in scenarios
        for call in _selected_calls(scenario, fast=fast)
    ]
    timestamps = _schedule(len(all_calls), fast=fast)
    first_config = _scenario_config(scenarios[0])
    store = EvidenceStore(first_config, db_path=db_path)
    decisions: dict[str, int] = {}

    try:
        offset = 0
        for scenario in scenarios:
            calls = _selected_calls(scenario, fast=fast)
            scenario_times = timestamps[offset : offset + len(calls)]
            offset += len(calls)
            for decision, count in _run_scenario(scenario, calls, scenario_times, store).items():
                decisions[decision] = decisions.get(decision, 0) + count

        valid, errors = store.verify_chain()
        if not valid:
            raise RuntimeError(f"Generated evidence chain is invalid: {errors}")
    finally:
        store.close()

    export_records(
        fmt="ndjson",
        since=DEMO_START.isoformat().replace("+00:00", "Z"),
        config_path=None,
        db_path=str(db_path),
        output_path=str(ndjson_path),
        session_id=None,
        quiet=True,
    )

    push_result = _push_to_platform(db_path) if push else None
    return DemoRunResult(
        db_path=db_path,
        ndjson_path=ndjson_path,
        agent_count=len(scenarios),
        evidence_count=len(all_calls),
        decisions=decisions,
        pushed=push,
        push_result=push_result,
    )


def _print_summary(result: DemoRunResult, *, fast: bool) -> None:
    print("Ancilis acquirer demo scenarios")
    print(f"Generated {result.agent_count} demo agents and {result.evidence_count} evidence records.")
    print(f"Mode: {'fast recording' if fast else '24-hour simulated timeline'}")
    print(f"Evidence store: {result.db_path}")
    print(f"NDJSON export: {result.ndjson_path}")
    print("Agents:")
    for factory in SCENARIO_FACTORIES:
        scenario = factory()
        print(f"  - {scenario.agent_id}: {scenario.architecture}, handles {', '.join(scenario.handles)}")
    print("Decisions: " + ", ".join(f"{key}={value}" for key, value in sorted(result.decisions.items())))
    if result.pushed:
        print(f"Platform sync: {json.dumps(result.push_result, sort_keys=True)}")
    else:
        print("Push to platform: set ANCILIS_PLATFORM_URL and ANCILIS_API_KEY, then rerun with --push.")


def main(argv: Sequence[str] | None = None) -> DemoRunResult:
    args = _parse_args(argv)
    db_path = Path(args.db).expanduser().resolve()
    ndjson_path = Path(args.output).expanduser().resolve() if args.output else db_path.with_suffix(".ndjson")
    result = run_demo(
        db_path=db_path,
        ndjson_path=ndjson_path,
        fast=args.fast,
        keep=args.keep,
        push=args.push,
    )
    _print_summary(result, fast=args.fast)
    return result


if __name__ == "__main__":
    main()
