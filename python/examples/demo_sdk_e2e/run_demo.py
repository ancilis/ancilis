"""Orchestrate the Ancilis SDK E2E demo recording."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import os
import shutil
import subprocess
import sys
import time

from scenarios import (
    ScenarioMismatch,
    blocker_payload,
    describe_result,
    scenario_benign,
    scenario_chd,
    scenario_pii,
)
from toy_agent import DemoLangChainAgent, SUMMARY_PATH


DEMO_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEMO_DIR.parents[2]
VENV_ANCILIS = REPO_ROOT / ".venv" / "bin" / "ancilis"
ANCILIS_BIN = str(VENV_ANCILIS) if VENV_ANCILIS.exists() else "ancilis"
DB_PATH = DEMO_DIR / "demo_evidence.duckdb"
BLOCKERS_PATH = Path("/tmp/ancilis_sdk_demo_blockers.md")


def title_card(title: str) -> None:
    print(flush=True)
    figlet = shutil.which("figlet")
    if figlet:
        subprocess.run([figlet, title], check=False)
        return
    line = "=" * (len(title) + 8)
    print(line, flush=True)
    print(f"=== {title} ===", flush=True)
    print(line, flush=True)


def pause() -> None:
    time.sleep(2)


def reset_demo_files() -> None:
    for path in (DB_PATH, DB_PATH.with_suffix(DB_PATH.suffix + ".wal"), SUMMARY_PATH):
        if path.exists():
            path.unlink()
    if BLOCKERS_PATH.exists():
        BLOCKERS_PATH.unlink()


def run_cli(command: list[str]) -> None:
    print(flush=True)
    display = ["ancilis", *command[1:]] if command and command[0] == ANCILIS_BIN else command
    print("$ " + " ".join(display), flush=True)
    env = {
        **os.environ,
        "ANCILIS_TELEMETRY_DISABLE_PROMPT": "1",
        "DO_NOT_TRACK": "1",
    }
    subprocess.run(command, cwd=DEMO_DIR, env=env, check=True)


def _records_for_blocker(agent: DemoLangChainAgent) -> list[dict[str, object]]:
    return [
        {
            "record_id": record.record_id,
            "tool_name": record.tool_name,
            "detected_data_types": record.detected_data_types,
            "data_classifications": record.data_classifications,
        }
        for record in agent.store.get_records(limit=None)
    ]


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    reset_demo_files()
    started = time.perf_counter()
    agent = DemoLangChainAgent(db_path=DB_PATH)
    pii_record_id = ""

    try:
        scenario_plan = [
            ("Scenario 1: Benign Request", scenario_benign),
            ("Scenario 2: PII Detected (DC-PII)", scenario_pii),
            ("Scenario 3: Cardholder Data Detected (DC-CHD / PCI-DSS)", scenario_chd),
        ]

        for title, scenario in scenario_plan:
            title_card(title)
            result = scenario(agent)
            for line in describe_result(result):
                print(line)
            if scenario is scenario_pii:
                pii_record_id = result.run.evidence_record.record_id
            pause()

        agent.store.close()

        title_card("EVIDENCE INSPECTION")
        db_arg = "./demo_evidence.duckdb"
        run_cli([ANCILIS_BIN, "evidence", "list", "--limit", "10", "--db", db_arg])
        pause()
        run_cli([ANCILIS_BIN, "evidence", "show", pii_record_id[:7], "--db", db_arg])
        pause()
        run_cli([ANCILIS_BIN, "certify", "--target", "soc2", "--db", db_arg])

        elapsed = time.perf_counter() - started
        title_card("DEMO COMPLETE")
        print(f"Recorded command runtime: {elapsed:.1f}s")
        print(f"Evidence database: {DB_PATH}")
        print(f"PII evidence record: {pii_record_id}")
        return 0
    except (ScenarioMismatch, subprocess.CalledProcessError, Exception) as exc:
        records = []
        try:
            records = _records_for_blocker(agent)
        except Exception:
            records = []
        BLOCKERS_PATH.write_text(blocker_payload(exc, records=records), encoding="utf-8")
        print(f"DEMO BLOCKED: {exc}", file=sys.stderr)
        print(f"Wrote blocker report: {BLOCKERS_PATH}", file=sys.stderr)
        return 1
    finally:
        agent.close()


if __name__ == "__main__":
    raise SystemExit(main())
