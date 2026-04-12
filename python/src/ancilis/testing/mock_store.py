"""MockEvidenceStore — in-memory evidence store for testing."""

from __future__ import annotations

from typing import Any

from ancilis.engine.result import EvaluationResult
from ancilis.evidence.record import EvidenceRecord
from ancilis.evidence.store import EvidenceStore
from ancilis.testing._helpers import make_test_config


class MockEvidenceStore:
    """In-memory evidence store for testing.

    Drop-in replacement for EvidenceStore that uses DuckDB :memory: mode.
    No filesystem writes, no DuckDB files. Safe to use in any test environment.

    Usage::

        from ancilis.testing import MockEvidenceStore

        def test_my_control():
            store = MockEvidenceStore()
            # Evaluate and store evidence
            store.store(evaluation, tool_name="my_tool")
            assert store.count() == 1
    """

    def __init__(
        self,
        agent_name: str = "test-agent",
        mode: str = "audit",
        overlay: str | None = None,
    ) -> None:
        self._config = make_test_config(agent_name=agent_name, mode=mode, overlay=overlay)
        self._store = EvidenceStore(self._config, in_memory=True)

    # --- Delegate the full EvidenceStore interface ---

    def store(
        self,
        evaluation: EvaluationResult,
        tool_name: str = "test_tool",
        output_summary: str | None = None,
    ) -> EvidenceRecord:
        """Store an evaluation result as evidence."""
        return self._store.store(evaluation, tool_name=tool_name, output_summary=output_summary)

    def get_records(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        since: str | None = None,
        limit: int | None = 100,
    ) -> list[EvidenceRecord]:
        """Query evidence records with optional filters."""
        return self._store.get_records(
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            decision=decision,
            since=since,
            limit=limit,
        )

    def count(self, session_id: str | None = None) -> int:
        """Return total number of evidence records."""
        return self._store.count(session_id=session_id)

    def get_summary(
        self,
        since: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate a summary for posture reports."""
        return self._store.get_summary(since=since, session_id=session_id)

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify hash chain integrity. Returns (valid, errors)."""
        return self._store.verify_chain()

    def reset(self) -> int:
        """Delete all records and reset the chain. Returns count deleted."""
        return self._store.reset()

    def close(self) -> None:
        """Close the in-memory DuckDB connection."""
        self._store.close()

    def __enter__(self) -> MockEvidenceStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
