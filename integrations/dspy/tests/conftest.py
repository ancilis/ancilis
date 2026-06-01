"""Shared test fixtures for ancilis-dspy tests.

The producer is duck-typed and never imports ``dspy``. To keep the test
suite fast and dep-free, we provide minimal mock LM / Module / Example /
Prediction objects that mimic the surface of the dspy public API we
record from.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Make the package importable without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# dspy.Example / dspy.Prediction mocks
# ---------------------------------------------------------------------------


class MockExample:
    """Mimics ``dspy.Example`` — a field-value container backed by ``_store``."""

    def __init__(self, **fields: Any) -> None:
        self._store = dict(fields)

    def __repr__(self) -> str:
        return f"MockExample({self._store!r})"

    def items(self) -> Any:
        return self._store.items()


class MockPrediction:
    """Mimics ``dspy.Prediction`` — same field-store shape as Example."""

    def __init__(self, **fields: Any) -> None:
        self._store = dict(fields)

    def __repr__(self) -> str:
        return f"MockPrediction({self._store!r})"

    def items(self) -> Any:
        return self._store.items()


# ---------------------------------------------------------------------------
# dspy.LM mock — duck-typed call surface (``__call__`` and ``request``).
# ---------------------------------------------------------------------------


class MockLM:
    """Mimics a ``dspy.LM`` for the call paths the wrapper instruments."""

    def __init__(
        self,
        *,
        model: str = "openai/gpt-4o-mini",
        response: Any = None,
        usage: dict[str, int] | None = None,
        call_exc: BaseException | None = None,
    ) -> None:
        self.model = model
        self._response = response if response is not None else ["the answer"]
        self._usage = usage or {
            "prompt_tokens": 12,
            "completion_tokens": 7,
            "total_tokens": 19,
        }
        self._call_exc = call_exc
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.kwargs_attr = "extra-attr-value"

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        if self._call_exc is not None:
            raise self._call_exc
        # Mirror dspy.LM: return list-of-strings + a usage attr on the
        # response object. We use a small wrapper to attach .usage.
        return _Response(self._response, self._usage)

    def request(self, *args: Any, **kwargs: Any) -> Any:
        return self.__call__(*args, **kwargs)


class _Response(list):
    """A list-of-completion-strings with a ``usage`` attribute attached."""

    def __init__(self, content: Any, usage: dict[str, int]) -> None:
        if isinstance(content, list):
            super().__init__(content)
        else:
            super().__init__([content])
        self.usage = usage
        # Also expose the joined text for ease of consumption.
        self.text = "".join(str(c) for c in self)


# ---------------------------------------------------------------------------
# dspy.Module mock — for callback module-surface tests.
# ---------------------------------------------------------------------------


class MockModule:
    """Mimics a ``dspy.Module`` instance — only ``__name__``-like attrs matter."""

    def __init__(self, name: str = "ChainOfThought") -> None:
        self.__name__ = name


class MockEvaluate:
    """Mimics a ``dspy.evaluate.Evaluate`` instance for the callback hooks."""

    def __init__(
        self,
        *,
        metric: Any = None,
        devset: list[Any] | None = None,
    ) -> None:
        self.metric = metric
        self.devset = devset or []


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_lm() -> MockLM:
    return MockLM()


@pytest.fixture
def mock_example_with_pii() -> MockExample:
    return MockExample(
        question="What's the SSN for record 4111111111111111?",
        context="user kevin@example.com asked yesterday",
    )


@pytest.fixture
def mock_prediction_with_pii() -> MockPrediction:
    return MockPrediction(
        answer="The SSN is 999-00-9999",
        rationale="Looked it up in the secret ledger",
    )


@pytest.fixture
def mock_trainset_with_pii() -> list[MockExample]:
    return [
        MockExample(q="ssn 111-22-3333", a="redacted"),
        MockExample(q="email kevin@example.com", a="redacted"),
        MockExample(q="card 4111111111111111", a="redacted"),
    ]


def _metric_accuracy(example: Any, pred: Any, trace: Any = None) -> float:
    """A toy metric for evaluate-callback tests."""
    return 1.0


@pytest.fixture
def mock_evaluate() -> MockEvaluate:
    return MockEvaluate(
        metric=_metric_accuracy,
        devset=[MockExample(q=f"q{i}", a=f"a{i}") for i in range(5)],
    )
