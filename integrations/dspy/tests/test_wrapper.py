"""Tests for ancilis_dspy.wrapper.wrap_lm."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from conftest import MockLM


def test_wrap_lm_proxies_unknown_attributes() -> None:
    from ancilis_dspy import wrap_lm

    lm = MockLM()
    lm.role = "completion-engine"
    wrapped = wrap_lm(lm, agent_id="ag-1")
    assert wrapped.role == "completion-engine"
    assert wrapped.kwargs_attr == "extra-attr-value"
    assert wrapped.model == "openai/gpt-4o-mini"


def test_wrap_lm_records_on_call() -> None:
    from ancilis_dspy import wrap_lm

    lm = MockLM()
    engine = MagicMock()
    store = MagicMock()
    wrapped = wrap_lm(
        lm, agent_id="ag-1", engine=engine, evidence_store=store
    )

    secret_prompt = "user kevin@example.com asked about ssn 999-00-1234"
    out = wrapped(prompt=secret_prompt)
    assert "the answer" in list(out)

    actions = wrapped.captured_actions
    assert len(actions) == 1
    rendered = repr(actions[0].parameters.raw)
    # Prompt content never appears in evidence.
    assert "999-00-1234" not in rendered
    assert "kevin@example.com" not in rendered
    # But its sha256 + length are recorded.
    assert actions[0].parameters.raw["prompt_length"] == len(secret_prompt)
    # Token usage captured.
    assert actions[0].parameters.raw["usage"]["total_tokens"] == 19
    # Engine + store both received the action.
    engine.evaluate.assert_called_once()
    store.append.assert_called_once()


def test_wrap_lm_records_completion_sanitized() -> None:
    from ancilis_dspy import wrap_lm

    secret_completion = "the SSN is 999-00-1234"
    lm = MockLM(response=[secret_completion])
    wrapped = wrap_lm(lm, agent_id="ag-1")
    wrapped(prompt="hi")

    actions = wrapped.captured_actions
    assert len(actions) == 1
    rendered = repr(actions[0].parameters.raw)
    assert "999-00-1234" not in rendered
    assert actions[0].parameters.raw["completion_length"] >= len(secret_completion)


def test_wrap_lm_exception_path_records_error_and_reraises() -> None:
    from ancilis_dspy import wrap_lm

    err = RuntimeError("rate limit")
    lm = MockLM(call_exc=err)
    wrapped = wrap_lm(lm, agent_id="ag-1")
    with pytest.raises(RuntimeError, match="rate limit"):
        wrapped(prompt="x")
    actions = wrapped.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["error_type"] == "RuntimeError"


def test_wrap_lm_observe_only_no_engine_no_store_still_captures() -> None:
    from ancilis_dspy import wrap_lm

    lm = MockLM()
    wrapped = wrap_lm(lm, agent_id="ag-1")  # no engine, no store
    wrapped(prompt="hello")
    assert len(wrapped.captured_actions) == 1


def test_wrap_lm_request_method_path_also_records() -> None:
    from ancilis_dspy import wrap_lm

    lm = MockLM()
    wrapped = wrap_lm(lm, agent_id="ag-1")
    wrapped.request("legacy completion call")
    assert len(wrapped.captured_actions) == 1
    assert wrapped.captured_actions[0].tool.name.startswith("dspy:lm:")


def test_wrap_lm_engine_failure_does_not_propagate() -> None:
    """engine.evaluate raising must not crash the wrapped call."""
    from ancilis_dspy import wrap_lm

    engine = MagicMock()
    engine.evaluate.side_effect = RuntimeError("engine down")
    lm = MockLM()
    wrapped = wrap_lm(lm, agent_id="ag-1", engine=engine)
    out = wrapped(prompt="ping")  # must not raise
    assert "the answer" in list(out)
    assert len(wrapped.captured_actions) == 1


def test_wrap_lm_session_id_passthrough() -> None:
    from ancilis_dspy import wrap_lm

    lm = MockLM()
    wrapped = wrap_lm(lm, agent_id="ag-1", session_id="fixed-session")
    wrapped(prompt="hi")
    assert wrapped.captured_actions[0].context.session_id == "fixed-session"
