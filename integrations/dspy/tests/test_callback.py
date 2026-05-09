"""Tests for ancilis_dspy.callback.AncilisCallback."""

from __future__ import annotations

from unittest.mock import MagicMock

from conftest import MockEvaluate, MockExample, MockLM, MockModule, MockPrediction


def _callback(**kwargs):
    from ancilis_dspy import AncilisCallback

    return AncilisCallback(**kwargs)


def test_on_module_start_emits_action_with_sanitized_inputs() -> None:
    cb = _callback(agent_id="dspy-1")
    inputs = MockExample(question="ssn 999-00-1234?", context="ctx")
    cb.on_module_start("call-1", MockModule("ChainOfThought"), inputs)

    actions = cb.captured_actions
    assert len(actions) == 1
    assert actions[0].action_type == "tool_call"
    assert actions[0].tool.name == "dspy:module:ChainOfThought"
    rendered = repr(actions[0].parameters.raw)
    assert "999-00-1234" not in rendered
    assert actions[0].parameters.raw["inputs"]["field_count"] == 2


def test_on_module_end_emits_action_with_sanitized_outputs() -> None:
    cb = _callback()
    outputs = MockPrediction(answer="leak: 4111111111111111", rationale="x")
    cb.on_module_end("call-1", outputs=outputs)

    actions = cb.captured_actions
    assert len(actions) == 1
    rendered = repr(actions[0].parameters.raw)
    assert "4111111111111111" not in rendered
    assert actions[0].parameters.raw["outputs"]["field_count"] == 2


def test_on_lm_start_and_end_emit_actions_with_prompt_completion_sanitized() -> None:
    cb = _callback()
    lm = MockLM()
    secret_prompt = "user 4111111111111111 records"
    cb.on_lm_start(
        "lm-1",
        lm,
        {"prompt": secret_prompt, "messages": None},
    )
    cb.on_lm_end(
        "lm-1",
        outputs={
            "text": "the answer is 999-00-9999",
            "usage": {"total_tokens": 50},
        },
    )

    actions = cb.captured_actions
    assert len(actions) == 2
    rendered = repr([a.parameters.raw for a in actions])
    assert "4111111111111111" not in rendered
    assert "999-00-9999" not in rendered
    # lm_end carries usage.
    end_action = actions[1]
    assert end_action.parameters.raw["usage"]["total_tokens"] == 50


def test_on_evaluate_start_and_end_emit_actions_with_score(
    mock_evaluate: MockEvaluate,
) -> None:
    cb = _callback()
    cb.on_evaluate_start("ev-1", mock_evaluate, {"devset": mock_evaluate.devset})
    cb.on_evaluate_end("ev-1", outputs={"score": 0.84})

    actions = cb.captured_actions
    assert len(actions) == 2
    start = actions[0]
    end = actions[1]
    assert start.tool.name.startswith("dspy:evaluate:")
    assert start.parameters.raw["dataset_size"] == 5
    assert end.parameters.raw["score"] == 0.84


def test_call_id_correlation_lm_inside_module() -> None:
    """LM events emitted inside a module hook should carry the module's call_id."""
    cb = _callback()
    cb.on_module_start("mod-1", MockModule("Predict"), MockExample(q="hi"))
    cb.on_lm_start("lm-1", MockLM(), {"prompt": "hi"})
    cb.on_lm_end("lm-1", outputs={"text": "ok"})
    cb.on_module_end("mod-1", outputs=MockPrediction(a="ok"))

    actions = cb.captured_actions
    assert len(actions) == 4
    # The lm_start action's parent should be the module's call_id.
    lm_start = next(
        a for a in actions if a.parameters.raw["kind"] == "lm_start"
    )
    assert lm_start.context.parent_action_id == "mod-1"
    # The lm_end action's parent should also be the module's call_id (the
    # lm_start's call_id was popped by on_lm_end).
    lm_end = next(
        a for a in actions if a.parameters.raw["kind"] == "lm_end"
    )
    assert lm_end.context.parent_action_id == "mod-1"


def test_exception_in_translate_is_swallowed() -> None:
    """A buggy producer must not crash a callback hook."""
    cb = _callback()
    # Replace producer.translate with a raiser.
    cb._producer.translate = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    # Should not raise.
    cb.on_module_start("call-1", MockModule(), MockExample(q="x"))
    # No action captured because translate failed.
    assert cb.captured_actions == []


def test_engine_failure_does_not_crash_callback() -> None:
    engine = MagicMock()
    engine.evaluate.side_effect = RuntimeError("engine down")
    cb = _callback(engine=engine)
    cb.on_lm_start("lm-1", MockLM(), {"prompt": "hi"})
    # Action still captured even though engine raised.
    assert len(cb.captured_actions) == 1


def test_evidence_store_failure_does_not_crash_callback() -> None:
    store = MagicMock()
    store.append.side_effect = RuntimeError("store down")
    cb = _callback(evidence_store=store)
    cb.on_lm_start("lm-1", MockLM(), {"prompt": "hi"})
    assert len(cb.captured_actions) == 1


def test_on_module_end_with_exception_records_error_type() -> None:
    cb = _callback()
    err = ValueError("module raised")
    cb.on_module_end("call-1", outputs=None, exception=err)
    actions = cb.captured_actions
    assert len(actions) == 1
    assert actions[0].parameters.raw["error_type"] == "ValueError"


def test_observe_only_mode_captures_without_engine_or_store() -> None:
    cb = _callback(agent_id="quiet-agent")
    cb.on_lm_start("lm-1", MockLM(), {"prompt": "hi"})
    cb.on_lm_end("lm-1", outputs={"text": "ok"})
    assert len(cb.captured_actions) == 2
