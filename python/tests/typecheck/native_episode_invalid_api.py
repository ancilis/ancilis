"""Negative type-check fixture for the native episode public API."""

from __future__ import annotations

from ancilis.episodes import Ancilis, ObservationInput


sdk = Ancilis("tenant", "source", source_instance="instance")
episode = sdk.episode("episode", expected_surfaces=("tool",))
observation = episode.observe(
    ObservationInput(
        "call",
        "2026-09-10T00:00:00.000000Z",
        "tool",
        "EXECUTE",
        "START",
        None,
        "STARTED",
    )
)

invalid_id: int = observation.to_dict()["event_id"]
