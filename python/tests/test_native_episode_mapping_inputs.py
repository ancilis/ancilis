"""Constructor mappings keep default handling and reject unknown fields."""

import hashlib

import pytest

from ancilis import Ancilis, ContentEvidence, ObservationInput, Relationship


def observation(**kwargs):
    return ObservationInput(
        "call", "2026-09-10T00:00:00.000000Z", "tool", "EXECUTE", "END", None,
        "SUCCEEDED", **kwargs,
    )


def test_mapping_constructors_preserve_optional_defaults():
    artifact = {"artifact": "a", "sha256": hashlib.sha256(b"a").hexdigest(), "byte_length": 1}
    relationship = {"kind": "ACCESSED", "from_artifact": "a", "to_artifact": "a"}
    value = observation(artifacts=(artifact,), relationships=(relationship,))
    assert value.artifacts == (ContentEvidence(**artifact),)
    assert value.relationships == (Relationship(**relationship),)


@pytest.mark.parametrize("field", ["artifacts", "relationships"])
def test_mapping_constructors_reject_unknown_fields(field):
    value = (
        ContentEvidence.from_bytes("a", b"a").to_dict()
        if field == "artifacts"
        else Relationship("ACCESSED", "a", "a").to_dict()
    )
    value["unrecognized_authority"] = "trusted"
    with pytest.raises(TypeError):
        observation(**{field: (value,)})


@pytest.mark.asyncio
async def test_mcp_preserves_keyword_call_and_async_result():
    class Client:
        async def call_tool(self, name, *, arguments):
            return (name, arguments)

    sdk = Ancilis("tenant", "source")
    attached = sdk.attach_mcp(
        Client(), surfaces={"read": {"surface": "document", "operation": "READ"}},
    )
    with sdk.episode("episode", expected_surfaces=("document",)) as episode:
        assert await attached.call_tool(name="read", arguments={"path": "a"}) == (
            "read", {"path": "a"},
        )
    assert len(episode.inspect().to_dict()["observations"]) == 2
