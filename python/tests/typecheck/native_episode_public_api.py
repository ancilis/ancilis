"""Positive type-check fixture for the native episode public API."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator

from ancilis import (
    ClassificationRequest,
    ClassificationResponse,
    EpisodeClassificationReport,
    ClassificationHistory,
    EpisodeClassificationReportDict,
    Episode,
    EpisodeSigner,
    EpisodeTrustPolicy,
    EpisodeTrustPolicyDict,
    ProtectedBodyRequest,
    SignedEpisodeVerificationDict,
)
from ancilis import Ancilis, EpisodeSnapshot, Observation, ObservationInput


def synchronous(value: int, *, suffix: str) -> str:
    return f"{value}{suffix}"


async def asynchronous(value: int) -> str:
    return str(value)


def streaming(value: int) -> Generator[int, None, str]:
    yield value
    return str(value)


async def async_streaming(value: int) -> AsyncGenerator[int, None]:
    yield value


class AsyncClient:
    async def call_tool(self, name: str, *, arguments: dict[str, str]) -> str:
        return name + arguments["value"]

    async def list_tools(self) -> list[str]:
        return ["read"]


async def use_public_api() -> None:
    sdk = Ancilis("tenant", "source", source_instance="instance")
    sync_tool = sdk.attach_tool(synchronous, name="sync", surface="tool", operation="EXECUTE")
    async_tool = sdk.attach_tool(asynchronous, name="async", surface="tool", operation="EXECUTE")
    stream_tool = sdk.attach_tool(streaming, name="stream", surface="tool", operation="EXECUTE")
    async_stream_tool = sdk.attach_tool(
        async_streaming, name="async-stream", surface="tool", operation="EXECUTE"
    )

    sync_result: str = sync_tool(1, suffix="!")
    async_result: str = await async_tool(2)
    stream_result: Generator[int, None, str] = stream_tool(3)
    async_stream_result: AsyncGenerator[int, None] = async_stream_tool(4)
    client = sdk.attach_mcp(
        AsyncClient(), surfaces={"read": {"surface": "document", "operation": "READ"}}
    )
    mcp_result: str = await client.call_tool("read", arguments={"value": "x"})
    mcp_tools: list[str] = await client.list_tools()

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
    assert observation is not None
    observation_id: str = observation.to_dict()["event_id"]
    observation_surface: str = observation.to_dict()["surface"]

    snapshot: EpisodeSnapshot = episode.inspect()
    snapshot_open_hash: str = snapshot.to_dict()["open_sha256"]
    snapshot_reason: str = snapshot.to_dict()["coverage"]["reasons"][0]


# Signed verification requests retain the existing typed content-reference fields.


def signed_types(
    request: ProtectedBodyRequest, policy: EpisodeTrustPolicy, result: SignedEpisodeVerificationDict
) -> int:
    document: EpisodeTrustPolicyDict = policy.to_dict()
    digest: str = request.reference.sha256
    length: int = request.reference.byte_length
    authenticated: bool = result["envelope_authenticated"]
    return length if authenticated and digest and document["tenant"] else 0


def public_signed_export(episode: Episode, signer: EpisodeSigner) -> str:
    return episode.export_signed(signer)


def classification_response(request: ClassificationRequest, body: bytes) -> ClassificationResponse:
    target: str = request.to_dict()["reference"]["artifact"]
    return {
        "schema": "ancilis-classification-response/1",
        "request_sha256": request.request_sha256,
        "outcome": "UNKNOWN",
        "classification": None,
        "evidence_refs": [],
        "reasons": ["UNRESOLVED" if body and target else "MISSING"],
    }


def classification_history(
    history: ClassificationHistory, report: EpisodeClassificationReport
) -> str | None:
    document: EpisodeClassificationReportDict = report.to_dict()
    appended: bool = history.append(report)
    return document["classifications"][0]["classification"] if appended else None
