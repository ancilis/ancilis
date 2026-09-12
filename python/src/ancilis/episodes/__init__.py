"""Bounded, volatile native episode capture.

This module deliberately has no dependency on the legacy engine, producers, or
evidence store.  Its records are integrity identifiers, not signatures or
durable evidence.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import datetime as dt
import functools
import hashlib
import inspect
import json
import secrets
import threading
import types
import uuid
from collections.abc import AsyncGenerator, Callable, Generator, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal, ParamSpec, Protocol, TypeAlias, TypeVar, TypedDict, cast

if TYPE_CHECKING:
    from .signed import EpisodeSigner

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")
Surface: TypeAlias = Literal["document", "tool", "execution", "memory", "output"]
Operation: TypeAlias = Literal["REQUEST", "READ", "EXECUTE", "WRITE", "RECEIVE"]
Phase: TypeAlias = Literal["START", "CHUNK", "END"]
VerificationStatus: TypeAlias = Literal["UNVERIFIED", "REJECTED"]
JSONValue: TypeAlias = None | bool | int | str | list["JSONValue"] | dict[str, "JSONValue"]


class AuthorityDict(TypedDict):
    principal: str | None
    service: str | None
    delegation: str | None
    approval: str | None
    scope: str | None
    basis: Literal["APPLICATION_ASSERTION"]


class ContentEvidenceDict(TypedDict):
    artifact: str
    sha256: str
    byte_length: int
    role: Literal["INPUT", "OUTPUT"]
    access_scope: str
    classification_receipt_refs: list[str]


class RelationshipDict(TypedDict):
    kind: str
    from_artifact: str
    to_artifact: str
    basis: Literal["APPLICATION_ASSERTION"]
    method: Literal["ancilis-application-assertion/1"]
    evidence_refs: list[str]


class ObservationInputDict(TypedDict):
    call_id: str
    occurred_at: str
    surface: Surface
    operation: Operation
    phase: Phase
    chunk_index: int | None
    outcome: str
    authority: AuthorityDict
    artifacts: list[ContentEvidenceDict]
    relationships: list[RelationshipDict]
    provenance_refs: list[str]
    capture_gaps: list[str]


class SourceDict(TypedDict):
    id: str
    instance: str
    sequence: int


class ObservationDict(ObservationInputDict):
    schema: Literal["ancilis-observation/1"]
    tenant: str
    episode: str
    episode_open: str
    event_id: str
    source: SourceDict
    captured_at: str
    clock_basis: Literal["COLLECTOR_CLOCK_ASSERTION"]
    clock_evidence_refs: list[str]


class CoverageDict(TypedDict):
    expected_surfaces: list[Surface]
    observed_surfaces: list[Surface]
    missing_surfaces: list[Surface]
    complete: bool
    lost_events: int
    incomplete_calls: int
    reasons: list[str]
    reconstruction_exclusions: list[str]


class EpisodeOpenDict(TypedDict):
    schema: Literal["ancilis-episode-open/1"]
    tenant: str
    episode: str
    owner_source: str
    open_nonce: str
    allowed_source_instances: list[str]
    expected_surfaces: list[Surface]
    correlation_basis: Literal["APPLICATION_ASSIGNED"]
    created_at: str
    policy_sha256: str


class EpisodeSnapshotDict(TypedDict):
    schema: Literal["ancilis-episode/1"]
    tenant: str
    episode: str
    open: EpisodeOpenDict
    open_sha256: str
    revision: int
    revision_id: str
    previous_revision_id: str | None
    observations: list[ObservationDict]
    coverage: CoverageDict
    method: Literal["ancilis-native-observation-ledger/1"]
    claims_basis: Literal["COLLECTOR_ASSERTION_NOT_INDEPENDENT_RECONSTRUCTION"]
    determination_refs: list[str]
    observation_chain_sha256: str
    revision_method: Literal["ancilis-native-revision/2"]


class NativePolicyDict(TypedDict):
    schema: Literal["ancilis-native-policy/1"]
    max_events: int
    max_bytes: int
    max_episodes: int
    max_attachments: int
    max_body_bytes: int
    max_diagnostic_keys: int
    strict_capture: bool


class DiagnosticsDict(TypedDict):
    schema: Literal["ancilis-native-diagnostics/1"]
    storage: Literal["MEMORY_ONLY"]
    closed: bool
    events: int
    accounted_bytes: int
    episodes: int
    lost: int
    discarded_events: int
    discarded_bytes: int
    discarded_episodes: int
    reasons: dict[str, int]
    attachments: list[dict[str, str | int | bool]]
    reconstruction: Literal["UNAVAILABLE"]
    semantic_recovery: Literal["UNQUALIFIED"]


class EpisodeVerificationDict(TypedDict):
    schema: Literal["ancilis-verification/1"]
    status: VerificationStatus
    envelope_authenticated: Literal[False]
    protected_bodies: Literal["NOT_REQUESTED"]
    reconstruction: Literal["UNSUPPORTED"]
    policy_sha256: str
    assessed_at: str
    reasons: list[str]
    verified_claim_refs: list[str]


class MCPClient(Protocol):
    """Structural attachment boundary; the concrete client signature is retained."""

    def call_tool(self, *args: Any, **kwargs: Any) -> Any: ...


C = TypeVar("C", bound=MCPClient)

_MAX_SAFE = 9007199254740991
_SURFACES = ("document", "tool", "execution", "memory", "output")
_OPERATIONS = ("REQUEST", "READ", "EXECUTE", "WRITE", "RECEIVE")
_PHASES = ("START", "CHUNK", "END")
_OUTCOMES = (
    "STARTED",
    "OBSERVED",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
    "CLOSED_EARLY",
    "CAPTURE_FAILED",
)
_REASONS = (
    "CONTENT_NOT_CAPTURED",
    "UNMAPPED_TOOL",
    "SDK_CLOSED",
    "EPISODE_FINISHED",
    "EPISODE_DISCARDED",
    "CONTEXT_EXIT_MISMATCH",
    "UNCORRELATED_CALL",
    "CAPTURE_CALLBACK_FAILED",
    "UNSUPPORTED_RETURN_PROTOCOL",
    "LEDGER_EVENT_CAP",
    "LEDGER_BYTE_CAP",
    "LEDGER_EPISODE_CAP",
    "ATTACHMENT_CAP",
    "BODY_SIZE_CAP",
    "EVENT_CONFLICT",
    "ARTIFACT_REBIND",
    "INVALID_OBSERVATION",
    "MISSING_START",
    "MISSING_END",
    "CHUNK_GAP",
    "SOURCE_MISMATCH",
    "DISCARDED_EPISODE",
    "REVISION_EXHAUSTED",
    "OTHER",
)
_CAPTURE_GAPS = ("CONTENT_NOT_CAPTURED", "UNMAPPED_TOOL", "CAPTURE_CALLBACK_FAILED", "UNSUPPORTED_RETURN_PROTOCOL")
_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_active_episode: contextvars.ContextVar[Episode | None] = contextvars.ContextVar(
    "ancilis_native_episode", default=None
)


class EpisodeError(ValueError):
    pass


class ObservationConflict(EpisodeError):  # noqa: N818 - public cross-SDK API name
    pass


class EpisodeCapacityError(EpisodeError):
    pass


class EpisodeLifecycleError(EpisodeError):
    pass


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validate_value(value: Any, *, seen: set[int] | None = None, depth: int = 0) -> None:
    if depth > 64:
        raise EpisodeError("INVALID_OBSERVATION")
    seen = set() if seen is None else seen
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise EpisodeError("INVALID_OBSERVATION")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if -_MAX_SAFE <= value <= _MAX_SAFE:
            return
        raise EpisodeError("INVALID_OBSERVATION")
    if isinstance(value, float):
        raise EpisodeError("INVALID_OBSERVATION")
    if type(value) in (list, tuple):
        marker = id(value)
        if marker in seen:
            raise EpisodeError("INVALID_OBSERVATION")
        seen.add(marker)
        for item in value:
            _validate_value(item, seen=seen, depth=depth + 1)
        seen.remove(marker)
        return
    if type(value) is dict:
        marker = id(value)
        if marker in seen:
            raise EpisodeError("INVALID_OBSERVATION")
        seen.add(marker)
        for key, item in value.items():
            if not isinstance(key, str) or key in {"__proto__", "prototype", "constructor"}:
                raise EpisodeError("INVALID_OBSERVATION")
            _validate_value(key, seen=seen, depth=depth + 1)
            _validate_value(item, seen=seen, depth=depth + 1)
        seen.remove(marker)
        return
    raise EpisodeError("INVALID_OBSERVATION")


def canonical_json(value: Any) -> bytes:
    """The cross-runtime JSON subset used by all native hashes."""
    _validate_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _hash(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\n" + canonical_json(value)).hexdigest()


def _hash_encoded(domain: str, encoded: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\n" + encoded).hexdigest()


def _id(value: str, name: str = "id") -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise EpisodeError(f"INVALID_{name.upper()}")
    return value


def _timestamp(value: str) -> str:
    if not isinstance(value, str) or not __import__("re").fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value
    ):
        raise EpisodeError("INVALID_OBSERVATION")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise EpisodeError("INVALID_OBSERVATION") from exc
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or not __import__("re").fullmatch(r"[0-9a-f]{64}", value):
        raise EpisodeError("INVALID_OBSERVATION")
    return value


def _safe_int(value: Any, *, minimum: int = 0, maximum: int = _MAX_SAFE) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EpisodeError("INVALID_OBSERVATION")
    return value


@dataclasses.dataclass(frozen=True)
class _FrozenObject:
    items: tuple[tuple[str, object], ...]


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return _FrozenObject(tuple((key, _freeze(item)) for key, item in value.items()))
    if type(value) in (list, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, _FrozenObject):
        return {key: _thaw(item) for key, item in value.items}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def _locked(method: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(method)
    def locked(*args: P.args, **kwargs: P.kwargs) -> R:
        # Decorated methods are Episode instance methods; the decorator is an
        # internal dispatch boundary, not part of the public JSON contract.
        episode = cast("Episode", args[0])
        with episode._sdk._lock:
            return method(*args, **kwargs)

    return locked


@dataclasses.dataclass(frozen=True)
class Authority:
    principal: str | None = None
    service: str | None = None
    delegation: str | None = None
    approval: str | None = None
    scope: str | None = None
    basis: Literal["APPLICATION_ASSERTION"] = "APPLICATION_ASSERTION"

    def __post_init__(self) -> None:
        if self.basis != "APPLICATION_ASSERTION":
            raise EpisodeError("INVALID_OBSERVATION")
        for value in (self.principal, self.service, self.delegation, self.approval, self.scope):
            if value is not None:
                _id(value)

    def to_dict(self) -> AuthorityDict:
        return {
            "principal": self.principal,
            "service": self.service,
            "delegation": self.delegation,
            "approval": self.approval,
            "scope": self.scope,
            "basis": self.basis,
        }


@dataclasses.dataclass(frozen=True)
class ContentEvidence:
    artifact: str
    sha256: str
    byte_length: int
    role: Literal["INPUT", "OUTPUT"] = "OUTPUT"
    access_scope: str = "application"
    classification_receipt_refs: tuple[str, ...] = ()

    @classmethod
    def from_bytes(
        cls,
        artifact: str,
        data: bytes,
        *,
        role: Literal["INPUT", "OUTPUT"] = "OUTPUT",
        access_scope: str = "application",
        classification_receipt_refs: tuple[str, ...] = (),
    ) -> ContentEvidence:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if len(data) > 1048576:
            raise EpisodeError("BODY_SIZE_CAP")
        return cls(
            _id(artifact, "artifact"),
            hashlib.sha256(data).hexdigest(),
            len(data),
            role,
            _id(access_scope, "access_scope"),
            classification_receipt_refs,
        )

    def __post_init__(self) -> None:
        _id(self.artifact, "artifact")
        _digest(self.sha256)
        _safe_int(self.byte_length, maximum=16777216)
        if self.role not in ("INPUT", "OUTPUT"):
            raise EpisodeError("INVALID_OBSERVATION")
        _id(self.access_scope, "access_scope")
        if len(self.classification_receipt_refs) > 64:
            raise EpisodeError("INVALID_OBSERVATION")
        for ref in self.classification_receipt_refs:
            _digest(ref)

    def to_dict(self) -> ContentEvidenceDict:
        return {
            "artifact": self.artifact,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "role": self.role,
            "access_scope": self.access_scope,
            "classification_receipt_refs": list(self.classification_receipt_refs),
        }


@dataclasses.dataclass(frozen=True)
class Relationship:
    kind: str
    from_artifact: str
    to_artifact: str
    basis: Literal["APPLICATION_ASSERTION"] = "APPLICATION_ASSERTION"
    method: Literal["ancilis-application-assertion/1"] = "ancilis-application-assertion/1"
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in (
            "ACCESSED",
            "OPERAND",
            "BYTE_EQUAL",
            "ASSERTED_ORIGIN",
            "WRITTEN",
            "READ",
            "SEMANTIC_PROPOSAL",
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        _id(self.from_artifact, "artifact")
        _id(self.to_artifact, "artifact")
        if (
            self.basis != "APPLICATION_ASSERTION"
            or self.method != "ancilis-application-assertion/1"
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        if len(self.evidence_refs) > 64:
            raise EpisodeError("INVALID_OBSERVATION")
        for ref in self.evidence_refs:
            _digest(ref)

    def to_dict(self) -> RelationshipDict:
        return {
            "kind": self.kind,
            "from_artifact": self.from_artifact,
            "to_artifact": self.to_artifact,
            "basis": self.basis,
            "method": self.method,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclasses.dataclass(frozen=True)
class ObservationInput:
    call_id: str
    occurred_at: str
    surface: Surface
    operation: Operation
    phase: Phase
    chunk_index: int | None
    outcome: str
    authority: Authority | AuthorityDict = dataclasses.field(default_factory=Authority)
    artifacts: tuple[ContentEvidence | ContentEvidenceDict, ...] = ()
    relationships: tuple[Relationship | RelationshipDict, ...] = ()
    provenance_refs: tuple[str, ...] = ()
    capture_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.authority, Mapping):
            object.__setattr__(self, "authority", Authority(**self.authority))
        object.__setattr__(
            self,
            "artifacts",
            tuple(
                # Forward the complete mapping to the validating constructor:
                # unknown keys must fail and omitted optional keys keep defaults.
                ContentEvidence(**cast(Any, x))
                if isinstance(x, Mapping)
                else x
                for x in self.artifacts
            ),
        )
        object.__setattr__(
            self,
            "relationships",
            tuple(
                Relationship(**cast(Any, x))
                if isinstance(x, Mapping)
                else x
                for x in self.relationships
            ),
        )
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "relationships", tuple(self.relationships))
        object.__setattr__(self, "provenance_refs", tuple(self.provenance_refs))
        object.__setattr__(self, "capture_gaps", tuple(self.capture_gaps))
        _id(self.call_id, "call_id")
        _timestamp(self.occurred_at)
        if (
            self.surface not in _SURFACES
            or self.operation not in _OPERATIONS
            or self.phase not in _PHASES
            or self.outcome not in _OUTCOMES
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        if (self.phase == "CHUNK") != (
            isinstance(self.chunk_index, int)
            and not isinstance(self.chunk_index, bool)
            and 0 <= self.chunk_index <= _MAX_SAFE
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        if (
            self.phase == "START"
            and self.outcome != "STARTED"
            or self.phase == "CHUNK"
            and self.outcome != "OBSERVED"
            or self.phase == "END"
            and self.outcome not in _OUTCOMES[2:]
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        if any(reason not in _CAPTURE_GAPS for reason in self.capture_gaps):
            raise EpisodeError("INVALID_OBSERVATION")
        if (
            any(not isinstance(item, ContentEvidence) for item in self.artifacts)
            or any(not isinstance(item, Relationship) for item in self.relationships)
            or len(self.artifacts) > 64
            or len(self.relationships) > 64
            or len(self.provenance_refs) > 64
            or len(self.capture_gaps) > 64
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        for ref in self.provenance_refs:
            _digest(ref)

    def to_dict(self) -> ObservationInputDict:
        authority = cast(Authority, self.authority)
        artifacts = cast(tuple[ContentEvidence, ...], self.artifacts)
        relationships = cast(tuple[Relationship, ...], self.relationships)
        return {
            "call_id": self.call_id,
            "occurred_at": self.occurred_at,
            "surface": self.surface,
            "operation": self.operation,
            "phase": self.phase,
            "chunk_index": self.chunk_index,
            "outcome": self.outcome,
            "authority": authority.to_dict(),
            "artifacts": [x.to_dict() for x in artifacts],
            "relationships": [x.to_dict() for x in relationships],
            "provenance_refs": list(self.provenance_refs),
            "capture_gaps": list(self.capture_gaps),
        }


@dataclasses.dataclass(frozen=True)
class Observation:
    _value: Any

    def to_dict(self) -> ObservationDict:
        return cast(ObservationDict, _thaw(self._value))

    def __getitem__(self, key: str) -> object:
        return cast(dict[str, object], self.to_dict())[key]

    @property
    def event_id(self) -> str:
        return self.to_dict()["event_id"]

    @property
    def episode_open(self) -> str:
        return self.to_dict()["episode_open"]

    @property
    def tenant(self) -> str:
        return self.to_dict()["tenant"]

    @property
    def episode(self) -> str:
        return self.to_dict()["episode"]

    @property
    def call_id(self) -> str:
        return self.to_dict()["call_id"]

    @property
    def surface(self) -> Surface:
        return self.to_dict()["surface"]

    @property
    def operation(self) -> Operation:
        return self.to_dict()["operation"]

    @property
    def phase(self) -> Phase:
        return self.to_dict()["phase"]

    @property
    def outcome(self) -> str:
        return self.to_dict()["outcome"]

    @property
    def source(self) -> SourceDict:
        return self.to_dict()["source"]

    @property
    def captured_at(self) -> str:
        return self.to_dict()["captured_at"]


@dataclasses.dataclass(frozen=True)
class CaptureFrame:
    phase: Phase
    args: tuple[Any, ...]
    kwargs: Mapping[str, Any]
    result: Any = None
    error: BaseException | None = None
    chunk_index: int | None = None


@dataclasses.dataclass(frozen=True)
class CaptureResult:
    artifacts: tuple[ContentEvidence, ...] = ()
    relationships: tuple[Relationship, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "relationships", tuple(self.relationships))


@dataclasses.dataclass(frozen=True)
class NativePolicy:
    max_events: int = 4096
    max_bytes: int = 16777216
    max_episodes: int = 256
    max_attachments: int = 256
    max_body_bytes: int = 1048576
    max_diagnostic_keys: int = 128
    strict_capture: bool = False

    def __post_init__(self) -> None:
        for name in (
            "max_events",
            "max_bytes",
            "max_episodes",
            "max_attachments",
            "max_body_bytes",
            "max_diagnostic_keys",
        ):
            value = getattr(self, name)
            maximum = {
                "max_events": 10000,
                "max_bytes": 268435456,
                "max_episodes": 4096,
                "max_attachments": 4096,
                "max_body_bytes": 16777216,
                "max_diagnostic_keys": 4096,
            }[name]
            if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
                raise EpisodeError("INVALID_POLICY")
        if not isinstance(self.strict_capture, bool):
            raise EpisodeError("INVALID_POLICY")

    def to_dict(self) -> NativePolicyDict:
        return {
            "schema": "ancilis-native-policy/1",
            "max_events": self.max_events,
            "max_bytes": self.max_bytes,
            "max_episodes": self.max_episodes,
            "max_attachments": self.max_attachments,
            "max_body_bytes": self.max_body_bytes,
            "max_diagnostic_keys": self.max_diagnostic_keys,
            "strict_capture": self.strict_capture,
        }

    @property
    def sha256(self) -> str:
        return _hash("ancilis-native-policy/1", self.to_dict())


@dataclasses.dataclass(frozen=True)
class EpisodeSnapshot:
    _value: Any

    def to_dict(self) -> EpisodeSnapshotDict:
        return cast(EpisodeSnapshotDict, _thaw(self._value))

    @property
    def open_sha256(self) -> str:
        return self.to_dict()["open_sha256"]

    @property
    def observation_chain_sha256(self) -> str:
        return self.to_dict()["observation_chain_sha256"]

    @property
    def revision_id(self) -> str:
        return self.to_dict()["revision_id"]

    @property
    def revision_method(self) -> str:
        return self.to_dict()["revision_method"]

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(Observation(_freeze(x)) for x in self.to_dict()["observations"])

    @property
    def coverage(self) -> Coverage:
        return Coverage(_freeze(self.to_dict()["coverage"]))


@dataclasses.dataclass(frozen=True)
class Diagnostics:
    _value: Any

    def to_dict(self) -> DiagnosticsDict:
        return cast(DiagnosticsDict, _thaw(self._value))

    @property
    def reasons(self) -> Mapping[str, int]:
        return self.to_dict()["reasons"]

    @property
    def discarded_episodes(self) -> int:
        return self.to_dict()["discarded_episodes"]


@dataclasses.dataclass(frozen=True)
class Coverage:
    _value: Any

    def to_dict(self) -> CoverageDict:
        return cast(CoverageDict, _thaw(self._value))

    @property
    def observed_surfaces(self) -> tuple[Surface, ...]:
        return tuple(self.to_dict()["observed_surfaces"])

    @property
    def incomplete_calls(self) -> int:
        return self.to_dict()["incomplete_calls"]

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(self.to_dict()["reasons"])


@dataclasses.dataclass(frozen=True)
class EpisodeVerification:
    _value: Any

    def to_dict(self) -> EpisodeVerificationDict:
        return cast(EpisodeVerificationDict, _thaw(self._value))

    @property
    def status(self) -> VerificationStatus:
        return self.to_dict()["status"]

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(self.to_dict()["reasons"])


class _CallState(TypedDict):
    started: bool
    ended: bool
    failed: bool
    next: int


class FlushResult(TypedDict):
    storage: Literal["MEMORY_ONLY"]
    admitted: int
    pending: Literal[0]
    durable: Literal[0]
    lost: int


class Episode:
    def __init__(
        self,
        sdk: Ancilis,
        episode_id: str,
        expected_surfaces: Sequence[Surface],
        *,
        saturated: bool = False,
    ) -> None:
        self._sdk = sdk
        self.id = episode_id
        self._expected: tuple[Surface, ...] = tuple(
            sorted(set(expected_surfaces), key=_SURFACES.index)
        )
        self._saturated = saturated
        self._finished = False
        self._discarded = False
        self._active = 0
        self._tokens: contextvars.ContextVar[tuple[contextvars.Token[Episode | None], ...]] = (
            contextvars.ContextVar("ancilis_episode_tokens", default=())
        )
        self._inflight = 0
        self._records: list[Observation] = []
        self._by_id: dict[str, Observation] = {}
        self._artifacts: dict[str, tuple[str, int]] = {}
        self._calls: dict[str, _CallState] = {}
        self._observed: set[Surface] = set()
        self._incomplete = 0
        self._reasons: dict[str, int] = {}
        self._lost = 0
        self._reserved_bytes = 0
        self._reserved_events = 0
        self._revision = 1
        self._previous: str | None = None
        self._open: EpisodeOpenDict = {
            "schema": "ancilis-episode-open/1",
            "tenant": sdk.tenant,
            "episode": episode_id,
            "owner_source": sdk.source,
            "open_nonce": sdk._nonce_factory(),
            "allowed_source_instances": [sdk.source_instance],
            "expected_surfaces": list(self._expected),
            "correlation_basis": "APPLICATION_ASSIGNED",
            "created_at": sdk._clock(),
            "policy_sha256": sdk.policy.sha256,
        }
        self._open_hash = _hash("ancilis-episode-open/1", self._open)
        self._chain = _hash("ancilis-native-observation-chain/1", {"open_sha256": self._open_hash})
        if saturated:
            self._reasons["LEDGER_EPISODE_CAP"] = 1
            self._lost = 1
        self._refresh()

    @_locked
    def __enter__(self) -> Episode:
        if self._sdk._closed:
            raise EpisodeLifecycleError("SDK_CLOSED")
        if self._discarded:
            raise EpisodeLifecycleError("EPISODE_DISCARDED")
        token = _active_episode.set(self)
        self._tokens.set(self._tokens.get() + (token,))
        self._active += 1
        return self

    @_locked
    def __exit__(
        self,
        typ: type[BaseException] | None,
        value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> Literal[False]:
        tokens = self._tokens.get()
        if not tokens or _active_episode.get() is not self:
            self._loss("CONTEXT_EXIT_MISMATCH")
            return False
        try:
            _active_episode.reset(tokens[-1])
        except (ValueError, RuntimeError):
            self._loss("CONTEXT_EXIT_MISMATCH")
            return False
        self._tokens.set(tokens[:-1])
        self._active = max(0, self._active - 1)
        return False

    async def __aenter__(self) -> Episode:
        return self.__enter__()

    async def __aexit__(
        self,
        typ: type[BaseException] | None,
        value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool:
        return self.__exit__(typ, value, traceback)

    @_locked
    def finish(self) -> Episode:
        if self._finished:
            return self
        self._finished = True
        if self._revision >= _MAX_SAFE:
            self._sdk._diag("REVISION_EXHAUSTED")
            return self
        if any(not c["ended"] for c in self._calls.values()):
            self._reasons["MISSING_END"] = 1
        self._previous = self._revision_id
        self._revision += 1
        self._refresh()
        return self

    @_locked
    def inspect(self) -> EpisodeSnapshot:
        return EpisodeSnapshot(_freeze(self._snapshot()))

    def export_signed(self, signer: EpisodeSigner) -> str:
        """Sign a detached inspect snapshot; signing holds no collector lock."""
        from .signed import sign_episode_snapshot

        return sign_episode_snapshot(self.inspect(), signer)

    @_locked
    def _loss(self, reason: str, *, incident: bool = True) -> bool:
        if self._revision >= _MAX_SAFE:
            self._sdk._diag("REVISION_EXHAUSTED")
            return False
        self._lost = min(_MAX_SAFE, self._lost + 1)
        self._sdk._loss_total = min(_MAX_SAFE, self._sdk._loss_total + 1)
        if incident:
            self._sdk._diag(reason)
        self._reasons[reason] = min(_MAX_SAFE, self._reasons.get(reason, 0) + 1)
        self._previous = self._revision_id
        self._revision = min(_MAX_SAFE, self._revision + 1)
        self._refresh()
        return True

    def _coverage(self) -> CoverageDict:
        return {
            "expected_surfaces": list(self._expected),
            "observed_surfaces": [s for s in _SURFACES if s in self._observed],
            "missing_surfaces": [
                s for s in _SURFACES if s in self._expected and s not in self._observed
            ],
            "complete": False,
            "lost_events": self._lost,
            "incomplete_calls": self._incomplete,
            "reasons": [r for r in _REASONS if r in self._reasons],
            "reconstruction_exclusions": [],
        }

    def _refresh(self) -> None:
        coverage = self._coverage()
        preimage = {
            "open_sha256": self._open_hash,
            "revision": self._revision,
            "previous_revision_id": self._previous,
            "observation_chain_sha256": self._chain,
            "coverage": coverage,
        }
        self._revision_id = _hash("ancilis-native-revision/2", preimage)

    def _snapshot(self) -> EpisodeSnapshotDict:
        return {
            "schema": "ancilis-episode/1",
            "tenant": self._sdk.tenant,
            "episode": self.id,
            "open": self._open,
            "open_sha256": self._open_hash,
            "revision": self._revision,
            "revision_id": self._revision_id,
            "previous_revision_id": self._previous,
            "observations": [r.to_dict() for r in self._records],
            "coverage": self._coverage(),
            "method": "ancilis-native-observation-ledger/1",
            "claims_basis": "COLLECTOR_ASSERTION_NOT_INDEPENDENT_RECONSTRUCTION",
            "determination_refs": [],
            "observation_chain_sha256": self._chain,
            "revision_method": "ancilis-native-revision/2",
        }

    def observe(self, input: ObservationInput) -> Observation | None:
        if not isinstance(input, ObservationInput):
            raise TypeError("ObservationInput required")
        return self._admit(input, manual=True)

    @_locked
    def _admit(self, input: ObservationInput, manual: bool = False) -> Observation | None:
        if self._sdk._closed:
            raise EpisodeLifecycleError("SDK_CLOSED")
        if self._discarded:
            raise EpisodeLifecycleError("EPISODE_DISCARDED")
        if self._finished:
            if manual:
                raise EpisodeLifecycleError("EPISODE_FINISHED")
            self._loss("EPISODE_FINISHED")
            return None
        if self._saturated:
            if manual and self._sdk.policy.strict_capture:
                raise EpisodeCapacityError("LEDGER_EPISODE_CAP")
            self._loss("LEDGER_EPISODE_CAP")
            return None
        if self._revision >= _MAX_SAFE:
            self._sdk._diag("REVISION_EXHAUSTED")
            if manual and self._sdk.policy.strict_capture:
                raise EpisodeCapacityError("REVISION_EXHAUSTED")
            return None
        data = input.to_dict()
        event_pre = {
            "tenant": self._sdk.tenant,
            "episode_open": self._open_hash,
            "source_instance": self._sdk.source_instance,
            "call_id": input.call_id,
            "phase": input.phase,
            "chunk_index": input.chunk_index,
        }
        event_id = _hash("ancilis-observation-id/1", event_pre)
        candidate = cast(ObservationDict, {
            **data,
            "schema": "ancilis-observation/1",
            "tenant": self._sdk.tenant,
            "episode": self.id,
            "episode_open": self._open_hash,
            "event_id": event_id,
            "source": {
                "id": self._sdk.source,
                "instance": self._sdk.source_instance,
                "sequence": 0,
            },
            "captured_at": "",
            "clock_basis": "COLLECTOR_CLOCK_ASSERTION",
            "clock_evidence_refs": [],
        })
        if event_id in self._by_id:
            old = self._by_id[event_id].to_dict()
            old["source"]["sequence"] = 0
            old["captured_at"] = ""
            if canonical_json(old) == canonical_json(candidate):
                return self._by_id[event_id]
            self._loss("EVENT_CONFLICT")
            if manual:
                raise ObservationConflict("EVENT_CONFLICT")
            return None
        artifacts = cast(tuple[ContentEvidence, ...], input.artifacts)
        relationships = cast(tuple[Relationship, ...], input.relationships)
        for artifact in artifacts:
            bound = self._artifacts.get(artifact.artifact)
            if bound is not None and bound != (artifact.sha256, artifact.byte_length):
                self._loss("ARTIFACT_REBIND")
                if manual:
                    raise EpisodeError("ARTIFACT_REBIND")
                return None
        staged: dict[str, tuple[str, int]] = {}
        for artifact in artifacts:
            binding = (artifact.sha256, artifact.byte_length)
            if artifact.byte_length > self._sdk.policy.max_body_bytes:
                self._loss("BODY_SIZE_CAP")
                if manual:
                    raise EpisodeError("BODY_SIZE_CAP")
                return None
            if artifact.artifact in staged and staged[artifact.artifact] != binding:
                self._loss("ARTIFACT_REBIND")
                if manual:
                    raise EpisodeError("ARTIFACT_REBIND")
                return None
            staged[artifact.artifact] = binding
        if any(
            (r.from_artifact not in self._artifacts and r.from_artifact not in staged)
            or (r.to_artifact not in self._artifacts and r.to_artifact not in staged)
            for r in relationships
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        previous_call = self._calls.get(input.call_id)
        proposed_call = cast(
            _CallState,
            dict(
                previous_call
                or {"started": False, "ended": False, "failed": False, "next": 0}
            ),
        )
        if proposed_call["ended"]:
            self._invalid(manual, "INVALID_OBSERVATION")
            return None
        # Partial capture is retained with explicit gaps, never upgraded to completeness.
        phase_reasons: list[str] = []
        if input.phase == "START":
            proposed_call["started"] = True
        elif input.phase == "CHUNK":
            if input.chunk_index != proposed_call["next"]:
                phase_reasons.append("CHUNK_GAP")
                proposed_call["failed"] = True
            proposed_call["next"] = cast(int, input.chunk_index) + 1
        else:
            proposed_call["ended"] = True
            proposed_call["failed"] |= input.outcome != "SUCCEEDED"
        if input.phase != "START" and not proposed_call["started"]:
            phase_reasons.append("MISSING_START")
        candidate["source"]["sequence"] = self._sdk._sequence + 1
        candidate["captured_at"] = self._sdk._clock()
        encoded = canonical_json(candidate)
        reserved = len(encoded) * 2 + 512 + len(staged) * 384
        if self._sdk._event_count >= self._sdk.policy.max_events:
            self._loss("LEDGER_EVENT_CAP")
            if manual and self._sdk.policy.strict_capture:
                raise EpisodeCapacityError("LEDGER_EVENT_CAP")
            return None
        if self._sdk._event_bytes + reserved > self._sdk.policy.max_bytes:
            self._loss("LEDGER_BYTE_CAP")
            if manual and self._sdk.policy.strict_capture:
                raise EpisodeCapacityError("LEDGER_BYTE_CAP")
            return None
        self._calls[input.call_id] = proposed_call

        def incomplete(call: _CallState) -> bool:
            return not call["started"] or not call["ended"] or call["failed"]

        self._incomplete += int(incomplete(proposed_call)) - int(
            previous_call is not None and incomplete(previous_call)
        )
        if input.phase == "CHUNK" or (input.phase == "END" and input.outcome == "SUCCEEDED"):
            self._observed.add(input.surface)
        for reason in phase_reasons:
            self._reasons[reason] = 1
        self._sdk._sequence += 1
        record = Observation(_freeze(candidate))
        self._records.append(record)
        self._by_id[event_id] = record
        self._sdk._event_bytes += reserved
        self._sdk._event_count += 1
        self._reserved_bytes += reserved
        self._reserved_events += 1
        payload = _hash_encoded("ancilis-observation-payload/1", encoded)
        self._chain = _hash(
            "ancilis-native-observation-chain/1",
            {"previous_observation_chain_sha256": self._chain, "observation_sha256": payload},
        )
        for artifact in artifacts:
            self._artifacts[artifact.artifact] = (artifact.sha256, artifact.byte_length)
        for reason in input.capture_gaps:
            self._reasons[reason] = 1
        self._previous = self._revision_id
        self._revision += 1
        self._refresh()
        return record

    @_locked
    def _discard(self) -> bool:
        if self._revision >= _MAX_SAFE:
            self._sdk._diag("REVISION_EXHAUSTED")
            return False
        self._previous = self._revision_id
        self._records.clear()
        self._by_id.clear()
        self._artifacts.clear()
        self._calls.clear()
        self._observed.clear()
        self._incomplete = 0
        self._chain = _hash("ancilis-native-observation-chain/1", {"open_sha256": self._open_hash})
        self._reserved_bytes = self._reserved_events = 0
        self._reasons["DISCARDED_EPISODE"] = min(
            _MAX_SAFE, self._reasons.get("DISCARDED_EPISODE", 0) + 1
        )
        self._revision += 1
        self._discarded = True
        self._refresh()
        return True

    def _invalid(self, manual: bool, reason: str) -> None:
        self._loss(reason)
        if manual:
            raise EpisodeError(reason)
        return None


@dataclasses.dataclass
class _Attachment:
    original: Callable[..., Any]
    name: str
    surface: Surface
    operation: Operation
    capture: Callable[[CaptureFrame], CaptureResult | None] | None
    # Wrapped tools can implement sync, coroutine, generator, or foreign awaitable
    # protocols. The public attach_tool boundary restores the original callable type.
    wrapper: Any = None
    active: bool = True
    started: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    events_admitted: int = 0

    def diagnostic(self) -> dict[str, str | int | bool]:
        return {
            key: getattr(self, key)
            for key in (
                "name",
                "surface",
                "started",
                "completed",
                "failed",
                "cancelled",
                "events_admitted",
                "active",
            )
        }


class _Call:
    """One operation; only immutable, validated references survive admission."""

    def __init__(
        self,
        sdk: Ancilis,
        registration: _Attachment,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> None:
        self.sdk = sdk
        self.registration = registration
        self.args, self.kwargs = args, kwargs
        self.call_id = secrets.token_hex(16)
        self.ended = False
        self.index = 0
        self.episode: Episode | None = None
        self.enabled = registration.active and not sdk._closed
        if not self.enabled:
            if sdk._closed:
                sdk._diag("SDK_CLOSED")
            return
        registration.started = min(_MAX_SAFE, registration.started + 1)
        episode = _active_episode.get()
        if episode is None or episode._sdk is not sdk:
            sdk._diag("UNCORRELATED_CALL")
        elif episode._discarded or episode._finished or episode._saturated:
            reason = (
                "EPISODE_DISCARDED"
                if episode._discarded
                else "EPISODE_FINISHED"
                if episode._finished
                else "LEDGER_EPISODE_CAP"
            )
            # A saturated handle is not another episode-cap incident per operation.
            if episode._saturated:
                episode._loss(reason, incident=False)
            else:
                episode._loss(reason)
        else:
            self.episode = episode
            with sdk._lock:
                episode._inflight += 1
        self.emit("START", "STARTED")

    def emit(
        self,
        phase: Phase,
        outcome: str,
        result: Any = None,
        error: BaseException | None = None,
        index: int | None = None,
        gap: str | None = None,
    ) -> None:
        episode = self.episode
        if not self.enabled or episode is None:
            return
        if self.sdk._closed or episode._finished or episode._discarded:
            reason = (
                "SDK_CLOSED"
                if self.sdk._closed
                else "EPISODE_DISCARDED"
                if episode._discarded
                else "EPISODE_FINISHED"
            )
            episode._loss(reason)
            return
        gaps = [gap] if gap else []
        captured = None
        try:
            callback = self.registration.capture
            if callback is not None:
                captured = callback(
                    CaptureFrame(phase, self.args, self.kwargs, result, error, index)
                )
                if captured is not None and not isinstance(captured, CaptureResult):
                    if type(captured) is types.CoroutineType:
                        captured.close()
                    raise EpisodeError("CAPTURE_CALLBACK_FAILED")
            if captured is not None:
                if any(not isinstance(a, ContentEvidence) for a in captured.artifacts):
                    raise EpisodeError("CAPTURE_CALLBACK_FAILED")
                if any(not isinstance(r, Relationship) for r in captured.relationships):
                    raise EpisodeError("CAPTURE_CALLBACK_FAILED")
        except BaseException:
            captured = None
            gaps.append("CAPTURE_CALLBACK_FAILED")
            episode._loss("CAPTURE_CALLBACK_FAILED")
        if captured is None or not captured.artifacts:
            gaps.append("CONTENT_NOT_CAPTURED")
        try:
            row = ObservationInput(
                self.call_id,
                self.sdk._clock(),
                self.registration.surface,
                self.registration.operation,
                phase,
                index,
                outcome,
                artifacts=captured.artifacts if captured else (),
                relationships=captured.relationships if captured else (),
                capture_gaps=tuple(gaps),
            )
            admitted = episode._admit(row)
            if admitted is not None:
                self.registration.events_admitted = min(
                    _MAX_SAFE, self.registration.events_admitted + 1
                )
        except BaseException:
            # Capture cannot replace the application's result or original exception.
            episode._loss("INVALID_OBSERVATION")

    def chunk(self, value: Any) -> None:
        if not self.ended:
            self.emit("CHUNK", "OBSERVED", result=value, index=self.index)
            self.index += 1

    def finish(
        self,
        outcome: str,
        value: Any = None,
        error: BaseException | None = None,
        gap: str | None = None,
    ) -> None:
        if self.ended:
            return
        self.ended = True
        if gap == "UNSUPPORTED_RETURN_PROTOCOL":
            self.sdk._diag(gap)
        if self.enabled:
            key = (
                "completed"
                if outcome == "SUCCEEDED"
                else "cancelled"
                if outcome == "CANCELLED"
                else "failed"
            )
            setattr(self.registration, key, min(_MAX_SAFE, getattr(self.registration, key) + 1))
        try:
            self.emit("END", outcome, value, error, gap=gap)
        finally:
            if self.episode is not None:
                with self.sdk._lock:
                    self.episode._inflight = max(0, self.episode._inflight - 1)
            self.args, self.kwargs = (), {}

    def failure(self, error: BaseException) -> None:
        self.finish(
            "CANCELLED" if isinstance(error, asyncio.CancelledError) else "FAILED", error=error
        )

    def __del__(self) -> None:
        # Abandonment is missing evidence, not observed completion/cancellation.
        # Release only collector bookkeeping: never call user capture callbacks,
        # close an application iterator, or schedule asynchronous work from GC.
        try:
            if self.ended or self.episode is None:
                return
            self.ended = True
            with self.sdk._lock:
                self.episode._inflight = max(0, self.episode._inflight - 1)
                self.episode._loss("MISSING_END")
        except BaseException:
            # Partial initialization and interpreter shutdown must stay harmless.
            pass


class _GeneratorProxy:
    def __init__(self, iterator: Generator[Any, Any, Any], call: _Call) -> None:
        self._iterator, self._call = iterator, call

    def __iter__(self) -> _GeneratorProxy:
        return self

    def _step(self, method: Callable[..., Any], *args: Any) -> Any:
        try:
            value = method(*args)
        except StopIteration as stopped:
            self._call.finish("SUCCEEDED", stopped.value)
            raise
        except BaseException as error:
            self._call.failure(error)
            raise
        self._call.chunk(value)
        return value

    def __next__(self) -> Any:
        return self._step(next, self._iterator)

    def send(self, value: Any) -> Any:
        return self._step(self._iterator.send, value)

    def throw(self, *args: Any) -> Any:
        return self._step(self._iterator.throw, *args)

    def close(self) -> None:
        try:
            self._iterator.close()
        except BaseException as error:
            self._call.failure(error)
            raise
        self._call.finish("CLOSED_EARLY")
        return None


class _AsyncGeneratorProxy:
    def __init__(self, iterator: AsyncGenerator[Any, Any], call: _Call) -> None:
        self._iterator, self._call = iterator, call

    def __aiter__(self) -> _AsyncGeneratorProxy:
        return self

    async def _step(self, method: Callable[..., Any], *args: Any) -> Any:
        try:
            value = await method(*args)
        except StopAsyncIteration:
            self._call.finish("SUCCEEDED")
            raise
        except BaseException as error:
            self._call.failure(error)
            raise
        self._call.chunk(value)
        return value

    async def __anext__(self) -> Any:
        return await self._step(self._iterator.__anext__)

    async def asend(self, value: Any) -> Any:
        return await self._step(self._iterator.asend, value)

    async def athrow(self, *args: Any) -> Any:
        return await self._step(self._iterator.athrow, *args)

    async def aclose(self) -> None:
        try:
            await self._iterator.aclose()
        except BaseException as error:
            self._call.failure(error)
            raise
        self._call.finish("CLOSED_EARLY")
        return None


class Ancilis:
    """Owns bounded advisory capture. No implicit engine, client, persistence or trust."""

    def __init__(
        self,
        tenant: str,
        source: str,
        *,
        source_instance: str | None = None,
        max_events: int = 4096,
        max_bytes: int = 16777216,
        max_episodes: int = 256,
        max_attachments: int = 256,
        max_body_bytes: int = 1048576,
        max_diagnostic_keys: int = 128,
        strict_capture: bool = False,
        _clock: Callable[[], str] | None = None,
        _nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self.tenant, self.source = _id(tenant), _id(source)
        self.source_instance = _id(
            str(uuid.uuid4()) if source_instance is None else source_instance
        )
        self.policy = NativePolicy(
            max_events,
            max_bytes,
            max_episodes,
            max_attachments,
            max_body_bytes,
            max_diagnostic_keys,
            strict_capture,
        )
        self._clock = _clock or _now
        self._nonce_factory = _nonce_factory or (lambda: secrets.token_hex(16))
        self._lock = threading.RLock()
        self._episodes: dict[str, Episode] = {}
        self._attachments: dict[int, _Attachment] = {}
        self._mcp_attachments: dict[int, tuple[MCPClient, tuple[tuple[str, str, str], ...], Any]] = {}
        self._closed = False
        self._event_bytes = self._event_count = self._sequence = self._loss_total = 0
        self._discarded_events = self._discarded_bytes = self._discarded = 0
        self._diagnostics: dict[str, int] = {}

    def __enter__(self) -> Ancilis:
        if self._closed:
            raise EpisodeLifecycleError("SDK_CLOSED")
        return self

    def __exit__(self, *args: object) -> Literal[False]:
        self.close()
        return False

    async def __aenter__(self) -> Ancilis:
        return self.__enter__()

    async def __aexit__(self, *args: object) -> Literal[False]:
        return self.__exit__(*args)

    def _diag(self, reason: str) -> None:
        with self._lock:
            reason = reason if reason in _REASONS else "OTHER"
            self._diagnostics[reason] = min(_MAX_SAFE, self._diagnostics.get(reason, 0) + 1)

    def diagnostics(self) -> Diagnostics:
        with self._lock:
            return Diagnostics(
                _freeze(
                    {
                        "schema": "ancilis-native-diagnostics/1",
                        "storage": "MEMORY_ONLY",
                        "closed": self._closed,
                        "events": self._event_count,
                        "accounted_bytes": self._event_bytes,
                        "episodes": len(self._episodes),
                        "lost": self._loss_total,
                        "discarded_events": self._discarded_events,
                        "discarded_bytes": self._discarded_bytes,
                        "discarded_episodes": self._discarded,
                        "reasons": {
                            r: self._diagnostics[r] for r in _REASONS if r in self._diagnostics
                        },
                        "attachments": [r.diagnostic() for r in self._attachments.values()],
                        "reconstruction": "UNAVAILABLE",
                        "semantic_recovery": "UNQUALIFIED",
                    }
                )
            )

    def episode(self, episode_id: str, *, expected_surfaces: Sequence[Surface]) -> Episode:
        with self._lock:
            if self._closed:
                raise EpisodeLifecycleError("SDK_CLOSED")
            _id(episode_id)
            if (
                not expected_surfaces
                or len(expected_surfaces) > 5
                or any(s not in _SURFACES for s in expected_surfaces)
                or len(set(expected_surfaces)) != len(expected_surfaces)
            ):
                raise EpisodeError("INVALID_OBSERVATION")
            normalized = cast(tuple[Surface, ...], tuple(s for s in _SURFACES if s in expected_surfaces))
            existing = self._episodes.get(episode_id)
            if existing is not None:
                if existing._expected != normalized:
                    raise EpisodeError("SOURCE_MISMATCH")
                return existing
            saturated = len(self._episodes) >= self.policy.max_episodes
            if saturated:
                self._diag("LEDGER_EPISODE_CAP")
                self._loss_total = min(_MAX_SAFE, self._loss_total + 1)
                if self.policy.strict_capture:
                    raise EpisodeCapacityError("LEDGER_EPISODE_CAP")
            episode = Episode(self, episode_id, normalized, saturated=saturated)
            if not saturated:
                self._episodes[episode_id] = episode
            return episode

    def get_episode(self, episode_id: str) -> Episode | None:
        return self._episodes.get(episode_id)

    def discard_episode(self, episode_id: str) -> bool:
        with self._lock:
            episode = self._episodes.get(episode_id)
            if episode is None:
                return False
            if episode._active or episode._inflight:
                raise EpisodeLifecycleError("OTHER")
            events, size = episode._reserved_events, episode._reserved_bytes
            if not episode._discard():
                return False
            del self._episodes[episode_id]
            self._event_bytes -= size
            self._event_count -= events
            self._discarded_events = min(_MAX_SAFE, self._discarded_events + events)
            self._discarded_bytes = min(_MAX_SAFE, self._discarded_bytes + size)
            self._discarded = min(_MAX_SAFE, self._discarded + 1)
            self._diag("DISCARDED_EPISODE")
            return True

    def flush(self) -> FlushResult:
        return {
            "storage": "MEMORY_ONLY",
            "admitted": self._event_count,
            "pending": 0,
            "durable": 0,
            "lost": self._loss_total,
        }

    async def aflush(self) -> FlushResult:
        return self.flush()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            for episode in self._episodes.values():
                episode.finish()
            self._closed = True
            for registration in self._attachments.values():
                registration.active = False
            self._attachments.clear()
            self._mcp_attachments.clear()

    async def aclose(self) -> None:
        self.close()

    def detach(self, wrapped: object) -> bool:
        with self._lock:
            key = getattr(wrapped, "__ancilis_attachment_key__", id(wrapped))
            registration = self._attachments.pop(key, None)
            if registration is None:
                return False
            registration.active = False
            return True

    def bind_episode(self, fn: Callable[P, R], episode: Episode) -> Callable[P, R]:
        if episode._sdk is not self:
            raise EpisodeError("SOURCE_MISMATCH")
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def bound(*args: P.args, **kwargs: P.kwargs) -> Any:
                token = _active_episode.set(episode)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _active_episode.reset(token)
        else:

            @functools.wraps(fn)
            def bound(*args: P.args, **kwargs: P.kwargs) -> R:
                token = _active_episode.set(episode)
                try:
                    return fn(*args, **kwargs)
                finally:
                    _active_episode.reset(token)

        return cast(Callable[P, R], bound)

    @staticmethod
    def _unsupported(value: object) -> bool:
        if type(value) in (
            str,
            bytes,
            bytearray,
            memoryview,
            list,
            tuple,
            dict,
            set,
            frozenset,
            range,
        ):
            return False
        marker = object()
        return any(
            inspect.getattr_static(value, name, marker) is not marker
            for name in ("__await__", "__iter__", "__aiter__", "__next__", "__anext__")
        )

    def _returned(self, value: Any, call: _Call) -> Any:
        if isinstance(value, asyncio.Future):

            def done(future: asyncio.Future[Any]) -> None:
                try:
                    result = future.result()
                except BaseException as error:
                    call.failure(error)
                else:
                    call.finish("SUCCEEDED", result)

            try:
                value.add_done_callback(done)
            except BaseException:
                call.finish("CAPTURE_FAILED", gap="UNSUPPORTED_RETURN_PROTOCOL")
            return value
        if type(value) is types.CoroutineType:

            async def waiting() -> Any:
                try:
                    result = await value
                except BaseException as error:
                    call.failure(error)
                    raise
                call.finish("SUCCEEDED", result)
                return result

            return waiting()
        if type(value) is types.GeneratorType:
            if value.gi_code.co_flags & inspect.CO_ITERABLE_COROUTINE:
                call.finish("CAPTURE_FAILED", gap="UNSUPPORTED_RETURN_PROTOCOL")
                return value
            return _GeneratorProxy(value, call)
        if type(value) is types.AsyncGeneratorType:
            return _AsyncGeneratorProxy(value, call)
        if self._unsupported(value):
            call.finish("CAPTURE_FAILED", gap="UNSUPPORTED_RETURN_PROTOCOL")
        else:
            call.finish("SUCCEEDED", value)
        return value

    def attach_tool(
        self,
        fn: Callable[P, R],
        *,
        name: str,
        surface: Surface,
        operation: Operation,
        capture: Callable[[CaptureFrame], CaptureResult | None] | None = None,
    ) -> Callable[P, R]:
        with self._lock:
            if self._closed:
                raise EpisodeLifecycleError("SDK_CLOSED")
            if (
                isinstance(fn, (staticmethod, classmethod, property, type))
                or not callable(fn)
                or surface not in _SURFACES
                or operation not in _OPERATIONS
                or capture is not None
                and (not callable(capture) or inspect.iscoroutinefunction(capture))
            ):
                raise EpisodeError("INVALID_OBSERVATION")
            _id(name)
            owner = getattr(fn, "__ancilis_attachment_owner__", None)
            if owner is not None and owner is not self:
                raise EpisodeError("SOURCE_MISMATCH")
            key = getattr(fn, "__ancilis_attachment_key__", id(fn))
            previous = self._attachments.get(key)
            if previous is not None:
                if (previous.name, previous.surface, previous.operation, previous.capture) != (
                    name,
                    surface,
                    operation,
                    capture,
                ):
                    raise EpisodeError("EVENT_CONFLICT")
                return cast(Callable[P, R], previous.wrapper)
            if len(self._attachments) >= min(
                self.policy.max_attachments, self.policy.max_diagnostic_keys
            ):
                self._diag("ATTACHMENT_CAP")
                raise EpisodeCapacityError("ATTACHMENT_CAP")
            registration = _Attachment(fn, name, surface, operation, capture)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                    call = _Call(self, registration, args, kwargs)
                    try:
                        result = await fn(*args, **kwargs)
                    except BaseException as error:
                        call.failure(error)
                        raise
                    call.finish("SUCCEEDED", result)
                    return result
            elif inspect.isgeneratorfunction(fn) and not (
                fn.__code__.co_flags & inspect.CO_ITERABLE_COROUTINE
            ):

                @functools.wraps(fn)
                def wrapper(*args: P.args, **kwargs: P.kwargs) -> Generator[Any, Any, Any]:
                    call = _Call(self, registration, args, kwargs)
                    try:
                        iterator = fn(*args, **kwargs)
                    except BaseException as error:
                        call.failure(error)
                        raise
                    return (yield from _GeneratorProxy(iterator, call))
            elif inspect.isasyncgenfunction(fn):

                @functools.wraps(fn)
                async def wrapper(*args: P.args, **kwargs: P.kwargs) -> AsyncGenerator[Any, Any]:
                    call = _Call(self, registration, args, kwargs)
                    try:
                        target = fn(*args, **kwargs)
                    except BaseException as error:
                        call.failure(error)
                        raise
                    iterator = _AsyncGeneratorProxy(target, call)
                    try:
                        value = await iterator.__anext__()
                        while True:
                            try:
                                sent = yield value
                            except GeneratorExit:
                                await iterator.aclose()
                                raise
                            except BaseException as error:
                                value = await iterator.athrow(error)
                            else:
                                value = await iterator.asend(sent)
                    except StopAsyncIteration:
                        return
            else:

                @functools.wraps(fn)
                def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                    call = _Call(self, registration, args, kwargs)
                    try:
                        value = fn(*args, **kwargs)
                    except BaseException as error:
                        call.failure(error)
                        raise
                    return self._returned(value, call)

            # Runtime attachment metadata is deliberately dynamic and private.
            dynamic_wrapper: Any = wrapper
            dynamic_wrapper.__ancilis_attachment_owner__ = self
            dynamic_wrapper.__ancilis_attachment_key__ = key
            registration.wrapper = dynamic_wrapper
            self._attachments[key] = registration
            return cast(Callable[P, R], dynamic_wrapper)

    def attach_mcp(
        self,
        client: C,
        *,
        capture: Callable[[CaptureFrame], CaptureResult | None] | None = None,
        surfaces: Mapping[str, Mapping[str, str]],
    ) -> C:
        with self._lock:
            if self._closed:
                raise EpisodeLifecycleError("SDK_CLOSED")
            if getattr(client, "__ancilis_mcp_owner__", None) is not None:
                raise EpisodeError("SOURCE_MISMATCH")
            canonical_json(surfaces)
            normalized = tuple(
                sorted(
                    (name, config["surface"], config["operation"])
                    for name, config in surfaces.items()
                )
            )
            if any(
                surface not in _SURFACES or operation not in _OPERATIONS
                for _, surface, operation in normalized
            ):
                raise EpisodeError("INVALID_OBSERVATION")
            existing = self._mcp_attachments.get(id(client))
            if existing:
                adapter, options, callback = existing
                if options != normalized or callback is not capture:
                    raise EpisodeError("EVENT_CONFLICT")
                return cast(C, adapter)
            # Validate the whole map and available budget before registering any
            # tool; a refused attachment must not consume the caller's slots.
            for name, _, _ in normalized:
                _id(name)
            if len(self._attachments) + len(normalized) > min(
                self.policy.max_attachments, self.policy.max_diagnostic_keys
            ):
                self._diag("ATTACHMENT_CAP")
                raise EpisodeCapacityError("ATTACHMENT_CAP")
            sdk = self

            class Adapter:
                __ancilis_mcp_owner__ = sdk

                def __init__(self) -> None:
                    self._wrapped: dict[str, Callable[..., object]] = {}
                    for name, surface, operation in normalized:

                        def invoke(*args: object, **kwargs: object) -> object:
                            return client.call_tool(*args, **kwargs)

                        self._wrapped[name] = sdk.attach_tool(
                            invoke,
                            name=name,
                            surface=cast(Surface, surface),
                            operation=cast(Operation, operation),
                            capture=capture,
                        )

                def __getattr__(self, name: str) -> Any:
                    return getattr(client, name)

                def call_tool(self, *args: Any, **kwargs: Any) -> object:
                    request = args[0] if args else kwargs.get("name", kwargs.get("request"))
                    name = (
                        request.get("name")
                        if type(request) is dict
                        else request
                        if type(request) is str
                        else None
                    )
                    wrapped = self._wrapped.get(name) if type(name) is str else None
                    if wrapped is None:
                        sdk._diag("UNMAPPED_TOOL")
                        return client.call_tool(*args, **kwargs)
                    return wrapped(*args, **kwargs)

            adapter = Adapter()
            self._mcp_attachments[id(client)] = (adapter, normalized, capture)
            # The facade delegates the client's ordinary methods and preserves
            # call_tool arguments/return protocol. It does not preserve identity,
            # isinstance checks, or special-method/context-manager dispatch.
            return cast(C, adapter)


__all__ = [
    "Ancilis",
    "Authority",
    "CaptureFrame",
    "CaptureResult",
    "ContentEvidence",
    "Diagnostics",
    "Coverage",
    "EpisodeVerification",
    "Episode",
    "EpisodeCapacityError",
    "EpisodeError",
    "EpisodeLifecycleError",
    "EpisodeSnapshot",
    "NativePolicy",
    "Observation",
    "ObservationConflict",
    "ObservationInput",
    "Relationship",
    "canonical_json",
    "verify_episode_snapshot",
]


@functools.lru_cache(maxsize=1)
def _native_snapshot_validator() -> Any:
    # Wheel assets are packaged under ancilis/shared. Only a real source checkout
    # may use its own shared directory; never search sibling repositories or cwd.
    from pathlib import Path
    from jsonschema import Draft202012Validator, FormatChecker

    here = Path(__file__).resolve()
    schema = here.parents[1] / "shared/episodes/v1/episode.schema.json"
    if not schema.is_file():
        root = here.parents[4]
        if (root / "python/src/ancilis/episodes/__init__.py").resolve() != here or not (
            root / "pyproject.toml"
        ).is_file():
            raise RuntimeError("Native episode schemas are missing from this installation")
        schema = root / "shared/episodes/v1/episode.schema.json"
    checker = FormatChecker()

    @checker.checks("date-time", raises=(EpisodeError, ValueError, TypeError))
    def valid_time(value: object) -> bool:
        if not isinstance(value, str):
            raise TypeError("date-time must be a string")
        _timestamp(value)
        return True

    return Draft202012Validator(json.loads(schema.read_text()), format_checker=checker)


def verify_episode_snapshot(
    snapshot: EpisodeSnapshot | Mapping[str, Any],
    *,
    assessed_at: str | None = None,
    expected_tenant: str | None = None,
) -> EpisodeVerification:
    """Unsigned integrity inspection. A match never authenticates a signer or body."""
    validator = _native_snapshot_validator()
    assessed = _now()
    policy_document = {
        "schema": "ancilis-native-verification-policy/1",
        "mode": "INTEGRITY_ONLY",
        "revision_method": "ancilis-native-revision/2",
        "expected_tenant": None,
    }
    policy = _hash("ancilis-native-verification-policy/1", policy_document)

    def result(status: VerificationStatus, *reasons: str) -> EpisodeVerification:
        return EpisodeVerification(
            _freeze(
                {
                    "schema": "ancilis-verification/1",
                    "status": status,
                    "envelope_authenticated": False,
                    "protected_bodies": "NOT_REQUESTED",
                    "reconstruction": "UNSUPPORTED",
                    "policy_sha256": policy,
                    "assessed_at": assessed,
                    "reasons": list(reasons),
                    "verified_claim_refs": [],
                }
            )
        )

    try:
        if assessed_at is not None:
            _timestamp(assessed_at)
            assessed = assessed_at
        if expected_tenant is not None:
            _id(expected_tenant)
        policy_document["expected_tenant"] = expected_tenant
        policy = _hash("ancilis-native-verification-policy/1", policy_document)
        value: EpisodeSnapshotDict
        if isinstance(snapshot, EpisodeSnapshot):
            value = snapshot.to_dict()
        else:
            # The mapping is a foreign input. Canonical JSON and schema validation
            # happen before the concrete snapshot projection used below.
            value = cast(EpisodeSnapshotDict, snapshot)
        canonical_json(value)
        if not validator.is_valid(value):
            return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
        opened = value["open"]
        expected = opened["expected_surfaces"]
        if (
            value["tenant"] != opened["tenant"]
            or value["episode"] != opened["episode"]
            or expected_tenant is not None
            and value["tenant"] != expected_tenant
            or expected != [s for s in _SURFACES if s in expected]
            or len(set(opened["allowed_source_instances"]))
            != len(opened["allowed_source_instances"])
            or _hash("ancilis-episode-open/1", opened) != value["open_sha256"]
        ):
            return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
        rows = value["observations"]
        if value["revision"] < len(rows) + 1 or (value["revision"] == 1) != (
            value["previous_revision_id"] is None
        ):
            return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
        chain = _hash("ancilis-native-observation-chain/1", {"open_sha256": value["open_sha256"]})
        last_sequence = 0
        seen: set[str] = set()
        observed: set[Surface] = set()
        required_reasons: set[str] = set()
        artifacts: dict[str, tuple[str, int]] = {}
        calls: dict[str, _CallState] = {}
        for row in rows:
            # Native capture accepts application assertions only. Other methods
            # require a separately supported provider, not a vocabulary upgrade.
            ObservationInput(
                row["call_id"], row["occurred_at"], row["surface"], row["operation"],
                row["phase"], row["chunk_index"], row["outcome"], row["authority"],
                tuple(row["artifacts"]), tuple(row["relationships"]),
                tuple(row["provenance_refs"]), tuple(row["capture_gaps"]),
            )
            source = row["source"]
            if (
                row["tenant"] != value["tenant"]
                or row["episode"] != value["episode"]
                or row["episode_open"] != value["open_sha256"]
                or source["id"] != opened["owner_source"]
                or source["instance"] not in opened["allowed_source_instances"]
                or source["sequence"] <= last_sequence
                or row["clock_basis"] != "COLLECTOR_CLOCK_ASSERTION"
                or row["clock_evidence_refs"]
            ):
                return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
            last_sequence = source["sequence"]
            event = _hash(
                "ancilis-observation-id/1",
                {
                    "tenant": row["tenant"],
                    "episode_open": row["episode_open"],
                    "source_instance": source["instance"],
                    "call_id": row["call_id"],
                    "phase": row["phase"],
                    "chunk_index": row["chunk_index"],
                },
            )
            if event != row["event_id"] or event in seen:
                return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
            seen.add(event)
            for artifact in row["artifacts"]:
                binding = artifact["sha256"], artifact["byte_length"]
                if artifact["artifact"] in artifacts and artifacts[artifact["artifact"]] != binding:
                    return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
                artifacts[artifact["artifact"]] = binding
            if any(
                r["from_artifact"] not in artifacts or r["to_artifact"] not in artifacts
                for r in row["relationships"]
            ):
                return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
            call = calls.setdefault(
                row["call_id"], {"started": False, "ended": False, "failed": False, "next": 0}
            )
            if call["ended"]:
                return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
            if row["phase"] == "START":
                call["started"] = True
            elif row["phase"] == "CHUNK":
                if row["chunk_index"] is None:
                    return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
                if row["chunk_index"] != call["next"]:
                    required_reasons.add("CHUNK_GAP")
                    call["failed"] = True
                call["next"] = row["chunk_index"] + 1
                observed.add(row["surface"])
            else:
                call["ended"] = True
                call["failed"] |= row["outcome"] != "SUCCEEDED"
                if row["outcome"] == "SUCCEEDED":
                    observed.add(row["surface"])
            if row["phase"] != "START" and not call["started"]:
                required_reasons.add("MISSING_START")
            required_reasons.update(row["capture_gaps"])
            chain = _hash(
                "ancilis-native-observation-chain/1",
                {
                    "previous_observation_chain_sha256": chain,
                    "observation_sha256": _hash_encoded(
                        "ancilis-observation-payload/1", canonical_json(row)
                    ),
                },
            )
        if chain != value["observation_chain_sha256"]:
            return result("REJECTED", "NATIVE_CHAIN_MISMATCH")
        coverage = value["coverage"]
        if (
            coverage["expected_surfaces"] != expected
            or coverage["observed_surfaces"] != [s for s in _SURFACES if s in observed]
            or coverage["missing_surfaces"] != [s for s in expected if s not in observed]
            or coverage["incomplete_calls"]
            != sum(not c["started"] or not c["ended"] or c["failed"] for c in calls.values())
            or coverage["reasons"] != [r for r in _REASONS if r in coverage["reasons"]]
            or not required_reasons.issubset(coverage["reasons"])
        ):
            return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
        revision = _hash(
            "ancilis-native-revision/2",
            {
                "open_sha256": value["open_sha256"],
                "revision": value["revision"],
                "previous_revision_id": value["previous_revision_id"],
                "observation_chain_sha256": chain,
                "coverage": coverage,
            },
        )
        if revision != value["revision_id"]:
            return result("REJECTED", "NATIVE_CHAIN_MISMATCH")
        if "DISCARDED_EPISODE" in coverage["reasons"]:
            if rows:
                return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
            return result("UNVERIFIED", "NATIVE_HISTORY_DISCARDED", "NATIVE_CHAIN_MATCH")
        return result("UNVERIFIED", "NATIVE_CHAIN_MATCH")
    except (EpisodeError, KeyError, TypeError, ValueError, RecursionError):
        return result("REJECTED", "INVALID_NATIVE_SNAPSHOT")
