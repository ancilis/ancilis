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
import types
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Generic, TypeVar

T = TypeVar("T")
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


def _frozen_dict(value: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    return tuple((key, _freeze(item)) for key, item in value.items())


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _frozen_dict(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if (
        isinstance(value, tuple)
        and value
        and all(isinstance(p, tuple) and len(p) == 2 and isinstance(p[0], str) for p in value)
    ):
        return {k: _thaw(v) for k, v in value}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclasses.dataclass(frozen=True)
class Authority:
    principal: str | None = None
    service: str | None = None
    delegation: str | None = None
    approval: str | None = None
    scope: str | None = None
    basis: str = "APPLICATION_ASSERTION"

    def __post_init__(self):
        if self.basis != "APPLICATION_ASSERTION":
            raise EpisodeError("INVALID_OBSERVATION")
        for value in (self.principal, self.service, self.delegation, self.approval, self.scope):
            if value is not None:
                _id(value)

    def to_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ContentEvidence:
    artifact: str
    sha256: str
    byte_length: int
    role: str = "OUTPUT"
    access_scope: str = "application"
    classification_receipt_refs: tuple[str, ...] = ()

    @classmethod
    def from_bytes(
        cls, artifact: str, data: bytes, *, role: str = "OUTPUT", access_scope: str = "application"
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
        )

    def __post_init__(self):
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

    def to_dict(self):
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
    basis: str = "APPLICATION_ASSERTION"
    method: str = "ancilis-application-assertion/1"
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self):
        if self.kind not in ("ACCESSED", "OPERAND", "BYTE_EQUAL", "ASSERTED_ORIGIN", "WRITTEN", "READ", "SEMANTIC_PROPOSAL"):
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

    def to_dict(self):
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
    surface: str
    operation: str
    phase: str
    chunk_index: int | None
    outcome: str
    authority: Authority = dataclasses.field(default_factory=Authority)
    artifacts: tuple[ContentEvidence, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    provenance_refs: tuple[str, ...] = ()
    capture_gaps: tuple[str, ...] = ()

    def __post_init__(self):
        if isinstance(self.authority, Mapping):
            object.__setattr__(self, "authority", Authority(**self.authority))
        object.__setattr__(
            self,
            "artifacts",
            tuple(ContentEvidence(**x) if isinstance(x, Mapping) else x for x in self.artifacts),
        )
        object.__setattr__(
            self,
            "relationships",
            tuple(Relationship(**x) if isinstance(x, Mapping) else x for x in self.relationships),
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
        if any(reason not in _REASONS for reason in self.capture_gaps):
            raise EpisodeError("INVALID_OBSERVATION")
        if any(not isinstance(item, ContentEvidence) for item in self.artifacts) or any(
            not isinstance(item, Relationship) for item in self.relationships
        ) or len(self.artifacts) > 64 or len(self.relationships) > 64 or len(self.provenance_refs) > 64 or len(self.capture_gaps) > 64:
            raise EpisodeError("INVALID_OBSERVATION")
        for ref in self.provenance_refs:
            _digest(ref)

    def to_dict(self):
        return {
            "call_id": self.call_id,
            "occurred_at": self.occurred_at,
            "surface": self.surface,
            "operation": self.operation,
            "phase": self.phase,
            "chunk_index": self.chunk_index,
            "outcome": self.outcome,
            "authority": self.authority.to_dict(),
            "artifacts": [x.to_dict() for x in self.artifacts],
            "relationships": [x.to_dict() for x in self.relationships],
            "provenance_refs": list(self.provenance_refs),
            "capture_gaps": list(self.capture_gaps),
        }


@dataclasses.dataclass(frozen=True)
class Observation:
    _value: Any

    def to_dict(self):
        return _thaw(self._value)

    def __getitem__(self, key):
        return self.to_dict()[key]


@dataclasses.dataclass(frozen=True)
class CaptureFrame:
    phase: str
    args: tuple[Any, ...]
    kwargs: Mapping[str, Any]
    result: Any = None
    error: BaseException | None = None
    chunk_index: int | None = None


@dataclasses.dataclass(frozen=True)
class CaptureResult:
    artifacts: tuple[ContentEvidence, ...] = ()
    relationships: tuple[Relationship, ...] = ()

    def __post_init__(self):
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

    def __post_init__(self):
        for name in (
            "max_events",
            "max_bytes",
            "max_episodes",
            "max_attachments",
            "max_body_bytes",
            "max_diagnostic_keys",
        ):
            value = getattr(self, name)
            maximum = {"max_events": 10000, "max_bytes": 268435456, "max_episodes": 4096, "max_attachments": 4096, "max_body_bytes": 16777216, "max_diagnostic_keys": 4096}[name]
            if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
                raise EpisodeError("INVALID_POLICY")
        if not isinstance(self.strict_capture, bool):
            raise EpisodeError("INVALID_POLICY")

    def to_dict(self):
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
    def sha256(self):
        return _hash("ancilis-native-policy/1", self.to_dict())


@dataclasses.dataclass(frozen=True)
class EpisodeSnapshot:
    _value: Any

    def to_dict(self):
        return _thaw(self._value)


@dataclasses.dataclass(frozen=True)
class Diagnostics:
    _value: Any

    def to_dict(self):
        return _thaw(self._value)


class Episode:
    def __init__(
        self, sdk: Ancilis, episode_id: str, expected_surfaces: Sequence[str], *, saturated=False
    ):
        self._sdk = sdk
        self.id = episode_id
        self._expected = tuple(sorted(set(expected_surfaces), key=_SURFACES.index))
        self._saturated = saturated
        self._finished = False
        self._discarded = False
        self._active = 0
        self._tokens = []
        self._records = []
        self._by_id = {}
        self._artifacts = {}
        self._calls = {}
        self._reasons = {}
        self._lost = 0
        self._reserved_bytes = 0
        self._reserved_events = 0
        self._revision = 1
        self._previous = None
        self._open = {
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
        if saturated:
            self._reasons["LEDGER_EPISODE_CAP"] = 1
            self._lost = 1
        self._refresh()

    def __enter__(self):
        if self._discarded:
            raise EpisodeLifecycleError("EPISODE_DISCARDED")
        self._active += 1
        self._tokens.append(_active_episode.set(self))
        return self

    def __exit__(self, typ, value, traceback):
        if not self._tokens or _active_episode.get() is not self:
            self._loss("CONTEXT_EXIT_MISMATCH")
        else:
            _active_episode.reset(self._tokens.pop())
        self._active = max(0, self._active - 1)
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, *args):
        return self.__exit__(*args)

    def finish(self):
        self._finished = True
        return self

    def inspect(self) -> EpisodeSnapshot:
        return EpisodeSnapshot(_freeze(self._snapshot()))

    def _loss(self, reason: str):
        self._lost = min(_MAX_SAFE, self._lost + 1)
        self._reasons[reason] = min(_MAX_SAFE, self._reasons.get(reason, 0) + 1)
        self._previous = self._revision_id
        self._revision = min(_MAX_SAFE, self._revision + 1)
        self._refresh()

    def _coverage(self):
        observed = set()
        incomplete = 0
        for call in self._calls.values():
            if call.get("good"):
                observed.add(call["surface"])
            if (call.get("started") and not call.get("ended")) or call.get("outcome") not in (
                None,
                "SUCCEEDED",
            ):
                incomplete += 1
        return {
            "expected_surfaces": list(self._expected),
            "observed_surfaces": [s for s in _SURFACES if s in observed],
            "missing_surfaces": [s for s in _SURFACES if s in self._expected and s not in observed],
            "complete": False,
            "lost_events": self._lost,
            "incomplete_calls": incomplete,
            "reasons": [r for r in _REASONS if r in self._reasons],
            "reconstruction_exclusions": [],
        }

    def _refresh(self):
        coverage = self._coverage()
        preimage = {
            "open_sha256": self._open_hash,
            "revision": self._revision,
            "previous_revision_id": self._previous,
            "event_ids": [r.to_dict()["event_id"] for r in self._records],
            "coverage": coverage,
        }
        self._revision_id = _hash("ancilis-native-revision/1", preimage)

    def _snapshot(self):
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
        }

    def observe(self, input: ObservationInput) -> Observation:
        if not isinstance(input, ObservationInput):
            raise TypeError("ObservationInput required")
        return self._admit(input, manual=True)

    def _admit(self, input: ObservationInput, manual=False):
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
        candidate = {
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
        }
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
        for artifact in input.artifacts:
            bound = self._artifacts.get(artifact.artifact)
            if bound is not None and bound != (artifact.sha256, artifact.byte_length):
                self._loss("ARTIFACT_REBIND")
                if manual:
                    raise EpisodeError("ARTIFACT_REBIND")
                return None
        existing = {
            artifact["artifact"] for record in self._records for artifact in record.to_dict()["artifacts"]
        }
        supplied = {a.artifact for a in input.artifacts}
        if any(
            r.from_artifact not in existing | supplied or r.to_artifact not in existing | supplied
            for r in input.relationships
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        proposed_call = dict(self._calls.get(input.call_id, {
            "surface": input.surface, "started": False, "ended": False, "next": 0,
            "good": False, "outcome": None,
        }))
        if input.phase == "START":
            if proposed_call["started"]:
                return self._invalid(manual, "MISSING_START")
            proposed_call["started"] = True
        elif input.phase == "CHUNK":
            if not proposed_call["started"] or proposed_call["ended"] or input.chunk_index != proposed_call["next"]:
                return self._invalid(manual, "CHUNK_GAP")
            proposed_call["next"] += 1
            proposed_call["good"] = True
        else:
            if not proposed_call["started"] or proposed_call["ended"]:
                return self._invalid(manual, "MISSING_END")
            proposed_call["ended"] = True
            proposed_call["outcome"] = input.outcome
            proposed_call["good"] = input.outcome == "SUCCEEDED"
        candidate["source"]["sequence"] = self._sdk._sequence + 1
        candidate["captured_at"] = self._sdk._clock()
        encoded = canonical_json(candidate)
        if self._sdk._event_count >= self._sdk.policy.max_events:
            self._loss("LEDGER_EVENT_CAP")
            if manual and self._sdk.policy.strict_capture:
                raise EpisodeCapacityError("LEDGER_EVENT_CAP")
            return None
        if self._sdk._event_bytes + len(encoded) > self._sdk.policy.max_bytes:
            self._loss("LEDGER_BYTE_CAP")
            if manual and self._sdk.policy.strict_capture:
                raise EpisodeCapacityError("LEDGER_BYTE_CAP")
            return None
        self._calls[input.call_id] = proposed_call
        self._sdk._sequence += 1
        record = Observation(_freeze(candidate))
        self._records.append(record)
        self._by_id[event_id] = record
        self._sdk._event_bytes += len(encoded)
        self._sdk._event_count += 1
        self._reserved_bytes += len(encoded)
        self._reserved_events += 1
        for artifact in input.artifacts:
            self._artifacts[artifact.artifact] = (artifact.sha256, artifact.byte_length)
        self._previous = self._revision_id
        self._revision += 1
        self._refresh()
        return record

    def _invalid(self, manual, reason):
        self._loss(reason)
        if manual:
            raise EpisodeError(reason)
        return None


class _GeneratorProxy:
    def __init__(self, iterator, terminal):
        self._iterator = iterator
        self._terminal = terminal
        self._index = 0
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            value = next(self._iterator)
        except StopIteration as stopped:
            self._terminal("SUCCEEDED", stopped.value)
            raise
        except BaseException as exc:
            self._terminal(
                "CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED", exc
            )
            raise
        self._terminal("CHUNK", value, self._index)
        self._index += 1
        return value

    def send(self, value):
        try:
            result = self._iterator.send(value)
        except StopIteration as stopped:
            self._terminal("SUCCEEDED", stopped.value)
            raise
        except BaseException as exc:
            self._terminal("FAILED", exc)
            raise
        self._terminal("CHUNK", result, self._index)
        self._index += 1
        return result

    def throw(self, *args):
        try:
            value = self._iterator.throw(*args)
        except StopIteration as stopped:
            self._terminal("SUCCEEDED", stopped.value)
            raise
        except BaseException as exc:
            self._terminal("CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED", exc)
            raise
        self._terminal("CHUNK", value, self._index)
        self._index += 1
        return value

    def close(self):
        try:
            return self._iterator.close()
        finally:
            self._terminal("CLOSED_EARLY", None)


class Ancilis:
    """A bounded in-memory native capture client; it does not persist evidence."""

    def __init__(
        self,
        tenant: str,
        source: str,
        *,
        source_instance: str | None = None,
        max_events=4096,
        max_bytes=16777216,
        max_episodes=256,
        max_attachments=256,
        max_body_bytes=1048576,
        max_diagnostic_keys=128,
        strict_capture=False,
        _clock: Callable[[], str] | None = None,
        _nonce_factory: Callable[[], str] | None = None,
    ):
        self.tenant = _id(tenant, "tenant")
        self.source = _id(source, "source")
        self.source_instance = str(uuid.uuid4()) if source_instance is None else source_instance
        _id(self.source_instance, "source_instance")
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
        self._episodes = {}
        self._attachments = {}
        self._mcp_attachments = {}
        self._closed = False
        self._event_bytes = 0
        self._event_count = 0
        self._sequence = 0
        self._diagnostics = {}
        self._discarded = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        return False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.close()
        return False

    def _diag(self, reason):
        self._diagnostics[reason] = min(_MAX_SAFE, self._diagnostics.get(reason, 0) + 1)

    def diagnostics(self):
        return Diagnostics(
            _freeze(
                {
                    "schema": "ancilis-native-diagnostics/1",
                    "reasons": [
                        {"reason": r, "count": self._diagnostics[r]}
                        for r in _REASONS
                        if r in self._diagnostics
                    ],
                    "discarded_episodes": self._discarded,
                }
            )
        )

    def episode(self, episode_id: str, *, expected_surfaces: Sequence[str]):
        if self._closed:
            raise EpisodeLifecycleError("SDK_CLOSED")
        episode_id = _id(episode_id, "episode")
        if not expected_surfaces or any(s not in _SURFACES for s in expected_surfaces):
            raise EpisodeError("INVALID_OBSERVATION")
        normalized = tuple(sorted(set(expected_surfaces), key=_SURFACES.index))
        existing = self._episodes.get(episode_id)
        if existing:
            if existing._expected != normalized:
                raise EpisodeError("EXPECTED_SURFACES_CONFLICT")
            return existing
        if len(self._episodes) >= self.policy.max_episodes:
            if self.policy.strict_capture:
                raise EpisodeCapacityError("LEDGER_EPISODE_CAP")
            self._diag("LEDGER_EPISODE_CAP")
            return Episode(self, episode_id, normalized, saturated=True)
        episode = Episode(self, episode_id, normalized)
        self._episodes[episode_id] = episode
        return episode

    def get_episode(self, episode_id):
        return self._episodes.get(episode_id)

    def discard_episode(self, episode_id):
        episode = self._episodes.get(episode_id)
        if episode is None:
            return False
        if episode._active or any(not c["ended"] for c in episode._calls.values() if c["started"]):
            raise EpisodeLifecycleError("EPISODE_ACTIVE")
        self._event_bytes -= episode._reserved_bytes
        self._event_count -= episode._reserved_events
        del self._episodes[episode_id]
        episode._discarded = True
        self._discarded = min(_MAX_SAFE, self._discarded + 1)
        self._diag("DISCARDED_EPISODE")
        return True

    def flush(self):
        return {
            "admitted_events": sum(len(e._records) for e in self._episodes.values()),
            "pending": 0,
            "durable": 0,
            "lost": sum(e._lost for e in self._episodes.values()),
            "storage": "MEMORY_ONLY",
        }

    async def aflush(self):
        return self.flush()

    def close(self):
        if not self._closed:
            self._closed = True
            for attachment in self._attachments.values():
                attachment.__ancilis_attachment_active__ = False
            self._attachments.clear()

    def detach(self, wrapped):
        attachment = self._attachments.pop(getattr(wrapped, "__ancilis_attachment_key__", None), None)
        if attachment is not None:
            attachment.__ancilis_attachment_active__ = False

    def bind_episode(self, fn: Callable[..., T], episode: Episode) -> Callable[..., T]:
        if episode._sdk is not self:
            raise EpisodeError("SOURCE_MISMATCH")
        context = contextvars.copy_context()

        def bound(*args, **kwargs):
            def run():
                token = _active_episode.set(episode)
                try:
                    return fn(*args, **kwargs)
                finally:
                    _active_episode.reset(token)

            return context.copy().run(run)

        return bound

    def _capture(
        self, episode, callback, frame, call_id, surface, operation, outcome, *, chunk=None
    ):
        if self._closed:
            self._diag("SDK_CLOSED")
            return
        if episode is None:
            self._diag("UNCORRELATED_CALL")
            return
        artifacts = ()
        relationships = ()
        gaps = ()
        if callback is None:
            gaps = ("CONTENT_NOT_CAPTURED",)
        else:
            try:
                result = callback(frame)
                if result is not None:
                    if not isinstance(result, CaptureResult):
                        raise TypeError
                    artifacts, relationships = result.artifacts, result.relationships
            except BaseException:
                episode._loss("CAPTURE_CALLBACK_FAILED")
                return
        phase = "CHUNK" if chunk is not None else "END"
        final = "OBSERVED" if phase == "CHUNK" else outcome
        try:
            episode._admit(
                ObservationInput(
                    call_id,
                    self._clock(),
                    surface,
                    operation,
                    phase,
                    chunk,
                    final,
                    artifacts=artifacts,
                    relationships=relationships,
                    capture_gaps=gaps,
                ),
                manual=False,
            )
        except EpisodeError:
            episode._loss("INVALID_OBSERVATION")

    def attach_tool(
        self,
        fn: Callable[..., T],
        *,
        name: str,
        surface: str,
        operation: str,
        capture: Callable[[CaptureFrame], CaptureResult | None] | None = None,
    ):
        if self._closed:
            raise EpisodeLifecycleError("SDK_CLOSED")
        if isinstance(fn, (staticmethod, classmethod, property)):
            raise TypeError("unsupported descriptor")
        if not callable(fn) or surface not in _SURFACES or operation not in _OPERATIONS:
            raise EpisodeError("INVALID_OBSERVATION")
        options = (name, surface, operation, id(capture))
        owned = getattr(fn, "__ancilis_attachment_owner__", None)
        if owned is self:
            if fn.__ancilis_attachment_options__ != options:
                raise EpisodeError("ATTACHMENT_CONFLICT")
            return fn
        if owned is not None:
            raise EpisodeError("ATTACHMENT_OTHER_SDK")
        key = id(fn)
        if key in self._attachments:
            existing = self._attachments[key]
            if existing.__ancilis_attachment_options__ != options:
                raise EpisodeError("ATTACHMENT_CONFLICT")
            return existing
        if len(self._attachments) >= self.policy.max_attachments:
            raise EpisodeCapacityError("ATTACHMENT_CAP")

        def start(args, kwargs):
            if self._closed or not wrapper.__ancilis_attachment_active__:
                return None, secrets.token_hex(16)
            episode = _active_episode.get()
            call_id = secrets.token_hex(16)
            if episode and episode._sdk is self:
                episode._admit(
                    ObservationInput(
                        call_id, self._clock(), surface, operation, "START", None, "STARTED"
                    ),
                    manual=False,
                )
            return episode, call_id

        def terminal(episode, call_id, args, kwargs, outcome, result=None, error=None, chunk=None):
            self._capture(
                episode,
                capture,
                CaptureFrame(
                    "CHUNK" if chunk is not None else "END", args, kwargs, result, error, chunk
                ),
                call_id,
                surface,
                operation,
                outcome,
                chunk=chunk,
            )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                episode, call_id = start(args, kwargs)
                try:
                    result = await fn(*args, **kwargs)
                except BaseException as exc:
                    terminal(
                        episode,
                        call_id,
                        args,
                        kwargs,
                        "CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED",
                        error=exc,
                    )
                    raise
                terminal(episode, call_id, args, kwargs, "SUCCEEDED", result)
                return result
        elif inspect.isasyncgenfunction(fn):

            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                episode, call_id = start(args, kwargs)
                iterator = fn(*args, **kwargs)
                index = 0
                sent = None
                first = True
                try:
                    while True:
                        try:
                            value = (
                                await iterator.__anext__() if first else await iterator.asend(sent)
                            )
                            first = False
                        except StopAsyncIteration:
                            terminal(episode, call_id, args, kwargs, "SUCCEEDED")
                            return
                        try:
                            sent = yield value
                            terminal(episode, call_id, args, kwargs, "CHUNK", value, chunk=index)
                            index += 1
                        except GeneratorExit:
                            await iterator.aclose()
                            terminal(episode, call_id, args, kwargs, "CLOSED_EARLY")
                            raise
                        except BaseException as exc:
                            try:
                                sent = await iterator.athrow(type(exc), exc, exc.__traceback__)
                            except StopAsyncIteration:
                                terminal(episode, call_id, args, kwargs, "FAILED", error=exc)
                                raise
                except BaseException as exc:
                    if not isinstance(exc, GeneratorExit):
                        terminal(
                            episode,
                            call_id,
                            args,
                            kwargs,
                            "CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED",
                            error=exc,
                        )
                    raise
        elif inspect.isgeneratorfunction(fn):

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                episode, call_id = start(args, kwargs)
                iterator = fn(*args, **kwargs)
                return _GeneratorProxy(
                    iterator,
                    lambda outcome, value, index=None: terminal(
                        episode, call_id, args, kwargs, outcome, value, chunk=index
                    ),
                )
        else:

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                episode, call_id = start(args, kwargs)
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    terminal(
                        episode,
                        call_id,
                        args,
                        kwargs,
                        "CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED",
                        error=exc,
                    )
                    raise
                if isinstance(result, (asyncio.Future, asyncio.Task)):

                    def done(future):
                        try:
                            terminal(episode, call_id, args, kwargs, "SUCCEEDED", future.result())
                        except BaseException as exc:
                            terminal(
                                episode,
                                call_id,
                                args,
                                kwargs,
                                "CANCELLED"
                                if isinstance(exc, asyncio.CancelledError)
                                else "FAILED",
                                error=exc,
                            )

                    result.add_done_callback(done)
                    return result
                if inspect.isawaitable(result) and not isinstance(result, types.CoroutineType):
                    if episode:
                        episode._loss("UNSUPPORTED_RETURN_PROTOCOL")
                    return result
                if isinstance(result, types.GeneratorType):
                    return _GeneratorProxy(
                        result,
                        lambda outcome, value, index=None: terminal(
                            episode, call_id, args, kwargs, outcome, value, chunk=index
                        ),
                    )
                terminal(episode, call_id, args, kwargs, "SUCCEEDED", result)
                return result

        wrapper.__ancilis_attachment_owner__ = self
        wrapper.__ancilis_attachment_options__ = options
        wrapper.__ancilis_attachment_key__ = key
        wrapper.__ancilis_attachment_active__ = True
        self._attachments[key] = wrapper
        return wrapper

    def attach_mcp(self, client, *, capture=None, surfaces: Mapping[str, Mapping[str, str]]):
        if self._closed:
            raise EpisodeLifecycleError("SDK_CLOSED")
        if getattr(client, "__ancilis_mcp_owner__", None) is not None:
            raise EpisodeError("SOURCE_MISMATCH")
        normalized = tuple(
            sorted(
                (name, config.get("surface"), config.get("operation"))
                for name, config in surfaces.items()
            )
        )
        if any(
            not isinstance(name, str) or surface not in _SURFACES or operation not in _OPERATIONS
            for name, surface, operation in normalized
        ):
            raise EpisodeError("INVALID_OBSERVATION")
        key = (id(client), normalized, id(capture))
        if key in self._mcp_attachments:
            return self._mcp_attachments[key]
        sdk = self

        class Adapter:
            def __init__(self):
                self._client = client
                self._wrapped = {}
                for tool_name, surface, operation in normalized:
                    async def invoke(request, _client=client):
                        result = _client.call_tool(request)
                        return await result if inspect.isawaitable(result) else result

                    self._wrapped[tool_name] = sdk.attach_tool(
                        invoke,
                        name=tool_name,
                        surface=surface,
                        operation=operation,
                        capture=capture,
                    )

            def __getattr__(self, name):
                return getattr(self._client, name)

            def call_tool(self, request, *args, **kwargs):
                name = request.get("name") if isinstance(request, dict) else request
                wrapped = self._wrapped.get(name)
                if wrapped is None:
                    sdk._diag("UNMAPPED_TOOL")
                    return self._client.call_tool(request, *args, **kwargs)
                return wrapped(request, *args, **kwargs)

        adapter = Adapter()
        adapter.__ancilis_mcp_owner__ = self
        self._mcp_attachments[key] = adapter
        return adapter


__all__ = [
    "Ancilis",
    "Authority",
    "CaptureFrame",
    "CaptureResult",
    "ContentEvidence",
    "Diagnostics",
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
]
