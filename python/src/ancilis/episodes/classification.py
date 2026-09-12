"""Classification orchestration over caller-trusted adapters, not a receipt verifier."""

from __future__ import annotations

import dataclasses
import functools
import inspect
import json
import re
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal, TypeAlias, TypedDict, cast

from . import ContentEvidenceDict, _freeze, _hash, _id, _thaw, _timestamp, canonical_json
from .signed import (
    AsyncBodyResolver,
    BodyResolver,
    EpisodeTrustPolicy,
    ProtectedBodyRequest,
    SignedEpisodeVerificationDict,
    averify_signed_episode,
    verify_signed_episode,
)

ClassificationOutcome: TypeAlias = Literal[
    "SUPPORTED_POSITIVE", "UNKNOWN", "ABSTAIN", "ERROR", "UNSUPPORTED"
]
ReportOrigin: TypeAlias = Literal["LOCAL_ASSESSMENT", "PARSED_UNAUTHENTICATED"]


class ClassificationError(ValueError):
    """A fixed-code configuration, import, or history error."""


class ClassificationAdapterDescriptor(TypedDict):
    provider_id: str
    method_id: str
    policy_sha256: str
    taxonomy: str
    supported_classes: list[str]


class SemanticProviderDescriptor(TypedDict):
    provider_id: str
    method_id: str
    runtime_id: str
    qualification: Literal["UNQUALIFIED"]


class ClassificationRequestDict(TypedDict):
    schema: Literal["ancilis-classification-request/1"]
    tenant: str
    episode: str
    open_sha256: str
    revision_id: str
    event_id: str
    artifact_index: int
    reference: ContentEvidenceDict
    assessed_at: str
    adapter: ClassificationAdapterDescriptor | None
    request_sha256: str


class ClassificationResponse(TypedDict):
    schema: Literal["ancilis-classification-response/1"]
    request_sha256: str
    outcome: ClassificationOutcome
    classification: str | None
    evidence_refs: list[str]
    reasons: list[str]


class SemanticRequestDict(TypedDict):
    schema: Literal["ancilis-semantic-request/1"]
    classification_request: ClassificationRequestDict
    trusted_response: ClassificationResponse
    provider: SemanticProviderDescriptor
    request_sha256: str


class SemanticProposal(TypedDict):
    schema: Literal["ancilis-semantic-proposal/1"]
    request_sha256: str
    status: Literal["PROPOSED", "UNKNOWN", "ABSTAIN", "ERROR", "UNSUPPORTED"]
    proposed_classification: str | None
    evidence_refs: list[str]
    reasons: list[str]


class SemanticAssessment(TypedDict):
    state: Literal["NOT_REQUESTED", "UNQUALIFIED"]
    request: SemanticRequestDict | None
    response: SemanticProposal | None
    sdk_reason: Literal["SEMANTIC_PROVIDER_ERROR", "INVALID_SEMANTIC_RESPONSE"] | None


class ClassificationAssessment(TypedDict):
    request: ClassificationRequestDict
    outcome: ClassificationOutcome
    classification: str | None
    response: ClassificationResponse | None
    sdk_reason: (
        Literal[
            "CLASSIFICATION_PROVIDER_UNAVAILABLE", "ADAPTER_CALL_FAILED", "INVALID_ADAPTER_RESPONSE"
        ]
        | None
    )
    trust_basis: Literal["NONE", "ADAPTER_ATTESTED"]
    semantic: SemanticAssessment


class EpisodeClassificationReportDict(TypedDict):
    schema: Literal["ancilis-classification-report/1"]
    tenant: str | None
    episode: str | None
    open_sha256: str | None
    revision_id: str | None
    export_sha256: str | None
    assessed_at: str
    verification: SignedEpisodeVerificationDict
    adapter: ClassificationAdapterDescriptor | None
    semantic_provider: SemanticProviderDescriptor | None
    classifications: list[ClassificationAssessment]
    report_sha256: str


class ClassificationHistoryEntry(TypedDict):
    origin: ReportOrigin
    report: EpisodeClassificationReportDict


@dataclasses.dataclass(frozen=True)
class ClassificationRequest:
    _document: object = dataclasses.field(repr=False)

    def to_dict(self) -> ClassificationRequestDict:
        return cast(ClassificationRequestDict, _thaw(self._document))

    @property
    def request_sha256(self) -> str:
        return self.to_dict()["request_sha256"]


@dataclasses.dataclass(frozen=True)
class SemanticRequest:
    _document: object = dataclasses.field(repr=False)

    def to_dict(self) -> SemanticRequestDict:
        return cast(SemanticRequestDict, _thaw(self._document))

    @property
    def request_sha256(self) -> str:
        return self.to_dict()["request_sha256"]


ClassificationResolver: TypeAlias = Callable[
    [ClassificationRequest, bytes], ClassificationResponse | Awaitable[ClassificationResponse]
]
SemanticProposer: TypeAlias = Callable[
    [SemanticRequest, bytes], SemanticProposal | Awaitable[SemanticProposal]
]


@functools.lru_cache(maxsize=5)
def _validator(name: str) -> Any:
    from jsonschema import Draft202012Validator, FormatChecker

    here = Path(__file__).resolve()
    path = here.parents[1] / "shared/episodes/v1" / f"{name}.schema.json"
    if not path.is_file():
        root = here.parents[4]
        if (root / "python/src/ancilis/episodes/classification.py").resolve() != here or not (
            root / "pyproject.toml"
        ).is_file():
            raise RuntimeError("Classification schemas are missing from this installation")
        path = root / "shared/episodes/v1" / f"{name}.schema.json"
    checker = FormatChecker()

    @checker.checks("date-time", raises=(ValueError, TypeError))
    def time(value: object) -> bool:
        _timestamp(value)  # type: ignore[arg-type]
        return True

    return Draft202012Validator(json.loads(path.read_text()), format_checker=checker)


def _json(value: object) -> Any:
    return json.loads(canonical_json(value))


def _ordered(values: list[str]) -> bool:
    return values == sorted(set(values))


def _descriptor(d: object, semantic: bool = False) -> Any:
    # The descriptor subschema is shared with requests, avoiding a second wire contract.
    document = _json(d)
    name = "semantic-request" if semantic else "classification-request"
    key = "provider" if semantic else "adapter"
    schema = _validator(name).schema["properties"][key]
    if not semantic:
        schema = schema["anyOf"][0]
    _validator(name).evolve(schema=schema).validate(document)
    if not semantic and not _ordered(document["supported_classes"]):
        raise ValueError()
    return document


@dataclasses.dataclass(frozen=True, init=False)
class TrustedClassificationAdapter:
    """Caller-trusted code that authenticates original receipts before returning."""

    _document: object = dataclasses.field(repr=False)
    _resolve: ClassificationResolver = dataclasses.field(repr=False)

    def __init__(
        self,
        *,
        provider_id: str,
        method_id: str,
        policy_sha256: str,
        taxonomy: str,
        supported_classes: list[str],
        resolve: ClassificationResolver,
    ) -> None:
        try:
            d = _descriptor(
                dict(
                    provider_id=provider_id,
                    method_id=method_id,
                    policy_sha256=policy_sha256,
                    taxonomy=taxonomy,
                    supported_classes=supported_classes,
                )
            )
            if not callable(resolve):
                raise ValueError()
        except Exception:
            raise ClassificationError("INVALID_CLASSIFICATION_ADAPTER") from None
        object.__setattr__(self, "_document", _freeze(d))
        object.__setattr__(self, "_resolve", resolve)

    def to_dict(self) -> ClassificationAdapterDescriptor:
        return cast(ClassificationAdapterDescriptor, _thaw(self._document))


@dataclasses.dataclass(frozen=True, init=False)
class ExperimentalSemanticProvider:
    """Explicitly UNQUALIFIED proposal callback; cannot create determinations."""

    _document: object = dataclasses.field(repr=False)
    _propose: SemanticProposer = dataclasses.field(repr=False)

    def __init__(
        self, *, provider_id: str, method_id: str, runtime_id: str, propose: SemanticProposer
    ) -> None:
        try:
            d = _descriptor(
                dict(
                    provider_id=provider_id,
                    method_id=method_id,
                    runtime_id=runtime_id,
                    qualification="UNQUALIFIED",
                ),
                True,
            )
            if not callable(propose):
                raise ValueError()
        except Exception:
            raise ClassificationError("INVALID_SEMANTIC_PROVIDER") from None
        object.__setattr__(self, "_document", _freeze(d))
        object.__setattr__(self, "_propose", propose)

    def to_dict(self) -> SemanticProviderDescriptor:
        return cast(SemanticProviderDescriptor, _thaw(self._document))


def _bound(d: dict[str, Any], field: str = "request_sha256") -> dict[str, Any]:
    return {**d, field: _hash(d["schema"], d)}


def _check_hash(d: dict[str, Any], field: str = "request_sha256") -> None:
    if d[field] != _hash(d["schema"], {k: v for k, v in d.items() if k != field}):
        raise ValueError()


def _response(value: object, request: dict[str, Any], semantic: bool = False) -> Any:
    d = _json(value)
    _validator("semantic-proposal" if semantic else "classification-response").validate(d)
    if (
        d["request_sha256"] != request["request_sha256"]
        or not _ordered(d["reasons"])
        or not _ordered(d["evidence_refs"])
    ):
        raise ValueError()
    positive = d["status"] == "PROPOSED" if semantic else d["outcome"] == "SUPPORTED_POSITIVE"
    classification = d["proposed_classification"] if semantic else d["classification"]
    if positive:
        if classification is None or not d["evidence_refs"]:
            raise ValueError()
        if not semantic and (
            classification not in request["adapter"]["supported_classes"]
            or d["evidence_refs"]
            != sorted(set(request["reference"]["classification_receipt_refs"]))
        ):
            raise ValueError()
    elif classification is not None or not d["reasons"]:
        raise ValueError()
    return d


def _validate_report(value: object) -> dict[str, Any]:
    d = _json(value)
    _validator("classification-report").validate(d)
    _check_hash(d, "report_sha256")
    v = d["verification"]
    if d["assessed_at"] != v["assessed_at"] or d["export_sha256"] != v["export_sha256"]:
        raise ValueError()
    if any(
        (d[k] is not None) != v["envelope_authenticated"]
        for k in ("tenant", "episode", "open_sha256", "revision_id")
    ):
        raise ValueError()
    if d["semantic_provider"] is not None and d["adapter"] is None:
        raise ValueError()
    if d["adapter"] is not None:
        _descriptor(d["adapter"])
    if d["semantic_provider"] is not None:
        _descriptor(d["semantic_provider"], True)
    if d["classifications"] and (
        v["status"] != "AUTHENTICATED"
        or v["protected_bodies"] != "VERIFIED"
        or not v["envelope_authenticated"]
    ):
        raise ValueError()
    if (
        v["protected_bodies"] == "VERIFIED"
        and len(d["classifications"]) != v["verified_body_count"]
    ):
        raise ValueError()
    seen = set()
    for row in d["classifications"]:
        q = row["request"]
        _check_hash(q)
        for key in ("tenant", "episode", "open_sha256", "revision_id", "assessed_at", "adapter"):
            if q[key] != d[key]:
                raise ValueError()
        identity = (q["event_id"], q["artifact_index"])
        if identity in seen:
            raise ValueError()
        seen.add(identity)
        response = row["response"]
        if response is not None:
            if (
                d["adapter"] is None
                or row["sdk_reason"] is not None
                or row["trust_basis"] != "ADAPTER_ATTESTED"
            ):
                raise ValueError()
            _response(response, q)
            if (row["outcome"], row["classification"]) != (
                response["outcome"],
                response["classification"],
            ):
                raise ValueError()
        else:
            expected = (
                "UNKNOWN" if row["sdk_reason"] == "CLASSIFICATION_PROVIDER_UNAVAILABLE" else "ERROR"
            )
            if (
                row["sdk_reason"] is None
                or row["trust_basis"] != "NONE"
                or row["outcome"] != expected
                or row["classification"] is not None
            ):
                raise ValueError()
            if (row["sdk_reason"] == "CLASSIFICATION_PROVIDER_UNAVAILABLE") != (
                d["adapter"] is None
            ):
                raise ValueError()
        sem = row["semantic"]
        runs = (
            d["semantic_provider"] is not None
            and response is not None
            and response["outcome"] == "UNKNOWN"
        )
        if not runs:
            if sem != {
                "state": "NOT_REQUESTED",
                "request": None,
                "response": None,
                "sdk_reason": None,
            }:
                raise ValueError()
        else:
            sq = sem["request"]
            if sem["state"] != "UNQUALIFIED" or sq is None:
                raise ValueError()
            _check_hash(sq)
            if (
                sq["classification_request"] != q
                or sq["trusted_response"] != response
                or sq["provider"] != d["semantic_provider"]
            ):
                raise ValueError()
            if sem["response"] is not None:
                if sem["sdk_reason"] is not None:
                    raise ValueError()
                _response(sem["response"], sq, True)
            elif sem["sdk_reason"] is None:
                raise ValueError()
    return cast(dict[str, Any], d)


@dataclasses.dataclass(frozen=True, init=False)
class EpisodeClassificationReport:
    _document: object = dataclasses.field(repr=False)
    _origin: ReportOrigin

    def __init__(self, document: EpisodeClassificationReportDict | dict[str, Any]) -> None:
        try:
            d = _validate_report(document)
        except Exception:
            raise ClassificationError("INVALID_CLASSIFICATION_REPORT") from None
        object.__setattr__(self, "_document", _freeze(d))
        object.__setattr__(self, "_origin", "PARSED_UNAUTHENTICATED")

    @property
    def origin(self) -> ReportOrigin:
        return self._origin

    def to_dict(self) -> EpisodeClassificationReportDict:
        return cast(EpisodeClassificationReportDict, _thaw(self._document))


class ClassificationHistory:
    """Bounded volatile report history. Imports remain visibly unauthenticated."""

    def __init__(
        self,
        tenant: str,
        episode: str,
        open_sha256: str,
        *,
        max_reports: int = 64,
        max_bytes: int = 16777216,
    ) -> None:
        try:
            _id(tenant)
            _id(episode)
            if (
                not re.fullmatch("[0-9a-f]{64}", open_sha256)
                or type(max_reports) is not int
                or not 1 <= max_reports <= 64
                or type(max_bytes) is not int
                or not 1 <= max_bytes <= 16777216
            ):
                raise ValueError()
        except Exception:
            raise ClassificationError("INVALID_CLASSIFICATION_HISTORY") from None
        self._scope = (tenant, episode, open_sha256)
        self._max_reports = max_reports
        self._max_bytes = max_bytes
        self._entries: list[tuple[ReportOrigin, bytes]] = []
        self._hashes: set[str] = set()
        self._bytes = 0
        self._lock = threading.RLock()

    def append(self, report: EpisodeClassificationReport) -> bool:
        with self._lock:
            if not isinstance(report, EpisodeClassificationReport):
                raise ClassificationError("INVALID_CLASSIFICATION_REPORT")
            d = report.to_dict()
            if tuple(d[k] for k in ("tenant", "episode", "open_sha256")) != self._scope:
                raise ClassificationError("HISTORY_SCOPE_MISMATCH")
            # Revalidate before retaining even a caller-mutated value object.
            EpisodeClassificationReport(d)
            digest = d["report_sha256"]
            if digest in self._hashes:
                return False
            raw = canonical_json(d)
            if len(self._entries) >= self._max_reports or self._bytes + len(raw) > self._max_bytes:
                raise ClassificationError("HISTORY_LIMIT")
            self._entries.append((report.origin, raw))
            self._hashes.add(digest)
            self._bytes += len(raw)
            return True

    def inspect(self) -> tuple[ClassificationHistoryEntry, ...]:
        with self._lock:
            return tuple(
                {"origin": origin, "report": json.loads(raw)} for origin, raw in self._entries
            )


def _config(
    trust: EpisodeTrustPolicy,
    adapter: TrustedClassificationAdapter | None,
    semantic: ExperimentalSemanticProvider | None,
    body: object,
    asynchronous: bool,
) -> tuple[Any, Any, Any, Any]:
    if (
        not isinstance(trust, EpisodeTrustPolicy)
        or trust.to_dict()["body_mode"] != "ALL_REFERENCED"
    ):
        raise ClassificationError("BODY_VERIFICATION_REQUIRED")
    if adapter is not None and not isinstance(adapter, TrustedClassificationAdapter):
        raise ClassificationError("INVALID_CLASSIFICATION_ADAPTER")
    if semantic is not None and not isinstance(semantic, ExperimentalSemanticProvider):
        raise ClassificationError("INVALID_SEMANTIC_PROVIDER")
    if semantic is not None and adapter is None:
        raise ClassificationError("SEMANTIC_REQUIRES_TRUSTED_ADAPTER")
    resolve = adapter._resolve if adapter else None
    propose = semantic._propose if semantic else None
    for cb in (resolve, propose, body):
        if cb is not None and not callable(cb):
            raise ClassificationError("INVALID_CALLBACK")
        if (
            not asynchronous
            and cb is not None
            and (inspect.iscoroutinefunction(cb) or inspect.iscoroutinefunction(type(cb).__call__))
        ):
            raise ClassificationError("ASYNC_CALLBACK_IN_SYNC_API")
    return (
        _json(adapter.to_dict()) if adapter else None,
        _json(semantic.to_dict()) if semantic else None,
        resolve,
        propose,
    )


def _base(
    export: str | bytes, v: SignedEpisodeVerificationDict, a: Any, s: Any
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot = json.loads(export)["snapshot"] if v["envelope_authenticated"] else None
    d = dict(
        schema="ancilis-classification-report/1",
        **{
            k: snapshot[k] if snapshot else None
            for k in ("tenant", "episode", "open_sha256", "revision_id")
        },
        export_sha256=v["export_sha256"],
        assessed_at=v["assessed_at"],
        verification=v,
        adapter=a,
        semantic_provider=s,
        classifications=[],
    )
    requests = []
    if (
        snapshot is not None
        and v["status"] == "AUTHENTICATED"
        and v["protected_bodies"] == "VERIFIED"
    ):
        for row in snapshot["observations"]:
            for index, reference in enumerate(row["artifacts"]):
                requests.append(
                    _bound(
                        dict(
                            schema="ancilis-classification-request/1",
                            **{
                                k: d[k]
                                for k in (
                                    "tenant",
                                    "episode",
                                    "open_sha256",
                                    "revision_id",
                                    "assessed_at",
                                    "adapter",
                                )
                            },
                            event_id=row["event_id"],
                            artifact_index=index,
                            reference=reference,
                        )
                    )
                )
    return d, requests


def _row(request: dict[str, Any], response: Any, reason: str | None) -> dict[str, Any]:
    return dict(
        request=request,
        outcome=response["outcome"]
        if response
        else ("UNKNOWN" if reason == "CLASSIFICATION_PROVIDER_UNAVAILABLE" else "ERROR"),
        classification=response["classification"] if response else None,
        response=response,
        sdk_reason=reason,
        trust_basis="ADAPTER_ATTESTED" if response else "NONE",
        semantic=dict(state="NOT_REQUESTED", request=None, response=None, sdk_reason=None),
    )


def _semantic_request(request: dict[str, Any], response: Any, provider: Any) -> dict[str, Any]:
    return _bound(
        dict(
            schema="ancilis-semantic-request/1",
            classification_request=request,
            trusted_response=response,
            provider=provider,
        )
    )


def _sync_call(cb: Any, request: object, body: bytes) -> Any:
    value = cb(request, body)
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):
            value.close()
        raise ValueError()
    return value


def _finish(d: dict[str, Any]) -> EpisodeClassificationReport:
    report = EpisodeClassificationReport(_bound(d, "report_sha256"))
    object.__setattr__(report, "_origin", "LOCAL_ASSESSMENT")
    return report


def assess_episode_classifications(
    export: str | bytes,
    *,
    trust: EpisodeTrustPolicy,
    adapter: TrustedClassificationAdapter | None = None,
    body_resolver: BodyResolver | None = None,
    assessed_at: str | None = None,
    experimental_semantic: ExperimentalSemanticProvider | None = None,
) -> EpisodeClassificationReport:
    a, s, resolve, propose = _config(trust, adapter, experimental_semantic, body_resolver, False)
    cache: list[bytes] = []

    def caching(request: ProtectedBodyRequest) -> bytes | None:
        body = body_resolver(request) if body_resolver else None
        if type(body) is bytes:
            cache.append(body)
        return body

    v = verify_signed_episode(
        export, trust, assessed_at=assessed_at, body_resolver=caching
    ).to_dict()
    d, requests = _base(export, v, a, s)
    for request, body in zip(requests, cache, strict=True) if requests else ():
        response = None
        reason: str | None = "CLASSIFICATION_PROVIDER_UNAVAILABLE"
        if resolve:
            try:
                raw = _sync_call(resolve, ClassificationRequest(_freeze(request)), body)
            except Exception:
                reason = "ADAPTER_CALL_FAILED"
            else:
                try:
                    response = _response(raw, request)
                    reason = None
                except Exception:
                    reason = "INVALID_ADAPTER_RESPONSE"
        row = _row(request, response, reason)
        if propose and response and response["outcome"] == "UNKNOWN":
            q = _semantic_request(request, response, s)
            p = None
            r = None
            try:
                raw = _sync_call(propose, SemanticRequest(_freeze(q)), body)
            except Exception:
                r = "SEMANTIC_PROVIDER_ERROR"
            else:
                try:
                    p = _response(raw, q, True)
                except Exception:
                    r = "INVALID_SEMANTIC_RESPONSE"
            row["semantic"] = dict(state="UNQUALIFIED", request=q, response=p, sdk_reason=r)
        d["classifications"].append(row)
    return _finish(d)


async def aassess_episode_classifications(
    export: str | bytes,
    *,
    trust: EpisodeTrustPolicy,
    adapter: TrustedClassificationAdapter | None = None,
    body_resolver: AsyncBodyResolver | None = None,
    assessed_at: str | None = None,
    experimental_semantic: ExperimentalSemanticProvider | None = None,
) -> EpisodeClassificationReport:
    a, s, resolve, propose = _config(trust, adapter, experimental_semantic, body_resolver, True)
    cache: list[bytes] = []

    async def caching(request: ProtectedBodyRequest) -> bytes | None:
        body = body_resolver(request) if body_resolver else None
        if inspect.isawaitable(body):
            body = await body
        if type(body) is bytes:
            cache.append(body)
        return body

    v = (
        await averify_signed_episode(export, trust, assessed_at=assessed_at, body_resolver=caching)
    ).to_dict()
    d, requests = _base(export, v, a, s)
    for request, body in zip(requests, cache, strict=True) if requests else ():
        response = None
        reason: str | None = "CLASSIFICATION_PROVIDER_UNAVAILABLE"
        if resolve:
            try:
                raw = resolve(ClassificationRequest(_freeze(request)), body)
                if inspect.isawaitable(raw):
                    raw = await raw
            except Exception:
                reason = "ADAPTER_CALL_FAILED"
            else:
                try:
                    response = _response(raw, request)
                    reason = None
                except Exception:
                    reason = "INVALID_ADAPTER_RESPONSE"
        row = _row(request, response, reason)
        if propose and response and response["outcome"] == "UNKNOWN":
            q = _semantic_request(request, response, s)
            p = None
            r = None
            try:
                raw = propose(SemanticRequest(_freeze(q)), body)
                if inspect.isawaitable(raw):
                    raw = await raw
            except Exception:
                r = "SEMANTIC_PROVIDER_ERROR"
            else:
                try:
                    p = _response(raw, q, True)
                except Exception:
                    r = "INVALID_SEMANTIC_RESPONSE"
            row["semantic"] = dict(state="UNQUALIFIED", request=q, response=p, sdk_reason=r)
        d["classifications"].append(row)
    return _finish(d)
