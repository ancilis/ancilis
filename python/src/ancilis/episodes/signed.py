"""Scoped native authentication and explicit protected-byte verification.

Signatures authenticate collector assertions, never classification or completeness.
Cryptography is loaded only when signing/trust configuration is constructed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast

from . import (
    ContentEvidence,
    EpisodeSnapshot,
    EpisodeSnapshotDict,
    _freeze,
    _hash,
    _id,
    _now,
    _thaw,
    _timestamp,
    canonical_json,
    verify_episode_snapshot,
)

if TYPE_CHECKING:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

MAX_SIGNED_EXPORT_BYTES = 32 * 1024 * 1024
_DOMAIN = b"ancilis-signed-episode/1\n"


class SignedEpisodeError(ValueError):
    """Fixed-code configuration/signing error; never contains evidence or keys."""


def _crypto() -> tuple[type[Ed25519PrivateKey], type[Ed25519PublicKey], type[InvalidSignature]]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError:
        raise SignedEpisodeError("CRYPTO_UNAVAILABLE") from None
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _hex(value: object, size: int) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is not None
    )


class EpisodeTrustKey(TypedDict):
    key_id: str
    public_key: str
    not_before: str | None
    not_after: str | None
    revoked: bool


class EpisodeTrustPolicyDict(TypedDict):
    schema: Literal["ancilis-episode-trust-policy/1"]
    tenant: str
    source: str
    keys: list[EpisodeTrustKey]
    body_mode: Literal["NONE", "ALL_REFERENCED"]
    max_body_bytes: int
    max_total_body_bytes: int
    max_body_requests: int


@dataclasses.dataclass(frozen=True, init=False)
class EpisodeTrustPolicy:
    """Independently provisioned, immutable key admission and body requirements."""

    _document: object = dataclasses.field(repr=False)
    _keys: Mapping[str, Ed25519PublicKey] = dataclasses.field(repr=False)
    sha256: str

    def __init__(self, document: Mapping[str, Any]) -> None:
        _, public_type, _ = _crypto()
        try:
            d = json.loads(canonical_json(document))
            if set(d) != set(EpisodeTrustPolicyDict.__annotations__):
                raise ValueError()
            if d["schema"] != "ancilis-episode-trust-policy/1" or d["body_mode"] not in (
                "NONE",
                "ALL_REFERENCED",
            ):
                raise ValueError()
            _id(d["tenant"])
            _id(d["source"])
            for name, maximum in (
                ("max_body_bytes", 16777216),
                ("max_total_body_bytes", 67108864),
                ("max_body_requests", 1024),
            ):
                if type(d[name]) is not int or not 1 <= d[name] <= maximum:
                    raise ValueError()
            keys = d["keys"]
            if type(keys) is not list or len(keys) > 64:
                raise ValueError()
            imported = {}
            previous = ""
            for key in keys:
                if type(key) is not dict or set(key) != set(EpisodeTrustKey.__annotations__):
                    raise ValueError()
                key_id = _id(key["key_id"])
                if (
                    key_id <= previous
                    or not _hex(key["public_key"], 64)
                    or type(key["revoked"]) is not bool
                ):
                    raise ValueError()
                for time in (key["not_before"], key["not_after"]):
                    if time is not None:
                        _timestamp(time)
                if (
                    key["not_before"] is not None
                    and key["not_after"] is not None
                    and key["not_before"] >= key["not_after"]
                ):
                    raise ValueError()
                imported[key_id] = public_type.from_public_bytes(bytes.fromhex(key["public_key"]))
                previous = key_id
            object.__setattr__(self, "_document", _freeze(d))
            object.__setattr__(self, "_keys", MappingProxyType(imported))
            object.__setattr__(self, "sha256", _hash("ancilis-episode-trust-policy/1", d))
        except Exception:
            raise SignedEpisodeError("INVALID_TRUST_POLICY") from None

    def to_dict(self) -> EpisodeTrustPolicyDict:
        return cast(EpisodeTrustPolicyDict, _thaw(self._document))


@dataclasses.dataclass(frozen=True)
class EpisodeSigner:
    tenant: str
    source: str
    key_id: str
    private_key: Ed25519PrivateKey = dataclasses.field(repr=False)

    def __post_init__(self) -> None:
        private_type, _, _ = _crypto()
        try:
            _id(self.tenant)
            _id(self.source)
            _id(self.key_id)
            if not isinstance(self.private_key, private_type):
                raise ValueError()
        except Exception:
            raise SignedEpisodeError("INVALID_SIGNER") from None

    @classmethod
    def from_seed(cls, tenant: str, source: str, key_id: str, *, seed: bytes) -> EpisodeSigner:
        private_type, _, _ = _crypto()
        try:
            if type(seed) is not bytes or len(seed) != 32:
                raise ValueError()
            key = private_type.from_private_bytes(bytes(seed))
        except Exception:
            raise SignedEpisodeError("INVALID_SIGNER") from None
        return cls(tenant, source, key_id, key)


def _native_reason(snapshot: object, assessed: str) -> str | None:
    checked = verify_episode_snapshot(
        cast(Mapping[str, Any], snapshot), assessed_at=assessed
    ).to_dict()
    if checked["status"] == "REJECTED":
        return "INVALID_NATIVE_SNAPSHOT"
    if "NATIVE_HISTORY_DISCARDED" in checked["reasons"]:
        return "NATIVE_HISTORY_DISCARDED"
    return None


def sign_episode_snapshot(
    snapshot: EpisodeSnapshot | Mapping[str, Any], signer: EpisodeSigner
) -> str:
    if not isinstance(signer, EpisodeSigner):
        raise SignedEpisodeError("INVALID_SIGNER")
    try:
        value = json.loads(
            canonical_json(
                snapshot.to_dict() if isinstance(snapshot, EpisodeSnapshot) else snapshot
            )
        )
        reason = _native_reason(value, _now())
    except Exception:
        raise SignedEpisodeError("INVALID_NATIVE_SNAPSHOT") from None
    if reason:
        raise SignedEpisodeError(reason)
    if value["tenant"] != signer.tenant or value["open"]["owner_source"] != signer.source:
        raise SignedEpisodeError("SCOPE_MISMATCH")
    unsigned = {
        "schema": "ancilis-signed-episode/1",
        "algorithm": "Ed25519",
        "key_id": signer.key_id,
        "snapshot": value,
    }
    encoded = canonical_json(unsigned)
    # The signature member adds 143 canonical bytes, including its separator.
    if len(encoded) + 143 > MAX_SIGNED_EXPORT_BYTES:
        raise SignedEpisodeError("EXPORT_TOO_LARGE")
    try:
        signature = signer.private_key.sign(_DOMAIN + encoded).hex()
    except Exception:
        raise SignedEpisodeError("SIGNATURE_VERIFICATION_ERROR") from None
    return canonical_json({**unsigned, "signature": signature}).decode("utf-8")


SignedStatus = Literal["AUTHENTICATED", "UNVERIFIED", "REJECTED", "ERROR"]
BodyStatus = Literal[
    "NOT_REQUESTED",
    "VERIFIED",
    "NO_REFERENCES",
    "UNAVAILABLE",
    "MISMATCH",
    "ERROR",
    "LIMIT_EXCEEDED",
]


class SignedEpisodeVerificationDict(TypedDict):
    schema: Literal["ancilis-signed-verification/1"]
    status: SignedStatus
    envelope_authenticated: bool
    protected_bodies: BodyStatus
    reconstruction: Literal["UNSUPPORTED"]
    policy_sha256: str
    assessed_at: str
    export_sha256: str | None
    verified_body_count: int
    reasons: list[str]
    verified_claim_refs: list[str]


@dataclasses.dataclass(frozen=True)
class SignedEpisodeVerification:
    _document: object = dataclasses.field(repr=False)

    def to_dict(self) -> SignedEpisodeVerificationDict:
        return cast(SignedEpisodeVerificationDict, _thaw(self._document))


@dataclasses.dataclass(frozen=True)
class ProtectedBodyRequest:
    tenant: str
    episode: str
    open_sha256: str
    revision_id: str
    event_id: str
    reference: ContentEvidence


_BodyPlan = tuple[ProtectedBodyRequest, int, str]


BodyResolver = Callable[[ProtectedBodyRequest], bytes | None]
AsyncBodyResolver = Callable[[ProtectedBodyRequest], bytes | None | Awaitable[bytes | None]]


def _out(
    result: SignedEpisodeVerificationDict,
    status: SignedStatus,
    reason: str,
    bodies: BodyStatus = "NOT_REQUESTED",
) -> None:
    result["status"] = status
    result["protected_bodies"] = bodies
    result["reasons"] = (["ENVELOPE_AUTHENTICATED"] if result["envelope_authenticated"] else []) + [
        reason
    ]


def _prepare(
    export: str | bytes, trust: EpisodeTrustPolicy, assessed_at: str | None
) -> tuple[SignedEpisodeVerificationDict, list[_BodyPlan]]:
    if not isinstance(trust, EpisodeTrustPolicy):
        raise SignedEpisodeError("INVALID_TRUST_POLICY")
    assessed = assessed_at if assessed_at is not None else _now()
    try:
        _timestamp(assessed)
    except Exception:
        raise SignedEpisodeError("INVALID_ASSESSMENT_TIME") from None
    result: SignedEpisodeVerificationDict = {
        "schema": "ancilis-signed-verification/1",
        "status": "UNVERIFIED",
        "envelope_authenticated": False,
        "protected_bodies": "NOT_REQUESTED",
        "reconstruction": "UNSUPPORTED",
        "policy_sha256": trust.sha256,
        "assessed_at": assessed,
        "export_sha256": None,
        "verified_body_count": 0,
        "reasons": [],
        "verified_claim_refs": [],
    }
    try:
        if type(export) not in (str, bytes):
            raise ValueError()
        if len(export) > MAX_SIGNED_EXPORT_BYTES:
            _out(result, "REJECTED", "EXPORT_TOO_LARGE")
            return result, []
        raw = export.encode("utf-8", errors="strict") if isinstance(export, str) else export
        if len(raw) > MAX_SIGNED_EXPORT_BYTES:
            _out(result, "REJECTED", "EXPORT_TOO_LARGE")
            return result, []
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if canonical_json(value) != raw:
            raise ValueError()
    except Exception:
        _out(result, "REJECTED", "INVALID_SIGNED_EXPORT")
        return result, []
    result["export_sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        if type(value) is not dict or set(value) != {
            "schema",
            "algorithm",
            "key_id",
            "snapshot",
            "signature",
        }:
            raise ValueError()
        if (
            value["schema"] != "ancilis-signed-episode/1"
            or value["algorithm"] != "Ed25519"
            or not _hex(value["signature"], 128)
        ):
            raise ValueError()
        _id(value["key_id"])
    except Exception:
        _out(result, "REJECTED", "INVALID_SIGNED_EXPORT")
        return result, []
    snapshot = cast(EpisodeSnapshotDict, value["snapshot"])
    reason = _native_reason(snapshot, assessed)
    if reason:
        _out(result, "REJECTED", reason)
        return result, []
    policy = trust.to_dict()
    if (
        snapshot["tenant"] != policy["tenant"]
        or snapshot["open"]["owner_source"] != policy["source"]
    ):
        _out(result, "REJECTED", "SCOPE_MISMATCH")
        return result, []
    key = next((k for k in policy["keys"] if k["key_id"] == value["key_id"]), None)
    if key is None:
        _out(result, "UNVERIFIED", "UNTRUSTED_KEY")
        return result, []
    if key["revoked"]:
        _out(result, "UNVERIFIED", "REVOKED_KEY")
        return result, []
    if (key["not_before"] is not None and assessed < key["not_before"]) or (
        key["not_after"] is not None and assessed >= key["not_after"]
    ):
        _out(result, "UNVERIFIED", "KEY_NOT_CURRENT")
        return result, []
    _, _, invalid_signature = _crypto()
    unsigned = {k: v for k, v in value.items() if k != "signature"}
    try:
        trust._keys[key["key_id"]].verify(
            bytes.fromhex(value["signature"]), _DOMAIN + canonical_json(unsigned)
        )
    except invalid_signature:
        _out(result, "REJECTED", "INVALID_SIGNATURE")
        return result, []
    except Exception:
        _out(result, "ERROR", "SIGNATURE_VERIFICATION_ERROR")
        return result, []
    result["envelope_authenticated"] = True
    if policy["body_mode"] == "NONE":
        _out(result, "AUTHENTICATED", "BODIES_NOT_REQUESTED")
        return result, []
    requests: list[_BodyPlan] = []
    total = 0
    for row in snapshot["observations"]:
        for reference in row["artifacts"]:
            total += reference["byte_length"]
            if (
                len(requests) >= policy["max_body_requests"]
                or reference["byte_length"] > policy["max_body_bytes"]
                or total > policy["max_total_body_bytes"]
            ):
                _out(result, "UNVERIFIED", "BODY_LIMIT_EXCEEDED", "LIMIT_EXCEEDED")
                return result, []
            frozen = ContentEvidence(
                reference["artifact"],
                reference["sha256"],
                reference["byte_length"],
                reference["role"],
                reference["access_scope"],
                tuple(reference["classification_receipt_refs"]),
            )
            request = ProtectedBodyRequest(
                snapshot["tenant"],
                snapshot["episode"],
                snapshot["open_sha256"],
                snapshot["revision_id"],
                row["event_id"],
                frozen,
            )
            # Callback-visible dataclasses are advisory frozen objects. Keep the
            # cryptographic expectations separately, never read them back from
            # a callback argument after user code runs.
            requests.append((request, reference["byte_length"], reference["sha256"]))
    if not requests:
        _out(result, "UNVERIFIED", "NO_BODY_REFERENCES", "NO_REFERENCES")
    return result, requests


def _check_body(
    result: SignedEpisodeVerificationDict,
    expected_length: int,
    expected_sha256: str,
    body: object,
) -> bool:
    if body is None:
        _out(result, "UNVERIFIED", "BODY_UNAVAILABLE", "UNAVAILABLE")
        return False
    if type(body) is not bytes:
        if inspect.iscoroutine(body):
            body.close()
        _out(result, "ERROR", "BODY_RESOLVER_ERROR", "ERROR")
        return False
    if len(body) != expected_length or hashlib.sha256(body).hexdigest() != expected_sha256:
        _out(result, "REJECTED", "BODY_MISMATCH", "MISMATCH")
        return False
    result["verified_body_count"] += 1
    return True


def _resolver_config(resolver: object, *, asynchronous: bool) -> None:
    if resolver is not None and (
        not callable(resolver)
        or (
            not asynchronous
            and (
                inspect.iscoroutinefunction(resolver)
                or inspect.iscoroutinefunction(type(resolver).__call__)
            )
        )
    ):
        raise SignedEpisodeError("INVALID_BODY_RESOLVER")


def verify_signed_episode(
    export: str | bytes,
    trust: EpisodeTrustPolicy,
    *,
    assessed_at: str | None = None,
    body_resolver: BodyResolver | None = None,
) -> SignedEpisodeVerification:
    _resolver_config(body_resolver, asynchronous=False)
    result, requests = _prepare(export, trust, assessed_at)
    for request, expected_length, expected_sha256 in requests:
        try:
            body = body_resolver(request) if body_resolver else None
        except Exception:
            _out(result, "ERROR", "BODY_RESOLVER_ERROR", "ERROR")
            break
        if not _check_body(result, expected_length, expected_sha256, body):
            break
    else:
        if requests:
            _out(result, "AUTHENTICATED", "BODIES_VERIFIED", "VERIFIED")
    return SignedEpisodeVerification(_freeze(result))


async def averify_signed_episode(
    export: str | bytes,
    trust: EpisodeTrustPolicy,
    *,
    assessed_at: str | None = None,
    body_resolver: AsyncBodyResolver | None = None,
) -> SignedEpisodeVerification:
    _resolver_config(body_resolver, asynchronous=True)
    result, requests = _prepare(export, trust, assessed_at)
    for request, expected_length, expected_sha256 in requests:
        try:
            body = body_resolver(request) if body_resolver else None
            if inspect.isawaitable(body):
                body = await body
        except Exception:
            _out(result, "ERROR", "BODY_RESOLVER_ERROR", "ERROR")
            break
        if not _check_body(result, expected_length, expected_sha256, body):
            break
    else:
        if requests:
            _out(result, "AUTHENTICATED", "BODIES_VERIFIED", "VERIFIED")
    return SignedEpisodeVerification(_freeze(result))
