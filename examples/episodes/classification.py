"""Synthetic same-operator trust demo; production receivers provision their own policy."""

import json
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ancilis import (
    Ancilis,
    CaptureFrame,
    CaptureResult,
    ContentEvidence,
    EpisodeSigner,
    EpisodeTrustPolicy,
    ProtectedBodyRequest,
    TrustedClassificationAdapter,
    ExperimentalSemanticProvider,
    ClassificationRequest,
    ClassificationResponse,
    SemanticRequest,
    SemanticProposal,
    ClassificationHistory,
    assess_episode_classifications,
)

DOCUMENT = b"Synthetic public document used only by this signing example."
RECEIPT = hashlib.sha256(b"SYNTHETIC DEMO RECEIPT").hexdigest()
private_key = Ed25519PrivateKey.generate()
signer = EpisodeSigner("demo", "application", "demo-key", private_key)
public_hex = (
    private_key.public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    .hex()
)

# Same-operator demonstration only. A real receiver obtains this independently,
# never from the signed export, and authorizes its own key validity/revocation.
trust = EpisodeTrustPolicy(
    {
        "schema": "ancilis-episode-trust-policy/1",
        "tenant": "demo",
        "source": "application",
        "keys": [
            {
                "key_id": "demo-key",
                "public_key": public_hex,
                "not_before": None,
                "not_after": None,
                "revoked": False,
            }
        ],
        "body_mode": "ALL_REFERENCED",
        "max_body_bytes": 16777216,
        "max_total_body_bytes": 67108864,
        "max_body_requests": 1024,
    }
)


def capture(frame: CaptureFrame) -> CaptureResult:
    if frame.phase == "END" and frame.error is None:
        return CaptureResult(
            artifacts=(
                ContentEvidence.from_bytes(
                    "document",
                    frame.result,
                    role="INPUT",
                    access_scope="synthetic",
                    classification_receipt_refs=(RECEIPT,),
                ),
            )
        )
    return CaptureResult()


def resolve(request: ProtectedBodyRequest) -> bytes | None:
    if (
        request.tenant == "demo"
        and request.reference.access_scope == "synthetic"
        and request.reference.artifact == "document"
    ):
        return DOCUMENT
    return None


with Ancilis("demo", "application") as owner:
    read_document = owner.attach_tool(
        lambda: DOCUMENT,
        name="read-document",
        surface="document",
        operation="READ",
        capture=capture,
    )
    with owner.episode("signed-example", expected_surfaces=("document",)) as episode:
        assert read_document() is DOCUMENT
    exported = episode.export_signed(signer)


# This toy callback stands in for a separately reviewed receipt verifier.
# Matching this demo constant is NOT GE issuer authentication or a qualified method.
def trusted(request: ClassificationRequest, body: bytes) -> ClassificationResponse:
    assert body == DOCUMENT and request.to_dict()["reference"]["classification_receipt_refs"] == [
        RECEIPT
    ]
    return {
        "schema": "ancilis-classification-response/1",
        "request_sha256": request.request_sha256,
        "outcome": "SUPPORTED_POSITIVE",
        "classification": "SYNTHETIC-SENSITIVE",
        "evidence_refs": [RECEIPT],
        "reasons": [],
    }


def stale(request: ClassificationRequest, body: bytes) -> ClassificationResponse:
    return {
        "schema": "ancilis-classification-response/1",
        "request_sha256": request.request_sha256,
        "outcome": "UNKNOWN",
        "classification": None,
        "evidence_refs": [],
        "reasons": ["STALE_LABEL"],
    }


def propose(request: SemanticRequest, body: bytes) -> SemanticProposal:
    return {
        "schema": "ancilis-semantic-proposal/1",
        "request_sha256": request.request_sha256,
        "status": "PROPOSED",
        "proposed_classification": "SYNTHETIC-SENSITIVE",
        "evidence_refs": [RECEIPT],
        "reasons": [],
    }


adapter = TrustedClassificationAdapter(
    provider_id="synthetic",
    method_id="demo/1",
    policy_sha256=hashlib.sha256(b"demo policy").hexdigest(),
    taxonomy="DEMO-v1",
    supported_classes=["SYNTHETIC-SENSITIVE"],
    resolve=trusted,
)
first = assess_episode_classifications(
    exported, trust=trust, adapter=adapter, body_resolver=resolve
)
changed_descriptor = adapter.to_dict()
changed_descriptor["policy_sha256"] = hashlib.sha256(b"changed demo policy").hexdigest()
changed = TrustedClassificationAdapter(**changed_descriptor, resolve=stale)
second = assess_episode_classifications(
    exported,
    trust=trust,
    adapter=changed,
    body_resolver=resolve,
    experimental_semantic=ExperimentalSemanticProvider(
        provider_id="synthetic", method_id="proposal/1", runtime_id="no-model", propose=propose
    ),
)
d = first.to_dict()
assert d["tenant"] is not None and d["episode"] is not None and d["open_sha256"] is not None
history = ClassificationHistory(d["tenant"], d["episode"], d["open_sha256"])
history.append(first)
history.append(second)
assert second.to_dict()["classifications"][0]["outcome"] == "UNKNOWN"
assert second.to_dict()["classifications"][0]["semantic"]["state"] == "UNQUALIFIED"
assert first.to_dict()["export_sha256"] == second.to_dict()["export_sha256"]
print(json.dumps(history.inspect(), indent=2))
