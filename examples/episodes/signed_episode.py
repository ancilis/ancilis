"""Synthetic same-operator trust demo; production receivers provision their own policy."""

import json

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
    verify_signed_episode,
)

DOCUMENT = b"Synthetic public document used only by this signing example."
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
                    "document", frame.result, role="INPUT", access_scope="synthetic"
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

result = verify_signed_episode(exported, trust, body_resolver=resolve).to_dict()
assert result["status"] == "AUTHENTICATED" and result["protected_bodies"] == "VERIFIED"
assert result["reconstruction"] == "UNSUPPORTED" and result["verified_claim_refs"] == []
missing = verify_signed_episode(exported, trust).to_dict()
assert missing["envelope_authenticated"] and missing["protected_bodies"] == "UNAVAILABLE"
tampered = verify_signed_episode(
    exported, trust, body_resolver=lambda request: b"changed"
).to_dict()
assert tampered["status"] == "REJECTED" and tampered["protected_bodies"] == "MISMATCH"
print(json.dumps(result, indent=2))
