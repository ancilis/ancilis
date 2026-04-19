"""Small HTTP client for future Ancilis platform evidence ingest."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

EVIDENCE_BATCH_ENDPOINT = "/api/evidence/batches"
DEFAULT_TIMEOUT_SECONDS = 10


class PlatformClientError(Exception):
    """Base class for platform client failures."""


class PlatformConnectionError(PlatformClientError):
    """Network-level platform connection failure."""


class PlatformHTTPError(PlatformClientError):
    """Batch-level HTTP failure from the platform."""

    def __init__(self, status_code: int, message: str | None = None) -> None:
        self.status_code = status_code
        self.message = message or f"platform returned HTTP {status_code}"
        super().__init__(self.message)


@dataclass(frozen=True)
class PlatformBatchItem:
    record_id: str
    status_code: int
    remote_evidence_id: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class PlatformBatchResponse:
    results: list[PlatformBatchItem]


class PlatformClient:
    """Post evidence batches to the platform ingest endpoint."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def post_evidence_batch(self, records: list[dict[str, Any]]) -> PlatformBatchResponse:
        body = json.dumps({"records": records}).encode()
        request = urllib.request.Request(
            f"{self._base_url}{EVIDENCE_BATCH_ENDPOINT}",
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                response_body = response.read()
                raw_status = getattr(response, "status", None)
                status_code = int(raw_status if raw_status is not None else response.getcode())
        except urllib.error.HTTPError as exc:
            raise PlatformHTTPError(exc.code) from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise PlatformConnectionError(str(getattr(exc, "reason", exc))) from exc

        if not response_body:
            return PlatformBatchResponse(results=[])
        payload = json.loads(response_body.decode())
        return PlatformBatchResponse(
            results=[
                _batch_item_from_payload(item, default_status_code=status_code)
                for item in payload.get("results", [])
            ]
        )


def _batch_item_from_payload(
    item: dict[str, Any],
    *,
    default_status_code: int,
) -> PlatformBatchItem:
    return PlatformBatchItem(
        record_id=str(item["record_id"]),
        status_code=int(item.get("status_code", default_status_code)),
        remote_evidence_id=item.get("remote_evidence_id"),
        error=item.get("error"),
    )
