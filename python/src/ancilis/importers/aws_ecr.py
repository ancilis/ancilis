"""AWS ECR importer — maps Elastic Container Registry events to AKSI controls.

AWS ECR (https://docs.aws.amazon.com/ecr) is the canonical AWS container
registry. AI agents that ship code (Devin, Claude Code in CI, Cursor agents)
push container images here, and supply-chain attacks — typosquatting,
vulnerable base images, malicious packages, unsigned production tags, mutable
tags in production — flow through this surface. ECR's CloudTrail-derived API
events plus its native scan-finding payload (vulnerability counts, signature
status, SBOM presence, image age) are some of the highest-signal evidence the
SDK can capture for container supply-chain governance.

This importer ingests ECR exports in four on-disk shapes:

  1. ``{"events":  [...]}`` — convenience envelope for ECR-only exports
  2. ``{"Records": [...]}`` — canonical CloudTrail S3-export envelope
  3. ``{"data":    [...]}`` — generic data envelope
  4. JSONL                    — one event per line

Signal mapping (see ``shared/mappings/aws-ecr-aksi-controls.json``):

  * eventName=PutImage                                       → PR-05 PASS (audit baseline)
  * eventName=PutImage + critical-vuln count > 0             → PR-03 FAIL
  * eventName=PutImage + high-vuln count > threshold (5)     → PR-03 FLAG
  * eventName=PutImage + image_age_days > 365                → PR-05 FLAG (un-rebuilt base)
  * eventName=PutImage + UNSIGNED + prod-repo                → PR-04 FAIL
  * eventName=PutImage + signature VERIFICATION_FAILED       → DE-01 FAIL
  * eventName=PutImage + sbom_present=false                  → PR-05 FLAG
  * eventName=PutImage + imageTag=latest + prod-repo         → PR-05 FLAG
  * eventName=PutImageTagMutability → MUTABLE in prod        → PR-02 FAIL
  * eventName=DeleteRepository                               → PR-02 FAIL
  * eventName=DeleteImages / BatchDeleteImage on prod        → PR-02 FLAG
  * eventName=PutRegistryPolicy widening cross-account       → PR-04 FAIL
  * eventName=DeleteRegistryPolicy                           → PR-04 FAIL
  * eventName=PutLifecyclePolicy reducing retention          → PR-05 FLAG
  * eventName=PutImageScanningConfiguration scanOnPush=false → PR-03 FAIL
  * eventName=BatchGetImage by external account              → PR-04 FLAG
  * userIdentity.type=Root + any operation                   → PR-01 FAIL
  * vulnerabilities ∈ critical-package list + HIGH/CRITICAL  → PR-03 FAIL

Synthetic findings:

  * Same repository with > N OPEN critical vulns across pushes (default 3)
    → PR-03 FAIL  (broken-image / supply-chain hot-spot)
  * Same external account doing > N BatchGetImage in 1h (default 50)
    → PR-04 FLAG  (cross-account pull burst)
  * Same userIdentity (CI bot) doing > N PutImage in 1h (default 30)
    → PR-05 FLAG  (rapid CI / agent firehose)

Sanitization (security-critical — ECR events can carry registry-internal
identifiers and CVE descriptions that grow unboundedly):

  * ``imageManifest`` raw is NEVER stored — only its length is captured.
  * ``lifecyclePolicyText`` / ``registryPolicyText`` raw is NEVER stored —
    only declared lengths are captured.
  * ``imageDigest`` is reduced to the trailing 16 hex chars of the SHA-256
    payload (the ``sha256:`` prefix is dropped). The full digest is not
    secret but is unbounded and noisy in evidence.
  * ``userIdentity.arn`` is masked: any access-key-shaped tail is reduced to
    first-4 + last-4 characters; the resource path is preserved.
  * ``userAgent`` is reduced to (first 80 chars + sha256). Full UA strings
    can be long and carry tool-fingerprint detail.
  * ``sourceIPAddress`` is normalized: ``"AWS Internal"`` preserved verbatim,
    public IPv4 reduced to ``/16`` pattern, public IPv6 reduced to
    ``/32`` pattern, RFC1918/loopback preserved.
  * ``vulnerabilities`` array is NEVER stored verbatim. Only the count, the
    maximum severity, and the top-3 CVE IDs are captured — full descriptions
    can run thousands of characters.
  * ``repositoryName`` and ``imageTag`` are captured verbatim (non-sensitive
    structured names).

The SDK does NOT depend on ``boto3``/``botocore``; ECR events are parsed with
the standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Path to the shared mapping table. This file lives at:
#   <repo>/python/src/ancilis/importers/aws_ecr.py
# so five .parent traversals reach the repo root containing shared/.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "aws-ecr-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

# ---- Default mapping fallbacks ---------------------------------------------

_DEFAULT_EVENT_SIGNALS: dict[str, dict[str, str]] = {
    "PutImage": {"signal": "ecr_put_image", "result": "PASS", "control": "PR-05"},
    "BatchGetImage": {"signal": "ecr_batch_get_image", "result": "PASS", "control": "PR-04"},
    "GetDownloadUrlForLayer": {"signal": "ecr_get_download_url", "result": "PASS", "control": "PR-04"},
    "InitiateLayerUpload": {"signal": "ecr_layer_upload", "result": "PASS", "control": "PR-05"},
    "CompleteLayerUpload": {"signal": "ecr_layer_upload", "result": "PASS", "control": "PR-05"},
    "PutLifecyclePolicy": {"signal": "ecr_lifecycle_policy", "result": "PASS", "control": "PR-05"},
    "PutImageScanningConfiguration": {"signal": "ecr_scan_config", "result": "PASS", "control": "PR-03"},
    "PutImageTagMutability": {"signal": "ecr_tag_mutability", "result": "PASS", "control": "PR-02"},
    "DescribeImageScanFindings": {"signal": "ecr_describe_scan", "result": "PASS", "control": "PR-03"},
    "PutRegistryScanningConfiguration": {"signal": "ecr_registry_scan_config", "result": "PASS", "control": "PR-03"},
    "DeleteRepository": {"signal": "ecr_delete_repository", "result": "FAIL", "control": "PR-02"},
    "DeleteImages": {"signal": "ecr_delete_images", "result": "FLAG", "control": "PR-02"},
    "BatchDeleteImage": {"signal": "ecr_delete_images", "result": "FLAG", "control": "PR-02"},
    "PutRegistryPolicy": {"signal": "ecr_registry_policy", "result": "PASS", "control": "PR-04"},
    "DeleteRegistryPolicy": {"signal": "ecr_delete_registry_policy", "result": "FAIL", "control": "PR-04"},
}

_DEFAULT_PRODUCTION_REPO_PATTERNS: tuple[str, ...] = ("prod*", "release*", "main*")
_DEFAULT_CRITICAL_PACKAGES: tuple[str, ...] = (
    "openssl", "libcrypto", "log4j", "glibc", "kernel*", "openssh", "sudo", "systemd"
)
_DEFAULT_HIGH_SEVERITY_THRESHOLD = 5
_DEFAULT_IMAGE_AGE_DAYS_THRESHOLD = 365
_DEFAULT_CROSS_ACCOUNT_PULL_THRESHOLD = 50
_DEFAULT_VULN_CONCENTRATION_THRESHOLD = 3
_DEFAULT_HIGH_VELOCITY_PUSH_THRESHOLD = 30

_USER_AGENT_PREFIX_LEN = 80


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the aws-ecr-aksi-controls.json mapping; tolerate missing file."""
    try:
        with open(_MAPPING_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _control_for(signal: str, mappings: dict[str, str], default: str) -> str:
    return mappings.get(signal, default)


# ---------------------------------------------------------------------------
# JSONL helper
# ---------------------------------------------------------------------------


def _iter_jsonl(content: str) -> Iterable[dict[str, Any]]:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _redact_arn(arn: str | None) -> str | None:
    """Mask the access-key-shaped portion of an ARN.

    AWS ARNs follow ``arn:aws:<service>:<region>:<account>:<resource>``. The
    ``account`` portion is a 12-digit ID (not secret) and the ``resource``
    portion is the principal (e.g. ``user/ci`` or ``role/agent/session``).
    Some session ARNs include access-key-shaped tails (e.g.
    ``role/agent/AKIAEXAMPLE12345``) that we mask down to first-4 + last-4.
    """
    if not isinstance(arn, str) or not arn:
        return None
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn":
        return arn
    resource = ":".join(parts[5:])
    # Within the resource, find any 16+-char alphanumeric token and mask it.
    masked_segments: list[str] = []
    for seg in resource.split("/"):
        if len(seg) >= 16 and seg.isalnum():
            masked_segments.append(f"{seg[:4]}...{seg[-4:]}")
        else:
            masked_segments.append(seg)
    return ":".join(parts[:5] + ["/".join(masked_segments)])


def _redact_user_agent(user_agent: str | None) -> dict[str, Any] | None:
    """Reduce a userAgent to (prefix, length, sha256). Never store full UA."""
    if not isinstance(user_agent, str) or not user_agent:
        return None
    return {
        "prefix": user_agent[:_USER_AGENT_PREFIX_LEN],
        "length": len(user_agent),
        "sha256": hashlib.sha256(user_agent.encode("utf-8")).hexdigest(),
    }


def _classify_source_ip(source_ip: str | None) -> str | None:
    """Normalize a sourceIPAddress to a privacy-aware form (mirrors CloudTrail)."""
    if not source_ip or not isinstance(source_ip, str):
        return None
    ip = source_ip.strip()
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return ip
        octets = ip.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.0.0/16"
        return ip
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return ip
    try:
        net = ipaddress.ip_network(f"{ip}/32", strict=False)
        first_two = ":".join(net.network_address.exploded.split(":")[:2])
        return f"{first_two}::/32"
    except ValueError:
        return ip


def _short_digest(digest: str | None) -> str | None:
    """Return the trailing 16 hex chars of a sha256 digest."""
    if not isinstance(digest, str) or not digest:
        return None
    raw = digest.split(":")[-1] if ":" in digest else digest
    return raw[-16:] if len(raw) >= 16 else raw


def _matches_any_pattern(name: str, patterns: Iterable[str]) -> bool:
    name_l = (name or "").lower()
    return any(fnmatch.fnmatchcase(name_l, p.lower()) for p in patterns)


_SEVERITY_RANK: dict[str, int] = {
    "INFORMATIONAL": 0,
    "UNDEFINED": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _max_severity(severities: Iterable[str]) -> str | None:
    best: tuple[int, str] | None = None
    for s in severities:
        if not isinstance(s, str):
            continue
        rank = _SEVERITY_RANK.get(s.upper(), -1)
        if rank < 0:
            continue
        if best is None or rank > best[0]:
            best = (rank, s.upper())
    return best[1] if best else None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class AwsEcrImporter:
    """Parse an ECR export and convert each event to ``EvaluationResult``."""

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        *,
        production_repo_patterns: list[str] | None = None,
        critical_packages: list[str] | None = None,
        high_severity_threshold: int | None = None,
        image_age_days_threshold: int | None = None,
        cross_account_pull_threshold: int | None = None,
        vulnerability_concentration_threshold: int | None = None,
        high_velocity_push_threshold: int | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        raw_mappings = table.get("mappings") if isinstance(table, dict) else None
        self._mappings: dict[str, str] = (
            {str(k): str(v) for k, v in raw_mappings.items()}
            if isinstance(raw_mappings, dict) and raw_mappings
            else {}
        )

        # Event signal table (CloudTrail eventName → signal/result/control).
        meta_events = meta.get("event_signals")
        if isinstance(meta_events, dict) and meta_events:
            self._event_signals: dict[str, dict[str, str]] = {
                str(k): {str(kk): str(vv) for kk, vv in (v or {}).items()}
                for k, v in meta_events.items()
                if isinstance(v, dict)
            }
        else:
            self._event_signals = {
                k: dict(v) for k, v in _DEFAULT_EVENT_SIGNALS.items()
            }

        # Production-repo patterns.
        meta_prod = meta.get("production_repo_patterns")
        if isinstance(meta_prod, list) and meta_prod:
            self._production_repo_patterns: tuple[str, ...] = tuple(
                str(p) for p in meta_prod
            )
        else:
            self._production_repo_patterns = _DEFAULT_PRODUCTION_REPO_PATTERNS

        # Critical-package patterns.
        meta_pkgs = meta.get("critical_packages")
        if isinstance(meta_pkgs, list) and meta_pkgs:
            self._critical_packages: tuple[str, ...] = tuple(
                str(p) for p in meta_pkgs
            )
        else:
            self._critical_packages = _DEFAULT_CRITICAL_PACKAGES

        # Thresholds (explicit kwarg > mapping metadata > default).
        self.high_severity_threshold = (
            int(high_severity_threshold)
            if high_severity_threshold is not None
            else int(meta.get("high_severity_threshold", _DEFAULT_HIGH_SEVERITY_THRESHOLD))
        )
        self.image_age_days_threshold = (
            int(image_age_days_threshold)
            if image_age_days_threshold is not None
            else int(meta.get("image_age_days_threshold", _DEFAULT_IMAGE_AGE_DAYS_THRESHOLD))
        )
        self.cross_account_pull_threshold = (
            int(cross_account_pull_threshold)
            if cross_account_pull_threshold is not None
            else int(meta.get("cross_account_pull_threshold", _DEFAULT_CROSS_ACCOUNT_PULL_THRESHOLD))
        )
        self.vulnerability_concentration_threshold = (
            int(vulnerability_concentration_threshold)
            if vulnerability_concentration_threshold is not None
            else int(meta.get("vulnerability_concentration_threshold", _DEFAULT_VULN_CONCENTRATION_THRESHOLD))
        )
        self.high_velocity_push_threshold = (
            int(high_velocity_push_threshold)
            if high_velocity_push_threshold is not None
            else int(meta.get("high_velocity_push_threshold", _DEFAULT_HIGH_VELOCITY_PUSH_THRESHOLD))
        )

        # Allow override hooks for production-repo / critical-package lists from
        # the explicit kwargs. (Useful for tests.)
        if production_repo_patterns is not None:
            self._production_repo_patterns = tuple(production_repo_patterns)
        if critical_packages is not None:
            self._critical_packages = tuple(critical_packages)

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse an ECR export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        events = self._events_from_text(text)
        return self._build_results(events, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse ECR export content from a JSON or JSONL string."""
        events = self._events_from_text(content)
        return self._build_results(events, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _events_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect ``{"events":[]}`` / ``{"Records":[]}`` / ``{"data":[]}`` / JSONL."""
        stripped = text.lstrip()
        if not stripped:
            return []
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return list(_iter_jsonl(text))
            if isinstance(doc, list):
                return [r for r in doc if isinstance(r, dict)]
            if isinstance(doc, dict):
                for key in ("events", "Records", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [r for r in doc[key] if isinstance(r, dict)]
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "aws_ecr",
            "source_tool_name": "aws_ecr",
            "source_tool_version": "",
        }
        if event_id is not None:
            provenance["event_id"] = event_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    def _is_production_repo(self, repo_name: str | None) -> bool:
        if not isinstance(repo_name, str) or not repo_name:
            return False
        return _matches_any_pattern(repo_name, self._production_repo_patterns)

    def _is_critical_package(self, package: str | None) -> bool:
        if not isinstance(package, str) or not package:
            return False
        return _matches_any_pattern(package, self._critical_packages)

    # ------------------------------------------------------------------
    # Top-level build
    # ------------------------------------------------------------------

    def _build_results(
        self,
        events: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        # First pass — aggregate signals for synthetic findings.
        repo_critical_counts: dict[str, int] = {}
        external_pull_counts: dict[str, int] = {}
        bot_push_counts: dict[str, int] = {}

        for ev in events:
            event_name = str(ev.get("eventName") or "")
            params = ev.get("requestParameters") or {}
            scan = ev.get("scan_findings") or {}
            ui = ev.get("userIdentity") or {}
            if not isinstance(params, dict):
                params = {}
            if not isinstance(scan, dict):
                scan = {}
            if not isinstance(ui, dict):
                ui = {}
            repo = params.get("repositoryName") if isinstance(params.get("repositoryName"), str) else None

            if event_name == "PutImage" and repo:
                crit = scan.get("criticalSeverityCount")
                if isinstance(crit, int) and not isinstance(crit, bool) and crit > 0:
                    repo_critical_counts[repo] = repo_critical_counts.get(repo, 0) + crit

            if event_name == "BatchGetImage":
                # External account = a userIdentity.accountId distinct from
                # the repository's registryId / requestParameters.registryId.
                acct = ui.get("accountId") if isinstance(ui.get("accountId"), str) else None
                registry_id = params.get("registryId") if isinstance(params.get("registryId"), str) else None
                if acct and registry_id and acct != registry_id:
                    external_pull_counts[acct] = external_pull_counts.get(acct, 0) + 1

            if event_name == "PutImage":
                arn = ui.get("arn") if isinstance(ui.get("arn"), str) else None
                user_name = ui.get("userName") if isinstance(ui.get("userName"), str) else None
                principal = arn or user_name
                if principal:
                    bot_push_counts[principal] = bot_push_counts.get(principal, 0) + 1

        results: list[EvaluationResult] = []
        for ev in events:
            results.append(self._parse_event(ev, file_sha256=file_sha256))

        # ---- Synthetic: per-repository vulnerability concentration ----
        for repo, count in sorted(repo_critical_counts.items()):
            if count > self.vulnerability_concentration_threshold:
                results.append(
                    self._synthetic_vuln_concentration(
                        repo=repo, count=count, file_sha256=file_sha256,
                    )
                )

        # ---- Synthetic: cross-account pull burst ----
        for acct, count in sorted(external_pull_counts.items()):
            if count > self.cross_account_pull_threshold:
                results.append(
                    self._synthetic_cross_account_pull(
                        external_account=acct, count=count, file_sha256=file_sha256,
                    )
                )

        # ---- Synthetic: high-velocity bot push ----
        for principal, count in sorted(bot_push_counts.items()):
            if count > self.high_velocity_push_threshold:
                results.append(
                    self._synthetic_high_velocity_push(
                        principal=principal, count=count, file_sha256=file_sha256,
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Per-event parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self,
        event: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        event_id = str(event.get("eventID") or event.get("event_id") or uuid.uuid4())
        event_name = str(event.get("eventName") or "").strip()
        event_time = str(event.get("eventTime") or datetime.now(timezone.utc).isoformat())
        aws_region = str(event.get("awsRegion") or "")
        request_id = str(event.get("requestID") or "")

        params = event.get("requestParameters") or {}
        if not isinstance(params, dict):
            params = {}
        response = event.get("responseElements") or {}
        if not isinstance(response, dict):
            response = {}
        scan = event.get("scan_findings") or {}
        if not isinstance(scan, dict):
            scan = {}

        ui = event.get("userIdentity") or {}
        if not isinstance(ui, dict):
            ui = {}
        identity_type = str(ui.get("type") or "")
        user_name = ui.get("userName") if isinstance(ui.get("userName"), str) else None
        account_id = ui.get("accountId") if isinstance(ui.get("accountId"), str) else None
        identity_arn_redacted = _redact_arn(
            ui.get("arn") if isinstance(ui.get("arn"), str) else None
        )
        principal_id = ui.get("principalId") if isinstance(ui.get("principalId"), str) else None

        repo_name = params.get("repositoryName") if isinstance(params.get("repositoryName"), str) else None
        registry_id = params.get("registryId") if isinstance(params.get("registryId"), str) else None
        image_tag = params.get("imageTag") if isinstance(params.get("imageTag"), str) else None
        image_identifier = params.get("imageIdentifier") if isinstance(params.get("imageIdentifier"), dict) else {}
        image_digest_short = _short_digest(
            image_identifier.get("imageDigest") if isinstance(image_identifier.get("imageDigest"), str) else None
        )
        if image_digest_short is None:
            # Fall back to responseElements.image.imageId.imageDigest.
            response_image = response.get("image") if isinstance(response.get("image"), dict) else {}
            response_image_id = response_image.get("imageId") if isinstance(response_image.get("imageId"), dict) else {}
            image_digest_short = _short_digest(
                response_image_id.get("imageDigest") if isinstance(response_image_id.get("imageDigest"), str) else None
            )
        if image_tag is None and isinstance(image_identifier.get("imageTag"), str):
            image_tag = image_identifier.get("imageTag")

        scan_cfg = params.get("imageScanningConfiguration") if isinstance(params.get("imageScanningConfiguration"), dict) else {}
        scan_on_push_raw = scan_cfg.get("scanOnPush")
        scan_on_push: bool | None = (
            bool(scan_on_push_raw) if isinstance(scan_on_push_raw, bool) else None
        )
        tag_mutability = params.get("imageTagMutability") if isinstance(params.get("imageTagMutability"), str) else None

        # ---- scan_findings counts / status / signature ----
        critical_count = _safe_int(scan.get("criticalSeverityCount"))
        high_count = _safe_int(scan.get("highSeverityCount"))
        medium_count = _safe_int(scan.get("mediumSeverityCount"))
        low_count = _safe_int(scan.get("lowSeverityCount"))
        info_count = _safe_int(scan.get("informationalCount"))
        undef_count = _safe_int(scan.get("undefinedCount"))
        scan_status = scan.get("image_scan_status") if isinstance(scan.get("image_scan_status"), str) else None
        signature_status = scan.get("signature_status") if isinstance(scan.get("signature_status"), str) else None
        is_signed_raw = scan.get("is_signed")
        is_signed: bool | None = bool(is_signed_raw) if isinstance(is_signed_raw, bool) else None
        sbom_present_raw = scan.get("sbom_present")
        sbom_present: bool | None = bool(sbom_present_raw) if isinstance(sbom_present_raw, bool) else None
        image_age_days = _safe_int(scan.get("image_age_days"))

        # Vulnerabilities — never store full descriptions; capture count + max
        # severity + top-3 CVE IDs only.
        vulns_raw = scan.get("vulnerabilities")
        vuln_count = 0
        top_cves: list[str] = []
        max_vuln_severity: str | None = None
        critical_package_hits: list[dict[str, str]] = []
        if isinstance(vulns_raw, list):
            vuln_count = len(vulns_raw)
            severities: list[str] = []
            for v in vulns_raw:
                if not isinstance(v, dict):
                    continue
                cve_id = v.get("name")
                sev = v.get("severity")
                pkg = v.get("package")
                if isinstance(sev, str):
                    severities.append(sev)
                if isinstance(cve_id, str) and cve_id and len(top_cves) < 3:
                    top_cves.append(cve_id)
                if (
                    isinstance(sev, str)
                    and sev.upper() in ("HIGH", "CRITICAL")
                    and self._is_critical_package(pkg if isinstance(pkg, str) else None)
                ):
                    critical_package_hits.append(
                        {
                            "name": cve_id if isinstance(cve_id, str) else "",
                            "severity": sev.upper(),
                            "package": pkg if isinstance(pkg, str) else "",
                        }
                    )
            max_vuln_severity = _max_severity(severities)

        # Lengths-only for known long fields.
        lifecycle_policy_length = _safe_int(params.get("lifecyclePolicyText_length"))
        registry_policy_length = _safe_int(params.get("registryPolicyText_length"))
        response_image = response.get("image") if isinstance(response.get("image"), dict) else {}
        image_manifest_length = _safe_int(response_image.get("imageManifest_length"))

        source_ip = _classify_source_ip(event.get("sourceIPAddress"))
        user_agent_redacted = _redact_user_agent(
            event.get("userAgent") if isinstance(event.get("userAgent"), str) else None
        )

        is_prod_repo = self._is_production_repo(repo_name)

        common_evidence: dict[str, Any] = {
            "ecr_event_id": event_id,
            "event_name": event_name,
            "event_time": event_time,
            "aws_region": aws_region,
            "request_id": request_id,
            "user_identity_type": identity_type,
            "user_name": user_name,
            "account_id": account_id,
            "identity_arn_redacted": identity_arn_redacted,
            "principal_id": principal_id,
            "source_ip_redacted": source_ip,
            "user_agent_redacted": user_agent_redacted,
            "repository_name": repo_name,
            "registry_id": registry_id,
            "image_tag": image_tag,
            "image_digest_short": image_digest_short,
            "is_production_repo": is_prod_repo,
            "scan_critical_count": critical_count,
            "scan_high_count": high_count,
            "scan_medium_count": medium_count,
            "scan_low_count": low_count,
            "scan_informational_count": info_count,
            "scan_undefined_count": undef_count,
            "scan_status": scan_status,
            "signature_status": signature_status,
            "is_signed": is_signed,
            "sbom_present": sbom_present,
            "image_age_days": image_age_days,
            "vulnerability_count": vuln_count,
            "max_vulnerability_severity": max_vuln_severity,
            "top_cve_ids": top_cves,
            "image_manifest_length": image_manifest_length,
            "lifecycle_policy_length": lifecycle_policy_length,
            "registry_policy_length": registry_policy_length,
            "scan_on_push": scan_on_push,
            "image_tag_mutability": tag_mutability,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=event_id
            ),
            "source_tool": "aws_ecr",
        }

        control_results: list[ControlResult] = []

        # ----------------------------------------------------------------
        # 1. Root identity — top-priority FAIL.
        # ----------------------------------------------------------------
        if identity_type == "Root":
            signal = "root_identity"
            control_id = _control_for(signal, self._mappings, "PR-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"ECR event {event_id} {event_name} performed by Root user — "
                        f"root usage is a critical compliance violation"
                    ),
                    evidence_data={**common_evidence, "signal": signal},
                )
            )

        # ----------------------------------------------------------------
        # 2. Per-event base classification.
        # ----------------------------------------------------------------
        ev_meta = self._event_signals.get(event_name)
        if ev_meta is not None:
            base_signal = ev_meta.get("signal", "unknown_event")
            base_result = ev_meta.get("result", "PASS")
            base_control = _control_for(base_signal, self._mappings, ev_meta.get("control", "PR-05"))
            control_results.append(
                ControlResult(
                    control_id=base_control,
                    control_name=_CONTROL_NAMES.get(base_control, base_control),
                    result=base_result,
                    detail=(
                        f"ECR event {event_id} {event_name} repo={repo_name or '<n/a>'} "
                        f"classified as {base_signal} ({base_result})"
                    ),
                    evidence_data={**common_evidence, "signal": base_signal},
                )
            )
        else:
            base_signal = "unknown_event"
            base_control = _control_for(base_signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=base_control,
                    control_name=_CONTROL_NAMES.get(base_control, base_control),
                    result="FLAG",
                    detail=(
                        f"ECR event {event_id} {event_name} has no matching pattern — "
                        f"surfaced for review"
                    ),
                    evidence_data={**common_evidence, "signal": base_signal},
                )
            )

        # ----------------------------------------------------------------
        # 3. PutImage overlays — vuln, signature, SBOM, mutable tag, age.
        # ----------------------------------------------------------------
        if event_name == "PutImage":
            # critical-vuln push
            if critical_count > 0:
                self._append_overlay(
                    control_results, common_evidence,
                    signal="critical_vuln_push",
                    default_control="PR-03",
                    result_level="FAIL",
                    detail=(
                        f"PutImage to {repo_name!r}: {critical_count} CRITICAL "
                        f"vulnerabilities — supply-chain risk"
                    ),
                )

            # high-vuln push
            if high_count > self.high_severity_threshold:
                self._append_overlay(
                    control_results, common_evidence,
                    signal="high_vuln_push",
                    default_control="PR-03",
                    result_level="FLAG",
                    detail=(
                        f"PutImage to {repo_name!r}: {high_count} HIGH vulnerabilities "
                        f"exceeds threshold {self.high_severity_threshold}"
                    ),
                )

            # stale base image
            if image_age_days > self.image_age_days_threshold:
                self._append_overlay(
                    control_results, common_evidence,
                    signal="stale_base_image_push",
                    default_control="PR-05",
                    result_level="FLAG",
                    detail=(
                        f"PutImage to {repo_name!r}: image_age_days={image_age_days} "
                        f"exceeds threshold {self.image_age_days_threshold} — "
                        f"un-rebuilt base image"
                    ),
                )

            # signature verification failed (DE-01 FAIL)
            if isinstance(signature_status, str) and signature_status.upper() == "VERIFICATION_FAILED":
                self._append_overlay(
                    control_results, common_evidence,
                    signal="signature_verification_fail",
                    default_control="DE-01",
                    result_level="FAIL",
                    detail=(
                        f"PutImage to {repo_name!r}: signature_status="
                        f"VERIFICATION_FAILED — signature mismatch"
                    ),
                )
            # unsigned production push
            elif (
                is_prod_repo
                and (
                    (isinstance(signature_status, str) and signature_status.upper() == "UNSIGNED")
                    or is_signed is False
                )
            ):
                self._append_overlay(
                    control_results, common_evidence,
                    signal="unsigned_prod_push",
                    default_control="PR-04",
                    result_level="FAIL",
                    detail=(
                        f"PutImage to production repo {repo_name!r}: image is unsigned — "
                        f"production images must be signed"
                    ),
                )

            # missing SBOM
            if sbom_present is False:
                self._append_overlay(
                    control_results, common_evidence,
                    signal="missing_sbom",
                    default_control="PR-05",
                    result_level="FLAG",
                    detail=(
                        f"PutImage to {repo_name!r}: SBOM not present — "
                        f"supply-chain evidence incomplete"
                    ),
                )

            # mutable tag (latest) in production
            if is_prod_repo and isinstance(image_tag, str) and image_tag.lower() == "latest":
                self._append_overlay(
                    control_results, common_evidence,
                    signal="mutable_tag_in_prod",
                    default_control="PR-05",
                    result_level="FLAG",
                    detail=(
                        f"PutImage to production repo {repo_name!r} with tag=latest — "
                        f"mutable tag in production = un-pinned reference"
                    ),
                )

            # critical-package + critical/high vulnerability
            if critical_package_hits:
                top_hits = critical_package_hits[:3]
                hit_summary = ", ".join(
                    f"{h.get('package', '')}:{h.get('name', '')}({h.get('severity', '')})"
                    for h in top_hits
                )
                self._append_overlay(
                    control_results, common_evidence,
                    signal="critical_package_vuln",
                    default_control="PR-03",
                    result_level="FAIL",
                    detail=(
                        f"PutImage to {repo_name!r}: critical-package vulnerability — "
                        f"{hit_summary}"
                    ),
                    extra_evidence={
                        "critical_package_hits": top_hits,
                        "critical_package_hit_count": len(critical_package_hits),
                    },
                )

        # ----------------------------------------------------------------
        # 4. PutImageTagMutability → MUTABLE in production.
        # ----------------------------------------------------------------
        if (
            event_name == "PutImageTagMutability"
            and is_prod_repo
            and isinstance(tag_mutability, str)
            and tag_mutability.upper() == "MUTABLE"
        ):
            self._append_overlay(
                control_results, common_evidence,
                signal="tag_mutability_to_mutable",
                default_control="PR-02",
                result_level="FAIL",
                detail=(
                    f"PutImageTagMutability on production repo {repo_name!r} set to "
                    f"MUTABLE — allows tag mutation in production"
                ),
            )

        # ----------------------------------------------------------------
        # 5. PutImageScanningConfiguration scanOnPush=false.
        # ----------------------------------------------------------------
        if event_name == "PutImageScanningConfiguration" and scan_on_push is False:
            self._append_overlay(
                control_results, common_evidence,
                signal="scan_on_push_disabled",
                default_control="PR-03",
                result_level="FAIL",
                detail=(
                    f"PutImageScanningConfiguration on {repo_name!r}: scanOnPush=false "
                    f"— vulnerability scanning disabled"
                ),
            )

        # ----------------------------------------------------------------
        # 6. PutRegistryPolicy widening cross-account access.
        # The policy text is not stored, but a non-zero registry_policy_length
        # combined with a PutRegistryPolicy event is treated as a widening
        # action (operator surfaces the change for review). This mirrors
        # CloudTrail's posture-on-policy-change pattern.
        # ----------------------------------------------------------------
        if event_name == "PutRegistryPolicy" and registry_policy_length > 0:
            self._append_overlay(
                control_results, common_evidence,
                signal="registry_policy_widening",
                default_control="PR-04",
                result_level="FAIL",
                detail=(
                    f"PutRegistryPolicy: registry-level policy modified "
                    f"(length={registry_policy_length}) — registry access widened, "
                    f"requires review"
                ),
            )

        # ----------------------------------------------------------------
        # 7. PutLifecyclePolicy with non-zero declared length → flag retention
        # change (the importer cannot prove "reduced" without state, so it
        # surfaces the change).
        # ----------------------------------------------------------------
        if event_name == "PutLifecyclePolicy" and lifecycle_policy_length > 0:
            self._append_overlay(
                control_results, common_evidence,
                signal="lifecycle_retention_reduced",
                default_control="PR-05",
                result_level="FLAG",
                detail=(
                    f"PutLifecyclePolicy on {repo_name!r}: lifecycle policy modified "
                    f"(length={lifecycle_policy_length}) — verify retention not reduced"
                ),
            )

        # ----------------------------------------------------------------
        # 8. BatchGetImage from external account (cross-account pull).
        # ----------------------------------------------------------------
        if (
            event_name == "BatchGetImage"
            and isinstance(account_id, str)
            and isinstance(registry_id, str)
            and account_id
            and registry_id
            and account_id != registry_id
        ):
            self._append_overlay(
                control_results, common_evidence,
                signal="cross_account_pull",
                default_control="PR-04",
                result_level="FLAG",
                detail=(
                    f"BatchGetImage on registry={registry_id} by external "
                    f"account={account_id} — cross-account pull"
                ),
            )

        # ---- Decision rollup ----
        if any(cr.result == "FAIL" for cr in control_results):
            decision = "BLOCK"
        elif any(cr.result == "FLAG" for cr in control_results):
            decision = "FLAG"
        else:
            decision = "ALLOW"

        decision_reason = (
            f"Imported from AWS ECR: event={event_name} repo={repo_name or 'unknown'} "
            f"identity_type={identity_type or 'unknown'} region={aws_region or 'unknown'}"
        )

        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"ecr-{event_id[:32]}",
            timestamp=event_time,
            agent_id=self.agent_id,
            source_type="aws_ecr_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=request_id or None,
        )

    def _append_overlay(
        self,
        control_results: list[ControlResult],
        common_evidence: dict[str, Any],
        *,
        signal: str,
        default_control: str,
        result_level: str,
        detail: str,
        extra_evidence: dict[str, Any] | None = None,
    ) -> None:
        control_id = _control_for(signal, self._mappings, default_control)
        evidence = {**common_evidence, "signal": signal}
        if extra_evidence:
            evidence.update(extra_evidence)
        control_results.append(
            ControlResult(
                control_id=control_id,
                control_name=_CONTROL_NAMES.get(control_id, control_id),
                result=result_level,
                detail=detail,
                evidence_data=evidence,
            )
        )

    # ------------------------------------------------------------------
    # Synthetic builders
    # ------------------------------------------------------------------

    def _synthetic_vuln_concentration(
        self,
        *,
        repo: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "vulnerability_concentration"
        control_id = _control_for(signal, self._mappings, "PR-03")
        synth_id = f"ecr-vuln-concentration-{repo}"
        evidence: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": signal,
            "repository_name": repo,
            "open_critical_count": count,
            "threshold": self.vulnerability_concentration_threshold,
            "signal": signal,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synth_id,
            ),
            "source_tool": "aws_ecr",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FAIL",
            detail=(
                f"ECR synthetic finding: repository {repo!r} accumulated {count} "
                f"OPEN critical vulnerabilities across pushed images "
                f"(threshold {self.vulnerability_concentration_threshold}) — "
                f"supply-chain hot-spot"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_ecr_import",
            mode=self.mode,
            control_results=[cr],
            decision="BLOCK",
            decision_reason=(
                f"Imported from AWS ECR: synthetic vulnerability-concentration "
                f"pattern for repo={repo!r} count={count}>"
                f"threshold={self.vulnerability_concentration_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_account_pull(
        self,
        *,
        external_account: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "cross_account_pull_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synth_id = f"ecr-cross-account-pull-{external_account}"
        evidence: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": signal,
            "external_account_id": external_account,
            "pull_count": count,
            "threshold": self.cross_account_pull_threshold,
            "signal": signal,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synth_id,
            ),
            "source_tool": "aws_ecr",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"ECR synthetic finding: external account {external_account} "
                f"performed {count} BatchGetImage pulls (threshold "
                f"{self.cross_account_pull_threshold}) — cross-account pull burst"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_ecr_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from AWS ECR: synthetic cross-account-pull pattern for "
                f"account={external_account} count={count}>"
                f"threshold={self.cross_account_pull_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_high_velocity_push(
        self,
        *,
        principal: str,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        signal = "high_velocity_push"
        control_id = _control_for(signal, self._mappings, "PR-05")
        # ARN-shaped principals can be long; truncate the synth_id deterministically.
        principal_key = hashlib.sha256(principal.encode("utf-8")).hexdigest()[:16]
        synth_id = f"ecr-high-velocity-push-{principal_key}"
        evidence: dict[str, Any] = {
            "synthetic": True,
            "synthetic_kind": signal,
            "principal_redacted": _redact_arn(principal) if principal.startswith("arn:") else principal,
            "push_count": count,
            "threshold": self.high_velocity_push_threshold,
            "signal": signal,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, event_id=synth_id,
            ),
            "source_tool": "aws_ecr",
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"ECR synthetic finding: principal performed {count} PutImage "
                f"operations (threshold {self.high_velocity_push_threshold}) — "
                f"rapid CI / agent firehose"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synth_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="aws_ecr_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from AWS ECR: synthetic high-velocity-push pattern "
                f"count={count}>threshold={self.high_velocity_push_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_int(value: Any) -> int:
    """Coerce a value to int; return 0 for non-int / bool / missing."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float) and not isinstance(value, bool):
        return int(value)
    return 0
