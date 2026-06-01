"""Twilio call/SMS audit-log importer — maps voice + messaging records to AKSI controls.

Twilio (https://www.twilio.com) is the dominant communications platform for AI
agents: voice agents place outbound calls, SMS agents push notifications, and
fraud-detection agents trigger verification calls. Voice and SMS carry direct
PII (phone numbers, conversation content) plus heavy regulatory exposure —
TCPA in the US (consent + DNC + time-of-day rules; statutory damages of
$500-$1500 per violating contact) and GDPR / national e-comm directives in the
EU. From a runtime-control perspective, an outbound voice call or SMS by an
agent is qualitatively different from an internal LLM completion: it crosses
into a regulated communications channel addressed at a phone-number-identified
human.

This importer ingests Twilio API exports from three endpoints:

  * ``/2010-04-01/Accounts/{Sid}/Calls.json``    (envelope: ``{"calls": [...]}``)
  * ``/2010-04-01/Accounts/{Sid}/Messages.json`` (envelope: ``{"messages": [...]}``)
  * ``/v1/audit_logs.json``                       (envelope: ``{"audit_logs": [...]}``)

Plus mixed exports under ``{"data": [...]}`` and JSONL — one record per line.
Record type is **auto-detected by SID prefix**: ``CA...``=call, ``SM.../MM...``
=message, ``AU...``=audit-log entry. A single import file may freely mix all
three.

Signal mapping (see shared/mappings/twilio-aksi-controls.json):

Calls
  * ``direction=outbound-api`` & ``status=completed``                       → PR-04 FLAG (outbound-call by agent — TCPA-relevant)
  * ``direction=inbound`` & ``status=completed``                            → PR-05 PASS (audit trail)
  * ``status=failed``                                                       → DE-01 FAIL
  * ``answered_by=machine_*``                                               → PR-04 PASS captured (TCPA treats machines differently)
  * ``answered_by=fax``                                                     → PR-04 FLAG (anomalous — possibly wrong number)
  * ``duration > long_call_threshold_s``  (default 1800s = 30min)           → PR-04 FLAG (recording-consent concern)
  * ``country_code_to`` ≠ ``country_code_from``                             → PR-04 FLAG (international outbound)

Messages
  * ``direction=outbound-api`` & ``status=delivered``                       → PR-04 FLAG (outbound SMS — TCPA / consent-required)
  * ``direction=outbound-api`` & ``status=delivered`` & ``is_marketing``    → PR-04 FAIL (marketing SMS without verified consent — direct TCPA violation)
  * ``direction=inbound`` & ``status=received``                             → PR-05 PASS
  * ``status=failed``                                                       → DE-01 FAIL
  * ``status=undelivered`` & ``error_code=30007`` (carrier spam-filter)     → PR-04 FAIL
  * ``status=undelivered`` & ``error_code=30003`` (delivery to invalid #)   → PR-03 FLAG
  * ``num_media > 0``                                                       → PR-04 FLAG (MMS — content surface)
  * ``country_code_to`` in SMS-pumping list (BR/CN/IN/EG/...)               → PR-02 FLAG

Synthetic patterns
  * Velocity: > N records to the same destination phone in 24h  (default N=5)   → PR-02 FLAG
  * Cross-country fan-out: one ``account_sid`` spanning > N distinct country codes
    in the export (default N=10)                                                → PR-04 FLAG

Sanitization (privacy-critical — phone numbers are PII in many jurisdictions):

  * ``to`` / ``from`` raw E.164 numbers are NEVER stored. Only a masked form
    survives: ``"+1•••••67"`` (country-code prefix + last 2 digits).
  * ``country_code_to`` / ``country_code_from`` are captured (already
    non-identifying at country granularity).
  * ``caller_name`` (CNAM lookup) is DROPPED entirely.
  * Message ``body`` and any text content is DROPPED entirely.
  * ``sid`` is preserved as ``"CA1234...XYZ4"`` (prefix + last 4 of the random
    portion only) — full SIDs are not strictly secret, but the abbreviation
    keeps evidence rows compact and discourages copy-paste joins to live API.
  * The original file is hashed (sha256) for source provenance.

The SDK does NOT depend on the ``twilio`` package; exports are parsed with the
standard library only.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ancilis.engine.result import ControlResult, EvaluationResult


# Mapping table lives at <repo>/shared/mappings/twilio-aksi-controls.json.
# This file lives at <repo>/python/src/ancilis/importers/twilio.py — five
# .parent traversals after .resolve() reach the repo root.
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent.parent
    / "shared" / "mappings" / "twilio-aksi-controls.json"
)

_CONTROL_NAMES: dict[str, str] = {
    "PR-01": "Prompt Injection Prevention",
    "PR-02": "Rate Limiting",
    "PR-03": "Input Validation",
    "PR-04": "Cryptographic Controls",
    "PR-05": "Secret Detection",
    "DE-01": "Data Exfiltration Prevention",
}

_DEFAULT_LONG_CALL_THRESHOLD_S = 1800
_DEFAULT_VELOCITY_THRESHOLD = 5
_DEFAULT_CROSS_COUNTRY_THRESHOLD = 10
_DEFAULT_SMS_PUMPING_COUNTRIES: frozenset[str] = frozenset(
    {"BR", "CN", "IN", "EG", "PK", "BD", "ID", "PH", "VN", "NG"}
)
_DEFAULT_TCPA_EXEMPT_PREFIXES: frozenset[str] = frozenset({"911", "411", "611"})


# ---------------------------------------------------------------------------
# Mapping table loader
# ---------------------------------------------------------------------------


def _load_mapping_table() -> dict[str, Any]:
    """Load the twilio-aksi-controls.json mapping; tolerate missing file."""
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


def _mask_phone_number(number: str | None, country_code: str | None) -> str | None:
    """Reduce a raw E.164 phone number to ``+<cc>•••••XX`` (last 2 digits only).

    Phone numbers are PII in many jurisdictions (GDPR Art.4(1) lists them as
    identifiers); even partial numbers risk re-identification. We retain only
    a country-code prefix + last 2 digits for correlation while staying well
    below any reasonable "directly identifies a natural person" bar. If the
    country_code is missing we still mask the local portion.
    """
    if not number or not isinstance(number, str):
        return None
    s = number.strip()
    if not s:
        return None
    # Pull out the trailing two ASCII digits if any survive.
    digits = "".join(ch for ch in s if ch.isdigit())
    last2 = digits[-2:] if len(digits) >= 2 else digits
    cc = (country_code or "").strip().upper()
    if cc:
        return f"+{cc}•••••{last2}" if last2 else f"+{cc}•••••"
    # No country code — keep the leading "+" if present.
    prefix = "+" if s.startswith("+") else ""
    return f"{prefix}•••••{last2}" if last2 else f"{prefix}•••••"


def _abbreviate_sid(sid: str | None) -> str | None:
    """Reduce a Twilio SID (34-char) to ``<4-prefix>...<last-4>``.

    Twilio SIDs are not strictly secret, but full preservation invites
    copy-paste joins back to the live API. The prefix carries the type
    (CA/SM/MM/AU) which is the only part downstream evidence needs.
    """
    if not sid or not isinstance(sid, str):
        return None
    s = sid.strip()
    if not s:
        return None
    if len(s) <= 8:
        return s
    return f"{s[:4]}...{s[-4:]}"


def _sid_kind(sid: str | None) -> str | None:
    """Auto-detect record type by SID prefix.

    Returns ``"call"`` for ``CA*``, ``"message"`` for ``SM*`` or ``MM*``,
    ``"audit"`` for ``AU*``, otherwise ``None``.
    """
    if not sid or not isinstance(sid, str):
        return None
    s = sid.strip().upper()
    if s.startswith("CA"):
        return "call"
    if s.startswith("SM") or s.startswith("MM"):
        return "message"
    if s.startswith("AU"):
        return "audit"
    return None


def _coerce_int(value: Any) -> int | None:
    """Coerce a Twilio-style stringified int to int; None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: Any) -> float | None:
    """Coerce a Twilio-style stringified float (price etc.) to float."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool | None:
    """Coerce a Twilio-style bool/string-bool to a Python bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
    return None


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class TwilioImporter:
    """Parse a Twilio call/message/audit export into ``EvaluationResult`` records.

    A single import file may mix ``CA*`` (call), ``SM.../MM...`` (message), and
    ``AU*`` (audit-log) records. Dispatch is driven by the ``sid`` prefix; an
    enclosing envelope (``{"calls": [...]}``, ``{"messages": [...]}``,
    ``{"data": [...]}``, JSONL, or single object) is auto-detected.
    """

    def __init__(
        self,
        agent_id: str = "import",
        mode: str = "audit",
        long_call_threshold_s: int | None = None,
        velocity_threshold: int | None = None,
        cross_country_threshold: int | None = None,
        sms_pumping_countries: Iterable[str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.mode = mode
        table = _load_mapping_table()
        meta = table.get("_metadata", {}) if isinstance(table, dict) else {}
        self._mappings: dict[str, str] = {
            str(k): str(v)
            for k, v in (table.get("mappings", {}) or {}).items()
        }
        # Long-call threshold precedence: explicit arg > mapping metadata > default.
        if long_call_threshold_s is not None:
            self.long_call_threshold_s = int(long_call_threshold_s)
        else:
            self.long_call_threshold_s = int(
                meta.get("long_call_threshold_s", _DEFAULT_LONG_CALL_THRESHOLD_S)
            )
        # Velocity threshold (records to same destination in 24h).
        if velocity_threshold is not None:
            self.velocity_threshold = int(velocity_threshold)
        else:
            self.velocity_threshold = int(
                meta.get("velocity_threshold", _DEFAULT_VELOCITY_THRESHOLD)
            )
        # Cross-country fan-out threshold.
        if cross_country_threshold is not None:
            self.cross_country_threshold = int(cross_country_threshold)
        else:
            self.cross_country_threshold = int(
                meta.get("cross_country_threshold", _DEFAULT_CROSS_COUNTRY_THRESHOLD)
            )
        # SMS-pumping country list.
        if sms_pumping_countries is not None:
            self.sms_pumping_countries = frozenset(
                str(c).upper() for c in sms_pumping_countries
            )
        else:
            meta_pumping = meta.get("sms_pumping_countries")
            if isinstance(meta_pumping, list) and meta_pumping:
                self.sms_pumping_countries = frozenset(
                    str(c).upper() for c in meta_pumping
                )
            else:
                self.sms_pumping_countries = _DEFAULT_SMS_PUMPING_COUNTRIES
        # TCPA-exempt short-code prefixes.
        meta_exempt = meta.get("tcpa_exempt_short_codes")
        if isinstance(meta_exempt, list) and meta_exempt:
            self.tcpa_exempt_prefixes: frozenset[str] = frozenset(
                str(p) for p in meta_exempt
            )
        else:
            self.tcpa_exempt_prefixes = _DEFAULT_TCPA_EXEMPT_PREFIXES
        # Marketing-consent flag.
        self.marketing_consent_required = bool(
            meta.get("marketing_consent_required", True)
        )

    # -- Public API ---------------------------------------------------------

    def parse(self, path: str | Path) -> list[EvaluationResult]:
        """Parse a Twilio export file (JSON or JSONL) from disk."""
        content_bytes = Path(path).read_bytes()
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        text = content_bytes.decode("utf-8")
        records = self._records_from_text(text)
        return self._build_results(records, file_sha256=file_sha256)

    def parse_string(self, content: str) -> list[EvaluationResult]:
        """Parse Twilio export content from a JSON or JSONL string."""
        records = self._records_from_text(content)
        return self._build_results(records, file_sha256=None)

    # -- Internals ----------------------------------------------------------

    def _records_from_text(self, text: str) -> list[dict[str, Any]]:
        """Detect Twilio-shaped envelopes / JSONL / single record."""
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
                # Twilio's documented envelopes — calls/messages/audit_logs.
                for key in ("calls", "messages", "audit_logs", "data"):
                    if key in doc and isinstance(doc[key], list):
                        return [r for r in doc[key] if isinstance(r, dict)]
                # Single record envelope.
                return [doc]
            return []
        return list(_iter_jsonl(text))

    def _build_results(
        self,
        records: list[dict[str, Any]],
        *,
        file_sha256: str | None,
    ) -> list[EvaluationResult]:
        """Per-record dispatch by SID prefix + synthetic velocity / cross-country findings."""
        # Aggregations for synthetic patterns.
        # destination -> count (for velocity)
        destination_counts: dict[str, int] = defaultdict(int)
        # account_sid -> set of country_code_to (for cross-country fan-out)
        account_countries: dict[str, set[str]] = defaultdict(set)

        for rec in records:
            kind = _sid_kind(rec.get("sid"))
            if kind not in ("call", "message"):
                continue
            to_raw = rec.get("to")
            if isinstance(to_raw, str) and to_raw.strip():
                destination_counts[to_raw.strip()] += 1
            account_sid = rec.get("account_sid")
            cc_to = rec.get("country_code_to")
            if (
                isinstance(account_sid, str)
                and account_sid
                and isinstance(cc_to, str)
                and cc_to
            ):
                account_countries[account_sid].add(cc_to.upper())

        velocity_destinations = {
            dest: count
            for dest, count in destination_counts.items()
            if count > self.velocity_threshold
        }
        cross_country_accounts = {
            acct: sorted(ccs)
            for acct, ccs in account_countries.items()
            if len(ccs) > self.cross_country_threshold
        }

        results: list[EvaluationResult] = []
        for rec in records:
            kind = _sid_kind(rec.get("sid"))
            if kind == "call":
                results.append(
                    self._parse_call(
                        rec,
                        file_sha256=file_sha256,
                        velocity_destinations=velocity_destinations,
                        cross_country_accounts=cross_country_accounts,
                    )
                )
            elif kind == "message":
                results.append(
                    self._parse_message(
                        rec,
                        file_sha256=file_sha256,
                        velocity_destinations=velocity_destinations,
                        cross_country_accounts=cross_country_accounts,
                    )
                )
            elif kind == "audit":
                results.append(
                    self._parse_audit(rec, file_sha256=file_sha256)
                )
            else:
                results.append(
                    self._parse_unknown(rec, file_sha256=file_sha256)
                )

        # Synthetic velocity findings — one per destination.
        for dest, count in sorted(velocity_destinations.items()):
            # Determine a country code for masking by checking any record matching this dest.
            cc = None
            for rec in records:
                if rec.get("to") == dest:
                    cc = rec.get("country_code_to")
                    break
            results.append(
                self._synthetic_velocity_result(
                    destination=dest,
                    country_code_to=cc if isinstance(cc, str) else None,
                    count=count,
                    file_sha256=file_sha256,
                )
            )

        # Synthetic cross-country findings — one per account_sid.
        for acct, ccs in sorted(cross_country_accounts.items()):
            results.append(
                self._synthetic_cross_country_result(
                    account_sid=acct,
                    country_codes=ccs,
                    file_sha256=file_sha256,
                )
            )
        return results

    def _source_provenance(
        self,
        *,
        file_sha256: str | None,
        record_id: str | None = None,
    ) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "source_format": "twilio",
            "source_tool_name": "twilio",
            "source_tool_version": "",
        }
        if record_id is not None:
            provenance["record_id"] = record_id
        if file_sha256 is not None:
            provenance["original_file_sha256"] = file_sha256
        return provenance

    # ------------------------------------------------------------------
    # Per-record parsers
    # ------------------------------------------------------------------

    def _common_evidence(
        self,
        record: dict[str, Any],
        *,
        kind: str,
        file_sha256: str | None,
    ) -> dict[str, Any]:
        """Build the shared evidence dict (sanitized — no raw phone or text)."""
        sid_raw = record.get("sid")
        sid_full = sid_raw if isinstance(sid_raw, str) else None
        sid_short = _abbreviate_sid(sid_full) or str(uuid.uuid4())
        account_sid_raw = record.get("account_sid")
        account_sid = (
            str(account_sid_raw) if isinstance(account_sid_raw, str) else None
        )
        direction = str(record.get("direction") or "").strip().lower()
        status = str(record.get("status") or "").strip().lower()
        cc_to_raw = record.get("country_code_to")
        cc_from_raw = record.get("country_code_from")
        cc_to = (
            str(cc_to_raw).strip().upper()
            if isinstance(cc_to_raw, str) and cc_to_raw.strip()
            else None
        )
        cc_from = (
            str(cc_from_raw).strip().upper()
            if isinstance(cc_from_raw, str) and cc_from_raw.strip()
            else None
        )
        to_masked = _mask_phone_number(
            record.get("to") if isinstance(record.get("to"), str) else None,
            cc_to,
        )
        from_masked = _mask_phone_number(
            record.get("from") if isinstance(record.get("from"), str) else None,
            cc_from,
        )
        price = _coerce_float(record.get("price"))
        evidence: dict[str, Any] = {
            "twilio_sid": sid_short,
            "twilio_record_kind": kind,
            "account_sid": account_sid,
            "to_masked": to_masked,
            "from_masked": from_masked,
            "country_code_to": cc_to,
            "country_code_from": cc_from,
            "direction": direction,
            "status": status,
            "price": price,
            "price_unit": (
                str(record.get("price_unit"))
                if isinstance(record.get("price_unit"), str)
                else None
            ),
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=sid_short,
            ),
            "source_tool": "twilio",
        }
        return evidence

    def _parse_call(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        velocity_destinations: dict[str, int],
        cross_country_accounts: dict[str, list[str]],
    ) -> EvaluationResult:
        evidence = self._common_evidence(record, kind="call", file_sha256=file_sha256)
        direction = evidence["direction"]
        status = evidence["status"]
        cc_to = evidence["country_code_to"]
        cc_from = evidence["country_code_from"]
        sid_short = evidence["twilio_sid"]
        account_sid = evidence["account_sid"]

        duration_s = _coerce_int(record.get("duration"))
        answered_by_raw = record.get("answered_by")
        answered_by = (
            str(answered_by_raw).strip().lower()
            if isinstance(answered_by_raw, str) and answered_by_raw.strip()
            else None
        )
        # Note: caller_name (CNAM) is intentionally NOT captured — even partial
        # CNAM data ("John S") can re-identify in small populations.
        evidence["duration_s"] = duration_s
        evidence["answered_by"] = answered_by
        evidence["start_time"] = (
            str(record.get("start_time"))
            if isinstance(record.get("start_time"), str)
            else None
        )
        evidence["end_time"] = (
            str(record.get("end_time"))
            if isinstance(record.get("end_time"), str)
            else None
        )

        control_results: list[ControlResult] = []

        # 1. Primary status / direction signal.
        if status == "failed":
            signal = "call_failed"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Twilio call {sid_short} direction={direction or 'unknown'} "
                        f"failed (status=failed)"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif direction == "outbound-api" and status == "completed":
            signal = "outbound_call_tcpa"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} outbound-api completed — "
                        f"agent-placed call to country={cc_to or 'unknown'} "
                        f"(TCPA-relevant; verify consent + DNC)"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif direction == "inbound" and status == "completed":
            signal = "inbound_call_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Twilio call {sid_short} inbound completed — "
                        f"audit trail recorded"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        else:
            # Unknown status / direction combination (queued, ringing, busy,
            # canceled, no-answer, outbound-dial). Surface as PR-05 FLAG.
            signal = "call_other_status"
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} direction={direction or 'unknown'} "
                        f"status={status or 'unknown'} — non-terminal or unrecognized"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 2. answered_by signals.
        if answered_by and answered_by.startswith("machine_"):
            signal = "machine_answered"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Twilio call {sid_short} answered_by={answered_by!r} "
                        f"— calling answering machines is differently regulated under TCPA"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        elif answered_by == "fax":
            signal = "fax_answered"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} answered_by=fax — anomalous, "
                        f"possibly wrong-number; review destination list"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 3. Long call (recording-consent surface).
        if duration_s is not None and duration_s > self.long_call_threshold_s:
            signal = "long_call"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} duration={duration_s}s exceeds "
                        f"long_call_threshold={self.long_call_threshold_s}s "
                        f"— recording-consent / two-party-consent surface"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "long_call_threshold_s": self.long_call_threshold_s,
                    },
                )
            )

        # 4. International outbound (cross-country pair).
        if (
            cc_to
            and cc_from
            and cc_to != cc_from
            and direction == "outbound-api"
        ):
            signal = "international_outbound_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} crosses country boundary "
                        f"{cc_from}->{cc_to} — different regulatory surface"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 5. Velocity / cross-country pattern markers (informational; the synthetic
        # finding lives in a separate EvaluationResult).
        to_raw = record.get("to") if isinstance(record.get("to"), str) else None
        if to_raw and to_raw in velocity_destinations:
            signal = "velocity_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} contributes to velocity pattern "
                        f"({velocity_destinations[to_raw]} > "
                        f"threshold {self.velocity_threshold})"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "velocity_count": velocity_destinations[to_raw],
                        "velocity_threshold": self.velocity_threshold,
                    },
                )
            )
        if account_sid and account_sid in cross_country_accounts:
            signal = "cross_country_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio call {sid_short} account {account_sid} fan-out "
                        f"({len(cross_country_accounts[account_sid])} countries > "
                        f"threshold {self.cross_country_threshold})"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "cross_country_codes": cross_country_accounts[account_sid],
                        "cross_country_threshold": self.cross_country_threshold,
                    },
                )
            )

        decision = self._decide(control_results)
        decision_reason = (
            f"Imported from Twilio: kind=call sid={sid_short} "
            f"direction={direction or 'unknown'} status={status or 'unknown'} "
            f"duration={duration_s if duration_s is not None else 'unknown'}s "
            f"answered_by={answered_by or 'unknown'}"
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"twilio-{sid_short}",
            timestamp=evidence.get("start_time")
            or datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="twilio_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=float(duration_s * 1000) if duration_s is not None else 0.0,
            session_id=account_sid or None,
        )

    def _parse_message(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
        velocity_destinations: dict[str, int],
        cross_country_accounts: dict[str, list[str]],
    ) -> EvaluationResult:
        evidence = self._common_evidence(record, kind="message", file_sha256=file_sha256)
        direction = evidence["direction"]
        status = evidence["status"]
        cc_to = evidence["country_code_to"]
        sid_short = evidence["twilio_sid"]
        account_sid = evidence["account_sid"]

        num_segments = _coerce_int(record.get("num_segments"))
        num_media = _coerce_int(record.get("num_media")) or 0
        body_length = _coerce_int(record.get("body_length"))
        is_marketing = _coerce_bool(record.get("is_marketing"))
        error_code = _coerce_int(record.get("error_code"))
        date_sent = (
            str(record.get("date_sent"))
            if isinstance(record.get("date_sent"), str)
            else None
        )

        # Note: message body / text content is intentionally NEVER captured —
        # even truncated bodies can leak OTP codes, account numbers, or
        # personal context.
        evidence["num_segments"] = num_segments
        evidence["num_media"] = num_media
        evidence["body_length"] = body_length
        evidence["is_marketing"] = is_marketing
        evidence["error_code"] = error_code
        evidence["date_sent"] = date_sent
        evidence["messaging_service_sid"] = (
            str(record.get("messaging_service_sid"))
            if isinstance(record.get("messaging_service_sid"), str)
            else None
        )

        control_results: list[ControlResult] = []

        # 1. Marketing SMS without verified consent — TCPA FAIL (highest priority).
        # We treat marketing+delivered+consent-required as a direct violation
        # indicator: in the absence of an upstream consent record, evidence of
        # delivery alone is enough to surface for legal review.
        if (
            self.marketing_consent_required
            and direction == "outbound-api"
            and status == "delivered"
            and is_marketing is True
        ):
            signal = "marketing_sms_no_consent"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Twilio message {sid_short} delivered marketing SMS "
                        f"to country={cc_to or 'unknown'} without verified consent "
                        f"— direct TCPA violation indicator"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        # 2. Carrier filtering (US 30007 = spam reputation) — FAIL.
        elif status == "undelivered" and error_code == 30007:
            signal = "carrier_filtering_spam"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Twilio message {sid_short} undelivered with error_code=30007 "
                        f"(US carrier filtering — flagged as spam) — bad sender "
                        f"reputation, likely TCPA / 10DLC issue"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        # 3. Invalid number (30003) — input validation.
        elif status == "undelivered" and error_code == 30003:
            signal = "invalid_number"
            control_id = _control_for(signal, self._mappings, "PR-03")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} undelivered with error_code=30003 "
                        f"(invalid destination number) — input-validation gap upstream"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        # 4. Generic failure.
        elif status == "failed":
            signal = "sms_failed"
            control_id = _control_for(signal, self._mappings, "DE-01")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FAIL",
                    detail=(
                        f"Twilio message {sid_short} failed "
                        f"(error_code={error_code if error_code is not None else 'none'})"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        # 5. Outbound delivered (non-marketing) — TCPA-relevant FLAG.
        elif direction == "outbound-api" and status == "delivered":
            signal = "outbound_sms_tcpa"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} outbound-api delivered to "
                        f"country={cc_to or 'unknown'} — TCPA / consent-required surface"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        # 6. Inbound received — audit trail PASS.
        elif direction == "inbound" and status == "received":
            signal = "inbound_sms_audit"
            control_id = _control_for(signal, self._mappings, "PR-05")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="PASS",
                    detail=(
                        f"Twilio message {sid_short} inbound received — "
                        f"audit trail recorded"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )
        else:
            signal = "sms_other_status"
            control_results.append(
                ControlResult(
                    control_id="PR-05",
                    control_name=_CONTROL_NAMES["PR-05"],
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} direction={direction or 'unknown'} "
                        f"status={status or 'unknown'} — non-terminal or unrecognized"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 7. MMS with media — content surface FLAG (additive).
        if num_media > 0:
            signal = "mms_with_media"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} carries num_media={num_media} "
                        f"— MMS content surface for review"
                    ),
                    evidence_data={**evidence, "signal": signal},
                )
            )

        # 8. SMS-pumping country — fraud risk FLAG (additive).
        if cc_to and cc_to in self.sms_pumping_countries:
            signal = "sms_pumping_country"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} destination country={cc_to} "
                        f"is on the SMS-pumping fraud watchlist"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "sms_pumping_countries": sorted(self.sms_pumping_countries),
                    },
                )
            )

        # 9. Velocity / cross-country markers (informational; synthetic finding separate).
        to_raw = record.get("to") if isinstance(record.get("to"), str) else None
        if to_raw and to_raw in velocity_destinations:
            signal = "velocity_pattern"
            control_id = _control_for(signal, self._mappings, "PR-02")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} contributes to velocity pattern "
                        f"({velocity_destinations[to_raw]} > "
                        f"threshold {self.velocity_threshold})"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "velocity_count": velocity_destinations[to_raw],
                        "velocity_threshold": self.velocity_threshold,
                    },
                )
            )
        if account_sid and account_sid in cross_country_accounts:
            signal = "cross_country_pattern"
            control_id = _control_for(signal, self._mappings, "PR-04")
            control_results.append(
                ControlResult(
                    control_id=control_id,
                    control_name=_CONTROL_NAMES.get(control_id, control_id),
                    result="FLAG",
                    detail=(
                        f"Twilio message {sid_short} account {account_sid} fan-out "
                        f"({len(cross_country_accounts[account_sid])} countries > "
                        f"threshold {self.cross_country_threshold})"
                    ),
                    evidence_data={
                        **evidence,
                        "signal": signal,
                        "cross_country_codes": cross_country_accounts[account_sid],
                        "cross_country_threshold": self.cross_country_threshold,
                    },
                )
            )

        decision = self._decide(control_results)
        decision_reason = (
            f"Imported from Twilio: kind=message sid={sid_short} "
            f"direction={direction or 'unknown'} status={status or 'unknown'} "
            f"num_segments={num_segments if num_segments is not None else 'unknown'} "
            f"num_media={num_media} "
            f"is_marketing={is_marketing if is_marketing is not None else 'unknown'} "
            f"error_code={error_code if error_code is not None else 'none'}"
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"twilio-{sid_short}",
            timestamp=date_sent or datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="twilio_import",
            mode=self.mode,
            control_results=control_results,
            decision=decision,
            decision_reason=decision_reason,
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=account_sid or None,
        )

    def _parse_audit(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Audit-log entries cover admin actions — PR-05 PASS by default."""
        sid_raw = record.get("sid")
        sid_full = sid_raw if isinstance(sid_raw, str) else None
        sid_short = _abbreviate_sid(sid_full) or str(uuid.uuid4())
        account_sid_raw = record.get("account_sid")
        account_sid = (
            str(account_sid_raw) if isinstance(account_sid_raw, str) else None
        )
        event_type = (
            str(record.get("event_type"))
            if isinstance(record.get("event_type"), str)
            else None
        )
        actor_sid = (
            str(record.get("actor_sid"))
            if isinstance(record.get("actor_sid"), str)
            else None
        )
        event_date = (
            str(record.get("event_date"))
            if isinstance(record.get("event_date"), str)
            else None
        )
        evidence: dict[str, Any] = {
            "twilio_sid": sid_short,
            "twilio_record_kind": "audit",
            "account_sid": account_sid,
            "actor_sid": actor_sid,
            "event_type": event_type,
            "event_date": event_date,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256,
                record_id=sid_short,
            ),
            "source_tool": "twilio",
            "signal": "audit_log",
        }
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="PASS",
            detail=(
                f"Twilio audit-log entry {sid_short} event_type={event_type or 'unknown'} "
                f"actor={actor_sid or 'unknown'} — admin audit trail recorded"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"twilio-{sid_short}",
            timestamp=event_date or datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="twilio_import",
            mode=self.mode,
            control_results=[cr],
            decision="ALLOW",
            decision_reason=(
                f"Imported from Twilio: kind=audit sid={sid_short} "
                f"event_type={event_type or 'unknown'}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=account_sid or None,
        )

    def _parse_unknown(
        self,
        record: dict[str, Any],
        *,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Record with no recognizable SID prefix — surface as PR-05 FLAG."""
        sid_raw = record.get("sid")
        sid_full = sid_raw if isinstance(sid_raw, str) else None
        sid_short = _abbreviate_sid(sid_full) or str(uuid.uuid4())
        evidence: dict[str, Any] = {
            "twilio_sid": sid_short,
            "twilio_record_kind": "unknown",
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=sid_short
            ),
            "source_tool": "twilio",
            "signal": "unknown_sid_prefix",
        }
        cr = ControlResult(
            control_id="PR-05",
            control_name=_CONTROL_NAMES["PR-05"],
            result="FLAG",
            detail=(
                f"Twilio record {sid_short} has no recognized SID prefix "
                f"(expected CA*/SM*/MM*/AU*) — surfaced for review"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=f"twilio-{sid_short}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="twilio_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=f"Imported from Twilio: unknown sid={sid_short}",
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_velocity_result(
        self,
        *,
        destination: str,
        country_code_to: str | None,
        count: int,
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-destination velocity finding (one phone, many records)."""
        signal = "velocity_pattern"
        control_id = _control_for(signal, self._mappings, "PR-02")
        masked = _mask_phone_number(destination, country_code_to) or "•••••"
        synthetic_id = f"twilio-velocity-{abs(hash(destination)) & 0xFFFFFFFF:08x}"
        evidence: dict[str, Any] = {
            "twilio_sid": synthetic_id,
            "twilio_record_kind": "synthetic_velocity",
            "to_masked": masked,
            "country_code_to": (
                country_code_to.upper()
                if isinstance(country_code_to, str)
                else None
            ),
            "velocity_count": count,
            "velocity_threshold": self.velocity_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "twilio",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Twilio synthetic finding: destination {masked} received {count} "
                f"records in this export — exceeds velocity threshold "
                f"{self.velocity_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="twilio_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Twilio: synthetic velocity pattern "
                f"destination={masked} count={count}>threshold={self.velocity_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    def _synthetic_cross_country_result(
        self,
        *,
        account_sid: str,
        country_codes: list[str],
        file_sha256: str | None,
    ) -> EvaluationResult:
        """Synthesize a per-account cross-country fan-out finding."""
        signal = "cross_country_pattern"
        control_id = _control_for(signal, self._mappings, "PR-04")
        synthetic_id = f"twilio-cross-country-{account_sid}"
        evidence: dict[str, Any] = {
            "twilio_sid": synthetic_id,
            "twilio_record_kind": "synthetic_cross_country",
            "account_sid": account_sid,
            "cross_country_codes": country_codes,
            "cross_country_count": len(country_codes),
            "cross_country_threshold": self.cross_country_threshold,
            "synthetic": True,
            "source_provenance": self._source_provenance(
                file_sha256=file_sha256, record_id=synthetic_id
            ),
            "source_tool": "twilio",
            "signal": signal,
        }
        cr = ControlResult(
            control_id=control_id,
            control_name=_CONTROL_NAMES.get(control_id, control_id),
            result="FLAG",
            detail=(
                f"Twilio synthetic finding: account {account_sid} sent to "
                f"{len(country_codes)} distinct countries in this export "
                f"({', '.join(country_codes)}) — exceeds cross-country threshold "
                f"{self.cross_country_threshold}"
            ),
            evidence_data=evidence,
        )
        return EvaluationResult(
            evaluation_id=str(uuid.uuid4()),
            action_id=synthetic_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            source_type="twilio_import",
            mode=self.mode,
            control_results=[cr],
            decision="FLAG",
            decision_reason=(
                f"Imported from Twilio: synthetic cross-country pattern "
                f"account={account_sid} countries={len(country_codes)}>threshold="
                f"{self.cross_country_threshold}"
            ),
            active_overlays=[],
            data_classifications=[],
            total_duration_ms=0.0,
            session_id=None,
        )

    @staticmethod
    def _decide(control_results: list[ControlResult]) -> str:
        """Decision: any FAIL → BLOCK; any FLAG → FLAG; else ALLOW."""
        if any(cr.result == "FAIL" for cr in control_results):
            return "BLOCK"
        if any(cr.result == "FLAG" for cr in control_results):
            return "FLAG"
        return "ALLOW"
