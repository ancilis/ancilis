"""Tests for the Snowflake QUERY_HISTORY / LOGIN_HISTORY importer.

Fixture builders use UPPERCASE keyword-argument names that mirror Snowflake's
actual ACCOUNT_USAGE column names (QUERY_ID, EVENT_TYPE, etc). This is
deliberate — it makes the tests read like real Snowflake exports — so we
disable the standard naming check at the file level.
"""

# ruff: noqa: N803

from __future__ import annotations

import json

from ancilis.importers.snowflake import SnowflakeImporter


# ---------------------------------------------------------------------------
# Fixture builders — inline records (no snowflake-connector-python required)
# ---------------------------------------------------------------------------


def _query(
    *,
    QUERY_ID: str = "01b3a1c2-0000-1234-0000-deadbeef0001",
    QUERY_TEXT_LENGTH: int = 120,
    DATABASE_NAME: str = "PROD_ANALYTICS",
    SCHEMA_NAME: str = "PUBLIC",
    QUERY_TYPE: str = "SELECT",
    SESSION_ID: int = 12345,
    USER_NAME: str = "AGENT_SVC",
    ROLE_NAME: str = "ANALYTICS_RW",
    WAREHOUSE_NAME: str = "AGENT_WH",
    WAREHOUSE_SIZE: str = "X-Small",
    EXECUTION_STATUS: str = "SUCCESS",
    ERROR_CODE: int | None = None,
    ERROR_MESSAGE_LENGTH: int = 0,
    START_TIME: str = "2026-04-01T12:00:00+00:00",
    END_TIME: str = "2026-04-01T12:00:01+00:00",
    TOTAL_ELAPSED_TIME: int = 1234,
    BYTES_SCANNED: int = 1024,
    ROWS_PRODUCED: int = 100,
    ROWS_INSERTED: int = 0,
    ROWS_UPDATED: int = 0,
    ROWS_DELETED: int = 0,
    OBJECTS_MODIFIED_COUNT: int = 0,
    OBJECTS_ACCESSED_COUNT: int = 1,
    BASE_OBJECTS_ACCESSED: list[str] | None = None,
    DIRECT_OBJECTS_ACCESSED: list[str] | None = None,
    OBJECT_MODIFIED: list[str] | None = None,
    POLICIES_REFERENCED: list[str] | None = None,
    CLIENT_APPLICATION_ID: str = "snowflake-py-client/3.6.0 (CPython 3.11.5)",
    CLIENT_IP: str = "203.0.113.10",
    QUERY_TAG: str | None = None,
    IS_CLIENT_GENERATED: bool = True,
) -> dict:
    return {
        "QUERY_ID": QUERY_ID,
        "QUERY_TEXT_LENGTH": QUERY_TEXT_LENGTH,
        "DATABASE_NAME": DATABASE_NAME,
        "SCHEMA_NAME": SCHEMA_NAME,
        "QUERY_TYPE": QUERY_TYPE,
        "SESSION_ID": SESSION_ID,
        "USER_NAME": USER_NAME,
        "ROLE_NAME": ROLE_NAME,
        "WAREHOUSE_NAME": WAREHOUSE_NAME,
        "WAREHOUSE_SIZE": WAREHOUSE_SIZE,
        "EXECUTION_STATUS": EXECUTION_STATUS,
        "ERROR_CODE": ERROR_CODE,
        "ERROR_MESSAGE_LENGTH": ERROR_MESSAGE_LENGTH,
        "START_TIME": START_TIME,
        "END_TIME": END_TIME,
        "TOTAL_ELAPSED_TIME": TOTAL_ELAPSED_TIME,
        "BYTES_SCANNED": BYTES_SCANNED,
        "ROWS_PRODUCED": ROWS_PRODUCED,
        "ROWS_INSERTED": ROWS_INSERTED,
        "ROWS_UPDATED": ROWS_UPDATED,
        "ROWS_DELETED": ROWS_DELETED,
        "OBJECTS_MODIFIED_COUNT": OBJECTS_MODIFIED_COUNT,
        "OBJECTS_ACCESSED_COUNT": OBJECTS_ACCESSED_COUNT,
        "BASE_OBJECTS_ACCESSED": BASE_OBJECTS_ACCESSED or [],
        "DIRECT_OBJECTS_ACCESSED": DIRECT_OBJECTS_ACCESSED or [],
        "OBJECT_MODIFIED": OBJECT_MODIFIED or [],
        "POLICIES_REFERENCED": POLICIES_REFERENCED or [],
        "CLIENT_APPLICATION_ID": CLIENT_APPLICATION_ID,
        "CLIENT_IP": CLIENT_IP,
        "QUERY_TAG": QUERY_TAG,
        "IS_CLIENT_GENERATED": IS_CLIENT_GENERATED,
    }


def _login(
    *,
    EVENT_ID: int = 9001,
    EVENT_TIMESTAMP: str = "2026-04-01T08:00:00+00:00",
    EVENT_TYPE: str = "LOGIN",
    USER_NAME: str = "ALICE",
    CLIENT_IP: str = "203.0.113.20",
    REPORTED_CLIENT_TYPE: str = "DRIVERS_PYTHON",
    REPORTED_CLIENT_VERSION: str = "3.6.0",
    FIRST_AUTHENTICATION_FACTOR: str = "PASSWORD",
    SECOND_AUTHENTICATION_FACTOR: str | None = "DUO_PUSH",
    IS_SUCCESS: str = "YES",
    ERROR_CODE: int | None = None,
) -> dict:
    return {
        "EVENT_ID": EVENT_ID,
        "EVENT_TIMESTAMP": EVENT_TIMESTAMP,
        "EVENT_TYPE": EVENT_TYPE,
        "USER_NAME": USER_NAME,
        "CLIENT_IP": CLIENT_IP,
        "REPORTED_CLIENT_TYPE": REPORTED_CLIENT_TYPE,
        "REPORTED_CLIENT_VERSION": REPORTED_CLIENT_VERSION,
        "FIRST_AUTHENTICATION_FACTOR": FIRST_AUTHENTICATION_FACTOR,
        "SECOND_AUTHENTICATION_FACTOR": SECOND_AUTHENTICATION_FACTOR,
        "IS_SUCCESS": IS_SUCCESS,
        "ERROR_CODE": ERROR_CODE,
    }


def _signals(result) -> list[str]:
    return [cr.evidence_data.get("signal") for cr in result.control_results]


# ---------------------------------------------------------------------------
# 1. Governed SELECT — masking policy yields PASS
# ---------------------------------------------------------------------------


def test_select_with_masking_policy_passes() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-aaaa-0001-pass",
                    QUERY_TYPE="SELECT",
                    BASE_OBJECTS_ACCESSED=[
                        "PROD_ANALYTICS.PUBLIC.TRANSACTIONS"
                    ],
                    POLICIES_REFERENCED=["PII_MASKING_POLICY"],
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "warehouse_read_governed" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "warehouse_read_governed")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["policies_masking_present"] is True


# ---------------------------------------------------------------------------
# 2. Large scan flags
# ---------------------------------------------------------------------------


def test_large_scan_flags() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-bbbb-0002-large",
                    QUERY_TYPE="SELECT",
                    BYTES_SCANNED=2_500_000_000,  # 2.5 GB > 1 GB threshold
                    BASE_OBJECTS_ACCESSED=[
                        "PROD_ANALYTICS.PUBLIC.TRANSACTIONS"
                    ],
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "warehouse_read_large_scan" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "warehouse_read_large_scan")
    assert cr.result == "FLAG"
    assert cr.evidence_data["bytes_scanned"] == 2_500_000_000


# ---------------------------------------------------------------------------
# 3. Sensitive-table SELECT flags
# ---------------------------------------------------------------------------


def test_sensitive_table_select_flags() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-cccc-0003-sens",
                    QUERY_TYPE="SELECT",
                    BASE_OBJECTS_ACCESSED=[
                        "PROD_ANALYTICS.CUSTOMER_DATA.CUSTOMERS",
                        "PROD_ANALYTICS.CUSTOMER_DATA.ORDERS",
                    ],
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "warehouse_read_sensitive" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "warehouse_read_sensitive")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"
    classification = cr.evidence_data["base_objects_classification"]
    assert classification["sensitive_count"] == 1  # only CUSTOMERS matches CUSTOMER*
    assert "CUSTOMER*" in classification["pattern_hits"]


# ---------------------------------------------------------------------------
# 4. DROP TABLE fails
# ---------------------------------------------------------------------------


def test_drop_table_fails() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-dddd-0004-drop",
                    QUERY_TYPE="DROP",
                    BASE_OBJECTS_ACCESSED=[],
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "schema_destruction" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "schema_destruction")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 5. GRANT under ACCOUNTADMIN fails
# ---------------------------------------------------------------------------


def test_grant_to_accountadmin_fails() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-eeee-0005-grant",
                    QUERY_TYPE="GRANT",
                    ROLE_NAME="ACCOUNTADMIN",
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "privilege_grant_admin" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "privilege_grant_admin")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-02"


# ---------------------------------------------------------------------------
# 6. UNLOAD to S3 fails — data exfiltration
# ---------------------------------------------------------------------------


def test_unload_to_s3_fails_exfiltration() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-ffff-0006-unload",
                    QUERY_TYPE="UNLOAD",
                    USER_NAME="DATA_EXPORT_SVC",
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "data_exfiltration" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "data_exfiltration")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 7. GET from stage flags egress
# ---------------------------------------------------------------------------


def test_get_from_stage_flags_egress() -> None:
    doc = json.dumps(
        {
            "queries": [
                _query(
                    QUERY_ID="01-gggg-0007-get",
                    QUERY_TYPE="GET",
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "stage_download" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "stage_download")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"


# ---------------------------------------------------------------------------
# 8. Login with MFA passes
# ---------------------------------------------------------------------------


def test_login_with_mfa_passes() -> None:
    doc = json.dumps(
        {
            "logins": [
                _login(
                    EVENT_ID=10001,
                    USER_NAME="ALICE",
                    FIRST_AUTHENTICATION_FACTOR="PASSWORD",
                    SECOND_AUTHENTICATION_FACTOR="DUO_PUSH",
                    IS_SUCCESS="YES",
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "ALLOW"
    assert "login_mfa" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "login_mfa")
    assert cr.result == "PASS"
    assert cr.control_id == "PR-01"


# ---------------------------------------------------------------------------
# 9. Human user with no MFA fails
# ---------------------------------------------------------------------------


def test_human_login_no_mfa_fails() -> None:
    doc = json.dumps(
        {
            "logins": [
                _login(
                    EVENT_ID=10002,
                    USER_NAME="BOB",  # not an agent pattern
                    FIRST_AUTHENTICATION_FACTOR="PASSWORD",
                    SECOND_AUTHENTICATION_FACTOR=None,
                    IS_SUCCESS="YES",
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "BLOCK"
    assert "login_no_mfa" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "login_no_mfa")
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-01"


# ---------------------------------------------------------------------------
# 10. Failed login flags
# ---------------------------------------------------------------------------


def test_failed_login_flags() -> None:
    doc = json.dumps(
        {
            "logins": [
                _login(
                    EVENT_ID=10003,
                    USER_NAME="CHARLIE",
                    IS_SUCCESS="NO",
                    ERROR_CODE=390100,
                )
            ]
        }
    )
    [r] = SnowflakeImporter().parse_string(doc)
    assert r.decision == "FLAG"
    assert "login_failed" in _signals(r)
    cr = next(c for c in r.control_results if c.evidence_data.get("signal") == "login_failed")
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-01"


# ---------------------------------------------------------------------------
# 11. Brute-force pattern produces synthetic finding
# ---------------------------------------------------------------------------


def test_brute_force_pattern_synthetic() -> None:
    # 6 failed logins from same IP within 1h → > default threshold of 5.
    logins = [
        _login(
            EVENT_ID=11000 + i,
            EVENT_TIMESTAMP=f"2026-04-01T08:{10 + i:02d}:00+00:00",
            USER_NAME=f"USER{i}",
            CLIENT_IP="198.51.100.50",
            IS_SUCCESS="NO",
            ERROR_CODE=390100,
        )
        for i in range(6)
    ]
    doc = json.dumps({"logins": logins})
    results = SnowflakeImporter().parse_string(doc)

    synthetic = [r for r in results if r.action_id.startswith("snowflake-brute-force-")]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "BLOCK"
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "brute_force_pattern"
    assert cr.result == "FAIL"
    assert cr.control_id == "PR-01"
    assert cr.evidence_data["brute_force_count"] == 6


# ---------------------------------------------------------------------------
# 12. Cross-database synthetic finding
# ---------------------------------------------------------------------------


def test_cross_database_synthetic() -> None:
    queries = [
        _query(
            QUERY_ID=f"01-cross-{i:04d}",
            DATABASE_NAME=f"DB_{i}",
            USER_NAME="WIDE_AGENT",
            BASE_OBJECTS_ACCESSED=[],
        )
        for i in range(4)  # 4 dbs > default threshold 3
    ]
    doc = json.dumps({"queries": queries})
    results = SnowflakeImporter().parse_string(doc)

    synthetic = [
        r for r in results if r.action_id.startswith("snowflake-cross-database-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "cross_database_pattern"
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-02"
    assert cr.evidence_data["cross_database_database_count"] == 4


# ---------------------------------------------------------------------------
# 13. High-volume sensitive-read synthetic finding
# ---------------------------------------------------------------------------


def test_high_volume_sensitive_read_synthetic() -> None:
    # 3 sensitive reads in 1h, threshold lowered to 2 to avoid 50 fixtures.
    queries = [
        _query(
            QUERY_ID=f"01-hv-{i:04d}",
            START_TIME=f"2026-04-01T12:{i:02d}:00+00:00",
            USER_NAME="GREEDY_AGENT",
            QUERY_TYPE="SELECT",
            BASE_OBJECTS_ACCESSED=[
                f"PROD.CUSTOMER_DATA.CUSTOMERS_{i}",
            ],
        )
        for i in range(3)
    ]
    doc = json.dumps({"queries": queries})
    importer = SnowflakeImporter(high_volume_sensitive_read_threshold=2)
    results = importer.parse_string(doc)

    synthetic = [
        r for r in results if r.action_id.startswith("snowflake-high-volume-sensitive-")
    ]
    assert len(synthetic) == 1
    syn = synthetic[0]
    assert syn.decision == "FLAG"
    cr = syn.control_results[0]
    assert cr.evidence_data["signal"] == "high_volume_sensitive_read"
    assert cr.result == "FLAG"
    assert cr.control_id == "PR-04"
    assert cr.evidence_data["high_volume_count"] == 3


# ---------------------------------------------------------------------------
# 14. QUERY_TEXT itself is never stored
# ---------------------------------------------------------------------------


def test_query_text_never_stored() -> None:
    """A record with an accidental QUERY_TEXT field must not surface it."""
    record = _query(
        QUERY_ID="01-noleak-0014",
        QUERY_TYPE="SELECT",
        BASE_OBJECTS_ACCESSED=["PROD.PUBLIC.T1"],
    )
    # Inject the worst case: an export that included QUERY_TEXT.
    record["QUERY_TEXT"] = "SELECT secret_column FROM customers WHERE ssn='123-45-6789'"
    doc = json.dumps({"queries": [record]})
    [r] = SnowflakeImporter().parse_string(doc)
    for cr in r.control_results:
        # Top-level evidence_data
        assert "QUERY_TEXT" not in cr.evidence_data
        assert "query_text" not in cr.evidence_data
        # Recursive scan of all string values
        for v in _walk_values(cr.evidence_data):
            assert "secret_column" not in str(v)
            assert "123-45-6789" not in str(v)
    # Length is what we keep.
    cr0 = r.control_results[0]
    assert "query_text_length" in cr0.evidence_data


def _walk_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_values(v)
    else:
        yield obj


# ---------------------------------------------------------------------------
# 15. BASE_OBJECTS_ACCESSED list is reduced to count + classification only
# ---------------------------------------------------------------------------


def test_objects_accessed_list_count_only() -> None:
    record = _query(
        QUERY_ID="01-objs-0015",
        QUERY_TYPE="SELECT",
        BASE_OBJECTS_ACCESSED=[
            "PROD.CUSTOMER_DATA.CUSTOMERS",
            "PROD.PUBLIC.SALARY_DETAILS",
            "PROD.OPS.SOMETHING_BENIGN",
        ],
        DIRECT_OBJECTS_ACCESSED=[
            "PROD.PUBLIC.CUSTOMER_VIEW",
        ],
    )
    doc = json.dumps({"queries": [record]})
    [r] = SnowflakeImporter().parse_string(doc)
    for cr in r.control_results:
        # Full lists must not be present
        assert "base_objects_accessed" not in cr.evidence_data
        assert "BASE_OBJECTS_ACCESSED" not in cr.evidence_data
        assert "direct_objects_accessed" not in cr.evidence_data
        # Recursively check no fully-qualified table names appear in string values
        for v in _walk_values(cr.evidence_data):
            s = str(v)
            assert "PROD.CUSTOMER_DATA.CUSTOMERS" not in s
            assert "PROD.PUBLIC.SALARY_DETAILS" not in s
            assert "PROD.OPS.SOMETHING_BENIGN" not in s
            assert "PROD.PUBLIC.CUSTOMER_VIEW" not in s
    # Counts and classification are surfaced.
    cr0 = r.control_results[0]
    assert cr0.evidence_data["base_objects_classification"]["total"] == 3
    assert cr0.evidence_data["base_objects_classification"]["sensitive_count"] == 2
    assert cr0.evidence_data["direct_objects_classification"]["total"] == 1


# ---------------------------------------------------------------------------
# 16. QUERY_TAG values are redacted to sha256; keys preserved
# ---------------------------------------------------------------------------


def test_query_tag_values_redacted() -> None:
    secret_tag = json.dumps(
        {
            "agent_id": "agent-007",
            "task": "summarize_pii_for_user_kevin@example.com",
            "customer_id": "CUST-9999",
        }
    )
    record = _query(
        QUERY_ID="01-tag-0016",
        QUERY_TYPE="SELECT",
        QUERY_TAG=secret_tag,
        BASE_OBJECTS_ACCESSED=["PROD.PUBLIC.T1"],
    )
    doc = json.dumps({"queries": [record]})
    [r] = SnowflakeImporter().parse_string(doc)
    cr0 = r.control_results[0]
    tag_redacted = cr0.evidence_data["query_tag_redacted"]
    assert tag_redacted is not None
    assert tag_redacted["is_json"] is True
    # Keys preserved (operationally useful)
    assert "agent_id" in tag_redacted["top_level_keys"]
    assert "task" in tag_redacted["top_level_keys"]
    assert "customer_id" in tag_redacted["top_level_keys"]
    # SHA256 of the value-string only — no plaintext value
    assert "value_sha256" in tag_redacted
    assert len(tag_redacted["value_sha256"]) == 64
    # Recursively scan: no PII value should leak
    for v in _walk_values(cr0.evidence_data):
        s = str(v)
        assert "kevin@example.com" not in s
        assert "CUST-9999" not in s
        assert "agent-007" not in s
    # The agent_attribution PASS finding should fire because the key was
    # detected.
    assert "agent_attribution" in _signals(r)
