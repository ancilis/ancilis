"""Code review framework demo scenario."""

from __future__ import annotations

from scenarios.common import DemoCall, DemoScenario


def scenario() -> DemoScenario:
    return DemoScenario(
        agent_id="code_review_agent",
        display_name="Code Review Agent",
        architecture="Framework",
        agent_owner="Iris Zhao, Platform Engineering",
        llm_provider="openai/gpt-5.4",
        handles=("general", "trade_secrets"),
        allowed_tools=(
            "fetch_pr_diff",
            "run_policy_scan",
            "post_review_comment",
        ),
        blocked_tools=("post_source_bundle",),
        calls=(
            DemoCall(
                tool_name="fetch_pr_diff",
                arguments={
                    "repo": "acme/payments-core",
                    "pull_request": 1842,
                    "changed_files": ["risk_engine.py", "token_vault.py"],
                    "destination": "github.internal",
                },
                response="Fetched 14-file diff for PR 1842.",
                detected_data_types=("DC-GEN", "DC-IP"),
                description="Fetch proprietary source changes for review.",
            ),
            DemoCall(
                tool_name="run_policy_scan",
                arguments={
                    "repo": "acme/payments-core",
                    "ruleset": "secure-code-review",
                    "secret_sample": "sk_live_demo_51N8redacted",
                    "destination": "codeql.internal",
                },
                response="Policy scan found one credential-handling warning.",
                outcome="FLAG",
                detected_data_types=("DC-IP",),
                reason="Flagged because a credential-like value appeared in the diff.",
                description="Run static review over proprietary source.",
            ),
            DemoCall(
                tool_name="post_review_comment",
                arguments={
                    "repo": "acme/payments-core",
                    "pull_request": 1842,
                    "comment": "Move token redaction before debug logging.",
                    "destination": "github.internal",
                },
                response="Review comment posted to PR 1842.",
                detected_data_types=("DC-GEN",),
                description="Post a scoped code-review comment.",
            ),
            DemoCall(
                tool_name="post_source_bundle",
                arguments={
                    "repo": "acme/payments-core",
                    "files": ["token_vault.py", "risk_engine.py"],
                    "destination": "external-paste.example",
                },
                response="Blocked before proprietary source bundle left the org.",
                outcome="BLOCK",
                detected_data_types=("DC-IP",),
                reason="Blocked because source bundles cannot be posted to external paste services.",
                description="Unsafe attempt to publish proprietary code externally.",
            ),
        ),
    )
