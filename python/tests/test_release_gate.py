"""Read-only release source approval checks against adversarial API evidence."""

from __future__ import annotations
import copy
import importlib.util
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("release_gate", ROOT / "scripts/release_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
sys.path.pop(0)
SHA, HEAD, MAIN, TREE = (c * 40 for c in "abcd")


@pytest.fixture
def api():
    class Fake:
        evidence = []
        data = {
            "branches/main": {"protected": True, "commit": {"sha": MAIN}},
            "branches/main/protection": {
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["test"],
                    "checks": [{"context": "test", "app_id": 15368}],
                },
                "required_pull_request_reviews": {"required_approving_review_count": 1},
            },
            f"compare/{SHA}...{MAIN}": {"status": "ahead", "merge_base_commit": {"sha": SHA}},
            f"commits/{SHA}/pulls": [{"number": 1}],
            "pulls/1": {
                "merged": True,
                "merge_commit_sha": SHA,
                "head": {"sha": HEAD},
                "base": {"ref": "main", "repo": {"full_name": "ancilis/ancilis"}},
                "user": {"login": "builder"},
            },
            f"git/commits/{SHA}": {"sha": SHA, "tree": {"sha": TREE}},
            f"git/commits/{HEAD}": {"sha": HEAD, "tree": {"sha": TREE}},
            "pulls/1/reviews": [
                {
                    "id": 1,
                    "state": "APPROVED",
                    "commit_id": HEAD,
                    "user": {"login": "reviewer", "type": "User"},
                }
            ],
            "collaborators/reviewer/permission": {"permission": "write"},
            f"commits/{SHA}/check-runs": [
                {
                    "id": 1,
                    "name": "test",
                    "app": {"id": 15368},
                    "head_sha": SHA,
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        }

        def get(self, path):
            return copy.deepcopy(self.data[path])

        def pages(self, path, key=None):
            return self.get(path)

    value = Fake()
    value.data = copy.deepcopy(value.data)
    return value


def verify(api):
    return gate.verify_release(api, "ancilis/ancilis", SHA, [{"context": "test", "app_id": 15368}])


def test_exact_approved_merge_passes(api):
    result = verify(api)
    assert (
        result["source"] == SHA
        and result["reviewed_head"] == HEAD
        and result["approvals"] == ["reviewer"]
    )


@pytest.mark.parametrize(
    "case",
    [
        "unprotected",
        "no_strict",
        "weakened_checks",
        "wrong_app",
        "wrong_merge",
        "off_main",
        "tree_changed",
        "stale_approval",
        "author_approval",
        "read_only_reviewer",
        "dismissed",
        "changes_requested",
        "check_failed",
        "check_pending",
        "wrong_check_sha",
        "later_failed_run",
        "missing_checks",
        "two_approvals_required",
        "ambiguous_pr",
    ],
)
def test_gate_fails_closed(api, case):
    d = api.data
    protection = d["branches/main/protection"]
    reviews = d["pulls/1/reviews"]
    check = d[f"commits/{SHA}/check-runs"][0]
    if case == "unprotected":
        d["branches/main"]["protected"] = False
    if case == "no_strict":
        protection["required_status_checks"]["strict"] = False
    if case == "weakened_checks":
        protection["required_status_checks"]["checks"] = []
    if case == "wrong_app":
        check["app"]["id"] = 123
    if case == "wrong_merge":
        d["pulls/1"]["merge_commit_sha"] = HEAD
    if case == "off_main":
        d[f"compare/{SHA}...{MAIN}"]["merge_base_commit"]["sha"] = HEAD
    if case == "tree_changed":
        d[f"git/commits/{HEAD}"]["tree"]["sha"] = MAIN
    if case == "stale_approval":
        reviews[0]["commit_id"] = SHA
    if case == "author_approval":
        reviews[0]["user"]["login"] = "builder"
    if case == "read_only_reviewer":
        d["collaborators/reviewer/permission"]["permission"] = "read"
    if case == "dismissed":
        reviews[0]["state"] = "DISMISSED"
    if case == "changes_requested":
        reviews.append(reviews[0] | {"id": 2, "state": "CHANGES_REQUESTED"})
    if case == "check_failed":
        check["conclusion"] = "failure"
    if case == "check_pending":
        check["status"] = "in_progress"
    if case == "wrong_check_sha":
        check["head_sha"] = HEAD
    if case == "later_failed_run":
        d[f"commits/{SHA}/check-runs"].append(check | {"id": 2, "conclusion": "failure"})
    if case == "missing_checks":
        d[f"commits/{SHA}/check-runs"] = []
    if case == "two_approvals_required":
        protection["required_pull_request_reviews"]["required_approving_review_count"] = 2
    if case == "ambiguous_pr":
        d[f"commits/{SHA}/pulls"].append({"number": 2})
        d["pulls/2"] = d["pulls/1"]
    with pytest.raises(gate.ReleaseError):
        verify(api)


def test_comment_does_not_erase_current_approval(api):
    api.data["pulls/1/reviews"].append(
        api.data["pulls/1/reviews"][0] | {"id": 2, "state": "COMMENTED"}
    )
    assert verify(api)["approvals"] == ["reviewer"]


def test_api_permission_failure_never_becomes_success(api):
    def denied(path):
        raise gate.ReleaseError("HTTP 403")

    api.get = denied
    with pytest.raises(gate.ReleaseError):
        verify(api)


def test_pagination_collects_all_pages_and_records_complete_count():
    api = gate.GitHub("ancilis/ancilis", "unused-test-token")
    requested = []

    def get(path):
        requested.append(path)
        return {"total_count": 101, "check_runs": list(range(100)) if path.endswith("&page=1") else [100]}

    api.get = get
    assert api.pages("commits/test/check-runs", "check_runs") == list(range(101))
    assert len(requested) == 2


def test_pagination_refuses_truncated_or_growing_collection():
    api = gate.GitHub("ancilis/ancilis", "unused-test-token")
    api.get = lambda _: {"total_count": 2, "check_runs": [1]}
    with pytest.raises(gate.ReleaseError):
        api.pages("commits/test/check-runs", "check_runs")


def test_missing_policy_credential_fails_before_any_api_call():
    with pytest.raises(gate.ReleaseError):
        gate.GitHub("ancilis/ancilis", "")
