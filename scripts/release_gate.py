#!/usr/bin/env python3
"""Verify the ordinary release path. This is not remote tag/environment protection."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from release_manifest import NoRedirect, ReleaseError, parse, require, sha

MINIMUM_CHECKS = [
    {"context": name, "app_id": 15368}
    for name in (
        "Python 3.10",
        "Python 3.11",
        "Python 3.12",
        "Python 3.13",
        "Python packaging verification",
        "TypeScript (Node 20)",
        "TypeScript (Node 22)",
        "Dependency Audit",
    )
]


class GitHub:
    """Bounded, GET-only API; tokens and review bodies are never written to evidence."""

    def __init__(self, repository, token):
        require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "Invalid repository",
        )
        require(bool(token), "Read-only policy credential is required")
        self.base = f"https://api.github.com/repos/{repository}/"
        self.token = token
        self.evidence = []

    def get(self, path):
        require(
            not path.startswith("/") and ".." not in path and "\\" not in path, "Invalid API path"
        )
        request = urllib.request.Request(
            self.base + path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "ancilis-release-gate",
            },
            method="GET",
        )
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                require(response.status == 200, "Unexpected GitHub status")
                raw = response.read(8 * 1024 * 1024 + 1)
                require(len(raw) <= 8 * 1024 * 1024, "GitHub response too large")
                result = parse(raw)
                self.evidence.append({"endpoint": path, "sha256": sha(raw)})
                return result
        except urllib.error.HTTPError as exc:
            raise ReleaseError(
                f"GitHub policy read failed: HTTP {exc.code}; no publication"
            ) from None
        except (OSError, urllib.error.URLError) as exc:
            raise ReleaseError("GitHub policy API unavailable; no publication") from exc

    def pages(self, path, key=None):
        result = []
        for page in range(1, 51):
            separator = "&" if "?" in path else "?"
            data = self.get(f"{path}{separator}per_page=100&page={page}")
            rows = data[key] if key else data
            require(isinstance(rows, list) and len(rows) <= 100, "Invalid API page")
            result.extend(rows)
            if len(rows) < 100:
                if key:
                    require(data.get("total_count") == len(result), "Incomplete API collection")
                return result
        raise ReleaseError("API pagination limit exceeded; no publication")


def commit_sha(value):
    require(
        isinstance(value, str) and re.fullmatch("[0-9a-f]{40}", value) is not None,
        "Invalid commit identity",
    )
    return value


def verify_release(api, repository, source, minimum_checks=MINIMUM_CHECKS):
    try:
        commit_sha(source)
        branch = api.get("branches/main")
        require(branch["protected"] is True, "Main branch is not protected")
        main = commit_sha(branch["commit"]["sha"])
        protection = api.get("branches/main/protection")
        policy = protection["required_status_checks"]
        require(policy["strict"] is True, "Strict current-base checks required")
        checks = policy["checks"]
        require(isinstance(checks, list) and bool(checks), "Required checks missing")
        required = {(c["context"], c["app_id"]) for c in checks}
        require(
            len(required) == len(checks)
            and all(isinstance(n, str) and type(a) is int and a > 0 for n, a in required),
            "Ambiguous check identity",
        )
        require(
            set(policy["contexts"]) == {c[0] for c in required}, "Incomplete protected context list"
        )
        require(
            {(c["context"], c["app_id"]) for c in minimum_checks} <= required,
            "Required release checks were weakened",
        )
        reviews_policy = protection["required_pull_request_reviews"]
        count = reviews_policy["required_approving_review_count"]
        require(type(count) is int and count >= 1, "Required PR approval missing")
        require(
            not reviews_policy.get("require_code_owner_reviews")
            and not reviews_policy.get("require_last_push_approval"),
            "Additional approval policy requires explicit supported verification",
        )
        comparison = api.get(f"compare/{source}...{main}")
        require(
            comparison["status"] in ("ahead", "identical")
            and comparison["merge_base_commit"]["sha"] == source,
            "Tag commit is not on main",
        )
        matches = []
        for candidate in api.pages(f"commits/{source}/pulls"):
            number = candidate["number"]
            require(type(number) is int and number > 0, "Invalid PR number")
            pr = api.get(f"pulls/{number}")
            if (
                pr["merged"] is True
                and pr["merge_commit_sha"] == source
                and pr["base"]["ref"] == "main"
                and pr["base"]["repo"]["full_name"] == repository
            ):
                matches.append((number, pr))
        require(len(matches) == 1, "Expected exactly one merged PR for tagged commit")
        number, pr = matches[0]
        head = commit_sha(pr["head"]["sha"])
        tagged = api.get(f"git/commits/{source}")
        reviewed = api.get(f"git/commits/{head}")
        require(tagged["sha"] == source and reviewed["sha"] == head, "Commit API identity mismatch")
        require(
            commit_sha(tagged["tree"]["sha"]) == commit_sha(reviewed["tree"]["sha"]),
            "Merged tree differs from reviewed PR head",
        )
        latest = {}
        seen_ids = set()
        for review in sorted(api.pages(f"pulls/{number}/reviews"), key=lambda r: r["id"]):
            require(
                type(review["id"]) is int and review["id"] not in seen_ids,
                "Ambiguous review identity",
            )
            seen_ids.add(review["id"])
            login = review["user"]["login"]
            require(re.fullmatch("[A-Za-z0-9-]+", login) is not None, "Invalid reviewer identity")
            if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
                latest[login.lower()] = review
        approvals = []
        for review in latest.values():
            login = review["user"]["login"]
            if login.lower() == pr["user"]["login"].lower() or review["user"]["type"] != "User":
                continue
            permission = api.get(f"collaborators/{login}/permission")["permission"]
            if permission not in ("admin", "maintain", "write"):
                continue
            require(review["state"] != "CHANGES_REQUESTED", "Outstanding change request")
            if review["state"] == "APPROVED" and review["commit_id"] == head:
                approvals.append(login)
        require(len(approvals) >= count, "Insufficient eligible approvals of exact PR head")
        runs = {}
        seen_ids = set()
        for check in api.pages(f"commits/{source}/check-runs", "check_runs"):
            key = (check["name"], check["app"]["id"])
            if key not in required:
                continue
            require(type(check["id"]) is int and check["id"] not in seen_ids, "Ambiguous check run")
            seen_ids.add(check["id"])
            if key not in runs or check["id"] > runs[key]["id"]:
                runs[key] = check
        require(set(runs) == required, "Required CI evidence missing")
        for check in runs.values():
            require(
                check["head_sha"] == source
                and check["status"] == "completed"
                and check["conclusion"] == "success",
                "Required CI is not successful on release commit",
            )
        return {
            "source": source,
            "main": main,
            "pull_request": number,
            "reviewed_head": head,
            "tree": tagged["tree"]["sha"],
            "approvals": sorted(approvals),
            "required_approvals": count,
            "check_run_ids": sorted(c["id"] for c in runs.values()),
            "trust_boundary": "Ordinary workflow process verification only; remote release protections are separately required.",
            "reads": api.evidence,
        }
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ReleaseError("Malformed or incomplete GitHub release evidence") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        # A separately authorized, read-only credential is needed for Administration:read.
        # The ordinary GITHUB_TOKEN is never silently treated as sufficient.
        api = GitHub(args.repository, os.environ.get("RELEASE_POLICY_READ_TOKEN", ""))
        result = verify_release(api, args.repository, args.source)
        result["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print("Verified exact merged source, eligible reviews and required CI")
        print("Evidence SHA256:", sha(args.output.read_bytes()))
    except ReleaseError as exc:
        parser.exit(1, f"Release gate refused: {exc}\n")


if __name__ == "__main__":
    main()
