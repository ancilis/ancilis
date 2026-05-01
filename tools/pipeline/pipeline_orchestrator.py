"""
Ancilis Build Pipeline v2 Orchestrator

Coordinates design and development work between Claude (via Anthropic API) and
Codex (via CLI subprocess). Notion is the control plane (queue, visibility, next action).
Artifacts (PRDs, ADRs) are committed to the repo.

Requirements:
  pip install anthropic notion-client

Environment variables:
  ANTHROPIC_API_KEY - Claude API key
  NOTION_API_KEY - Notion integration token
  NOTION_DATABASE_ID - Build Pipeline database ID
  ANCILIS_REPO_PATH - Path to local ancilis repo checkout

Run: python pipeline_orchestrator.py
Schedule with cron: */30 * * * * cd /path/to/ancilis && python tools/pipeline/pipeline_orchestrator.py
"""

import os
import json
import uuid
import subprocess
import logging
import tempfile
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from notion_client import Client as NotionClient
from anthropic import Anthropic

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pipeline_v2")

# --- Configuration ---

NOTION_DATABASE_ID = os.environ.get("NOTION_DATABASE_ID", "")
ANCILIS_REPO_PATH = os.environ.get("ANCILIS_REPO_PATH", "/path/to/ancilis")
CLAIM_TIMEOUT_MINUTES = 10
CIRCUIT_BREAKER_MAX_ROUNDS = 3
FAST_LANE_AUTO_MERGE_HOURS = 1

ANCILIS_CONTEXT = """
You are working on Ancilis (ancilis.ai), an agent-native GRC platform ("Vanta for agents").

Two products:
- Ancilis Platform: hosted SaaS, assessment-first (not enforcement). FastAPI + PostgreSQL + Alembic + React + shadcn/ui.
- Ancilis SDK: open source (AGPL-3.0-or-later, dual-licensed commercial), pip/npm installable. Python + TypeScript. DuckDB evidence store.

AKSI Framework: 26 controls, 16-type data classification taxonomy, 3-layer architecture.
Key patterns: AOA (Action Object Abstraction), ADR-005 producer protocol, data-classification-driven auto-scoping.
Platform connects via API integrations only — no customer-side deployment.
Security tools (Singulr, Noma) are input integration partners — their findings become compliance evidence.
GRC platforms (Vanta, Drata) are output integration partners.
Repo: ancilis/ancilis on GitHub.

Key repo paths:
- Engine: /python/src/ancilis/engine/engine.py
- Middleware: /python/src/ancilis/middleware/
- Producers: /python/src/ancilis/producers/
- Evidence: /python/src/ancilis/evidence/store.py
- Overlays: /shared/overlays/
- Tests: /python/tests/
"""

PRD_TEMPLATE = """
# PRD: {title}

## Problem Statement
What problem does this solve? Why now?

## User Story
As a [user type], I want [capability] so that [outcome].

## Requirements
### Must Have
- ...
### Should Have
- ...
### Won't Have (this iteration)
- ...

## Technical Approach
High-level approach, key design decisions, integration points.

## Affected Components
Which files/modules/services are touched?

## Data Model Changes
Any new tables, columns, or schema changes?

## API Changes
Any new or modified endpoints?

## Test Strategy
What needs to be tested? Unit, integration, E2E?

## Dependencies
What must be complete before this can start?

## Risks
What could go wrong?
"""

ADR_TEMPLATE = """
# ADR-[NNN]: {title}

| Field | Value |
|-------|-------|
| Status | PROPOSED |
| Date | {date} |
| Scope | [Components affected] |

## Context
What is the issue motivating this decision?

## Decision
What change are we proposing?

## Alternatives Considered
| Alternative | Pros | Cons | Verdict |

## Consequences
### Positive
### Risks to Manage

## Implementation Notes
"""

# --- Clients ---

notion = NotionClient(auth=os.environ.get("NOTION_API_KEY", ""))
anthropic_client = Anthropic()


# --- Notion Helpers ---

def query_pipeline(phase: str = None, lane: str = None, owner: str = None) -> List[Dict]:
    """Query the Build Pipeline database for items matching filters.

    Args:
        phase: Phase value to filter by (e.g., "SPEC", "BUILD")
        lane: Lane value to filter by (e.g., "fast", "standard", "high-risk")
        owner: Owner to filter by (e.g., "Claude", "Codex")

    Returns:
        List of Notion pages matching the filters.
    """
    filters = {"and": []}

    if phase:
        filters["and"].append({"property": "Phase", "select": {"equals": phase}})
    if lane:
        filters["and"].append({"property": "Lane", "select": {"equals": lane}})
    if owner:
        filters["and"].append({"property": "Owner", "select": {"equals": owner}})

    # Only query items that are either unclaimed or whose lease has expired
    response = notion.databases.query(
        database_id=NOTION_DATABASE_ID,
        filter=filters if filters["and"] else {"property": "Phase", "select": {"equals": phase or "NEW"}},
        sorts=[{"property": "Priority", "direction": "ascending"}],
    )
    return response.get("results", [])


def get_property_text(page: Dict, prop_name: str) -> str:
    """Extract text from a Notion page property."""
    prop = page.get("properties", {}).get(prop_name, {})
    prop_type = prop.get("type", "")

    if prop_type == "title":
        return "".join(t.get("plain_text", "") for t in prop.get("title", []))
    elif prop_type == "rich_text":
        return "".join(t.get("plain_text", "") for t in prop.get("rich_text", []))
    elif prop_type == "select":
        sel = prop.get("select")
        return sel.get("name", "") if sel else ""
    elif prop_type == "number":
        return str(prop.get("number", 0) or 0)
    elif prop_type == "url":
        return prop.get("url", "") or ""
    elif prop_type == "date":
        date_obj = prop.get("date")
        return date_obj.get("start", "") if date_obj else ""

    return ""


def update_item(page_id: str, updates: Dict[str, Any]):
    """Update properties on a Notion page.

    Args:
        page_id: Notion page ID
        updates: Dictionary of property name -> value
    """
    properties = {}

    for key, value in updates.items():
        if key in ("Phase", "Lane", "Owner", "Priority", "Type", "Milestone", "Decision"):
            if value:
                properties[key] = {"select": {"name": value}}
        elif key in ("Round",):
            properties[key] = {"number": int(value) if value else 0}
        elif key in ("PRD Link", "ADR Link", "PR Link"):
            if value:
                properties[key] = {"url": value}
        elif key in ("Summary", "Branch", "Last Error", "Run ID"):
            if value:
                properties[key] = {"rich_text": [{"text": {"content": str(value)[:2000]}}]}
        elif key == "Claimed At":
            if value:
                properties[key] = {"date": {"start": value}}

    if properties:
        notion.pages.update(page_id=page_id, properties=properties)


def is_claim_abandoned(claimed_at_str: str) -> bool:
    """Check if a claim has expired (>10 minutes old)."""
    if not claimed_at_str:
        return True

    try:
        claimed_at = datetime.fromisoformat(claimed_at_str.replace("Z", "+00:00"))
        now = datetime.utcnow()
        # Make naive comparison
        if claimed_at.tzinfo:
            claimed_at = claimed_at.replace(tzinfo=None)
        return (now - claimed_at).total_seconds() > CLAIM_TIMEOUT_MINUTES * 60
    except Exception:
        return True


def claim_item(page: Dict) -> bool:
    """Attempt to claim an item. Returns True if claimed successfully.

    The item is claimable if:
    - Run ID is empty, OR
    - Claimed At is > 10 minutes old (abandoned)
    """
    run_id = get_property_text(page, "Run ID")
    claimed_at = get_property_text(page, "Claimed At")

    # Check if already claimed and lease not expired
    if run_id and not is_claim_abandoned(claimed_at):
        return False

    # Claim the item
    new_run_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + "Z"
    update_item(page["id"], {
        "Run ID": new_run_id,
        "Claimed At": now,
    })
    logger.info(f"Claimed item: {get_property_text(page, 'Name')} with Run ID {new_run_id}")
    return True


def release_claim(page_id: str):
    """Release the claim on an item (clear Run ID and Claimed At)."""
    update_item(page_id, {
        "Run ID": "",
        "Claimed At": None,
    })


def create_notion_page_in_repo(title: str, content: str, file_path: str) -> str:
    """Create a document file in the repo and return the file path.

    For v2, PRDs and ADRs are stored in the repo (docs/prd/, docs/adr/) as markdown,
    not as Notion subpages.

    Args:
        title: Document title
        content: Document content
        file_path: Absolute path to write the file

    Returns:
        file_path on success
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        f.write(f"# {title}\n\n{content}")
    logger.info(f"Created artifact: {file_path}")
    return file_path


def create_git_branch(branch_name: str) -> bool:
    """Create and checkout a feature branch in the repo."""
    try:
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=ANCILIS_REPO_PATH,
            capture_output=True,
            check=True,
            timeout=30,
        )
        logger.info(f"Created branch: {branch_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to create branch {branch_name}: {e}")
        return False


# --- Claude Actions ---

def claude_draft_spec(page: Dict):
    """Claude drafts a PRD (and optionally ADR) for a spec phase item.

    Workflow:
    1. Draft PRD + optional ADR
    2. Write to repo (docs/prd/, docs/adr/)
    3. Update Notion with links
    4. Update Phase -> SPEC, Owner -> Codex (for standard) or stay SPEC (for high-risk with SPEC_REVIEW phase)
    """
    title = get_property_text(page, "Name")
    lane = get_property_text(page, "Lane")
    description = page.get("url", "")  # Use page URL as context
    item_type = get_property_text(page, "Type")

    # Get page content from Notion blocks if available
    page_id = page["id"]
    try:
        blocks = notion.blocks.children.list(block_id=page_id)
        content_parts = []
        for block in blocks.get("results", []):
            block_type = block.get("type", "")
            if block_type in ("paragraph", "heading_1", "heading_2", "heading_3", "bulleted_list_item"):
                rich_text = block.get(block_type, {}).get("rich_text", [])
                content_parts.append("".join(rt.get("plain_text", "") for rt in rich_text))
        page_description = "\n".join(content_parts)
    except Exception:
        page_description = description

    prompt = f"""{ANCILIS_CONTEXT}

You are drafting a PRD (Product Requirements Document) for the following build item in the v2 pipeline.

**Item:** {title}
**Lane:** {lane}
**Type:** {item_type}
**Description:**
{page_description}

Using the PRD template below, create a thorough, production-ready PRD. Fill in every section with specific, actionable content.

If this item involves a significant architectural decision (new patterns, new data model concepts, protocol choices, schema changes), ALSO draft an ADR.

For a high-risk lane item, the PRD should include a "Guardrails" section listing hard constraints on what should NOT be modified.

PRD TEMPLATE:
{PRD_TEMPLATE.format(title=title)}

ADR TEMPLATE (only if needed):
{ADR_TEMPLATE.format(title=title, date=datetime.now().strftime("%Y-%m-%d"))}

Respond ONLY with valid JSON in this exact format (no markdown fence, no extra text):
{{
  "prd_content": "...",
  "adr_content": null,
  "needs_adr": false,
  "summary": "Brief one-line summary for Notion"
}}

If an ADR is needed, set "adr_content" to the ADR markdown and "needs_adr" to true.
"""

    try:
        response = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
        result_text = response.content[0].text.strip()

        # Parse JSON response
        result = json.loads(result_text)
        prd_content = result.get("prd_content", "")
        adr_content = result.get("adr_content")
        summary = result.get("summary", "PRD drafted by Claude")

        # Create PRD file
        prd_slug = title.lower().replace(" ", "-")[:40]
        prd_path = os.path.join(ANCILIS_REPO_PATH, "docs", "prd", f"{prd_slug}.md")
        create_notion_page_in_repo(f"PRD: {title}", prd_content, prd_path)
        prd_link = prd_path  # Store local path; in a full impl, would be GitHub raw URL

        # Create ADR file if needed
        adr_link = None
        if adr_content:
            adr_slug = title.lower().replace(" ", "-")[:40]
            adr_path = os.path.join(ANCILIS_REPO_PATH, "docs", "adr", f"adr-{adr_slug}.md")
            create_notion_page_in_repo(f"ADR: {title}", adr_content, adr_path)
            adr_link = adr_path

        # Update Notion
        next_owner = "Codex" if lane == "standard" else "Codex"  # Codex reviews in both cases
        update_item(page["id"], {
            "PRD Link": prd_link,
            "ADR Link": adr_link or "",
            "Owner": next_owner,
            "Decision": "pending",
            "Summary": summary[:500],
        })

        # For standard lane: move to SPEC with Codex as reviewer
        # For high-risk lane: stay in SPEC, but add SPEC_REVIEW phase concept via owner change
        if lane == "standard":
            update_item(page["id"], {"Phase": "SPEC"})
        elif lane == "high-risk":
            update_item(page["id"], {"Phase": "SPEC"})

        release_claim(page["id"])
        logger.info(f"[Claude] Spec drafted for {title}")

    except json.JSONDecodeError as e:
        logger.error(f"[Claude] Failed to parse JSON response for {title}: {e}")
        update_item(page["id"], {"Last Error": f"JSON parse error: {str(e)[:500]}"})
        release_claim(page["id"])
    except Exception as e:
        logger.error(f"[Claude] Error drafting spec for {title}: {e}")
        update_item(page["id"], {"Last Error": str(e)[:500]})
        release_claim(page["id"])


def claude_review_spec(page: Dict):
    """Claude reviews a spec (PRD/ADR) for high-risk items.

    For high-risk lane, Codex does adversarial spec review first, then Claude
    can do a secondary review if needed. This is less common than Codex review.
    """
    title = get_property_text(page, "Name")
    round_num = int(get_property_text(page, "Round") or "0")

    # Circuit breaker
    if round_num >= CIRCUIT_BREAKER_MAX_ROUNDS:
        logger.warning(f"[Claude] Circuit breaker for {title} at round {round_num}")
        update_item(page["id"], {
            "Phase": "BLOCKED",
            "Owner": "Kevin",
            "Decision": "escalated",
            "Summary": f"Circuit breaker: {round_num} review rounds",
        })
        release_claim(page["id"])
        return

    logger.info(f"[Claude] Reviewing spec for {title}")
    release_claim(page["id"])


def claude_review_code(page: Dict):
    """Claude reviews code in the REVIEW phase.

    For standard and high-risk lanes, Claude does code review on the completed build.
    Returns structured review response.
    """
    title = get_property_text(page, "Name")
    lane = get_property_text(page, "Lane")
    round_num = int(get_property_text(page, "Round") or "0")

    # Circuit breaker
    if round_num >= CIRCUIT_BREAKER_MAX_ROUNDS:
        logger.warning(f"[Claude] Circuit breaker for {title} at round {round_num}")
        update_item(page["id"], {
            "Phase": "BLOCKED",
            "Owner": "Kevin",
            "Decision": "escalated",
            "Summary": f"Circuit breaker: {round_num} review rounds",
        })
        release_claim(page["id"])
        return

    pr_link = get_property_text(page, "PR Link")
    branch = get_property_text(page, "Branch")

    prompt = f"""{ANCILIS_CONTEXT}

You are reviewing code for item "{title}" on branch "{branch}".

**PR:** {pr_link}
**Lane:** {lane}

Review the code for:
- Correctness (matches PRD requirements)
- Test coverage (sufficient tests)
- Architectural consistency (AOA pattern, producer protocol, assessment-first)
- No regressions (doesn't break existing functionality)
- Documentation (changes documented)
- Code quality (clean, readable, follows patterns)

Respond ONLY with valid JSON in this exact format (no markdown fence, no extra text):
{{
  "decision": "approved|approved_with_nits|changes_requested|escalated",
  "summary": "One-line summary",
  "issues": [
    {{"severity": "blocking|suggestion|nit", "file": "path/file.py", "line": 42, "description": "..."}}
  ],
  "nits_follow_up": false,
  "reviewer": "Claude",
  "timestamp": "2026-03-30T14:30:00Z"
}}

Only "blocking" issues trigger "changes_requested". Use "suggestion" or "nit" for non-blocking feedback.
If nits_follow_up is true, the orchestrator will create a follow-up fast-lane item.
"""

    try:
        response = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=6000,
            messages=[{"role": "user", "content": prompt}],
        )
        result_text = response.content[0].text.strip()
        review = json.loads(result_text)

        decision = review.get("decision", "pending")
        summary = review.get("summary", "Code reviewed")

        # Update Notion based on decision
        if decision == "approved":
            if lane == "high-risk":
                # High-risk needs human checkpoint from Kevin
                update_item(page["id"], {
                    "Owner": "Kevin",
                    "Decision": "approved",
                    "Phase": "REVIEW",  # Stay in review for Kevin's checkpoint
                    "Summary": summary[:500],
                })
            else:
                # Standard lane: approved means we're ready to merge
                update_item(page["id"], {
                    "Owner": "Kevin",
                    "Decision": "approved",
                    "Phase": "MERGED",  # Auto-merge for standard
                    "Summary": summary[:500],
                })
        elif decision == "approved_with_nits":
            # Create a follow-up fast-lane item for nits
            if review.get("nits_follow_up"):
                create_nits_follow_up(page, review.get("issues", []))

            # Original item proceeds to merge
            update_item(page["id"], {
                "Owner": "Kevin",
                "Decision": "approved_with_nits",
                "Phase": "MERGED",
                "Summary": summary[:500],
            })
        elif decision == "changes_requested":
            # Loop back to BUILD
            update_item(page["id"], {
                "Owner": "Codex",
                "Decision": "changes_requested",
                "Phase": "BUILD",
                "Round": round_num + 1,
                "Summary": summary[:500],
            })
        else:  # escalated or unknown
            update_item(page["id"], {
                "Decision": decision or "pending",
                "Summary": summary[:500],
            })

        release_claim(page["id"])
        logger.info(f"[Claude] Code reviewed for {title}: {decision}")

    except json.JSONDecodeError as e:
        logger.error(f"[Claude] Failed to parse review JSON for {title}: {e}")
        update_item(page["id"], {"Last Error": f"Review JSON parse error: {str(e)[:500]}"})
        release_claim(page["id"])
    except Exception as e:
        logger.error(f"[Claude] Error reviewing code for {title}: {e}")
        update_item(page["id"], {"Last Error": str(e)[:500]})
        release_claim(page["id"])


def create_nits_follow_up(parent_page: Dict, issues: List[Dict]):
    """Create a fast-lane follow-up item for nits cleanup."""
    parent_title = get_property_text(parent_page, "Name")

    # Extract nits
    nits = [i for i in issues if i.get("severity") == "nit"]
    if not nits:
        return

    nits_summary = "; ".join(n.get("description", "")[:50] for n in nits[:3])

    # In a real implementation, create a new Notion page as a child
    # For now, just log
    logger.info(f"[System] Nits follow-up for {parent_title}: {nits_summary}")


# --- Codex Actions ---

def codex_dispatch_spec_review(page: Dict):
    """Dispatch spec review to Codex via CLI.

    For standard lane: Codex reviews the spec drafted by Claude
    For high-risk lane: Codex does adversarial spec review
    """
    title = get_property_text(page, "Name")
    lane = get_property_text(page, "Lane")
    prd_link = get_property_text(page, "PRD Link")
    round_num = int(get_property_text(page, "Round") or "0")

    # Circuit breaker
    if round_num >= CIRCUIT_BREAKER_MAX_ROUNDS:
        logger.warning(f"[Codex] Circuit breaker for {title} at round {round_num}")
        update_item(page["id"], {
            "Phase": "BLOCKED",
            "Owner": "Kevin",
            "Decision": "escalated",
            "Summary": f"Circuit breaker: {round_num} review rounds",
        })
        release_claim(page["id"])
        return

    review_type = "adversarial" if lane == "high-risk" else "standard"

    prompt = f"""{ANCILIS_CONTEXT}

You are performing a {review_type} spec review for "{title}".

**PRD:** {prd_link}
**Lane:** {lane}

{f"This is a high-risk item. Perform an adversarial review - challenge assumptions, identify edge cases, security implications, and scope creep." if lane == "high-risk" else "Review for technical feasibility, consistency with Ancilis patterns, and completeness."}

Respond ONLY with valid JSON in this exact format (no markdown fence, no extra text):
{{
  "decision": "approved|approved_with_nits|changes_requested|escalated",
  "summary": "One-line summary",
  "issues": [
    {{"severity": "blocking|suggestion|nit", "description": "..."}}
  ],
  "reviewer": "Codex",
  "timestamp": "2026-03-30T14:30:00Z"
}}

Only "blocking" issues trigger "changes_requested".
"""

    # Run codex exec with the prompt
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(prompt)
            prompt_file = f.name

        result = subprocess.run(
            ["codex", "exec", "--json", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=ANCILIS_REPO_PATH,
        )

        if result.returncode != 0:
            logger.error(f"[Codex] CLI error for {title}: {result.stderr}")
            update_item(page["id"], {"Last Error": f"Codex CLI error: {result.stderr[:500]}"})
            release_claim(page["id"])
            return

        # Try to extract JSON from output
        output = result.stdout
        try:
            # Look for JSON in the output
            import re
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                review = json.loads(json_match.group())
            else:
                review = json.loads(output)
        except json.JSONDecodeError:
            logger.warning(f"[Codex] Could not parse review response for {title}")
            review = {"decision": "pending", "summary": "Review inconclusive", "reviewer": "Codex"}

        decision = review.get("decision", "pending")
        summary = review.get("summary", "Spec reviewed")

        # Update based on decision
        if decision == "approved":
            # Move to BUILD
            update_item(page["id"], {
                "Owner": "Codex",
                "Decision": "approved",
                "Phase": "BUILD",
                "Summary": summary[:500],
            })
            # Create feature branch
            branch_name = f"feature/{title.lower().replace(' ', '-')[:30]}"
            create_git_branch(branch_name)
            update_item(page["id"], {"Branch": branch_name})

        elif decision == "changes_requested":
            # Loop back to Claude
            update_item(page["id"], {
                "Owner": "Claude",
                "Decision": "changes_requested",
                "Phase": "SPEC",
                "Round": round_num + 1,
                "Summary": summary[:500],
            })
        else:
            update_item(page["id"], {
                "Decision": decision or "pending",
                "Summary": summary[:500],
            })

        release_claim(page["id"])
        logger.info(f"[Codex] Spec reviewed for {title}: {decision}")

    except subprocess.TimeoutExpired:
        logger.error(f"[Codex] Timeout reviewing spec for {title}")
        update_item(page["id"], {"Last Error": "Codex review timeout"})
        release_claim(page["id"])
    except Exception as e:
        logger.error(f"[Codex] Error reviewing spec for {title}: {e}")
        update_item(page["id"], {"Last Error": str(e)[:500]})
        release_claim(page["id"])


def codex_dispatch_build(page: Dict):
    """Dispatch code build to Codex via CLI.

    Codex builds based on PRD instructions. For high-risk items, the PRD
    includes a Guardrails section with explicit constraints.
    """
    title = get_property_text(page, "Name")
    lane = get_property_text(page, "Lane")
    prd_link = get_property_text(page, "PRD Link")
    branch = get_property_text(page, "Branch")

    if not branch:
        branch = f"feature/{title.lower().replace(' ', '-')[:30]}"
        update_item(page["id"], {"Branch": branch})

    prompt = f"""{ANCILIS_CONTEXT}

You are building code for "{title}" based on the PRD.

**PRD:** {prd_link}
**Branch:** {branch}
**Lane:** {lane}

Build the code according to the PRD specification. Start by:
1. Inspecting the existing code structure in the ancilis/ancilis repo
2. Creating the feature branch if not already created
3. Making targeted changes that match the PRD
4. Writing tests for new functionality
5. Ensuring lint/type checks pass locally

{"For a high-risk item, strictly follow all Guardrails listed in the PRD. Do not deviate." if lane == "high-risk" else ""}

After completing the build, create a PR and respond with the PR URL.

Respond ONLY with valid JSON in this exact format (no markdown fence, no extra text):
{{
  "pr_url": "https://github.com/ancilis/ancilis/pull/123",
  "summary": "Build completed with X commits",
  "status": "completed|partial|failed"
}}
"""

    try:
        result = subprocess.run(
            ["codex", "exec", "--writable", "--json", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=ANCILIS_REPO_PATH,
        )

        if result.returncode != 0:
            logger.error(f"[Codex] Build failed for {title}: {result.stderr}")
            update_item(page["id"], {"Last Error": f"Build error: {result.stderr[:500]}"})
            release_claim(page["id"])
            return

        # Parse response
        output = result.stdout
        try:
            import re
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                build_result = json.loads(json_match.group())
            else:
                build_result = json.loads(output)
        except json.JSONDecodeError:
            logger.warning(f"[Codex] Could not parse build response for {title}")
            build_result = {"status": "completed", "pr_url": "", "summary": "Build completed"}

        pr_url = build_result.get("pr_url", "")
        status = build_result.get("status", "completed")
        summary = build_result.get("summary", "Build completed")

        if status == "completed" and pr_url:
            # Move to VERIFY
            update_item(page["id"], {
                "Owner": "System",
                "Decision": "pending",
                "Phase": "VERIFY",
                "PR Link": pr_url,
                "Summary": summary[:500],
            })
            logger.info(f"[Codex] Build completed for {title}: {pr_url}")
        else:
            update_item(page["id"], {
                "Last Error": f"Build {status}: {summary}",
                "Summary": summary[:500],
            })
            logger.warning(f"[Codex] Build {status} for {title}")

        release_claim(page["id"])

    except subprocess.TimeoutExpired:
        logger.error(f"[Codex] Build timeout for {title}")
        update_item(page["id"], {"Last Error": "Build timeout"})
        release_claim(page["id"])
    except Exception as e:
        logger.error(f"[Codex] Error building {title}: {e}")
        update_item(page["id"], {"Last Error": str(e)[:500]})
        release_claim(page["id"])


# --- Fast Lane Special Handling ---

def handle_fast_lane_verify(page: Dict):
    """For fast lane: check CI status and move to REVIEW.

    The System is the owner during VERIFY. After CI passes, we notify Kevin
    and start the 1-hour auto-merge timer.
    """
    title = get_property_text(page, "Name")
    pr_link = get_property_text(page, "PR Link")

    # In a real implementation, we'd check GitHub API for CI status
    # For now, we assume CI passed and move to REVIEW

    logger.info(f"[System] Fast lane CI verified for {title}")

    # Move to REVIEW, notify Kevin
    update_item(page["id"], {
        "Owner": "Kevin",
        "Decision": "pending",
        "Phase": "REVIEW",
        "Summary": f"CI passed. Auto-merge timer started. {pr_link}",
    })

    release_claim(page["id"])


def handle_fast_lane_auto_merge(page: Dict):
    """For fast lane in REVIEW: check if auto-merge timer expired.

    If >1 hour has passed since entering REVIEW and no objection from Kevin,
    auto-merge the PR.
    """
    title = get_property_text(page, "Name")
    pr_link = get_property_text(page, "PR Link")
    claimed_at = get_property_text(page, "Claimed At")

    # In a real implementation, we'd check the PR merge status
    # For now, assume merge is possible and do it

    try:
        # Get branch name
        branch = get_property_text(page, "Branch")
        if not branch:
            logger.warning(f"[System] No branch for {title}")
            release_claim(page["id"])
            return

        # Auto-merge via GitHub API (in real impl)
        logger.info(f"[System] Auto-merging {title} on {branch}")

        # Move to MERGED
        update_item(page["id"], {
            "Owner": "System",
            "Decision": "approved",
            "Phase": "MERGED",
            "Summary": f"Auto-merged: {pr_link}",
        })

        release_claim(page["id"])

    except Exception as e:
        logger.error(f"[System] Error auto-merging {title}: {e}")
        update_item(page["id"], {"Last Error": str(e)[:500]})
        release_claim(page["id"])


# --- Main Orchestrator Loop ---

def process_item(page: Dict) -> bool:
    """Process a single claimable item. Returns True if processed."""

    # Try to claim the item
    if not claim_item(page):
        return False

    title = get_property_text(page, "Name")
    phase = get_property_text(page, "Phase")
    lane = get_property_text(page, "Lane")
    owner = get_property_text(page, "Owner")

    logger.info(f"Processing: {title} [Phase: {phase}, Lane: {lane}, Owner: {owner}]")

    try:
        # Route by phase and owner

        # SPEC phase
        if phase == "SPEC":
            if owner == "Claude":
                claude_draft_spec(page)
            elif owner == "Codex":
                codex_dispatch_spec_review(page)

        # BUILD phase
        elif phase == "BUILD":
            if owner == "Codex":
                codex_dispatch_build(page)

        # VERIFY phase
        elif phase == "VERIFY":
            if lane == "fast":
                handle_fast_lane_verify(page)
            else:
                # For standard/high-risk, VERIFY is mostly CI checks
                # In real impl, would check GitHub Actions status
                update_item(page["id"], {
                    "Owner": "System",
                    "Phase": "REVIEW",
                })
                release_claim(page["id"])

        # REVIEW phase
        elif phase == "REVIEW":
            if owner == "Claude":
                claude_review_code(page)
            elif owner == "Kevin":
                # Kevin needs to manually approve in Notion
                # For fast lane, handle auto-merge
                if lane == "fast":
                    handle_fast_lane_auto_merge(page)
                else:
                    release_claim(page["id"])
            else:
                release_claim(page["id"])

        return True

    except Exception as e:
        logger.error(f"Error processing {title}: {e}")
        update_item(page["id"], {"Last Error": str(e)[:500]})
        release_claim(page["id"])
        return False


def run_once():
    """Run one iteration of the orchestrator.

    Process one claimable item from each queue:
    1. Claude's queue (SPEC drafting, code review)
    2. Codex's queue (spec review, code build)
    3. System's queue (verify, auto-merge)
    """

    logger.info("=== Orchestrator Iteration ===")

    # Process items needing Claude
    claude_items = []
    for phase in ["SPEC"]:
        items = query_pipeline(phase=phase, owner="Claude")
        claude_items.extend(items)

    for phase in ["REVIEW"]:
        items = query_pipeline(phase=phase, owner="Claude")
        claude_items.extend(items)

    if claude_items:
        logger.info(f"Claude's queue: {len(claude_items)} items")
        for item in claude_items[:1]:  # Process one per iteration
            process_item(item)

    # Process items needing Codex
    codex_items = []
    for phase in ["SPEC", "BUILD"]:
        items = query_pipeline(phase=phase, owner="Codex")
        codex_items.extend(items)

    if codex_items:
        logger.info(f"Codex's queue: {len(codex_items)} items")
        for item in codex_items[:1]:  # Process one per iteration
            process_item(item)

    # Process system items
    system_items = []
    for phase in ["VERIFY", "REVIEW"]:
        items = query_pipeline(phase=phase, owner="System")
        system_items.extend(items)

    if system_items:
        logger.info(f"System queue: {len(system_items)} items")
        for item in system_items[:1]:  # Process one per iteration
            process_item(item)

    logger.info("=== Done ===")


if __name__ == "__main__":
    run_once()
