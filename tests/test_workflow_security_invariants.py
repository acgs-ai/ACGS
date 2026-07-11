import json
import pathlib
import re

import pytest


REPO_ROOT = pathlib.Path(__file__).parent.parent


@pytest.fixture
def ai_review_workflows() -> list[pathlib.Path]:
    return sorted((REPO_ROOT / ".github" / "workflows").glob("*code-review.yml"))


def test_ai_review_workflows_gate_trusted_author_associations(
    ai_review_workflows: list[pathlib.Path],
) -> None:
    trusted_associations = ("OWNER", "MEMBER", "COLLABORATOR")

    for workflow in ai_review_workflows:
        text = workflow.read_text()
        assert "author_association" in text, workflow
        assert any(association in text for association in trusted_associations), workflow


def test_ai_review_workflows_do_not_request_id_token_write(
    ai_review_workflows: list[pathlib.Path],
) -> None:
    for workflow in ai_review_workflows:
        assert "id-token: write" not in workflow.read_text(), workflow


# Fork PRs on a public repo must never execute on the self-hosted runner: a
# pull_request-triggered job checks out and runs untrusted fork code, which on
# self-hosted means arbitrary code execution on the maintainer's machine.
FORK_PR_GUARD = (
    "github.event_name != 'pull_request' "
    "|| github.event.pull_request.head.repo.full_name == github.repository"
)


def _has_pull_request_trigger(text: str) -> bool:
    if re.search(r"^  pull_request:", text, re.MULTILINE):
        return True
    inline = re.search(r"^on:\s*\[([^\]]*)\]", text, re.MULTILINE)
    return bool(inline and re.search(r"\bpull_request\b", inline.group(1)))


def _jobs(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if "jobs:" not in lines:
        return {}
    jobs: dict[str, str] = {}
    current: str | None = None
    block: list[str] = []
    for line in lines[lines.index("jobs:") + 1 :]:
        if line and not line.startswith((" ", "#")):
            break  # another top-level key ends the jobs section
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            if current is not None:
                jobs[current] = "\n".join(block)
            current = match.group(1)
            block = []
        elif current is not None:
            block.append(line)
    if current is not None:
        jobs[current] = "\n".join(block)
    return jobs


def _runs_on_self_hosted(job_block: str) -> bool:
    lines = job_block.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("runs-on:"):
            continue
        if "self-hosted" in stripped:
            return True
        # multi-line list form: runs-on:\n  - self-hosted\n  - ...
        for follower in lines[i + 1 :]:
            if not follower.strip().startswith("-"):
                break
            if "self-hosted" in follower:
                return True
    return False


def _guard_is_top_level_conjunct(if_line: str) -> bool:
    # The guard must be the whole expression or AND-composed at top level.
    # `true || (<guard>)` would render it vacuous, so after stripping the
    # guard itself, no `||` may remain anywhere in the expression.
    expression = if_line.split("if:", 1)[1].strip()
    if FORK_PR_GUARD not in expression:
        return False
    remainder = expression.replace(f"({FORK_PR_GUARD})", "").replace(FORK_PR_GUARD, "")
    return "||" not in remainder


def test_pull_request_workflows_guard_self_hosted_jobs_against_forks() -> None:
    workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows

    checked: set[tuple[str, str]] = set()
    for workflow in workflows:
        text = workflow.read_text()
        if not _has_pull_request_trigger(text):
            continue
        for job_name, block in _jobs(text).items():
            if not _runs_on_self_hosted(block):
                continue
            # The guard must sit on a single-line job-level `if:` (step-level
            # ifs do not stop the job from starting on the runner), and it
            # must not be defeated by OR-composition with another condition.
            guarded = any(
                line.startswith("    if:") and _guard_is_top_level_conjunct(line)
                for line in block.splitlines()
            )
            assert guarded, (
                f"{workflow.name} job '{job_name}' runs on self-hosted with a "
                f"pull_request trigger but lacks the same-repo fork guard: "
                f"if: {FORK_PR_GUARD}"
            )
            checked.add((workflow.name, job_name))

    # Canary: prove the parser actually saw a known guarded job, so a parsing
    # regression cannot silently turn this test into a no-op.
    assert ("tests-root.yml", "test") in checked


def test_claude_settings_do_not_allow_broad_git_wildcards() -> None:
    settings = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text())
    allow_list = settings["permissions"]["allow"]
    broad_git_pattern = re.compile(r"^Bash\(git -C [^ )]+:\*\)$")

    assert not any(broad_git_pattern.match(entry) for entry in allow_list)
