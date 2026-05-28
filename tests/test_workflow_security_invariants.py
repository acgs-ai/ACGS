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


def test_claude_settings_do_not_allow_broad_git_wildcards() -> None:
    settings = json.loads((REPO_ROOT / ".claude" / "settings.json").read_text())
    allow_list = settings["permissions"]["allow"]
    broad_git_pattern = re.compile(r"^Bash\(git -C [^ )]+:\*\)$")

    assert not any(broad_git_pattern.match(entry) for entry in allow_list)
