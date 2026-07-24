from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/saas-beta-required.yml"
PNPM_SELECTOR = (
    "pnpm@9.15.4+sha512.b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0"
)


def _workflow_text() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _index(text: str, needle: str) -> int:
    assert needle in text, f"Missing required workflow text: {needle}"
    return text.index(needle)


def _step_block(text: str, step_start: str) -> str:
    start = _index(text, step_start)
    next_step = text.find("\n      - ", start + 1)
    if next_step == -1:
        return text[start:]
    return text[start:next_step]


def _job_block(text: str) -> str:
    return text[_index(text, "  required:\n") :]


JOB_LEVEL_KEY = re.compile(r"^    (name|runs-on|timeout-minutes|steps):(?:\s|$)")


def _job_level_key_violations(job: str) -> list[str]:
    violations: list[str] = []
    for line in job.splitlines():
        if not line.startswith("    ") or line.startswith("     "):
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" in line and JOB_LEVEL_KEY.match(line) is None:
            violations.append(line)
    return violations


def test_saas_beta_required_gate_covers_every_master_pr_without_path_filters() -> None:
    text = _workflow_text()

    assert "Branch protection/ruleset enforcement is external to this workflow" in text
    assert "currently absent until a repository administrator configures the check" in text
    assert re.search(r"^name: saas-beta-required$", text, re.MULTILINE)
    assert re.search(r"^on:\n  pull_request:\n    branches: \[master\]$", text, re.MULTILINE)
    assert not re.search(r"^\s+paths:", text, re.MULTILINE)
    assert "paths-ignore" not in text
    assert re.search(r"^permissions:\n  contents: read$", text, re.MULTILINE)

    job = _job_block(text)
    assert "    name: SaaS beta required gate" in job
    assert "    runs-on: ubuntu-24.04" in job
    assert "    timeout-minutes: 60" in job
    assert re.search(
        r"^concurrency:\n"
        r"  group: saas-beta-required-\$\{\{ github\.event\.pull_request\.number \|\| github\.sha \}\}\n"
        r"  cancel-in-progress: true$",
        text,
        re.MULTILINE,
    )
    assert "self-hosted" not in text


def test_saas_beta_required_gate_cannot_self_skip_or_widen_permissions() -> None:
    text = _workflow_text()
    job = _job_block(text)

    assert "write-all" not in text
    assert "read-all" not in text
    assert _job_level_key_violations(job) == []


def test_job_level_key_allowlist_rejects_plain_quoted_and_escaped_skip_or_permission_keys() -> None:
    invalid_jobs = (
        """
  required:
    permissions: {}
    steps:
      - run: echo ok
""",
        """
  required:
    "permissions" : {}
    steps:
      - run: echo ok
""",
        """
  required:
    "\\u0070ermissions": {}
    steps:
      - run: echo ok
""",
        """
  required:
    if: github.event_name == 'pull_request'
    steps:
      - run: echo ok
""",
        """
  required:
    'if' : github.event_name == 'pull_request'
    steps:
      - run: echo ok
""",
        """
  required:
    "\\u0069f": github.event_name == 'pull_request'
    steps:
      - run: echo ok
""",
    )
    nested_step_if = """
  required:
    name: fixture
    runs-on: ubuntu-24.04
    timeout-minutes: 1
    steps:
      - if: github.event_name == 'pull_request'
        run: echo ok
"""

    for job in invalid_jobs:
        assert _job_level_key_violations(job)
    assert _job_level_key_violations(nested_step_if) == []


def test_saas_beta_required_gate_uses_pinned_toolchain_and_locked_inputs() -> None:
    text = _workflow_text()

    action_refs = re.findall(r"^\s+- uses: ([^\s]+)$", text, re.MULTILINE)
    assert action_refs == [
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        "astral-sh/setup-uv@d0cc045d04ccac9d8b7881df0226f9e82c39688e",
        "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    ]
    assert all(re.search(r"@[0-9a-f]{40}$", ref) for ref in action_refs)

    checkout = _step_block(text, "- uses: actions/checkout@")
    assert "          persist-credentials: false" in checkout
    assert "          submodules: false" in checkout

    setup_uv = _step_block(text, "- uses: astral-sh/setup-uv@")
    assert "          version: 0.11.19" in setup_uv
    assert "          enable-cache: false" in setup_uv

    uv_auth = _step_block(text, "- name: Authenticate and pin uv")
    assert "expected=a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b" in uv_auth
    assert 'actual="$(sha256sum "$source_uv" | awk \'{print $1}\')"' in uv_auth
    assert '[[ "$actual" == "$expected" ]]' in uv_auth
    assert 'sudo install -D -m 0755 "$source_uv" /home/martin/.local/bin/uv' in uv_auth
    assert "[[ ! -L /home/martin/.local/bin/uv ]]" in uv_auth
    assert 'sha256sum /home/martin/.local/bin/uv' in uv_auth
    assert "printf 'UV_BIN=/home/martin/.local/bin/uv\\n' >>\"$GITHUB_ENV\"" in uv_auth
    assert "printf '%s\\n' /home/martin/.local/bin >>\"$GITHUB_PATH\"" in uv_auth
    assert "$RUNNER_TEMP/acgs-bin" not in text
    assert "UV_BIN=%s" not in text
    assert text.count("UV_BIN=/home/martin/.local/bin/uv") == 1

    setup_node = _step_block(text, "- uses: actions/setup-node@")
    assert "          node-version: 24.18.0" in setup_node
    assert "cache:" not in setup_node
    assert "cache-dependency-path:" not in setup_node

    assert f"corepack prepare {PNPM_SELECTOR} --activate" in text
    assert '[[ "$(pnpm --version)" == "9.15.4" ]]' in text
    for lock in (
        "requirements/saas-beta/evidence-test.lock",
        "requirements/saas-beta/cp-test.lock",
        "requirements/saas-beta/gz-test.lock",
    ):
        assert lock in text
    assert text.count("--require-hashes") == 3
    assert "--offline --no-index --no-cache --no-build-isolation --no-deps" in text


def test_saas_beta_required_gate_runs_ordered_local_contract_sequence() -> None:
    text = _workflow_text()
    ordered_needles = [
        "ACGS_EVIDENCE_ROOT: ${{ runner.temp }}/acgs-evidence",
        "node_evidence=\"$ACGS_EVIDENCE_ROOT/P0-EVIDENCE-000\"",
        'install -d -m 0700 "$ACGS_EVIDENCE_ROOT" "$node_evidence"',
        "scripts/evidence/verify_environment.py",
        "environment-EVID.json",
        "scripts/evidence/capture_environment.py",
        "environment-CP.json",
        "environment-GZ.json",
        "scripts/evidence/validate_environment_identities.py",
        "environment-identities.json",
        "- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
        "corepack prepare pnpm@9.15.4+sha512",
        "pnpm install --frozen-lockfile --ignore-workspace",
        "tests/saas_beta/test_ci_gate_contract.py",
        "tests/saas_beta/test_evidence_bootstrap.py",
        "packages/acgs-control-plane/.venv/bin/python -m pytest -q",
        "packages/acgs-control-plane/tests --import-mode=importlib",
        "packages/gove-zone/.venv-beta/bin/python -m pytest -q",
        "packages/gove-zone/tests --import-mode=importlib",
        "pnpm run lint",
        "pnpm run build",
        "pnpm run test:all",
        "pnpm test:unit",
        "git diff --exit-code -- .",
        "git diff --cached --exit-code -- .",
    ]

    positions = [_index(text, needle) for needle in ordered_needles]
    assert positions == sorted(positions)
    assert text.rstrip().endswith(
        "      - name: Assert tracked worktree clean\n"
        "        run: |\n"
        "          git diff --exit-code -- .\n"
        "          git diff --cached --exit-code -- ."
    )


def test_control_plane_test_step_uses_offline_indexless_cache_available_uv_env() -> None:
    text = _workflow_text()
    cp_step = _step_block(text, "- name: Run control-plane tests")

    assert "          UV_OFFLINE: '1'" in cp_step
    assert "          UV_NO_INDEX: '1'" in cp_step
    assert "          UV_NO_CACHE:" not in cp_step
    assert "packages/acgs-control-plane/.venv/bin/python -m pytest -q" in cp_step
    assert "packages/acgs-control-plane/tests --import-mode=importlib" in cp_step


def test_saas_beta_required_gate_has_no_privileged_or_external_side_effect_surface() -> None:
    text = _workflow_text()

    forbidden_tokens = (
        "pull_request_target",
        "workflow_dispatch",
        "paths-ignore",
        "id-token:",
        "secrets.",
        "${{ secrets",
        "continue-on-error",
        "environment:",
        "gcloud ",
        "curl ",
        "wget ",
        "ssh ",
        "scp ",
        "rsync ",
        "aws ",
        "az ",
        "helm ",
        "wrangler",
        "cloudflare",
        "docker ",
        "kubectl ",
        "terraform ",
        "npm publish",
        "twine ",
        "git clean",
        "git reset",
        "git push",
        "gh pr",
        "gh release",
        "actions/upload-artifact",
        "actions/deploy-pages",
        "cloudflare/wrangler-action",
        "google-github-actions/auth",
        "google-github-actions/setup-gcloud",
        "docker/build-push-action",
    )
    for token in forbidden_tokens:
        assert token not in text

    external_mutation_words = re.compile(
        r"\b(deploy|publish|upload-artifact|pages|cloud run|oidc|workload identity|release)\b",
        re.IGNORECASE,
    )
    assert not external_mutation_words.search(text)
