"""Fail-closed contract for the canonical SaaS-beta CI and deploy boundary.

This module intentionally uses only the Python standard library.  The final
aggregate selector runs it from the control-plane hash lock, which must not gain
an undeclared YAML parser merely to validate CI text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PNPM_SELECTOR = (
    "pnpm@9.15.4+sha512."
    "b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb"
    "40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0"
)

ACTION_PINS = {
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "astral-sh/setup-uv": "d0cc045d04ccac9d8b7881df0226f9e82c39688e",
    "pnpm/action-setup": "b906affcce14559ad1aafd4ab0e942779e9f58b1",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "google-github-actions/auth": "c200f3691d83b41bf9bbd8638997a462592937ed",
    "google-github-actions/setup-gcloud": "e427ad8a34f8676edf47cf7d7925499adf3eb74f",
    "docker/setup-buildx-action": "8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "docker/build-push-action": "10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
    "cloudflare/wrangler-action": "9acf94ace14e7dc412b076f2c5c20b8ce93c79cd",
    "actions/configure-pages": "983d7736d9b0ae728b81ab479565c72886d7745b",
    "actions/upload-pages-artifact": "56afc609e74202658d3ffba0e8f6dda462b719fa",
    "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
}

AGGREGATE = ROOT / ".github/workflows/saas-beta-required.yml"
VERIFY_WORKFLOWS = (
    ROOT / ".github/workflows/console.yml",
    ROOT / ".github/workflows/marketing.yml",
    ROOT / ".github/workflows/storybook.yml",
)
DEPLOY_WORKFLOWS = (
    ROOT / ".github/workflows/console-deploy.yml",
    ROOT / ".github/workflows/marketing-cloudflare.yml",
    ROOT / ".github/workflows/storybook-deploy.yml",
)
OWNED_WORKFLOWS = (
    AGGREGATE,
    ROOT / ".github/workflows/python-acgs-control-plane.yml",
    ROOT / ".github/workflows/python-gove-zone.yml",
    ROOT / ".github/workflows/tthw.yml",
    *VERIFY_WORKFLOWS,
    *DEPLOY_WORKFLOWS,
)

GATE_COMMANDS = (
    ".venv-evidence/bin/python -m pytest -q "
    "tests/saas_beta/test_evidence_bootstrap.py::test_universal_evidence_interpreter_offline",
    ".venv/bin/ruff check .",
    ".venv/bin/ruff format --check .",
    ".venv/bin/mypy src/",
    ".venv/bin/pytest -q",
    ".venv/bin/pytest -q "
    "tests/integration/test_production_posture.py::test_production_rejects_legacy_unsigned_routes "
    "tests/integration/test_production_posture.py::"
    "test_tenant_bootstrap_and_register_contract_stub_no_mutation",
    "uv run --active --no-sync --python 3.11 --package gove-zone ruff check "
    "packages/gove-zone/src packages/gove-zone/tests packages/gove-zone/examples",
    "uv run --active --no-sync --python 3.11 --package gove-zone ruff format --check "
    "packages/gove-zone/src packages/gove-zone/tests packages/gove-zone/examples",
    "uv run --active --no-sync --python 3.11 --package gove-zone mypy "
    "packages/gove-zone/src/gove_zone",
    "uv run --active --no-sync --python 3.11 --package gove-zone python -m pytest "
    "packages/gove-zone/tests --import-mode=importlib -q --cov=gove_zone --cov-fail-under=90",
    "fnm exec --using 24.18.0 -- pnpm lint",
    "fnm exec --using 24.18.0 -- pnpm build",
    "fnm exec --using 24.18.0 -- pnpm test:all",
    "fnm exec --using 24.18.0 -- pnpm test:unit",
    "fnm exec --using 24.18.0 -- pnpm test:playwright",
    "packages/acgs-control-plane/.venv/bin/python -m pytest -q "
    "tests/saas_beta/test_ci_gate_contract.py::test_all_owned_scope_gates_are_required",
)

GATE_WORKING_DIRECTORIES = (
    None,
    "packages/acgs-control-plane",
    "packages/acgs-control-plane",
    "packages/acgs-control-plane",
    "packages/acgs-control-plane",
    "packages/acgs-control-plane",
    None,
    None,
    None,
    None,
    "acgi-ai",
    "acgi-ai",
    "acgi-ai",
    "acgi-ai",
    "acgi-ai",
    None,
)


def _read(path: Path) -> str:
    assert path.is_file(), f"missing required workflow: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def _trigger_block(source: str) -> str:
    match = re.search(r"^on:\n(?P<body>.*?)(?=^[a-z][a-z_-]*:|^jobs:)", source, re.M | re.S)
    assert match, "workflow must contain a top-level on block"
    return match.group("body")


def _assert_pinned_actions(path: Path) -> None:
    source = _read(path)
    uses = re.findall(r"^\s*-?\s*uses:\s*([^\s@]+)@([^\s#]+)", source, re.M)
    assert uses, f"{path.name} must pin at least one action"
    for action, revision in uses:
        assert re.fullmatch(r"[0-9a-f]{40}", revision), (
            f"{path.name}: {action}@{revision} is not an immutable 40-hex revision"
        )
        assert action in ACTION_PINS, f"{path.name}: unreviewed action {action}"
        assert revision == ACTION_PINS[action], (
            f"{path.name}: {action} must use reviewed revision {ACTION_PINS[action]}"
        )


def _extract_gate_contract(source: str) -> tuple[tuple[str, str | None], ...]:
    blocks = list(
        re.finditer(
            r"^      - name: Gate (?P<number>\d{2}) - [^\n]+\n"
            r"(?P<body>.*?)(?=^      - name: Gate |\Z)",
            source,
            re.M | re.S,
        )
    )
    assert [int(block.group("number")) for block in blocks] == list(range(1, 17))
    extracted: list[tuple[str, str | None]] = []
    for block in blocks:
        body = block.group("body")
        command = re.search(r"^        run: ([^\n]+)$", body, re.M)
        assert command, (
            f"Gate {block.group('number')} must have one literal single-line run command"
        )
        working_directory = re.search(r"^        working-directory: ([^\n]+)$", body, re.M)
        extracted.append(
            (
                command.group(1),
                working_directory.group(1) if working_directory else None,
            )
        )
    return tuple(extracted)


def _assert_read_only_pr_workflow(path: Path) -> None:
    source = _read(path)
    trigger = _trigger_block(source)
    assert "pull_request:" in trigger
    assert "push:" not in trigger, f"{path.name} must be PR-only after privilege separation"
    assert re.search(r"^permissions:\n  contents: read\s*$", source, re.M)
    assert "runs-on: ubuntu-24.04" in source
    assert "self-hosted" not in source
    assert "github.event.pull_request.head.repo.full_name" not in source
    assert "${{ secrets." not in source
    assert "id-token: write" not in source
    assert "continue-on-error:" not in source
    for privileged in (
        "google-github-actions/auth@",
        "google-github-actions/setup-gcloud@",
        "docker/build-push-action@",
        "cloudflare/wrangler-action@",
        "actions/deploy-pages@",
        "gcloud run services replace",
    ):
        assert privileged not in source, f"{path.name} PR workflow contains {privileged}"
    assert "node-version: '24.18.0'" in source
    assert "pnpm/action-setup@" in source
    assert "version: '9.15.4'" not in source, (
        "pnpm/action-setup must consume the integrity-qualified packageManager selector; "
        "the pinned action rejects a duplicate plain version"
    )
    _assert_pinned_actions(path)


def _assert_push_only_deploy_workflow(path: Path) -> None:
    source = _read(path)
    trigger = _trigger_block(source)
    assert "push:" in trigger
    assert "pull_request:" not in trigger, f"{path.name} must never receive PR code"
    assert not re.search(r"^permissions:\n(?:  .+\n)+", source, re.M), (
        f"{path.name} must grant privileges per job, not at workflow scope"
    )
    assert "environment:" in source
    assert "version: '9.15.4'" not in source
    _assert_pinned_actions(path)


def test_all_owned_scope_gates_are_required() -> None:
    aggregate = _read(AGGREGATE)
    trigger = _trigger_block(aggregate)

    assert "pull_request:" in trigger and "branches: [master]" in trigger
    assert "push:" not in trigger
    required_paths = (
        "requirements/saas-beta/**",
        "schemas/evidence/**",
        "scripts/evidence/**",
        "packages/acgs-control-plane/**",
        "packages/gove-zone/**",
        "acgi-ai/**",
        "tests/saas_beta/**",
        "scripts/run_acgi_node24_gate.sh",
        "scripts/platform_readiness_report.py",
        "package.json",
        "pyproject.toml",
        "uv.lock",
    )
    for required_path in required_paths:
        assert f"'{required_path}'" in trigger

    jobs = aggregate.split("\njobs:\n", 1)[1]
    assert re.findall(r"^  ([a-zA-Z0-9_-]+):\s*$", jobs, re.M) == ["gates"]
    assert "runs-on: ubuntu-24.04" in jobs
    assert re.search(r"^permissions:\n  contents: read\s*$", aggregate, re.M)
    for forbidden in (
        "self-hosted",
        "continue-on-error:",
        "${{ secrets.",
        "id-token: write",
        "github.event.pull_request.head.repo.full_name",
    ):
        assert forbidden not in aggregate

    assert "persist-credentials: false" in aggregate
    assert "submodules: false" in aggregate
    assert "python-version: '3.11'" in aggregate
    assert "version: '0.11.19'" in aggregate
    assert "node-version: '24.18.0'" in aggregate
    assert "version: '9.15.4'" not in aggregate
    assert 'test "$(pnpm --version)" = 9.15.4' in aggregate
    assert "uv pip sync --python .venv-evidence/bin/python --require-hashes" in aggregate
    assert (
        "uv pip sync --python packages/acgs-control-plane/.venv/bin/python --require-hashes"
        in aggregate
    )
    assert (
        "uv pip sync --python packages/gove-zone/.venv-beta/bin/python --require-hashes"
        in aggregate
    )
    assert aggregate.count("UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1 uv pip install") == 3
    assert aggregate.count("--no-build-isolation --no-deps --editable") == 3
    assert "VIRTUAL_ENV: ${{ github.workspace }}/packages/gove-zone/.venv-beta" in aggregate
    assert PNPM_SELECTOR in aggregate

    gates = _extract_gate_contract(aggregate)
    assert tuple(command for command, _ in gates) == GATE_COMMANDS
    assert tuple(cwd for _, cwd in gates) == GATE_WORKING_DIRECTORIES
    assert aggregate.rstrip().endswith(f"run: {GATE_COMMANDS[-1]}")
    _assert_pinned_actions(AGGREGATE)

    for package_workflow in (
        ROOT / ".github/workflows/python-acgs-control-plane.yml",
        ROOT / ".github/workflows/python-gove-zone.yml",
    ):
        source = _read(package_workflow)
        assert "runs-on: ubuntu-24.04" in source
        assert "python-version: '3.11'" in source
        assert "--require-hashes" in source
        assert "UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1" in source
        assert "self-hosted" not in source
        assert "github.event.pull_request.head.repo.full_name" not in source
        assert "${{ secrets." not in source
        _assert_pinned_actions(package_workflow)

    for verification in VERIFY_WORKFLOWS:
        _assert_read_only_pr_workflow(verification)
    for deployment in DEPLOY_WORKFLOWS:
        _assert_push_only_deploy_workflow(deployment)

    console_deploy = _read(ROOT / ".github/workflows/console-deploy.yml")
    assert "id-token: write" in console_deploy
    assert "google-github-actions/auth@" in console_deploy
    assert "credentials_json" not in console_deploy
    assert "environment: production" in console_deploy

    marketing_deploy = _read(ROOT / ".github/workflows/marketing-cloudflare.yml")
    for marker in (
        "Cloudflare Workers deploy blocked",
        "infra/cloudflare/workers/_redirects",
        "deploy --config infra/cloudflare/workers/wrangler.toml",
        "environment: production",
    ):
        assert marker in marketing_deploy

    storybook_deploy = _read(ROOT / ".github/workflows/storybook-deploy.yml")
    assert "pages: write" in storybook_deploy
    assert "id-token: write" in storybook_deploy
    assert "environment:" in storybook_deploy
    assert "github-pages" in storybook_deploy

    tthw = _read(ROOT / ".github/workflows/tthw.yml")
    assert "runs-on: ubuntu-24.04" in tthw
    assert "node-version: '24.18.0'" in tthw
    assert 'test "$(pnpm --version)" = 9.15.4' in tthw
    _assert_pinned_actions(ROOT / ".github/workflows/tthw.yml")

    root_package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    app_package = json.loads((ROOT / "acgi-ai/package.json").read_text(encoding="utf-8"))
    assert root_package["packageManager"] == PNPM_SELECTOR
    assert app_package["packageManager"] == PNPM_SELECTOR
    assert (ROOT / "acgi-ai/.node-version").read_text(encoding="utf-8").strip() == "24.18.0"
