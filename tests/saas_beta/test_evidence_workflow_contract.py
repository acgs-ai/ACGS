from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/saas-beta-p0-evidence.yml"
CONTROL_PLANE_WORKFLOW = ROOT / ".github/workflows/python-acgs-control-plane.yml"
TESTS_ROOT = ROOT / ".github/workflows/tests-root.yml"
TESTS_ROOT_HOSTED = ROOT / ".github/workflows/tests-root-hosted.yml"
RESERVED_HOSTED_WORKFLOW_TOKENS = ("prove_clean_", "self-hosted", "exact-proof")


def _text(path: Path = WORKFLOW) -> str:
    return path.read_text(encoding="utf-8")


def _index(text: str, needle: str) -> int:
    assert needle in text, f"missing required workflow text: {needle}"
    return text.index(needle)


def _job_block(text: str, job_name: str) -> str:
    start = _index(text, f"  {job_name}:\n")
    match = re.search(r"\n  [A-Za-z0-9_-]+:\n", text[start + 1 :])
    end = start + 1 + match.start() if match else len(text)
    return text[start:end]


def _jobs_block(text: str) -> str:
    start = _index(text, "jobs:\n")
    body_start = start + len("jobs:\n")
    next_top_level = re.search(r"^[A-Za-z0-9_-]+:\n", text[body_start:], re.MULTILINE)
    end = body_start + next_top_level.start() if next_top_level else len(text)
    return text[start:end]


def _job_names(text: str) -> set[str]:
    jobs = _jobs_block(text)
    block_names = set(
        re.findall(r"^  ['\"]?([A-Za-z0-9_-]+)['\"]?\s*:", jobs, re.MULTILINE)
    )
    flow_names = set(
        re.findall(r"\{\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*:\s*\{", jobs)
    )
    return block_names | flow_names


def _step_block(job_block: str, step_name: str) -> str:
    start = _index(job_block, f"      - name: {step_name}\n")
    next_step = job_block.find("\n      - ", start + 1)
    return job_block[start:] if next_step == -1 else job_block[start:next_step]


def _checkout_block(job_block: str) -> str:
    start = _index(job_block, "      - uses: actions/checkout@")
    next_step = job_block.find("\n      - ", start + 1)
    return job_block[start:] if next_step == -1 else job_block[start:next_step]


def _workflow_dispatch_block(text: str) -> str:
    start = _index(text, "  workflow_dispatch:\n")
    end = _index(text, "\nconcurrency:")
    return text[start:end]


def _pull_request_paths(text: str) -> list[str]:
    start = _index(text, "  pull_request:\n")
    next_event = re.search(r"^  [A-Za-z0-9_-]+:\n", text[start + 1 :], re.MULTILINE)
    end = start + 1 + next_event.start() if next_event else len(text)
    pull_request = text[start:end]
    paths_start = _index(pull_request, "    paths:\n")
    paths = []

    for line in pull_request[paths_start:].splitlines()[1:]:
        if line.strip() and not line.startswith("      "):
            break
        match = re.match(r"^\s{6}-\s+['\"]?(?P<path>[^'\"]+)['\"]?\s*$", line)
        if match:
            paths.append(match.group("path"))

    return paths


def _reserved_hosted_workflow_tokens(text: str) -> list[str]:
    folded = text.casefold()
    return [token for token in RESERVED_HOSTED_WORKFLOW_TOKENS if token in folded]


def test_public_workflow_has_no_exact_proof_job_or_runner_surface() -> None:
    text = _text()
    job_names = _job_names(text)

    assert job_names == {"hosted-contract"}
    assert "exact-proof" not in job_names

    for job_name in job_names:
        job = _job_block(text, job_name)
        runs_on_lines = [line.strip() for line in job.splitlines() if "runs-on:" in line]
        assert runs_on_lines == ["runs-on: ubuntu-latest"]

    assert _reserved_hosted_workflow_tokens(text) == []


def test_public_workflow_job_names_detect_flow_style_runner_injection() -> None:
    injected = _text().replace(
        "  hosted-contract:\n",
        "  injected: {runs-on: SELF-HOSTED, steps: [{run: echo bypass}]}\n"
        "  hosted-contract:\n",
    )

    assert _job_names(injected) == {"hosted-contract", "injected"}
    assert _reserved_hosted_workflow_tokens(injected) == ["self-hosted"]


def test_public_workflow_job_names_detect_quoted_and_custom_runner_jobs() -> None:
    injected = _text().replace(
        "  hosted-contract:\n",
        "  'custom-runner':\n"
        + "    runs-on: [linux, exact-proof-runner]\n"
        + "    steps:\n"
        + "      - run: echo bypass\n"
        + "  hosted-contract:\n",
    )

    assert _job_names(injected) == {"hosted-contract", "custom-runner"}
    assert _reserved_hosted_workflow_tokens(injected) == ["exact-proof"]


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        ("      - run: scripts/evidence/prove_clean_sibling 0\n", ["prove_clean_"]),
        ("      - run: |\n          scripts/evidence/prove_clean_sibling 0\n", ["prove_clean_"]),
        (
            "jobs: { injected: { steps: [ { run: scripts/evidence/prove_clean_sibling } ] } }\n",
            ["prove_clean_"],
        ),
        (
            "x-command: &p scripts/evidence/prove_clean_sibling 0\n"
            "      - run: *p\n",
            ["prove_clean_"],
        ),
        ("      - run: scripts/evidence/prove_clean_\n          sibling 0\n", ["prove_clean_"]),
        ("      - run: scripts/evidence/prove_clean_\\\n          sibling 0\n", ["prove_clean_"]),
        ("    runs-on: self-hosted\n", ["self-hosted"]),
        ("    if: inputs.lane == 'exact-proof'\n", ["exact-proof"]),
        ("      - run: scripts/evidence/PrOvE_CLeAn_sibling 0\n", ["prove_clean_"]),
        ("    runs-on: SELF-HOSTED\n", ["self-hosted"]),
        ("    if: inputs.lane == 'EXACT-PROOF'\n", ["exact-proof"]),
    ],
)
def test_public_workflow_reserved_tokens_reject_bypass_variants(
    variant: str, expected: list[str]
) -> None:
    assert _reserved_hosted_workflow_tokens(variant) == expected


def test_public_workflow_reserved_tokens_allow_unrelated_prose() -> None:
    benign = (
        "# exact local trusted-broker work remains outside this hosted lane.\n"
        "notes: |\n"
        "  Proof commands stay local and manually reviewed.\n"
        "jobs:\n"
        "  injected:\n"
        "    runs-on: ubuntu-latest\n"
    )

    assert _reserved_hosted_workflow_tokens(benign) == []


def test_manual_dispatch_reaches_hosted_contract_only_without_lane_input() -> None:
    text = _text()
    dispatch = _workflow_dispatch_block(text)
    hosted = _job_block(text, "hosted-contract")

    assert dispatch == "  workflow_dispatch:\n"
    assert "inputs:" not in dispatch
    assert "lane" not in dispatch
    assert "exact-proof" not in dispatch
    assert (
        "    if: github.event_name == 'pull_request' || "
        "github.event_name == 'workflow_dispatch'\n"
        in hosted
    )
    assert "    runs-on: ubuntu-latest\n" in hosted


def test_concurrency_group_is_safe_for_duplicate_hosted_runs_only() -> None:
    text = _text()

    assert re.search(
        r"^concurrency:\n"
        r"  group: saas-beta-p0-evidence-\$\{\{ github\.event_name \}\}-"
        r"\$\{\{ github\.sha \}\}\n"
        r"  cancel-in-progress: true$",
        text,
        re.MULTILINE,
    )
    assert "inputs.lane" not in text


def test_hosted_lane_asserts_checkout_head_matches_event_sha_before_running_code() -> None:
    hosted = _job_block(_text(), "hosted-contract")
    checkout = _checkout_block(hosted)
    assertion = _step_block(hosted, "Assert checked-out event SHA")

    assert hosted.index(checkout) < hosted.index(assertion)
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in assertion
    assert "          persist-credentials: false\n" in checkout
    assert "          submodules: false\n" in checkout
    assert "          ref: ${{ github.sha }}\n" not in checkout


def test_hosted_contract_installs_bubblewrap_before_evidence_contracts() -> None:
    text = _text()
    hosted = _job_block(text, "hosted-contract")
    prerequisite = _step_block(hosted, "Install bubblewrap prerequisite")
    contracts = _step_block(hosted, "Run environment-independent P0 evidence contracts")

    assert hosted.index(prerequisite) < hosted.index(contracts)
    assert "        shell: bash\n" in prerequisite
    assert "sudo apt-get install --yes bubblewrap" in prerequisite
    assert "command -v apparmor_parser" in prerequisite
    assert "sudo apt-get install --yes apparmor" in prerequisite
    assert 'test "$(command -v bwrap)" = /usr/bin/bwrap' in prerequisite
    assert "profile acgs-ci-bwrap /usr/bin/bwrap flags=(unconfined) {" in prerequisite
    assert "sudo apparmor_parser -r /etc/apparmor.d/acgs-ci-bwrap" in prerequisite
    assert "--unshare-all --unshare-user --die-with-parent --new-session --disable-userns" in (
        prerequisite
    )
    assert "/bin/sh -c 'test ! -e /run/docker.sock" in prerequisite


def test_hosted_contract_runs_workflow_contract_tests_with_bootstrap_suite() -> None:
    contracts = _step_block(
        _job_block(_text(), "hosted-contract"), "Run environment-independent P0 evidence contracts"
    )

    assert "tests/saas_beta/test_evidence_bootstrap.py \\\n" in contracts
    assert "tests/saas_beta/test_evidence_workflow_contract.py \\\n" in contracts
    assert "-k " in contracts


def test_control_plane_workflow_changes_trigger_hosted_contract_lane() -> None:
    paths = _pull_request_paths(_text())

    assert ".github/workflows/python-acgs-control-plane.yml" in paths


def test_control_plane_workflow_path_must_be_in_pull_request_paths() -> None:
    misplaced = _text().replace(
        "      - '.github/workflows/python-acgs-control-plane.yml'\n",
        "",
    )
    misplaced += "\nenv:\n  WATCHED: '.github/workflows/python-acgs-control-plane.yml'\n"

    assert ".github/workflows/python-acgs-control-plane.yml" not in _pull_request_paths(
        misplaced
    )


def test_bubblewrap_prerequisite_matches_existing_control_plane_gate() -> None:
    workflow = _text()
    control_plane = _text(CONTROL_PLANE_WORKFLOW)

    hosted_prerequisite = _step_block(
        _job_block(workflow, "hosted-contract"), "Install bubblewrap prerequisite"
    )
    control_plane_prerequisite = _step_block(
        _job_block(control_plane, "p2-idempotency-evidence-gate"),
        "Install bubblewrap prerequisite",
    )

    assert hosted_prerequisite == control_plane_prerequisite


def test_root_workflow_comments_keep_exact_proof_local_trusted_broker_only() -> None:
    for path in (TESTS_ROOT, TESTS_ROOT_HOSTED):
        text = _text(path)
        normalized = re.sub(r"\s+", " ", text.replace("#", " "))
        assert re.search(
            r"exact proof is (?:intentionally )?local trusted-broker (?:work|only)",
            normalized,
        )
        assert "never dispatched to the persistent runner" in normalized
        assert "exact proof authorized/manual" not in text
        assert "authenticated self-hosted environment" not in text
