from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/saas-beta-p0-evidence.yml"
CONTROL_PLANE_WORKFLOW = ROOT / ".github/workflows/python-acgs-control-plane.yml"
TESTS_ROOT = ROOT / ".github/workflows/tests-root.yml"
TESTS_ROOT_HOSTED = ROOT / ".github/workflows/tests-root-hosted.yml"


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


def _job_names(text: str) -> set[str]:
    jobs_start = _index(text, "jobs:\n")
    return set(re.findall(r"^  ([A-Za-z0-9_-]+):\n", text[jobs_start:], re.MULTILINE))


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


def test_public_workflow_has_no_exact_proof_job_or_runner_surface() -> None:
    text = _text()
    job_names = _job_names(text)

    assert job_names == {"hosted-contract"}
    assert "exact-proof" not in job_names

    for job_name in job_names:
        job = _job_block(text, job_name)
        runs_on_lines = [line.strip() for line in job.splitlines() if "runs-on:" in line]
        assert runs_on_lines == ["runs-on: ubuntu-latest"]

    executable_surface = "\n".join(
        line for line in text.splitlines() if re.match(r"\s+(run|if|uses|runs-on):", line)
    )
    assert "self-hosted" not in executable_surface
    assert "prove_clean_sibling" not in executable_surface
    assert "Prove exact reviewed candidate" not in text


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
