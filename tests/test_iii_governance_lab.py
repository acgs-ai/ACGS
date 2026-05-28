"""iii governance lab experiment contract."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "experiments" / "iii-governance-lab"
STATIC_WORKFLOW = ROOT / ".github" / "workflows" / "iii-governance-lab-static.yml"


def _read(rel: str) -> str:
    return (LAB / rel).read_text()


def test_iii_governance_lab_is_isolated_from_production_surfaces():
    expected_files = [
        "AGENTS.md",
        "README.md",
        "config.yaml",
        "scripts/smoke.sh",
        "workers/governance-worker/governance_worker.py",
        "workers/governance-worker/requirements.txt",
        "workers/caller-worker/package-lock.json",
        "workers/caller-worker/package.json",
        "workers/caller-worker/tsconfig.json",
        "workers/caller-worker/src/worker.ts",
    ]

    missing = [rel for rel in expected_files if not (LAB / rel).is_file()]
    assert not missing, f"iii governance lab missing files: {missing}"

    readme = _read("README.md")
    assert "Experimental only" in readme
    assert "not production deployment proof" in readme
    assert "ws://localhost:49134" in readme
    assert "http://localhost:3111" in readme

    boundary = _read("AGENTS.md")
    assert "Do not edit acgi-ai/" in boundary
    assert "Do not edit .github/workflows/" in boundary
    assert "Do not store secrets" in boundary


def test_iii_governance_lab_declares_stable_worker_contracts():
    config = yaml.safe_load((LAB / "config.yaml").read_text())
    worker_names = {worker["name"] for worker in config["workers"]}
    assert worker_names == {"iii-worker-manager", "iii-http"}
    assert config["workers"][0]["config"]["port"] == 49134
    assert config["workers"][1]["config"] == {"host": "127.0.0.1", "port": 3111}
    assert "engine" not in config
    assert "adapters" not in config
    assert "http" not in config
    for worker in config["workers"]:
        assert "path" not in worker
        assert "language" not in worker

    python_worker = _read("workers/governance-worker/governance_worker.py")
    assert "governance::evaluate_policy" in python_worker
    assert "request_schema" in python_worker
    assert "response_schema" in python_worker
    assert "default_deny" in python_worker
    assert "request_format=request_schema" in python_worker
    assert "response_format=response_schema" in python_worker
    assert "request_schema=request_schema" not in python_worker
    assert "response_schema=response_schema" not in python_worker

    ts_worker = _read("workers/caller-worker/src/worker.ts")
    assert "governance::evaluate_request" in ts_worker
    assert "governance::evaluate_policy" in ts_worker
    assert "http::evaluate_request" in ts_worker
    assert "/governance/evaluate" in ts_worker
    assert "new InitOptions" not in ts_worker
    assert 'registerWorker(process.env.III_URL ?? "ws://localhost:49134", {' in ts_worker


def test_iii_governance_lab_does_not_modify_deploy_workflows():
    console = (ROOT / ".github/workflows/console.yml").read_text()
    assert "iii-governance-lab" not in console
    assert "experiments/" not in console

    marketing = yaml.safe_load((ROOT / ".github/workflows/marketing.yml").read_text())
    marketing_triggers = marketing[True]
    marketing_paths = ["acgi-ai/**", "!acgi-ai/infra/**", "!acgi-ai/DEPLOY.md"]
    for event in ("pull_request", "push"):
        assert marketing_triggers[event]["paths"] == marketing_paths

    marketing_text = (ROOT / ".github/workflows/marketing.yml").read_text()
    assert "iii-governance-lab" not in marketing_text
    assert "experiments/" not in marketing_text
    assert "iii_lab_static" not in marketing_text


def test_iii_governance_lab_static_workflow_is_path_filtered():
    workflow = yaml.safe_load(STATIC_WORKFLOW.read_text())
    triggers = workflow[True]  # YAML 1.1 parses bare "on:" as True.

    expected_paths = {
        "experiments/iii-governance-lab/**",
        "tests/test_iii_governance_lab.py",
        "tests/conftest.py",
        "pyproject.toml",
        ".github/workflows/iii-governance-lab-static.yml",
    }
    assert set(triggers) == {"pull_request", "push"}
    for event in ("pull_request", "push"):
        assert set(triggers[event]["paths"]) == expected_paths


def test_iii_governance_lab_static_workflow_does_not_run_live_iii_engine():
    workflow = yaml.safe_load(STATIC_WORKFLOW.read_text())
    text = STATIC_WORKFLOW.read_text()
    assert "secrets." not in text
    assert "deploy" not in text.lower()
    assert "service.yaml" not in text
    assert "gcloud" not in text
    assert "vercel" not in text.lower()

    assert workflow["permissions"] == {"contents": "read"}
    assert "env" not in workflow
    assert workflow["jobs"]["static-contract"]["runs-on"] == "ubuntu-latest"

    job = workflow["jobs"]["static-contract"]
    assert "env" not in job
    assert "services" not in job

    steps = job["steps"]
    assert all("env" not in step for step in steps)

    uses_steps = [step["uses"] for step in steps if "uses" in step]
    assert uses_steps == ["actions/checkout@v4", "astral-sh/setup-uv@v3"]

    run_commands = [step["run"].strip() for step in steps if "run" in step]
    assert run_commands == [
        "\n".join(
            [
                "uv python install 3.11",
                "uv venv --python 3.11 .venv",
                "uv pip install --python .venv/bin/python pytest pyyaml",
            ]
        ),
        "\n".join(
            [
                ".venv/bin/python -m py_compile experiments/iii-governance-lab/workers/governance-worker/governance_worker.py",
                "bash -n experiments/iii-governance-lab/scripts/smoke.sh",
                "npm ci --prefix experiments/iii-governance-lab/workers/caller-worker --ignore-scripts",
                "npm run --prefix experiments/iii-governance-lab/workers/caller-worker typecheck",
            ]
        ),
        ".venv/bin/python -m pytest tests/test_iii_governance_lab.py -q",
    ]

    forbidden_commands = [
        "iii --config",
        "docker run",
        "docker compose",
    ]
    assert not any(
        command in run_command
        for run_command in run_commands
        for command in forbidden_commands
    )
