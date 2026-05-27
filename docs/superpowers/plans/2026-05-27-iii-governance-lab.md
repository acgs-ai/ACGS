# iii Governance Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an isolated iii pilot that composes a Python governance worker and TypeScript caller worker without touching production deploy surfaces.

**Architecture:** The experiment lives under `experiments/iii-governance-lab/` and uses iii's local engine, worker, trigger, and HTTP concepts. A root test enforces isolation from `acgi-ai/` and `.github/workflows/` while checking stable function IDs.

**Tech Stack:** iii 0.11.0, Python worker, TypeScript worker, YAML config, root pytest-style contract test.

---

### Task 1: Contract Test

**Files:**
- Create: `tests/test_iii_governance_lab.py`

- [x] **Step 1: Write the failing test**

The test requires the lab files, stable function IDs, local-only documentation,
and no production workflow references.

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -c 'import importlib.util; spec=importlib.util.spec_from_file_location("test_iii_governance_lab", "tests/test_iii_governance_lab.py"); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); mod.test_iii_governance_lab_is_isolated_from_production_surfaces()'
```

Expected: fail with missing lab files.

### Task 2: Experiment Files

**Files:**
- Create: `experiments/iii-governance-lab/AGENTS.md`
- Create: `experiments/iii-governance-lab/README.md`
- Create: `experiments/iii-governance-lab/config.yaml`
- Create: `experiments/iii-governance-lab/scripts/smoke.sh`
- Create: `experiments/iii-governance-lab/workers/governance-worker/governance_worker.py`
- Create: `experiments/iii-governance-lab/workers/governance-worker/requirements.txt`
- Create: `experiments/iii-governance-lab/workers/caller-worker/package.json`
- Create: `experiments/iii-governance-lab/workers/caller-worker/src/worker.ts`

- [x] **Step 1: Add the local boundary contract**

`AGENTS.md` keeps future edits inside the experiment and bans secrets,
production workflow edits, and console changes.

- [x] **Step 2: Add operator docs**

`README.md` documents setup, local ports, trigger examples, HTTP example,
teardown, and production guardrails.

- [x] **Step 3: Add worker config**

`config.yaml` declares `governance-worker`, `caller-worker`, memory adapters,
engine port `49134`, and HTTP port `3111`.

- [x] **Step 4: Add workers**

The Python worker registers `governance::evaluate_policy`. The TypeScript
worker registers `governance::evaluate_request`, calls the Python function,
and exposes `http::evaluate_request` at `/governance/evaluate`.

### Task 3: Verification

**Files:**
- Verify: `tests/test_iii_governance_lab.py`
- Verify: `experiments/iii-governance-lab/**`

- [x] **Step 1: Run focused direct test fallback**

Run:

```bash
python3 -c 'import importlib.util; spec=importlib.util.spec_from_file_location("test_iii_governance_lab", "tests/test_iii_governance_lab.py"); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); mod.test_iii_governance_lab_is_isolated_from_production_surfaces(); mod.test_iii_governance_lab_declares_stable_worker_contracts(); mod.test_iii_governance_lab_does_not_modify_deploy_workflows(); print("direct iii governance lab tests passed")'
```

Expected: `direct iii governance lab tests passed`.

- [x] **Step 2: Run syntax and parse checks**

Run:

```bash
python3 -m py_compile experiments/iii-governance-lab/workers/governance-worker/governance_worker.py
python3 -c 'import json, yaml; json.load(open("experiments/iii-governance-lab/workers/caller-worker/package.json")); yaml.safe_load(open("experiments/iii-governance-lab/config.yaml")); print("json and yaml parse passed")'
```

Expected: exit 0 and parse confirmation.

- [x] **Step 3: Attempt authoritative root gate**

Run:

```bash
uv run --package acgs_governance_eval_mvp python -m pytest tests/test_iii_governance_lab.py -q
```

Expected in this environment: unavailable because `uv` is not installed.
