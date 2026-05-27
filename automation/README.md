# Automation Self-Build System

This directory contains a repo-local automation factory for AI, governance, and code workflows. It is intentionally governed: automations move through `Spec -> Plan -> Risk Review -> Generate -> Test -> Approve -> Install -> Monitor`.

The MVP does not run background agents, deploy services, access secrets, call the network, auto-merge, or auto-deploy. Everything is file-based and reviewable before execution.

## Safety Model

- Automations are tracked in `registry.yaml`.
- Proposals live in `proposals/` until reviewed.
- Approved specs live in `approved/`.
- Rejected specs live in `rejected/`.
- Installed workflow manifests live in `workflows/`.
- Every proposal, validation, install, or rejection decision should be logged to `logs/audit.jsonl`.
- `policies/constitution.yaml` is the hard-rule policy source.
- `validate_automation.py` fails closed when required fields, rollback plans, tests, or policy checks are missing.

Hard stops include destructive commands without explicit approval, secret exposure, protected branch mutation, deploys without tests, missing audit logging, and missing rollback instructions.

## Propose A New Automation

Create a draft proposal from a prompt:

```bash
python automation/scripts/propose_automation.py \
  --prompt "Create a weekly dependency audit that runs tests before reporting" \
  --owner martin
```

This writes a YAML proposal under `automation/proposals/` and appends an audit event.

To include bounded local project context in the draft, add `--include-context`:

```bash
python automation/scripts/propose_automation.py \
  --prompt "Create a weekly dependency audit that runs tests before reporting" \
  --owner martin \
  --include-context
```

The context mode only reads local repo files such as `README.md`, `pyproject.toml`, `package.json`, `docs/*.md`, `.github/workflows/*`, and `scripts/*`. It records path plus a short summary line, never full file dumps, and performs no network calls.

Fill in the generated proposal fields before review:

- `trigger`
- `inputs`
- `outputs`
- `files_touched`
- `commands_executed`
- `risk_assessment`
- `rollback_plan`
- `acceptance_criteria`
- `tests`

## Validate

Required validation commands before approval or install:

```bash
python automation/scripts/validate_automation.py \
  --registry automation/registry.yaml \
  --policy automation/policies/constitution.yaml
```

Validate one proposal as well:

```bash
python automation/scripts/validate_automation.py \
  --registry automation/registry.yaml \
  --policy automation/policies/constitution.yaml \
  --proposal automation/proposals/<automation-id>.yaml
```

The validator reports dangerous commands, missing rollback plans, missing tests, and required-field failures. Any violation exits non-zero.

## Approval

Approval is manual in the MVP:

1. Review the proposal and validator output.
2. Move an accepted proposal to `automation/approved/<automation-id>.yaml`.
3. Add or update a matching `registry.yaml` entry with `status: approved`.
4. Keep `approval_required: true` unless the automation is explicitly low-risk.
5. Record the decision in the audit log.

Rejected proposals should move to `automation/rejected/` and should keep their validation evidence.

## Install

Install only approved automations:

```bash
python automation/scripts/install_automation.py \
  --automation-id <automation-id> \
  --registry automation/registry.yaml
```

The installer fails closed unless the registry status is `approved` and `automation/approved/<automation-id>.yaml` exists. Installation writes a reviewable workflow manifest to `automation/workflows/<automation-id>.yaml`, updates the registry status to `installed`, and appends an audit event.

## Rollback

Rollback is always spec-defined:

1. Read the installed entry in `registry.yaml`.
2. Follow its `rollback_plan`.
3. Disable the automation by setting `status: disabled`.
4. Remove or revert the installed workflow manifest from `automation/workflows/`.
5. Append a rollback audit event to `logs/audit.jsonl`.

No automation should be approved without a concrete rollback plan.
