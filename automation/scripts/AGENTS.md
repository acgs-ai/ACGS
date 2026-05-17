# AGENTS.md — automation/scripts

## Purpose

Executable Python utilities that implement the four phases of the repo's
automation lifecycle: proposing a new automation, validating its registry /
policy / proposal artefacts, installing an approved proposal into the active
registry, and writing append-only audit events for every step. These scripts
are the only sanctioned entry points for mutating `automation/registry.yaml`
or `automation/proposals/` — the surrounding governance gates assume their
output shape.

## Key Files

- `audit_log.py` — `append_event(...)` writes a JSONL line to
  `automation/logs/audit.jsonl` with UTC timestamp, actor, action,
  `automation_id`, `files_changed`, `validation_result`, and `decision`
- `propose_automation.py` — Generates a reviewable proposal under
  `automation/proposals/` from a free-text prompt; logs `action=proposed`
- `validate_automation.py` — Schema + danger-pattern validation for the
  registry, individual policies, and pending proposals; defines
  `REGISTRY_REQUIRED_FIELDS`, `detect_dangerous_commands`, `load_yaml`,
  `validate_policy`, `validate_proposal`, `validate_registry`
- `install_automation.py` — Promotes an approved proposal into the active
  registry; calls the validators first and logs `action=installed`

## Workflow / Commands

```bash
# Validate everything (registry + policies + any open proposals)
python automation/scripts/validate_automation.py --strict

# Draft a new automation proposal
python automation/scripts/propose_automation.py \
  --prompt "Nightly governance evidence rotation" \
  --actor reviewer@acgs

# Install an approved proposal (validation runs implicitly)
python automation/scripts/install_automation.py --proposal-id auto-2026-05-17-001

# Inspect the audit log
jq -c '.' automation/logs/audit.jsonl | tail -20
```

## Gotchas / Conventions

- `propose_automation.py` and `validate_automation.py` import sibling modules
  via a `sys.path` bootstrap (`SCRIPT_DIR` prepended to `sys.path`). The
  `# noqa: E402  # sys.path bootstrap must precede sibling import` comment is
  load-bearing — do not let an autoformatter reorder those imports.
- Every state-changing script must call `audit_log.append_event(...)` before
  returning success. The surrounding governance review treats a missing audit
  line as a failed run.
- `REGISTRY_REQUIRED_FIELDS` is the contract for `automation/registry.yaml`.
  Adding a new required field is a breaking change — bump the registry version
  and add a migration in the same PR.
- `detect_dangerous_commands` is conservative by design (denies `rm -rf`,
  `curl | sh`, etc.). Weakening it requires explicit reviewer sign-off; do
  not bypass with `# noqa` or pattern allowlists in proposals.
- Scripts are marked executable (`chmod +x`) and have `#!/usr/bin/env python3`
  shebangs so they can be invoked directly from CI or governance hooks.
