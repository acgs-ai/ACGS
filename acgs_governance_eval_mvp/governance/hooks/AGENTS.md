# AGENTS.md - acgs_governance_eval_mvp/governance/hooks

## Purpose

Post-gate verification seams that perform formal-method or symbolic checks
on the proposed action. Hooks are wired into `PolicyRecallGate` AFTER
deterministic policy matching and BEFORE the gate returns allow. The
scaffold ships stub hooks so the runtime has zero hard dependency on OPA
or Z3; integrators flip a flag to require them in production.

## Modules

- `formal.py` - `FormalPolicyHooks` class. Two callables:
  - `evaluate_opa(input_doc)` -> `{"allow": bool, "reasons": [...], "rule_ids": [...]}` (Open Policy Agent rego evaluation seam).
  - `prove_z3(claim)` -> `{"satisfiable": bool, "model": {...}, "reasons": [...]}` (Z3 SMT proof seam).

## Hook Contract

- Constructor flags `require_opa` and `require_z3` toggle fail-closed behavior. When required-but-unconfigured, both methods return a deny / unsatisfiable shape with the reason `"... adapter is required but not configured."`.
- Hooks MUST be side-effect free with respect to the audit chain — they return data only; the caller decides whether to short-circuit `PolicyRecallGate`.
- Production wiring: instantiate `FormalPolicyHooks(require_opa=True, require_z3=True)` and inject the adapter before `PolicyRecallGate.validate` is called. The deterministic policy match still runs first.

## Extension Notes

New formal-method hooks (e.g. CVC5, Lean, model-checking backends) belong here. They MUST follow the fail-closed pattern: a `require_<name>=True` flag with no adapter wired = deny.
