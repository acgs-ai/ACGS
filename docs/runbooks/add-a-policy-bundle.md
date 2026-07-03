# Runbook v0: Add a policy bundle (RuleSetPolicy)

> **Scope:** how to contribute one reviewed `RuleSetPolicy` bundle plus the
> fixture/gate tests that prove its intended allow / deny / escalate decisions —
> the policy "good first issue" in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).
> This covers bundle **shape + tests only**. Policy lifecycle (active / stale /
> revoked registries) is **not** implemented and is out of scope — see §Non-goals.
>
> **Last updated:** 2026-06-07

---

## Purpose

A policy bundle expresses deterministic rules over the proposed tool, canonical
path, organization state, and actor trust tier. Contributing a reviewed bundle
for a common scenario (read-only file access, allow-listed HTTP egress, DB read
vs. write separation) is a self-contained way to extend ACGS's coverage without
touching kernel code.

---

## Bundle shape

Use `RuleSetPolicy` (`packages/gove-zone/src/gove_zone/policy.py`). Two things to
get right:

1. **Effects are limited to `deny` / `escalate`.** The code rejects any other
   effect (`RuleSetPolicy effects are limited to deny/escalate` in `policy.py`).
   There is **no `allow` effect.**
2. **Positive authorization is exemption-based**, not an allow rule. A rule
   carries `allow.actors` / `allow.trust_tiers` exemptions, so an allow can never
   accidentally mask a later denial. See the `allowed_trust_tiers` /
   `trust_tier_key` fields in `policy.py`.

Canonical example (from `packages/gove-zone/README.md`):

```python
from gove_zone import RuleSetPolicy

policy = RuleSetPolicy.from_dict(
    {
        "id": "legal-privilege/v1",
        "rules": [
            {
                "id": "PRIVILEGED_NOTES_REVIEW",
                "effect": "deny",
                "tools": ["matter.fetch"],
                "path_prefix": "tenant-7/matter-9821/private-notes",
                "state_equals": {"matter_status": "privileged"},
                "allow": {
                    "actors": ["review-lead"],
                    "trust_tiers": ["reviewer", "admin"],
                },
            }
        ],
    }
)
```

Bundle versions are content-addressed. Normalize and inspect a bundle without
executing any tool:

```bash
gove-zone policy export --bundle policy.raw.json --output policy.bundle.json
gove-zone policy inspect --bundle policy.bundle.json
```

---

## The tests you must add

1. **A fixture decision test** — assert the bundle yields the intended
   allow / deny / escalate decisions for representative calls. Mirror
   `packages/gove-zone/tests/test_policy_bundle_io.py`.
2. **A CLI-gate test** — assert the bundle, passed via `--policy-bundle`, blocks
   the side effect at the gate. Mirror the policy-bundle gate cases in
   `packages/gove-zone/tests/test_setup.py`.

Optionally, replay the bundle against AgentDojo / InjecAgent / ToolEmu-shaped
fixtures with `gove-zone eval --bundle ... --benchmark-format ...` and assert the
expected decision-mismatch metrics.

---

## Non-goals

- **No policy lifecycle / registry.** There is no active / stale / revoked
  bundle registry; that is explicitly incomplete (`docs/SECURITY_MODEL.md`,
  policy-bundle-substitution row). Keep your contribution to a single reviewed
  bundle plus its tests.
- **No new effects.** Do not add an `allow` effect or any effect beyond
  `deny` / `escalate`.

---

## Run the gate

```bash
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

Expected: your fixture test and gate test pass; no existing test regresses.

---

## Checklist

- [ ] Bundle uses only `deny` / `escalate`; positive auth via `allow` exemptions.
- [ ] Fixture decision test (intended allow/deny/escalate).
- [ ] CLI-gate test proving the bundle blocks the side effect.
- [ ] No lifecycle/registry assumptions introduced.
- [ ] `uv run --package gove-zone python -m pytest packages/gove-zone/tests` passes.
- [ ] No capability overclaim; wording traces to code (see
      [`docs/CLAIMS.md`](../CLAIMS.md)).
