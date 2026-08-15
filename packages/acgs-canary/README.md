# acgs-canary

R0 tooling for licensee-keyed canary variants of the published AGEC
governance sample pack: restricted canary store, pool management, variant
manifests with Merkle commitments, an append-only acceptance ledger, and
external-anchor interfaces.

**Private infrastructure only.** R0 performs no public dataset rebuild, no
modification of any Hugging Face release, no public canary disclosure, no
commercial issuance, and no production signing. See
`docs/IMPLEMENTATION.md` for the threat model, trust boundaries, state
machine, and — critically — what this system does and does not prove.

Quick start (isolated, ephemeral, non-production):

```bash
uv run --package acgs-canary acgs-canary r0-selfcheck
uv run --package acgs-canary acgs-canary protocol-hash
```

Tests:

```bash
uv run --package acgs-canary python -m pytest packages/acgs-canary/tests --import-mode=importlib -q
```

Normative design: `RUNG3_CANARY_DESIGN.md` v2.1 (approved with conditions,
two independent adversarial review rounds; conditions applied). The frozen
protocol identity is `acgs-canary protocol-hash`; any semantic change to
the protocol changes that hash.
