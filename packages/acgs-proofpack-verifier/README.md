# acgs-proofpack-verifier

Dependency-minimal, **offline** verifier for ACGS proof packs.

An ACGS *proof pack* is a portable evidence bundle for a governed action —
a decision receipt, a hash-chained audit trail, an integrity manifest, and a
human-readable summary. This package lets a relying party (auditor, regulator,
CI gate) verify such a bundle **without installing the `gove-zone` governance
engine** and with **zero third-party runtime dependencies**.

That property is the whole point, and it is enforced by a clean-room test
(`scripts/cleanroom_verify.sh`) that builds the wheel, installs it alone into a
fresh virtualenv, asserts `import gove_zone` fails, and then verifies a golden
pack successfully.

## Install

```bash
pip install acgs-proofpack-verifier            # unsigned-pack verification, no deps
pip install "acgs-proofpack-verifier[crypto]"  # + Ed25519 signature checking
```

## Verify a pack

```bash
acgs-verify proofpack verify ./my-proof-pack
# exit 0 = valid, 1 = refused (fail-closed), 2 = usage / trust-anchor error

# with an out-of-band verifier public key (requires the [crypto] extra):
acgs-verify proofpack verify ./my-proof-pack --verifier-key pub.key --require-signature
```

```python
from acgs_proofpack_verifier import verify_pack

result = verify_pack("./my-proof-pack")
assert result.valid
```

## What is NOT included

The optional **decision-replay** tier of a full `gove-zone` install re-runs the
policy engine to re-derive every decision. That requires the engine and is
intentionally out of scope for a dependency-minimal verifier. Supplying replay
material (`--policy-bundle` / `--side-store`) fails **closed** here rather than
silently skipping replay — a pack must never verify as valid on the strength of
a check this package cannot perform.

## Relationship to gove-zone

The modules under `src/acgs_proofpack_verifier/` are a **vendored snapshot** of
the `gove_zone` verify surface (namespace rewritten, no logic change). The
authoritative source is `packages/gove-zone`; changes to the engine's verify
surface land there and are re-vendored here deliberately.
