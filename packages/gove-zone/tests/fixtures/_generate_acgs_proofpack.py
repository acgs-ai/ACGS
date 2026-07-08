"""Deterministic generator for the ACGS proof-pack golden fixture.

Unlike the ``proofpacks/`` corpus (kernel-path, nondeterministic bytes, verdict
contract only), the ACGS pack golden IS byte-reproducible: its inputs are the
already-committed ``proofpacks/valid-replay`` artifacts and the generation
timestamp is pinned, so ``acgs proofpack generate`` over the same bytes must
produce the same bytes. ``test_acgs_proofpack.py`` enforces byte-identity —
any drift in the pack format shows up as a golden diff that must be reviewed
and regenerated deliberately.

Run from the repo root::

    uv run --package gove-zone --extra dev --extra crypto python \
        packages/gove-zone/tests/fixtures/_generate_acgs_proofpack.py
"""

from __future__ import annotations

from pathlib import Path

from gove_zone.proofpack import generate_proof_pack

FIXTURES = Path(__file__).parent
INPUT_PACK = FIXTURES / "proofpacks" / "valid-replay"
GOLDEN_DIR = FIXTURES / "acgs_proofpack" / "golden"

# Pinned generation clock — the golden bundle must be byte-reproducible.
NOW_ISO = "2026-01-01T00:00:00+00:00"


def write_golden(dest: str | Path) -> dict[str, object]:
    """Generate the golden ACGS pack into *dest* from the committed inputs."""
    return generate_proof_pack(
        dest,
        receipt_path=INPUT_PACK / "receipts" / "r1.json",
        audit_path=INPUT_PACK / "audit.jsonl",
        policy_bundle=INPUT_PACK / "policy_bundle.json",
        side_store=INPUT_PACK / "replay_side_store.jsonl",
        now_iso=NOW_ISO,
        force=True,
    )


if __name__ == "__main__":
    summary = write_golden(GOLDEN_DIR)
    print(f"wrote golden ACGS proof pack to {GOLDEN_DIR}: {summary['preflight']}")
