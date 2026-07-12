"""acgs-proofpack-verifier — dependency-minimal, offline ACGS proof-pack verifier.

This package is a **vendored snapshot** of the ``gove_zone`` verify surface
(receipt / audit-chain / proof-pack verification), re-homed under the
``acgs_proofpack_verifier`` namespace with the import namespace rewritten. The
only intentional logic divergence from the upstream snapshot is the optional,
fail-closed constitution-hash registry cross-check (G2.5): :func:`verify_pack`
accepts a ``constitution_registry`` and, when supplied, cross-checks the
bundle's stamped constitution hash against it (absent registry => carried, not
checked). Its reason to exist is a single, testable property: a relying
party can verify an ACGS proof pack **without gove-zone installed** and with
zero third-party runtime dependencies (Ed25519 signature checks use the optional
``cryptography`` extra).

The optional *decision-replay* tier of a full gove-zone install re-runs the
policy engine and is therefore intentionally **not** vendored here; supplying
replay material to :func:`verify_pack` fails closed rather than silently
skipping it. Offline integrity + receipt + audit-chain verification is complete
and load-bearing.

Programmatic entry point: :func:`verify_pack`. CLI: ``acgs-verify proofpack
verify <pack_dir>`` (see :mod:`acgs_proofpack_verifier.cli`).
"""

from __future__ import annotations

from acgs_proofpack_verifier.proofpack import (
    PackGenerationError,
    PackRejectionReason,
    PackVerificationResult,
    generate_proof_pack,
    verify_pack,
)
from acgs_proofpack_verifier.revocation import RevocationList
from acgs_proofpack_verifier.signing import Ed25519Signer

__all__ = [
    "Ed25519Signer",
    "PackGenerationError",
    "PackRejectionReason",
    "PackVerificationResult",
    "RevocationList",
    "generate_proof_pack",
    "verify_pack",
]

__version__ = "0.1.0a1"
