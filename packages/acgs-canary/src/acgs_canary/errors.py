"""Typed failure hierarchy for acgs-canary.

Every failure mode fails closed: callers must treat any CanaryError as
"the operation did not happen / the artifact is not valid". Error messages
must never carry secret material; constructors here accept only public
identifiers and diagnostic strings that the caller has already classified
as non-secret.
"""

from __future__ import annotations


class CanaryError(Exception):
    """Base class for all acgs-canary failures."""


class StoreError(CanaryError):
    """Restricted-store configuration or access failure."""


class StoreLocationError(StoreError):
    """The restricted path is absent, ambiguous, inside the repo, or unsafe."""


class StoreIntegrityError(StoreError):
    """Store content failed integrity or schema validation."""


class StoreConflictError(StoreError):
    """Refusing to initialize over, or concurrently mutate, an existing store."""


class PoolError(CanaryError):
    """Canary-pool invariant violation."""


class SelectionError(PoolError):
    """Canary selection could not satisfy the requested invariants."""


class MerkleError(CanaryError):
    """Malformed, mixed-protocol, or inconsistent Merkle input."""


class ProofError(MerkleError):
    """An inclusion proof failed verification."""


class ManifestError(CanaryError):
    """Variant-manifest construction or validation failure."""


class LedgerError(CanaryError):
    """Acceptance-ledger chain violation."""


class LedgerStateError(LedgerError):
    """An entry was used in a state its lifecycle does not permit."""


class SignatureError(CanaryError):
    """Signature creation, binding, or verification failure."""


class KeyPolicyError(SignatureError):
    """A key was offered for a role or environment its policy forbids."""


class AnchorError(CanaryError):
    """External-anchor evidence is missing, malformed, or insufficient."""


class ProtocolError(CanaryError):
    """Frozen-protocol identity mismatch or unknown critical field."""
