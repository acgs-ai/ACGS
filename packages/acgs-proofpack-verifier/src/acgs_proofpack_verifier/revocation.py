"""Runtime revocation of compromised signing keys (B2, first slice).

The signing module closes the recomputed-hash residual: only the private-key
holder can mint a valid signature over ``receipt_hash``. But that closure has a
documented gap (:mod:`acgs_proofpack_verifier.signing`, "Revocation"): once a signing key is
compromised, the only remedy is to *remove it from the verifier map* and
redeploy — until then a receipt signed by the compromised key, with a
cryptographically valid signature, is always accepted.

This module makes "is this signing key revoked?" a first-class runtime check at
the gate. A :class:`RevocationList` is an in-memory set of revoked
``signing_key_id`` values; the gate rejects a receipt whose key is revoked
**before** trusting its signature, *independent of verifier-map membership* — a
revoked key still present in the map, with a valid signature, is rejected.

Scope (first slice): this revokes **issuer / signing** ``key_id`` values only —
the keys that sign receipts (``DecisionReceipt.signing_key_id``). It is not a
caller-credential revocation list; a future per-call caller-identity subsystem
(distinct key population) carries its own revocation surface. No PKI, no CRL
fetch, no expiry/rotation, no revocation metadata — a flat set, loaded from a
JSON array. Off by default: with no list configured the gate behaves
byte-for-byte as before.

Surfaces covered: the live gates (:func:`acgs_proofpack_verifier.executor.execute_with_receipt`,
:class:`acgs_proofpack_verifier.executor.GovernedExecutor`,
:class:`acgs_proofpack_verifier.contracts.ReceiptVerifier`,
and via them :func:`acgs_proofpack_verifier.escalation.resume_with_receipt`); the offline
inner-receipt path of :func:`acgs_proofpack_verifier.workflow.verify_workflow_replay`; and the
**offline** proof-pack verifier :func:`acgs_proofpack_verifier.verifier.verify_proof_pack` with
its ``verify-proofpack --revoked-keys`` CLI (all default-``None`` so behavior is
unchanged when no list is supplied) — so a key compromised *after* a pack is
minted cannot be verified as valid by a relying party.
Deliberately NOT covered yet (documented fast-follow): the workflow **envelope**
and **plan-authorization** signatures (``WorkflowStepReceipt`` /
``WorkflowAuthorization`` — a *distinct* key population from
``DecisionReceipt.signing_key_id``, belonging to the deferred caller/plan-credential
subsystem).

stdlib-only; never imports ``cryptography`` (revocation is a set membership
test, not a crypto operation).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path


class RevocationListError(Exception):
    """Raised when a revocation list cannot be loaded — fail-closed.

    A list that cannot be read or parsed must never degrade into an empty
    (permissive) list; loading raises instead.
    """


class RevocationList:
    """An in-memory set of revoked signing ``key_id`` values.

    Membership is exact-match and fail-closed at the gate: a receipt whose
    ``signing_key_id`` is in the set is rejected even when its signature is
    cryptographically valid.
    """

    def __init__(self, revoked_key_ids: Iterable[str] = ()) -> None:
        ids = frozenset(revoked_key_ids)
        if "" in ids:
            # The empty string is the *unsigned* sentinel
            # (``signature_algorithm == "none"`` ⇒ ``signing_key_id == ""``).
            # Revoking it would aim a foot-gun at every unsigned receipt, so it
            # is rejected at construction rather than silently honored.
            raise RevocationListError("revocation list must not contain the empty key_id")
        self._revoked = ids

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked

    @classmethod
    def from_json(cls, path: str | Path) -> RevocationList:
        """Load from JSON: ``["key_id", ...]`` (an array of signing key_ids).

        Fail-closed: any read, parse, or shape error raises
        :class:`RevocationListError` rather than yielding an empty list. An
        empty ``key_id`` in the array is a shape error (see ``__init__``).
        """
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RevocationListError(f"cannot load revocation list at {path}: {exc}") from exc
        if not isinstance(raw, list) or not all(isinstance(k, str) for k in raw):
            raise RevocationListError("revocation list must be a JSON array of strings")
        return cls(raw)
