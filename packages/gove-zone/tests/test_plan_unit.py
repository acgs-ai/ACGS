"""Direct unit tests for :mod:`gove_zone.plan`.

:class:`WorkflowAuthorization` is the plan-level analog of a
:class:`~gove_zone.receipt.DecisionReceipt`, so the properties under test are
the same three: plan MACI is fail-closed at mint, the hash covers every field
*except* ``authorization_hash`` and ``signature``, and the signing algorithm +
key id are bound into the hash before it is signed (anti-downgrade).
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac

import pytest

from gove_zone.errors import ReceiptValidationError
from gove_zone.plan import WorkflowAuthorization
from gove_zone.receipt import Validator

DAG_HASH = "dag-hash-unit"
WORKFLOW_ID = "wf-plan-unit"
PROPOSER = "plan-author"
PLAN_VALIDATOR = Validator("plan-council", role="validator")
AUTHORITY = "tenant-unit/plan-grant"
TENANT = "tenant-unit"
BOUNDARY = "plan-unit-sandbox"
GOAL = "run the unit plan"


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    def __init__(
        self,
        key: bytes = b"plan-unit-key",
        key_id: str = "plan-key-1",
        algorithm: str = "test-hmac-sha256",
    ) -> None:
        self._key = key
        self.key_id = key_id
        self.algorithm = algorithm

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def _auth(**overrides: object) -> WorkflowAuthorization:
    kwargs: dict[str, object] = {
        "workflow_id": WORKFLOW_ID,
        "plan_proposer": PROPOSER,
        "plan_validator": PLAN_VALIDATOR,
        "authority": AUTHORITY,
        "tenant_id": TENANT,
        "execution_boundary": BOUNDARY,
        "declared_goal": GOAL,
    }
    dag_hash = str(overrides.pop("dag_hash", DAG_HASH))
    kwargs.update(overrides)
    return WorkflowAuthorization.from_plan(dag_hash, **kwargs)  # type: ignore[arg-type]


# --- fail-closed plan MACI --------------------------------------------------- #


def test_from_plan_rejects_plan_self_validation() -> None:
    with pytest.raises(ReceiptValidationError, match="self-validation forbidden"):
        _auth(plan_validator=Validator(PROPOSER))


def test_from_plan_accepts_a_distinct_plan_validator() -> None:
    authorization = _auth()
    assert authorization.plan_proposer == PROPOSER
    assert authorization.plan_validator_id == PLAN_VALIDATOR.validator_id
    assert authorization.plan_validator_role == PLAN_VALIDATOR.role


# --- unsigned defaults -------------------------------------------------------- #


def test_unsigned_authorization_has_the_documented_defaults() -> None:
    authorization = _auth()
    assert authorization.signature_algorithm == "none"
    assert authorization.signing_key_id == ""
    assert authorization.signature == "unsigned_local"
    assert authorization.constraints == {}
    assert authorization.policy_hash == ""
    assert authorization.issued_at == ""
    assert authorization.expires_at == ""


def test_from_plan_computes_a_self_consistent_hash() -> None:
    authorization = _auth()
    assert authorization.authorization_hash
    assert authorization.compute_authorization_hash() == authorization.authorization_hash


def test_constraints_are_copied_not_aliased() -> None:
    supplied = {"max_steps": 3}
    authorization = _auth(constraints=supplied)
    supplied["max_steps"] = 999
    assert authorization.constraints == {"max_steps": 3}


# --- what the hash covers ------------------------------------------------------ #


def test_hash_excludes_authorization_hash_and_signature() -> None:
    """Rewriting either excluded field must not change the computed hash."""
    authorization = _auth()
    tampered = dataclasses.replace(authorization, authorization_hash="bogus", signature="forged")
    assert tampered.compute_authorization_hash() == authorization.authorization_hash


@pytest.mark.parametrize(
    "field_name,new_value",
    [
        ("workflow_id", "wf-other"),
        ("dag_hash", "dag-hash-other"),
        ("plan_proposer", "other-author"),
        ("plan_validator_id", "other-council"),
        ("plan_validator_role", "auditor"),
        ("authority", "tenant-unit/other-grant"),
        ("tenant_id", "tenant-other"),
        ("execution_boundary", "other-boundary"),
        ("declared_goal", "a different plan"),
        ("policy_hash", "policy/v2"),
        ("issued_at", "2026-01-01T00:00:00+00:00"),
        ("expires_at", "2026-01-02T00:00:00+00:00"),
        ("signature_algorithm", "ed25519"),
        ("signing_key_id", "smuggled-key"),
    ],
)
def test_every_covered_field_changes_the_hash(field_name: str, new_value: str) -> None:
    authorization = _auth()
    mutated = dataclasses.replace(authorization, **{field_name: new_value})
    assert mutated.compute_authorization_hash() != authorization.authorization_hash


def test_constraints_are_inside_the_hash() -> None:
    plain = _auth()
    constrained = _auth(constraints={"max_steps": 3})
    assert constrained.authorization_hash != plain.authorization_hash


def test_authorization_is_frozen() -> None:
    authorization = _auth()
    with pytest.raises(dataclasses.FrozenInstanceError):
        authorization.dag_hash = "rewritten"  # type: ignore[misc]


# --- signing ------------------------------------------------------------------- #


def test_signed_authorization_binds_alg_and_key_id_then_signs_the_hash() -> None:
    signer = FakeSigner()
    authorization = _auth(signer=signer)
    assert authorization.signature_algorithm == signer.algorithm
    assert authorization.signing_key_id == signer.key_id
    # The hash was computed AFTER alg/key_id were set...
    assert authorization.compute_authorization_hash() == authorization.authorization_hash
    # ...and the signature attests that hash.
    assert signer.verify(authorization.authorization_hash.encode("utf-8"), authorization.signature)


def test_a_different_signing_key_yields_a_different_hash() -> None:
    """Anti-downgrade: the key id is inside the hash, not merely alongside it."""
    a = _auth(signer=FakeSigner(key_id="key-a"))
    b = _auth(signer=FakeSigner(key_id="key-b"))
    assert a.authorization_hash != b.authorization_hash


def test_downgrading_a_signed_authorization_to_unsigned_breaks_the_hash() -> None:
    signed = _auth(signer=FakeSigner())
    downgraded = dataclasses.replace(
        signed, signature_algorithm="none", signing_key_id="", signature="unsigned_local"
    )
    assert downgraded.compute_authorization_hash() != downgraded.authorization_hash
