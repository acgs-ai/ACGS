from __future__ import annotations

import pytest

from governance.utils import canonical_input_hash


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_canonical_hash_invariants",
    coverage_angle="canonical_hash_deterministic",
)
def test_canonical_hash_is_deterministic():
    payload = {"contract_id": "supplier-123", "amount_cents": 5000}
    assert canonical_input_hash(payload) == canonical_input_hash(payload)


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_canonical_hash_invariants",
    coverage_angle="canonical_hash_key_order_invariant",
)
def test_canonical_hash_is_key_order_invariant():
    a = {"a": 1, "b": 2, "nested": {"x": 1, "y": 2}}
    b = {"b": 2, "a": 1, "nested": {"y": 2, "x": 1}}
    assert canonical_input_hash(a) == canonical_input_hash(b)


@pytest.mark.regression(
    pr="dislovelhl/govern-zone#6",
    severity="MEDIUM",
    issue="pr6_canonical_hash_invariants",
    coverage_angle="canonical_hash_value_sensitive",
)
def test_canonical_hash_differs_for_different_values():
    a = {"contract_id": "supplier-123"}
    b = {"contract_id": "supplier-124"}
    assert canonical_input_hash(a) != canonical_input_hash(b)
