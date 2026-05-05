from __future__ import annotations

from governance.utils import canonical_input_hash


def test_canonical_hash_is_deterministic():
    payload = {"contract_id": "supplier-123", "amount_cents": 5000}
    assert canonical_input_hash(payload) == canonical_input_hash(payload)


def test_canonical_hash_is_key_order_invariant():
    a = {"a": 1, "b": 2, "nested": {"x": 1, "y": 2}}
    b = {"b": 2, "a": 1, "nested": {"y": 2, "x": 1}}
    assert canonical_input_hash(a) == canonical_input_hash(b)


def test_canonical_hash_differs_for_different_values():
    a = {"contract_id": "supplier-123"}
    b = {"contract_id": "supplier-124"}
    assert canonical_input_hash(a) != canonical_input_hash(b)
