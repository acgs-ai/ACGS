from __future__ import annotations

from acgs_cft_governance_pack.hashing import hash_json, merkle_root


def test_hash_json_is_order_independent_for_mappings() -> None:
    assert hash_json({"b": 2, "a": 1}) == hash_json({"a": 1, "b": 2})


def test_merkle_root_duplicates_last_leaf_for_odd_leaf_count() -> None:
    first = hash_json("first")
    second = hash_json("second")
    third = hash_json("third")
    expected_pair = hash_json(first + second, canonicalize=False)
    expected_odd_pair = hash_json(third + third, canonicalize=False)

    assert merkle_root(["first", "second", "third"]) == hash_json(
        expected_pair + expected_odd_pair,
        canonicalize=False,
    )
