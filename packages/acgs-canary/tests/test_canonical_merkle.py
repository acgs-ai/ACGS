from __future__ import annotations

import pytest
from acgs_canary.canonical import canonical_bytes, canonical_sha256_hex, length_prefixed
from acgs_canary.errors import MerkleError, ProofError, ProtocolError
from acgs_canary.merkle import (
    DOMAIN_T0,
    DOMAIN_T1,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    proof_from_public_dict,
    verify_inclusion,
)


class TestCanonical:
    def test_key_order_equivalence(self):
        assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})

    def test_value_difference_is_not_equivalent(self):
        assert canonical_bytes({"a": 1}) != canonical_bytes({"a": 2})

    def test_nested_structures_stable(self):
        one = {"x": [1, {"z": "s", "y": None}], "w": True}
        two = {"w": True, "x": [1, {"y": None, "z": "s"}]}
        assert canonical_sha256_hex(one) == canonical_sha256_hex(two)

    def test_list_order_is_significant(self):
        assert canonical_bytes({"a": [1, 2]}) != canonical_bytes({"a": [2, 1]})

    def test_floats_rejected(self):
        with pytest.raises(ProtocolError):
            canonical_bytes({"a": 1.5})

    def test_nan_rejected(self):
        with pytest.raises(ProtocolError):
            canonical_bytes({"a": float("nan")})

    def test_non_string_keys_rejected(self):
        with pytest.raises(ProtocolError):
            canonical_bytes({1: "a"})

    def test_unrepresentable_type_rejected(self):
        with pytest.raises(ProtocolError):
            canonical_bytes({"a": b"bytes"})

    def test_length_prefix_is_unambiguous(self):
        # ("ab","c") must not collide with ("a","bc")
        assert length_prefixed(b"ab", b"c") != length_prefixed(b"a", b"bc")

    def test_length_prefix_rejects_non_bytes(self):
        with pytest.raises(ProtocolError):
            length_prefixed("str")  # type: ignore[arg-type]


def _leaves(domain: str, n: int) -> list[bytes]:
    return [leaf_hash(domain, f"leaf-{i}".encode()) for i in range(n)]


class TestMerkle:
    def test_root_is_input_order_independent(self):
        lv = _leaves(DOMAIN_T0, 5)
        assert merkle_root(DOMAIN_T0, lv) == merkle_root(DOMAIN_T0, list(reversed(lv)))

    def test_duplicate_leaf_rejected(self):
        lv = _leaves(DOMAIN_T0, 3)
        with pytest.raises(MerkleError):
            merkle_root(DOMAIN_T0, [*lv, lv[0]])

    def test_empty_set_rejected(self):
        with pytest.raises(MerkleError):
            merkle_root(DOMAIN_T0, [])

    def test_domain_separation_changes_root(self):
        raw = [f"leaf-{i}".encode() for i in range(4)]
        r0 = merkle_root(DOMAIN_T0, [leaf_hash(DOMAIN_T0, b) for b in raw])
        r1 = merkle_root(DOMAIN_T1, [leaf_hash(DOMAIN_T1, b) for b in raw])
        assert r0 != r1

    def test_unknown_domain_rejected(self):
        with pytest.raises(MerkleError):
            leaf_hash("acgs-canary/v1/evil", b"x")

    @pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 33])
    def test_inclusion_proofs_verify_for_all_leaves(self, n: int):
        lv = _leaves(DOMAIN_T1, n)
        root = merkle_root(DOMAIN_T1, lv)
        for target in lv:
            proof = inclusion_proof(DOMAIN_T1, lv, target)
            assert verify_inclusion(proof, root)

    def test_exclusion_fails(self):
        lv = _leaves(DOMAIN_T0, 6)
        root = merkle_root(DOMAIN_T0, lv)
        outsider = leaf_hash(DOMAIN_T0, b"not-in-set")
        with pytest.raises(MerkleError):
            inclusion_proof(DOMAIN_T0, lv, outsider)
        # A stolen proof for another leaf does not verify for the outsider.
        stolen = inclusion_proof(DOMAIN_T0, lv, lv[0])
        forged = type(stolen)(domain=stolen.domain, leaf=outsider, path=stolen.path)
        assert not verify_inclusion(forged, root)

    def test_proof_against_wrong_root_fails(self):
        lv = _leaves(DOMAIN_T0, 4)
        other = _leaves(DOMAIN_T0, 5)
        proof = inclusion_proof(DOMAIN_T0, lv, lv[1])
        assert not verify_inclusion(proof, merkle_root(DOMAIN_T0, other))

    def test_proof_domain_confusion_fails(self):
        raw = [f"leaf-{i}".encode() for i in range(4)]
        lv0 = [leaf_hash(DOMAIN_T0, b) for b in raw]
        proof = inclusion_proof(DOMAIN_T0, lv0, lv0[0])
        cross = type(proof)(domain=DOMAIN_T1, leaf=proof.leaf, path=proof.path)
        lv1 = [leaf_hash(DOMAIN_T1, b) for b in raw]
        assert not verify_inclusion(cross, merkle_root(DOMAIN_T1, lv1))

    def test_path_order_manipulation_fails(self):
        lv = _leaves(DOMAIN_T0, 8)
        root = merkle_root(DOMAIN_T0, lv)
        proof = inclusion_proof(DOMAIN_T0, lv, lv[3])
        if len(proof.path) >= 2:
            swapped = type(proof)(
                domain=proof.domain,
                leaf=proof.leaf,
                path=(proof.path[1], proof.path[0], *proof.path[2:]),
            )
            assert not verify_inclusion(swapped, root)

    def test_malformed_public_proof_fails_closed(self):
        lv = _leaves(DOMAIN_T0, 4)
        good = inclusion_proof(DOMAIN_T0, lv, lv[0]).to_public_dict()
        for mutate in (
            lambda d: d.update({"extra": 1}),
            lambda d: d.update({"leaf": "zz"}),
            lambda d: d["path"].append({"sibling": "00" * 32}),
            lambda d: d["path"][0].update({"sibling_is_left": "yes"}),
        ):
            bad = {**good, "path": [dict(s) for s in good["path"]]}
            mutate(bad)
            with pytest.raises(ProofError):
                proof_from_public_dict(bad)

    def test_truncated_proof_does_not_verify(self):
        lv = _leaves(DOMAIN_T0, 8)
        root = merkle_root(DOMAIN_T0, lv)
        proof = inclusion_proof(DOMAIN_T0, lv, lv[0])
        truncated = type(proof)(domain=proof.domain, leaf=proof.leaf, path=proof.path[:-1])
        assert not verify_inclusion(truncated, root)
