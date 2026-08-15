"""Domain-separated Merkle commitments over canary membership.

Construction (frozen by the protocol hash, see protocol.py):

- Hash: SHA-256 throughout.
- Leaf hash:  SHA256(0x00 || leaf_domain || 0x1f || leaf_bytes)
- Node hash:  SHA256(0x01 || node_domain || 0x1f || left || right)
- Leaves are sorted lexicographically by leaf hash before tree
  construction. Sorting makes the root order-independent of input
  order (selection order must not leak), and duplicate leaf hashes
  are rejected rather than deduplicated.
- Odd nodes are promoted (not duplicated): a lone right-edge node is
  carried up unchanged. Duplication-style padding (Bitcoin-like) is
  deliberately avoided because it admits distinct trees with equal
  roots (CVE-2012-2459 class).
- Domains separate T0 from T1 commitments cryptographically:
  a T0 leaf can never verify against a T1 root.

Inclusion proofs reveal only the proven leaf and sibling hashes —
never other leaf preimages.
"""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass

from .errors import MerkleError, ProofError

_LEAF_TAG = b"\x00"
_NODE_TAG = b"\x01"
_SEP = b"\x1f"

# Domain strings are part of the frozen protocol.
DOMAIN_T0 = "acgs-canary/v1/t0"
DOMAIN_T1 = "acgs-canary/v1/t1"
_VALID_DOMAINS = frozenset({DOMAIN_T0, DOMAIN_T1})


def _check_domain(domain: str) -> bytes:
    if domain not in _VALID_DOMAINS:
        raise MerkleError(f"unknown merkle domain: {domain!r}")
    return domain.encode("ascii")


def leaf_hash(domain: str, leaf_bytes: bytes) -> bytes:
    """Hash one leaf under an explicit domain."""
    dom = _check_domain(domain)
    if not isinstance(leaf_bytes, bytes) or not leaf_bytes:
        raise MerkleError("leaf must be non-empty bytes")
    return hashlib.sha256(_LEAF_TAG + dom + _SEP + leaf_bytes).digest()


def _node_hash(dom: bytes, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_TAG + dom + _SEP + left + right).digest()


def merkle_root(domain: str, leaves: list[bytes]) -> bytes:
    """Root over pre-hashed leaves (outputs of leaf_hash)."""
    dom = _check_domain(domain)
    if not leaves:
        raise MerkleError("refusing to commit to an empty leaf set")
    for lf in leaves:
        if not isinstance(lf, bytes) or len(lf) != 32:
            raise MerkleError("leaves must be 32-byte digests from leaf_hash")
    ordered = sorted(leaves)
    for a, b in itertools.pairwise(ordered):
        if a == b:
            raise MerkleError("duplicate leaf hash in commitment set")
    level = ordered
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_node_hash(dom, level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promote, never duplicate
        level = nxt
    return level[0]


@dataclass(frozen=True)
class InclusionProof:
    """Sibling path for one leaf. Reveals no other leaf preimage."""

    domain: str
    leaf: bytes  # 32-byte leaf hash being proven
    # (sibling_hash, sibling_is_left) from leaf level upward. A level at
    # which the node was promoted contributes no step.
    path: tuple[tuple[bytes, bool], ...]

    def to_public_dict(self) -> dict:
        return {
            "domain": self.domain,
            "leaf": self.leaf.hex(),
            "path": [
                {"sibling": sib.hex(), "sibling_is_left": is_left} for sib, is_left in self.path
            ],
        }


def inclusion_proof(domain: str, leaves: list[bytes], target: bytes) -> InclusionProof:
    """Build the sibling path for target within the sorted leaf set."""
    _check_domain(domain)
    root_check = merkle_root(domain, leaves)  # validates set & dedup
    dom = domain.encode("ascii")
    level = sorted(leaves)
    try:
        idx = level.index(target)
    except ValueError as exc:
        raise MerkleError("target leaf not in commitment set") from exc
    path: list[tuple[bytes, bool]] = []
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            left, right = level[i], level[i + 1]
            if i == idx or i + 1 == idx:
                if i == idx:
                    path.append((right, False))
                else:
                    path.append((left, True))
                idx = len(nxt)
            nxt.append(_node_hash(dom, left, right))
        if len(level) % 2 == 1:
            if idx == len(level) - 1:
                idx = len(nxt)
            nxt.append(level[-1])
        level = nxt
    assert level[0] == root_check
    return InclusionProof(domain=domain, leaf=target, path=tuple(path))


def verify_inclusion(proof: InclusionProof, root: bytes) -> bool:
    """Fail-closed verification of an inclusion proof against a root."""
    dom = _check_domain(proof.domain)
    if not isinstance(proof.leaf, bytes) or len(proof.leaf) != 32:
        raise ProofError("proof leaf must be a 32-byte digest")
    if not isinstance(root, bytes) or len(root) != 32:
        raise ProofError("root must be a 32-byte digest")
    acc = proof.leaf
    for sib, sib_is_left in proof.path:
        if not isinstance(sib, bytes) or len(sib) != 32:
            raise ProofError("proof sibling must be a 32-byte digest")
        acc = _node_hash(dom, sib, acc) if sib_is_left else _node_hash(dom, acc, sib)
    return acc == root


def proof_from_public_dict(data: dict) -> InclusionProof:
    """Parse an externally supplied proof; every malformation fails closed."""
    try:
        domain = data["domain"]
        leaf = bytes.fromhex(data["leaf"])
        raw_path = data["path"]
        unknown = set(data) - {"domain", "leaf", "path"}
        if unknown:
            raise ProofError(f"unknown critical proof fields: {sorted(unknown)}")
        path = []
        for step in raw_path:
            if set(step) != {"sibling", "sibling_is_left"}:
                raise ProofError("malformed proof step")
            sib = bytes.fromhex(step["sibling"])
            if len(sib) != 32:
                raise ProofError("malformed sibling digest")
            if not isinstance(step["sibling_is_left"], bool):
                raise ProofError("sibling_is_left must be a boolean")
            path.append((sib, step["sibling_is_left"]))
    except ProofError:
        raise
    except Exception as exc:
        raise ProofError(f"malformed inclusion proof: {type(exc).__name__}") from exc
    if len(leaf) != 32:
        raise ProofError("malformed leaf digest")
    return InclusionProof(domain=domain, leaf=leaf, path=tuple(path))
