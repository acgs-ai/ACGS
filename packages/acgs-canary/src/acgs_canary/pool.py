"""Canary pool: generation, invariants, burn state, and selection.

R0 scope notes (normative, from the approved design):
- No fully synthetic trajectory records are generated here — a canary is a
  token plus placement multiplicity, to be injected into real records by
  the R1 variant builder.
- Nothing in this module claims statistical camouflage or detection power;
  the only citable camouflage statement is the R1 distinguisher test.
- T0 and T1 are separate namespaces: a canary carries its tier at creation,
  tier-crossing selection is refused, and the Merkle domains differ
  cryptographically (merkle.DOMAIN_T0 / DOMAIN_T1).
- Burned or contaminated canaries are never selected for new variants.
- Probe material is custody-split from token material (design §6.5):
  probe records are written through a SEPARATE store backend when one is
  configured (``CanaryPool(store, probe_store=...)``), giving them their
  own location and access grant. The distinct record prefix alone is
  namespace hygiene, not a custody boundary — operators satisfying §6.5
  must configure a separate probe store.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import secrets as pysecrets
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes
from .errors import PoolError, SelectionError
from .merkle import DOMAIN_T0, DOMAIN_T1, leaf_hash, merkle_root
from .store import CanaryStoreBackend, Secret

TIER_T0 = "T0"
TIER_T1 = "T1"
_TIERS = frozenset({TIER_T0, TIER_T1})
_STATUSES = frozenset({"active", "burned", "contaminated", "retired"})

_POOL_META = "pool-meta"
_CANARY_PREFIX = "canary-"
_PROBE_PREFIX = "probe-"
_ALLOC_PREFIX = "alloc-"

_SELECTION_DOMAIN = b"acgs-canary/v1/selection"
_TOKEN_BYTES = 24  # 192-bit tokens
_MIN_PLACEMENTS = 2  # design §6.2: no singleton placement assumptions


def _tier_domain(tier: str) -> str:
    if tier == TIER_T0:
        return DOMAIN_T0
    if tier == TIER_T1:
        return DOMAIN_T1
    raise PoolError(f"unknown tier: {tier!r}")


@dataclass(frozen=True)
class CanaryPublic:
    """The non-secret projection of a canary. Safe to export."""

    canary_id: str
    tier: str
    token_sha256: str
    status: str
    placements: int
    created_at: str
    retired_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "tier": self.tier,
            "token_sha256": self.token_sha256,
            "status": self.status,
            "placements": self.placements,
            "created_at": self.created_at,
            "retired_at": self.retired_at,
        }


def canary_leaf_bytes(canary_id: str, token_sha256: str) -> bytes:
    """Leaf preimage: binds the id to the token digest, never the raw token."""
    return canonical_bytes({"canary_id": canary_id, "token_sha256": token_sha256})


class CanaryPool:
    """Pool operations over a store backend. All mutations are explicit.

    ``probe_store`` is the §6.5 custody boundary for probe material: when
    provided, probe records are read/written ONLY through it, so a
    disclosure of the token store does not also surrender the probe set.
    When omitted, probes share the token store (prefix separation only).
    """

    def __init__(
        self,
        store: CanaryStoreBackend,
        *,
        probe_store: CanaryStoreBackend | None = None,
    ) -> None:
        self._store = store
        self._probe_store = probe_store if probe_store is not None else store

    # -- lifecycle ---------------------------------------------------------

    def init_pool(self, *, pool_id: str, created_at: str, operator: str) -> None:
        if self._store.read_record(_POOL_META) is not None:
            raise PoolError("pool already initialized; refusing to overwrite")
        selection_salt = pysecrets.token_bytes(32)
        self._store.write_record(
            _POOL_META,
            {
                "schema": "acgs_canary_pool/v1",
                "pool_id": pool_id,
                "created_at": created_at,
                "operator": operator,
                "selection_salt_hex": selection_salt.hex(),
            },
            overwrite=False,
        )

    def _meta(self) -> dict[str, Any]:
        meta = self._store.read_record(_POOL_META)
        if meta is None:
            raise PoolError("pool is not initialized")
        return meta

    def _selection_salt(self) -> Secret:
        return Secret(bytes.fromhex(self._meta()["selection_salt_hex"]))

    # -- generation --------------------------------------------------------

    def generate(
        self,
        *,
        tier: str,
        count: int,
        placements: int,
        created_at: str,
    ) -> list[str]:
        """Generate canaries with CSPRNG tokens. Returns public canary_ids."""
        self._meta()
        if tier not in _TIERS:
            raise PoolError(f"unknown tier: {tier!r}")
        if count < 1:
            raise PoolError("count must be >= 1")
        if placements < _MIN_PLACEMENTS:
            raise PoolError(
                f"placements must be >= {_MIN_PLACEMENTS}: single-occurrence "
                "canaries are a design-refuted assumption (design §6.2)"
            )
        ids: list[str] = []
        for _ in range(count):
            canary_id = f"cn_{pysecrets.token_hex(8)}"
            token = pysecrets.token_bytes(_TOKEN_BYTES)
            probe_prefix_note = pysecrets.token_bytes(16)
            token_sha = hashlib.sha256(token).hexdigest()
            self._store.write_record(
                f"{_CANARY_PREFIX}{canary_id}",
                {
                    "schema": "acgs_canary_record/v1",
                    "canary_id": canary_id,
                    "tier": tier,
                    "token_hex": token.hex(),  # SECRET: never exported
                    "token_sha256": token_sha,
                    "status": "active",
                    "placements": placements,
                    "created_at": created_at,
                    "retired_at": None,
                },
                overwrite=False,
            )
            # Probe custody split (§6.5): separate store when configured.
            self._probe_store.write_record(
                f"{_PROBE_PREFIX}{canary_id}",
                {
                    "schema": "acgs_canary_probe/v1",
                    "canary_id": canary_id,
                    "probe_seed_hex": probe_prefix_note.hex(),  # SECRET
                    "created_at": created_at,
                },
                overwrite=False,
            )
            ids.append(canary_id)
        return ids

    # -- reads -------------------------------------------------------------

    def _record(self, canary_id: str) -> dict[str, Any]:
        rec = self._store.read_record(f"{_CANARY_PREFIX}{canary_id}")
        if rec is None:
            raise PoolError(f"unknown canary: {canary_id}")
        return rec

    def public(self, canary_id: str) -> CanaryPublic:
        rec = self._record(canary_id)
        return CanaryPublic(
            canary_id=rec["canary_id"],
            tier=rec["tier"],
            token_sha256=rec["token_sha256"],
            status=rec["status"],
            placements=rec["placements"],
            created_at=rec["created_at"],
            retired_at=rec["retired_at"],
        )

    def all_public(self) -> list[CanaryPublic]:
        names = self._store.list_records(_CANARY_PREFIX)
        return [self.public(n[len(_CANARY_PREFIX) :]) for n in names]

    def token(self, canary_id: str) -> Secret:
        """Secret token bytes — dispute-time use only."""
        return Secret(bytes.fromhex(self._record(canary_id)["token_hex"]))

    # -- invariants --------------------------------------------------------

    def validate(self) -> dict[str, Any]:
        """Check pool invariants; raises PoolError on the first violation."""
        self._meta()
        seen_token_hashes: set[str] = set()
        counts = {"active": 0, "burned": 0, "contaminated": 0, "retired": 0}
        publics = self.all_public()
        for pub in publics:
            rec = self._record(pub.canary_id)
            if rec["status"] not in _STATUSES:
                raise PoolError(f"{pub.canary_id}: illegal status {rec['status']!r}")
            if rec["tier"] not in _TIERS:
                raise PoolError(f"{pub.canary_id}: illegal tier {rec['tier']!r}")
            if rec["placements"] < _MIN_PLACEMENTS:
                raise PoolError(f"{pub.canary_id}: singleton placement")
            actual = hashlib.sha256(bytes.fromhex(rec["token_hex"])).hexdigest()
            if actual != rec["token_sha256"]:
                raise PoolError(f"{pub.canary_id}: token digest mismatch")
            if rec["token_sha256"] in seen_token_hashes:
                raise PoolError(f"{pub.canary_id}: duplicate token")
            seen_token_hashes.add(rec["token_sha256"])
            if self._probe_store.read_record(f"{_PROBE_PREFIX}{pub.canary_id}") is None:
                raise PoolError(f"{pub.canary_id}: missing probe record")
            counts[rec["status"]] += 1
        return {"total": len(publics), "by_status": counts}

    # -- burn / contamination ---------------------------------------------

    def mark(self, canary_id: str, *, status: str, at: str) -> None:
        if status not in {"burned", "contaminated", "retired"}:
            raise PoolError(f"illegal transition target: {status!r}")
        rec = self._record(canary_id)
        if rec["status"] != "active":
            raise PoolError(f"{canary_id}: cannot mark {status}; status is {rec['status']!r}")
        rec["status"] = status
        rec["retired_at"] = at
        self._store.write_record(f"{_CANARY_PREFIX}{canary_id}", rec, overwrite=True)

    # -- selection ---------------------------------------------------------

    def _rank(self, salt: Secret, context: bytes, canary_id: str) -> bytes:
        return hmac_mod.new(
            salt.reveal(),
            _SELECTION_DOMAIN + b"\x1f" + context + b"\x1f" + canary_id.encode(),
            hashlib.sha256,
        ).digest()

    def _active_ids(self, tier: str) -> list[str]:
        return [p.canary_id for p in self.all_public() if p.tier == tier and p.status == "active"]

    def select_t0(self, *, count: int) -> list[str]:
        """Deterministic T0 selection (secret-salted ranking)."""
        if not isinstance(count, int) or count < 1:
            raise SelectionError(f"count must be a positive integer, got {count!r}")
        salt = self._selection_salt()
        candidates = self._active_ids(TIER_T0)
        if len(candidates) < count:
            raise SelectionError(f"need {count} active T0 canaries, have {len(candidates)}")
        ranked = sorted(candidates, key=lambda c: self._rank(salt, b"t0", c))
        return ranked[:count]

    def select_t1(self, *, variant_id: str, shared: int, unique: int) -> dict[str, list[str]]:
        """T1 selection: a shared subset plus a variant-unique subset.

        Deterministic given the pool state and variant_id; ranking is keyed
        by the secret selection salt so allocation cannot be derived from
        public inputs. Unique canaries already allocated to another variant
        are excluded (allocation is recorded per canary).
        """
        if not isinstance(shared, int) or shared < 0:
            raise SelectionError(f"shared must be a non-negative integer, got {shared!r}")
        if not isinstance(unique, int) or unique < 0:
            raise SelectionError(f"unique must be a non-negative integer, got {unique!r}")
        if shared + unique < 1:
            raise SelectionError("T1 selection requires a positive total count")
        salt = self._selection_salt()
        candidates = self._active_ids(TIER_T1)
        shared_ranked = sorted(candidates, key=lambda c: self._rank(salt, b"t1-shared", c))
        shared_ids = shared_ranked[:shared]
        if len(shared_ids) < shared:
            raise SelectionError(f"need {shared} shared T1 canaries, have {len(shared_ids)}")
        taken: set[str] = set(shared_ids)
        for name in self._store.list_records(_ALLOC_PREFIX):
            alloc = self._store.read_record(name)
            if alloc is not None and alloc["kind"] == "unique":
                taken.add(alloc["canary_id"])
        unique_pool = [c for c in candidates if c not in taken]
        unique_ranked = sorted(
            unique_pool,
            key=lambda c: self._rank(salt, b"t1-unique\x1f" + variant_id.encode(), c),
        )
        unique_ids = unique_ranked[:unique]
        if len(unique_ids) < unique:
            raise SelectionError(
                f"need {unique} unallocated unique T1 canaries, have {len(unique_ids)}"
            )
        for cid in unique_ids:
            self._store.write_record(
                f"{_ALLOC_PREFIX}{variant_id}-{cid}",
                {
                    "schema": "acgs_canary_alloc/v1",
                    "variant_id": variant_id,
                    "canary_id": cid,
                    "kind": "unique",
                },
                overwrite=False,
            )
        for cid in shared_ids:
            self._store.write_record(
                f"{_ALLOC_PREFIX}{variant_id}-{cid}",
                {
                    "schema": "acgs_canary_alloc/v1",
                    "variant_id": variant_id,
                    "canary_id": cid,
                    "kind": "shared",
                },
                overwrite=False,
            )
        return {"shared": shared_ids, "unique": unique_ids}

    # -- commitments and export -------------------------------------------

    def commitment(self, canary_ids: list[str], *, tier: str) -> bytes:
        """Merkle root over the given canaries in the tier's domain."""
        domain = _tier_domain(tier)
        leaves = []
        for cid in canary_ids:
            rec = self._record(cid)
            if rec["tier"] != tier:
                raise PoolError(f"{cid}: tier {rec['tier']} cannot enter a {tier} commitment")
            leaves.append(leaf_hash(domain, canary_leaf_bytes(cid, rec["token_sha256"])))
        return merkle_root(domain, leaves)

    def pool_manifest(self) -> dict[str, Any]:
        """Non-secret pool manifest: ids, tiers, token digests, statuses."""
        meta = self._meta()
        return {
            "schema": "acgs_canary_pool_manifest/v1",
            "pool_id": meta["pool_id"],
            "created_at": meta["created_at"],
            "canaries": [p.to_dict() for p in self.all_public()],
        }
