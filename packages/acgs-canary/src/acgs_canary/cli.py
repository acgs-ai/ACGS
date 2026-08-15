"""Operator CLI for acgs-canary R0.

Contract:
- exactly one JSON object on stdout (machine-readable result);
- diagnostics go to stderr;
- exit codes: 0 success; 2 usage error; 3 store/location refusal;
  4 validation/integrity failure; 5 policy refusal (key policy,
  production gates); 6 internal error;
- no secret material is printed on any path — results carry public
  identifiers and digests only;
- no command touches the public corpus or any remote service.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import demo as demo_mod
from .anchor import build_anchor_bundle, bundle_hash, serialize_bundle
from .canonical import canonical_sha256_hex
from .errors import (
    CanaryError,
    KeyPolicyError,
    StoreConflictError,
    StoreLocationError,
)
from .ledger import AcceptanceLedger, ledger_path
from .manifest import (
    build_manifest,
    load_manifest,
    new_variant_id,
    store_manifest,
)
from .pool import CanaryPool
from .protocol import PROTOCOL, protocol_hash
from .store import RestrictedFileStore

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_STORE = 3
EXIT_VALIDATION = 4
EXIT_POLICY = 5
EXIT_INTERNAL = 6


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _diag(message: str) -> None:
    sys.stderr.write(message + "\n")


def _store(args: argparse.Namespace) -> RestrictedFileStore:
    return RestrictedFileStore(args.store)


def _pool(args: argparse.Namespace) -> CanaryPool:
    probe_path = getattr(args, "probe_store", None)
    probe_store = RestrictedFileStore(probe_path) if probe_path else None
    return CanaryPool(_store(args), probe_store=probe_store)


# -- command handlers ------------------------------------------------------


def cmd_pool_init(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    if args.init_store:
        store.initialize(operator=args.operator)
        if args.probe_store:
            RestrictedFileStore(args.probe_store).initialize(operator=args.operator)
    pool = CanaryPool(store)
    pool.init_pool(pool_id=args.pool_id, created_at=_now(), operator=args.operator)
    return {"ok": True, "command": "pool-init", "pool_id": args.pool_id}


def cmd_pool_generate(args: argparse.Namespace) -> dict[str, Any]:
    pool = _pool(args)
    ids = pool.generate(
        tier=args.tier,
        count=args.count,
        placements=args.placements,
        created_at=_now(),
    )
    return {"ok": True, "command": "pool-generate", "tier": args.tier, "canary_ids": ids}


def cmd_pool_validate(args: argparse.Namespace) -> dict[str, Any]:
    report = _pool(args).validate()
    return {"ok": True, "command": "pool-validate", "report": report}


def cmd_pool_burn(args: argparse.Namespace) -> dict[str, Any]:
    if not args.confirm:
        raise KeyPolicyError("burning is irreversible; pass --confirm to proceed")
    _pool(args).mark(args.canary_id, status=args.status, at=_now())
    return {
        "ok": True,
        "command": "pool-burn",
        "canary_id": args.canary_id,
        "status": args.status,
    }


def cmd_pool_manifest(args: argparse.Namespace) -> dict[str, Any]:
    manifest = _pool(args).pool_manifest()
    return {
        "ok": True,
        "command": "pool-manifest",
        "pool_manifest_sha256": canonical_sha256_hex(manifest),
        "canary_count": len(manifest["canaries"]),
    }


def cmd_variant_prepare(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    pool = CanaryPool(store)
    variant_id = new_variant_id()
    # Validate operator-supplied manifest inputs BEFORE any selection is
    # persisted: select_t1 reserves unique canaries immediately, so a
    # manifest rejection after selection would strand allocations on a
    # variant that never exists (pool exhaustion on retries).
    build_manifest(
        variant_id=variant_id,
        tier=args.tier,
        source_release=args.source_release,
        source_tree_sha256=args.source_tree_sha256,
        canary_commitment_hex="00" * 32,
        placement_commitment_hex="00" * 32,
        created_at=_now(),
        protocol_sha256=protocol_hash(),
        issuer_ref=args.issuer_ref,
    )
    if args.tier == "T0":
        selection = {"shared": pool.select_t0(count=args.count), "unique": []}
    else:
        selection = pool.select_t1(variant_id=variant_id, shared=args.shared, unique=args.unique)
    all_ids = selection["shared"] + selection["unique"]
    commitment = pool.commitment(all_ids, tier=args.tier)
    allocation = {
        "schema": "acgs_canary_allocation/v1",
        "variant_id": variant_id,
        "tier": args.tier,
        "shared": sorted(selection["shared"]),
        "unique": sorted(selection["unique"]),
    }
    manifest = build_manifest(
        variant_id=variant_id,
        tier=args.tier,
        source_release=args.source_release,
        source_tree_sha256=args.source_tree_sha256,
        canary_commitment_hex=commitment.hex(),
        placement_commitment_hex=canonical_sha256_hex(allocation),
        created_at=_now(),
        protocol_sha256=protocol_hash(),
        issuer_ref=args.issuer_ref,
    )
    store_manifest(store, manifest)
    store.write_record(f"allocation-{variant_id}", allocation, overwrite=False)
    return {
        "ok": True,
        "command": "variant-prepare",
        "variant_id": variant_id,
        "tier": args.tier,
        "canary_commitment_hex": commitment.hex(),
        "allocation_manifest_sha256": canonical_sha256_hex(allocation),
        "canary_count": len(all_ids),
    }


def cmd_variant_verify(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    pool = CanaryPool(store)
    manifest = load_manifest(store, args.variant_id)
    allocation = store.read_record(f"allocation-{args.variant_id}")
    if allocation is None:
        raise CanaryError("allocation record missing")
    all_ids = allocation["shared"] + allocation["unique"]
    recomputed = pool.commitment(all_ids, tier=manifest["tier"]).hex()
    commitment_ok = recomputed == manifest["canary_commitment_hex"]
    placement_ok = canonical_sha256_hex(allocation) == manifest["placement_commitment_hex"]
    protocol_ok = manifest["protocol_sha256"] == protocol_hash()
    ok = commitment_ok and placement_ok and protocol_ok
    if not ok:
        raise CanaryError(
            "variant verification failed: "
            f"commitment={commitment_ok} placement={placement_ok} protocol={protocol_ok}"
        )
    return {
        "ok": True,
        "command": "variant-verify",
        "variant_id": args.variant_id,
        "commitment_ok": commitment_ok,
        "placement_ok": placement_ok,
        "protocol_ok": protocol_ok,
    }


def cmd_ledger_init(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    store.assert_initialized()
    path = ledger_path(store)
    ledger = AcceptanceLedger.create(
        path, protocol_sha256=protocol_hash(), operator=args.operator, timestamp=_now()
    )
    report = ledger.verify()
    return {
        "ok": True,
        "command": "ledger-init",
        "entries": report.entries,
        "head_hash": report.head_hash,
    }


def cmd_ledger_verify(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    report = AcceptanceLedger(ledger_path(store)).verify()
    return {
        "ok": True,
        "command": "ledger-verify",
        "entries": report.entries,
        "head_hash": report.head_hash,
        "torn_tail": report.torn_tail,
    }


def cmd_protocol_hash(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "ok": True,
        "command": "protocol-hash",
        "protocol_sha256": protocol_hash(),
        "protocol_version": PROTOCOL["version"],
    }


def cmd_anchor_prepare(args: argparse.Namespace) -> dict[str, Any]:
    store = _store(args)
    pool = CanaryPool(store)
    ledger = AcceptanceLedger(ledger_path(store))
    report = ledger.verify()
    bundle = build_anchor_bundle(
        ledger_head_hash=report.head_hash,
        pool_manifest_sha256=canonical_sha256_hex(pool.pool_manifest()),
        protocol_sha256=protocol_hash(),
        commitment_roots_hex=args.commitment_root or [],
        created_at=_now(),
    )
    out = Path(args.out)
    if out.exists():
        raise StoreConflictError(f"anchor bundle exists: {out}")
    # Write the exact canonical byte form: the on-disk bundle must hash to
    # bundle_sha256 with no re-serialization step.
    out.write_bytes(serialize_bundle(bundle))
    return {
        "ok": True,
        "command": "anchor-prepare",
        "bundle_sha256": bundle_hash(bundle),
        "bundle_path": str(out),
        "note": "submit bundle_sha256 to RFC3161/OTS out of band; "
        "unanchored bundles are publisher testimony",
    }


def cmd_r0_selfcheck(args: argparse.Namespace) -> dict[str, Any]:
    return demo_mod.run_selfcheck()


# -- parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="acgs-canary",
        description="R0 canary-provenance tooling (private; no public effects)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_store_arg(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--store",
            default=None,
            help="restricted store path (default: ACGS_CANARY_STORE env)",
        )

    def add_probe_store_arg(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--probe-store",
            default=None,
            help="separate restricted store for probe material "
            "(design §6.5 custody split; default: token store)",
        )

    sp = sub.add_parser("pool-init", help="initialize store marker and pool")
    add_store_arg(sp)
    add_probe_store_arg(sp)
    sp.add_argument("--pool-id", required=True)
    sp.add_argument("--operator", required=True)
    sp.add_argument("--init-store", action="store_true")
    sp.set_defaults(fn=cmd_pool_init)

    sp = sub.add_parser("pool-generate", help="generate canaries (CSPRNG)")
    add_store_arg(sp)
    add_probe_store_arg(sp)
    sp.add_argument("--tier", choices=["T0", "T1"], required=True)
    sp.add_argument("--count", type=int, required=True)
    sp.add_argument("--placements", type=int, default=2)
    sp.set_defaults(fn=cmd_pool_generate)

    sp = sub.add_parser("pool-validate", help="check pool invariants")
    add_store_arg(sp)
    add_probe_store_arg(sp)
    sp.set_defaults(fn=cmd_pool_validate)

    sp = sub.add_parser("pool-burn", help="mark a canary burned/contaminated")
    add_store_arg(sp)
    sp.add_argument("--canary-id", required=True)
    sp.add_argument("--status", choices=["burned", "contaminated", "retired"], required=True)
    sp.add_argument("--confirm", action="store_true")
    sp.set_defaults(fn=cmd_pool_burn)

    sp = sub.add_parser("pool-manifest", help="non-secret pool manifest hash")
    add_store_arg(sp)
    sp.set_defaults(fn=cmd_pool_manifest)

    sp = sub.add_parser("variant-prepare", help="select canaries + build manifest")
    add_store_arg(sp)
    sp.add_argument("--tier", choices=["T0", "T1"], required=True)
    sp.add_argument("--count", type=int, default=4, help="T0 canary count")
    sp.add_argument("--shared", type=int, default=2, help="T1 shared count")
    sp.add_argument("--unique", type=int, default=2, help="T1 unique count")
    sp.add_argument("--source-release", required=True)
    sp.add_argument("--source-tree-sha256", required=True)
    sp.add_argument("--issuer-ref", required=True)
    sp.set_defaults(fn=cmd_variant_prepare)

    sp = sub.add_parser("variant-verify", help="recompute commitments for a variant")
    add_store_arg(sp)
    sp.add_argument("--variant-id", required=True)
    sp.set_defaults(fn=cmd_variant_verify)

    sp = sub.add_parser("ledger-init", help="create the acceptance ledger")
    add_store_arg(sp)
    sp.add_argument("--operator", required=True)
    sp.set_defaults(fn=cmd_ledger_init)

    sp = sub.add_parser("ledger-verify", help="verify the full chain")
    add_store_arg(sp)
    sp.set_defaults(fn=cmd_ledger_verify)

    sp = sub.add_parser("anchor-prepare", help="build the canonical anchor bundle")
    add_store_arg(sp)
    sp.add_argument("--out", required=True)
    sp.add_argument("--commitment-root", action="append")
    sp.set_defaults(fn=cmd_anchor_prepare)

    sp = sub.add_parser("protocol-hash", help="frozen protocol identity")
    sp.set_defaults(fn=cmd_protocol_hash)

    sp = sub.add_parser("r0-selfcheck", help="isolated end-to-end evidence pack")
    sp.set_defaults(fn=cmd_r0_selfcheck)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code in (0, None):
            return 0
        # Keep the one-JSON-object stdout contract even for parse failures:
        # argparse already wrote usage text to stderr.
        _emit(
            {
                "ok": False,
                "error_class": "UsageError",
                "error": "invalid command-line usage; see stderr",
            }
        )
        return EXIT_USAGE
    try:
        result = args.fn(args)
    except (StoreLocationError, StoreConflictError) as exc:
        _diag(f"store refusal: {exc}")
        _emit({"ok": False, "error_class": type(exc).__name__, "error": str(exc)})
        return EXIT_STORE
    except KeyPolicyError as exc:
        _diag(f"policy refusal: {exc}")
        _emit({"ok": False, "error_class": type(exc).__name__, "error": str(exc)})
        return EXIT_POLICY
    except CanaryError as exc:
        _diag(f"validation failure: {exc}")
        _emit({"ok": False, "error_class": type(exc).__name__, "error": str(exc)})
        return EXIT_VALIDATION
    except Exception as exc:
        _diag(f"internal error: {type(exc).__name__}")
        _emit({"ok": False, "error_class": type(exc).__name__, "error": "internal error"})
        return EXIT_INTERNAL
    _emit(result)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
