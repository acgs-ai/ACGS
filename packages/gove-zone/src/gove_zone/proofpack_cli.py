"""``acgs`` command-line interface — enterprise proof-pack tooling.

Subcommands::

    acgs proofpack generate --receipt R.json --audit audit.jsonl --out proofpack/
    acgs proofpack verify proofpack/ [--verifier-key pub.key]

Exit codes (both subcommands): ``0`` success/valid, ``1`` refused/invalid
(fail-closed), ``2`` usage or trust-anchor loading errors.

Kept separate from the ``gove-zone`` operator CLI (:mod:`gove_zone.cli`): this
entry point is the artifact relying parties (auditors, regulators, CI gates)
interact with, so its surface stays minimal and its output stays strictly
machine-readable JSON. The human-readable narrative lives inside the pack
itself (``verification-summary.md``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _generate(args: argparse.Namespace) -> int:
    from gove_zone.proofpack import PackGenerationError, generate_proof_pack

    try:
        summary = generate_proof_pack(
            args.out,
            receipt_path=args.receipt,
            audit_path=args.audit,
            policy_bundle=args.policy_bundle,
            side_store=args.side_store,
            now_iso=args.now_iso,
            force=args.force,
        )
    except PackGenerationError as exc:
        print(f"acgs proofpack generate: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


def _load_trust_anchor(args: argparse.Namespace) -> tuple[Any, Any] | None:
    """Load the out-of-band verifier key / revocation list, or None on failure.

    Mirrors ``gove-zone verify-proofpack``: a bad trust anchor must not verify
    anything (exit 2), and keys are never read from inside the pack.
    """
    verifier = None
    if args.verifier_key:
        from gove_zone.signing import Ed25519Signer

        try:
            raw = Path(args.verifier_key).read_bytes()
            signer = Ed25519Signer.from_public_bytes(raw, key_id=args.key_id or None)
        except Exception as exc:  # noqa: BLE001 — bad trust anchor must not verify anything
            print(f"acgs proofpack verify: cannot load --verifier-key: {exc}", file=sys.stderr)
            return None
        verifier = {signer.key_id: signer}

    revoked_keys = None
    if args.revoked_keys:
        from gove_zone.revocation import RevocationList

        try:
            revoked_keys = RevocationList.from_json(args.revoked_keys)
        except Exception as exc:  # noqa: BLE001 — a broken revocation list must not verify anything
            print(f"acgs proofpack verify: cannot load --revoked-keys: {exc}", file=sys.stderr)
            return None
    return verifier, revoked_keys


def _verify(args: argparse.Namespace) -> int:
    from gove_zone.proofpack import verify_pack

    if (args.policy_bundle is None) != (args.side_store is None):
        # Usage error, not a pack verdict: half-supplied replay material must not
        # make a valid pack look tampered.
        print(
            "acgs proofpack verify: --policy-bundle and --side-store must be supplied together",
            file=sys.stderr,
        )
        return 2

    anchor = _load_trust_anchor(args)
    if anchor is None:
        return 2
    verifier, revoked_keys = anchor

    result = verify_pack(
        args.pack_dir,
        verifier=verifier,
        require_signature=True if args.require_signature else None,
        now_iso=args.now_iso,
        revoked_keys=revoked_keys,
        policy_bundle=args.policy_bundle,
        side_store=args.side_store,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.valid else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acgs",
        description="ACGS governance evidence tooling.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    proofpack = subparsers.add_parser(
        "proofpack",
        help="generate or verify a portable evidence bundle for a governed action",
    )
    pp_sub = proofpack.add_subparsers(dest="proofpack_command", required=True)

    generate = pp_sub.add_parser(
        "generate",
        help="package a receipt + audit chain (+ optional replay material) as evidence",
    )
    generate.add_argument(
        "--receipt", required=True, help="Decision Receipt JSON for the governed action"
    )
    generate.add_argument(
        "--audit", required=True, help="audit chain JSONL the receipt is anchored in"
    )
    generate.add_argument("--out", required=True, help="output pack directory")
    generate.add_argument(
        "--policy-bundle",
        default=None,
        help="RuleSetPolicy bundle JSON enabling decision replay (with --side-store)",
    )
    generate.add_argument(
        "--side-store",
        default=None,
        help="replay side store JSONL of retained raw arguments (with --policy-bundle)",
    )
    generate.add_argument(
        "--now-iso",
        default=None,
        help="inject the generation timestamp (deterministic output for testing)",
    )
    generate.add_argument(
        "--force", action="store_true", help="overwrite pack files already in --out"
    )
    generate.set_defaults(func=_generate)

    verify = pp_sub.add_parser(
        "verify",
        help="verify a pack offline: integrity, receipt, audit chain, optional replay",
    )
    verify.add_argument("pack_dir", help="proof pack directory to verify")
    verify.add_argument(
        "--verifier-key",
        default=None,
        help="raw 32-byte Ed25519 public key file, obtained OUT-OF-BAND (never from the pack)",
    )
    verify.add_argument(
        "--key-id", default=None, help="key id the receipt's signing_key_id must match"
    )
    verify.add_argument(
        "--require-signature",
        action="store_true",
        help="fail-closed on unsigned packs: a declared-accept receipt MUST carry a signature",
    )
    verify.add_argument(
        "--revoked-keys",
        default=None,
        help="JSON revocation list of signing key ids, supplied out-of-band",
    )
    verify.add_argument(
        "--now-iso", default=None, help="inject the verification clock (expiry checks)"
    )
    verify.add_argument(
        "--policy-bundle",
        default=None,
        help="re-derive decisions now from this policy bundle (with --side-store)",
    )
    verify.add_argument(
        "--side-store",
        default=None,
        help="replay side store JSONL for re-derivation (with --policy-bundle)",
    )
    verify.set_defaults(func=_verify)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
