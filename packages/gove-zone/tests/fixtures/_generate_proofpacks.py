"""Deterministic-shape generator for the offline proof-pack fixture corpus (B4 §8).

Each pack is a portable ``gove-zone/proof-pack/v1`` directory — receipts + an audit
chain + a manifest (+ optional replay material / consumption ledger) — built from the
**real kernel / tenant issuance path** so the chain and receipts are exactly what the
runtime writes. A TEST-ONLY ``meta.json`` sidecar records the expected verdict; the
verifier never reads it (mirrors the single-receipt corpus in ``_generate_receipts.py``).

Determinism note: the kernel path uses wall-clock timestamps + uuid event ids, so the
pack *bytes* are not reproducible. That is intentional — the contract these fixtures pin
is the VERDICT (``test_proofpack_corpus.py`` asserts ``(valid, reasons ⊇ expected)`` via
each pack's ``meta.json``), not the bytes. There is no byte-drift guard here.

The two golden packs (``valid-allow`` signed; ``valid-replay`` unsigned with a replay
tier) are built first, then six failure packs are derived by copying a golden pack and
applying exactly one documented mutation — the "one edit" philosophy of the receipt corpus.

Run from the repo root::

    uv run --package gove-zone --extra dev --extra crypto python \
        packages/gove-zone/tests/fixtures/_generate_proofpacks.py
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    DecisionReceipt,
    Ed25519Signer,
    Kernel,
    ReceiptConsumptionLedger,
    ReplaySideStore,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    evaluate_tenant_action,
)

# Fixed deterministic key material reused from the single-receipt corpus (NOT prod keys).
SEED = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
SIGNER = Ed25519Signer.from_private_bytes(SEED, key_id="fixture-key-1")

COUNCIL = Validator("constitutional-council")
TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ACTOR = "compliance-officer"
AUTHORITY = "tenant-A/write-grant"

# A RuleSetPolicy that ALLOWs ordinary writes (denies only id_rsa) — so every receipt we
# mint is a genuine ALLOW, anchored in the chain. Mirrors the CLI `_proofpack` recipe.
_POLICY_SPEC: dict[str, Any] = {
    "id": "compliance-ruleset/v1",
    "rules": [
        {
            "id": "BLOCK_SSH_KEY_ACCESS",
            "effect": "deny",
            "tools": [ACTION],
            "path_prefix": "id_rsa",
            "reason": "Direct access to SSH keys is strictly forbidden",
        }
    ],
}

PROOFPACKS_DIR = Path(__file__).parent / "proofpacks"


# --- low-level builders ------------------------------------------------------


def _new_policy() -> RuleSetPolicy:
    return RuleSetPolicy.from_dict(_POLICY_SPEC)


def _write_meta(
    pack: Path, *, expected_valid: bool, expected_reasons: list[str], verifier: str
) -> None:
    """Write the TEST-ONLY sidecar. ``verify_proof_pack`` does NOT read this."""
    meta = {
        "expected_valid": expected_valid,
        "expected_reasons": expected_reasons,
        "verifier": verifier,
        "produced_by": "tests/fixtures/_generate_proofpacks.py",
    }
    (pack / "meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _build_signed_allow_pack(pack: Path) -> None:
    """One signed ALLOW receipt, valid chain, anchored, fresh (empty) ledger."""
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "receipts").mkdir(exist_ok=True)
    audit = ChainHashAuditStore(pack / "audit.jsonl")
    store = TenantPolicyStore(pack / "tenant_store")
    store.store_bundle(TENANT, _new_policy())

    receipt = evaluate_tenant_action(
        store=store,
        tenant_id=TENANT,
        requester_tenant_id=TENANT,
        action=ACTION,
        args={"path": "public_report.txt", "content": "all safe"},
        goal="write compliance report",
        execution_boundary=BOUNDARY,
        request_id="req-allow",
        actor=ACTOR,
        validator=COUNCIL,
        authority=AUTHORITY,
        audit_store=audit,
        signer=SIGNER,
    )
    (pack / "receipts" / "allow.json").write_text(receipt.to_json() + "\n", encoding="utf-8")

    # Fresh consumption ledger: the file must EXIST (an empty/missing file is treated as
    # unprovable by the verifier) and verify clean. Empty == nothing consumed == fresh.
    ReceiptConsumptionLedger(pack / "consumed.jsonl")
    (pack / "consumed.jsonl").write_text("", encoding="utf-8")

    # Drop the internal tenant_store scratch dir — not part of the portable pack.
    shutil.rmtree(pack / "tenant_store", ignore_errors=True)

    manifest = {
        "schema_version": "gove-zone/proof-pack/v1",
        "generated_with": "tests/fixtures/_generate_proofpacks.py",
        "receipts": [
            {
                "name": "allow",
                "file": "receipts/allow.json",
                "declared_verdict": "accept",
                "reason_code": None,
            }
        ],
        "audit_chain": "audit.jsonl",
        "replay": None,
        "consumption_ledger": "consumed.jsonl",
    }
    (pack / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _build_replay_pack(pack: Path) -> None:
    """Multi-event chain + policy_bundle + side_store; receipts anchored, replay tier valid."""
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "receipts").mkdir(exist_ok=True)
    audit = ChainHashAuditStore(pack / "audit.jsonl")
    side = ReplaySideStore(pack / "replay_side_store.jsonl")
    policy = _new_policy()
    kernel = Kernel(policy=policy, audit=audit, actor=ACTOR, side_store=side)

    @kernel.tool(ACTION)
    def _write(path: str, content: str) -> int:  # pragma: no cover - exercised via dispatch
        return len(content)

    dispatches = [
        ({"path": "public_report.txt", "content": "first"}, "g-1", "req-1"),
        ({"path": "notes.txt", "content": "second"}, "g-2", "req-2"),
    ]
    prev = audit.last_hash()
    for i, (args, goal, request_id) in enumerate(dispatches, start=1):
        _result, wrap = kernel.dispatch(ACTION, args, goal=goal, path=args["path"])
        # Mint a DecisionReceipt over the kernel's recorded (record, audit_hash). The kernel
        # `Receipt` wrapper is not a DecisionReceipt; from_record produces the portable one,
        # anchored to this exact chain. Unsigned (dev posture) — verifier="none".
        receipt = DecisionReceipt.from_record(
            record=wrap.record,
            audit_hash=wrap.audit_hash,
            previous_audit_hash=prev,
            tenant_id=TENANT,
            execution_boundary=BOUNDARY,
            policy_bundle_id=policy.policy_id,
            policy_hash=policy.version,
            request_id=request_id,
            validator=COUNCIL,
            authority=AUTHORITY,
            expires_at="",
            signer=None,
        )
        (pack / "receipts" / f"r{i}.json").write_text(receipt.to_json() + "\n", encoding="utf-8")
        prev = wrap.audit_hash

    (pack / "policy_bundle.json").write_text(
        json.dumps(policy.to_dict(), indent=2) + "\n", encoding="utf-8"
    )

    manifest = {
        "schema_version": "gove-zone/proof-pack/v1",
        "generated_with": "tests/fixtures/_generate_proofpacks.py",
        "receipts": [
            {
                "name": "r1",
                "file": "receipts/r1.json",
                "declared_verdict": "accept",
                "reason_code": None,
            },
            {
                "name": "r2",
                "file": "receipts/r2.json",
                "declared_verdict": "accept",
                "reason_code": None,
            },
        ],
        "audit_chain": "audit.jsonl",
        "replay": {
            "policy_bundle": "policy_bundle.json",
            "side_store": "replay_side_store.jsonl",
        },
        "consumption_ledger": None,
    }
    (pack / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


# --- mutation helpers (one documented edit per failure pack) -----------------


def _copy_pack(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def _load_manifest(pack: Path) -> dict[str, Any]:
    return json.loads((pack / "manifest.json").read_text(encoding="utf-8"))


def _dump_manifest(pack: Path, manifest: dict[str, Any]) -> None:
    (pack / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


# --- corpus ------------------------------------------------------------------


def write_proofpacks(dest_dir: str | Path) -> int:
    """Generate the full proof-pack matrix into ``dest_dir/<pack-name>/``.

    Returns the number of packs written.
    """
    root = Path(dest_dir)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    def _drop_lock_files() -> None:
        # The audit / ledger stores create transient ``*.lock`` files for their
        # cross-process file lock. They are runtime scratch, never part of the
        # portable pack — strip them so the committed corpus is clean.
        for lock in root.rglob("*.lock"):
            lock.unlink(missing_ok=True)

    # --- Golden packs --------------------------------------------------------
    _build_signed_allow_pack(root / "valid-allow")
    _write_meta(
        root / "valid-allow",
        expected_valid=True,
        expected_reasons=[],
        verifier="trusted",
    )

    _build_replay_pack(root / "valid-replay")
    _write_meta(
        root / "valid-replay",
        expected_valid=True,
        expected_reasons=[],
        verifier="none",
    )

    # --- tampered-receipt: hand-edit one bound field WITHOUT recomputing hash.
    # Pack CLAIMS accept; verify() rejects on the hash binding.
    tampered = root / "tampered-receipt"
    _copy_pack(root / "valid-allow", tampered)
    rpath = tampered / "receipts" / "allow.json"
    receipt_json = json.loads(rpath.read_text(encoding="utf-8"))
    receipt_json["actor"] = "attacker"  # bound into receipt_hash; not recomputed
    rpath.write_text(json.dumps(receipt_json, indent=2) + "\n", encoding="utf-8")
    _write_meta(
        tampered,
        expected_valid=False,
        expected_reasons=["RECEIPT_UNEXPECTED_REJECT", "RECEIPT_HASH_MISMATCH"],
        verifier="trusted",
    )

    # --- chain-break: flip one event_hash char in a chain line (the receipt is intact).
    chain_break = root / "chain-break"
    _copy_pack(root / "valid-allow", chain_break)
    audit_path = chain_break / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    target = json.loads(lines[0])
    recorded = target["event_hash"]
    flipped = ("0" if recorded[0] != "0" else "f") + recorded[1:]
    lines[0] = lines[0].replace(recorded, flipped)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _write_meta(
        chain_break,
        expected_valid=False,
        expected_reasons=["AUDIT_CHAIN_BROKEN"],
        verifier="trusted",
    )

    # --- replay-mismatch: tamper a side-store arg so re-derivation diverges.
    replay_mismatch = root / "replay-mismatch"
    _copy_pack(root / "valid-replay", replay_mismatch)
    side_path = replay_mismatch / "replay_side_store.jsonl"
    entries = [json.loads(line) for line in side_path.read_text(encoding="utf-8").splitlines()]
    for entry in entries:
        if entry.get("args", {}).get("path") == "public_report.txt":
            entry["args"]["path"] = "tampered.txt"
    side_path.write_text(
        "".join(
            json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            for e in entries
        ),
        encoding="utf-8",
    )
    _write_meta(
        replay_mismatch,
        expected_valid=False,
        expected_reasons=["REPLAY_MISMATCH"],
        verifier="none",
    )

    # --- replayed: a fresh ledger that ALREADY burns the accept receipt's anchor.
    replayed = root / "replayed"
    _copy_pack(root / "valid-allow", replayed)
    ledger_path = replayed / "consumed.jsonl"
    ledger_path.unlink(missing_ok=True)
    ledger = ReceiptConsumptionLedger(ledger_path)
    accept = DecisionReceipt.from_json(
        (replayed / "receipts" / "allow.json").read_text(encoding="utf-8")
    )
    ledger.consume(accept)  # burns audit_event_hash during generation
    _write_meta(
        replayed,
        expected_valid=False,
        expected_reasons=["RECEIPT_ALREADY_USED"],
        verifier="trusted",
    )

    # --- missing-receipt: manifest lists a file that is absent on disk.
    missing = root / "missing-receipt"
    _copy_pack(root / "valid-allow", missing)
    (missing / "receipts" / "allow.json").unlink()
    _write_meta(
        missing,
        expected_valid=False,
        expected_reasons=["RECEIPT_FILE_MISSING"],
        verifier="trusted",
    )

    # --- stale-schema: manifest schema_version pinned to the unsupported v0.
    stale = root / "stale-schema"
    _copy_pack(root / "valid-allow", stale)
    manifest = _load_manifest(stale)
    manifest["schema_version"] = "gove-zone/proof-pack/v0"
    _dump_manifest(stale, manifest)
    _write_meta(
        stale,
        expected_valid=False,
        expected_reasons=["SCHEMA_VERSION_UNSUPPORTED"],
        verifier="trusted",
    )

    # --- sig-downgrade-with-verifier: the trust-anchor negative path. Downgrade the
    # signed accept receipt to UNSIGNED (algorithm="none") and RECOMPUTE its hash so
    # binding_intact holds — a forgery that strips the signature yet looks intact. With
    # the relying party's verifier supplied, an unsigned accept MUST be rejected
    # (UNSIGNED_REJECTED); deriving the signature requirement from the receipt alone
    # would fail OPEN here. Regression guard for the governance-review BLOCKER.
    downgrade = root / "sig-downgrade-with-verifier"
    _copy_pack(root / "valid-allow", downgrade)
    rpath = downgrade / "receipts" / "allow.json"
    original = DecisionReceipt.from_json(rpath.read_text(encoding="utf-8"))
    stripped = dataclasses.replace(
        original,
        signature_algorithm="none",
        signing_key_id="",
        signature="unsigned_local",
        receipt_hash="",
    )
    rehashed = dataclasses.replace(stripped, receipt_hash=stripped.compute_hash())
    rpath.write_text(rehashed.to_json() + "\n", encoding="utf-8")
    _write_meta(
        downgrade,
        expected_valid=False,
        expected_reasons=["RECEIPT_UNEXPECTED_REJECT", "UNSIGNED_REJECTED"],
        verifier="trusted",
    )

    _drop_lock_files()
    return sum(1 for p in root.iterdir() if p.is_dir())


if __name__ == "__main__":
    n = write_proofpacks(PROOFPACKS_DIR)
    print(f"wrote {n} proof packs to {PROOFPACKS_DIR}")
