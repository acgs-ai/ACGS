"""CLI replay contract tests."""

from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path

import pytest

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionRecord,
    DeniedError,
    Kernel,
    RuleSetPolicy,
    sha256_json,
)
from gove_zone.cli import main
from gove_zone.replay_store import ReplaySideStore


def _record(event_id: str) -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.ALLOW,
        tool="write_file",
        argument_hash=sha256_json({"id": event_id}),
        policy_version="v0",
        event_id=event_id,
    )


def test_pyproject_installs_gove_zone_cli() -> None:
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    assert data["project"]["scripts"]["gove-zone"] == "gove_zone.cli:main"


def test_cli_defines_expected_commands() -> None:
    from gove_zone.cli import build_parser

    parser = build_parser()
    # Find the subparsers action
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    commands = list(subparsers_action.choices.keys())
    expected = [
        "doctor",
        "smoke",
        "gate",
        "validate",
        "replay",
        "setup",
        "enable",
        "policy",
        "eval",
        "proofpack",
    ]
    for cmd in expected:
        assert cmd in commands


def test_cli_replay_accepts_frontend_command_shape(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["replay", "--event", "ev_1", "--audit-hash", "abc"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_id"] == "ev_1"
    assert payload["expected_audit_hash"] == "abc"
    assert payload["status"] == "hash-only"


def test_cli_replay_verifies_audit_event_when_path_supplied(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "audit.jsonl"
    event = ChainHashAuditStore(path).append(_record("ev_1"))

    exit_code = main(
        [
            "replay",
            "--event",
            "ev_1",
            "--audit",
            str(path),
            "--audit-hash",
            event["event_hash"],
        ]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "verified"
    assert payload["verified"] is True
    assert payload["chain_valid"] is True
    assert payload["actual_audit_hash"] == event["event_hash"]


def test_cli_proofpack_generates_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Run in tmp_path directory to avoid dirtying local directory
    monkeypatch.chdir(tmp_path)
    exit_code = main(["proofpack"])

    assert exit_code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["status"] == "pass"

    dist_dir = tmp_path / "dist-govern-zone-proofpack"
    assert dist_dir.is_dir()
    assert (dist_dir / "manifest.json").is_file()
    assert (dist_dir / "audit.jsonl").is_file()
    assert (dist_dir / "verification.json").is_file()
    assert (dist_dir / "conformance-results.json").is_file()
    assert (dist_dir / "limitations.md").is_file()

    receipts_dir = dist_dir / "receipts"
    assert receipts_dir.is_dir()
    assert (receipts_dir / "allowed_receipt.json").is_file()
    assert (receipts_dir / "denied_receipt.json").is_file()
    assert (receipts_dir / "transformed_receipt.json").is_file()

    results = payload["results"]
    assert results["allowed_action_executed"] is True
    assert results["denied_action_blocked"] is True
    assert results["transformed_action_executed"] is True
    assert results["missing_receipt_blocked"] is True
    assert results["tampered_receipt_blocked"] is True
    assert results["audit_chain_verified"] is True


def test_cli_proofpack_roundtrip_verifies(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`proofpack` must emit a manifest the offline verifier accepts (round-trip).

    Regression guard: the generator's manifest historically carried only a flat
    ``files`` array and no structured ``receipts``, so ``verify-proofpack`` read
    zero receipts and returned ``valid=false`` (exit 1). This proves the real
    generate->verify loop closes on the unsigned dev pack with no ``--verifier-key``.
    """
    import shutil

    monkeypatch.chdir(tmp_path)
    gen_code = main(["proofpack"])
    assert gen_code == 0
    capsys.readouterr()  # drain the generator's emitted JSON

    dist_dir = tmp_path / "dist-govern-zone-proofpack"
    try:
        verify_code = main(["verify-proofpack", "dist-govern-zone-proofpack"])
        assert verify_code == 0

        result = json.loads(capsys.readouterr().out)
        assert result["valid"] is True
        assert result["reasons"] == []
        # Every declared verdict matched what the verifier observed.
        assert all(r["matches_declared"] is True for r in result["receipts"])
    finally:
        shutil.rmtree(dist_dir, ignore_errors=True)


def _write_replay_bundle(tmp_path: Path) -> Path:
    bundle_path = tmp_path / "policy.bundle.json"
    bundle_path.write_text(
        json.dumps(
            {
                "id": "replay-test/v1",
                "rules": [
                    {
                        "id": "BLOCK_SECRETS",
                        "effect": "deny",
                        "tools": ["write"],
                        "path_prefix": "repo/secrets",
                        "reason": "secret paths are blocked",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return bundle_path


def _seed_chain_and_side_store(
    tmp_path: Path,
    *,
    args: dict[str, object],
    path: str,
) -> tuple[Path, Path, Path, str]:
    """Dispatch one call through a kernel with a side-store; return paths + id."""
    bundle_path = _write_replay_bundle(tmp_path)
    audit_path = tmp_path / "audit.jsonl"
    side_path = tmp_path / "replay.jsonl"
    policy = RuleSetPolicy.load(bundle_path)
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(audit_path),
        side_store=ReplaySideStore(side_path),
    )

    @k.tool("write")
    def write(**kwargs: object) -> str:
        return "ok"

    try:
        _, receipt = k.dispatch("write", args, path=path)
        event_id = receipt.record.event_id
    except DeniedError as exc:
        event_id = exc.record.event_id
    return audit_path, side_path, bundle_path, event_id


def test_cli_replay_rederivation_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, side_path, bundle_path, event_id = _seed_chain_and_side_store(
        tmp_path, args={"content": "safe"}, path="repo/public/file"
    )

    rc = main(
        [
            "replay",
            "--event",
            event_id,
            "--audit",
            str(audit_path),
            "--side-store",
            str(side_path),
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["rederived"] is True
    assert payload["rederivation_status"] == "verified"
    assert payload["replayed_decision"] == "allow"
    assert payload["policy_version_match"] is True


def test_cli_replay_deny_rederivation_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, side_path, bundle_path, event_id = _seed_chain_and_side_store(
        tmp_path, args={"content": "secret"}, path="repo/secrets/key"
    )

    rc = main(
        [
            "replay",
            "--event",
            event_id,
            "--audit",
            str(audit_path),
            "--side-store",
            str(side_path),
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["rederived"] is True
    assert payload["rederivation_status"] == "verified"
    assert payload["replayed_decision"] == "deny"


def test_cli_replay_no_side_record(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit_path, side_path, bundle_path, event_id = _seed_chain_and_side_store(
        tmp_path, args={"content": "safe"}, path="repo/public/file"
    )
    # An event that exists in the chain but not the side-store.
    empty_side = tmp_path / "empty-replay.jsonl"

    rc = main(
        [
            "replay",
            "--event",
            event_id,
            "--audit",
            str(audit_path),
            "--side-store",
            str(empty_side),
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["rederivation_status"] == "no-side-record"
    assert payload["rederived"] is False
    assert payload["chain_valid"] is True
    assert rc == 0  # chain verified; re-derivation not attempted


def test_cli_replay_redacted_event(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle_path = _write_replay_bundle(tmp_path)
    audit_path = tmp_path / "audit.jsonl"
    side_path = tmp_path / "replay.jsonl"
    policy = RuleSetPolicy.load(bundle_path)
    k = Kernel(
        policy=policy,
        audit=ChainHashAuditStore(audit_path),
        side_store=ReplaySideStore(side_path, redact=lambda c: True),
    )

    @k.tool("write")
    def write(**kwargs: object) -> str:
        return "ok"

    _, receipt = k.dispatch("write", {"content": "safe"}, path="repo/public/file")

    rc = main(
        [
            "replay",
            "--event",
            receipt.record.event_id,
            "--audit",
            str(audit_path),
            "--side-store",
            str(side_path),
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["rederivation_status"] == "redacted"
    assert payload["rederived"] is False
    assert rc == 0


def test_cli_replay_bad_policy_bundle_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, side_path, _bundle, event_id = _seed_chain_and_side_store(
        tmp_path, args={"content": "safe"}, path="repo/public/file"
    )
    bad_bundle = tmp_path / "bad.json"
    bad_bundle.write_text("{ not valid json", encoding="utf-8")

    rc = main(
        [
            "replay",
            "--event",
            event_id,
            "--audit",
            str(audit_path),
            "--side-store",
            str(side_path),
            "--policy-bundle",
            str(bad_bundle),
        ]
    )

    assert rc == 2
    err = capsys.readouterr().err
    assert "failed to load policy bundle" in err


def test_cli_replay_backward_compatible_without_new_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, _side, _bundle, event_id = _seed_chain_and_side_store(
        tmp_path, args={"content": "safe"}, path="repo/public/file"
    )

    rc = main(["replay", "--event", event_id, "--audit", str(audit_path)])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["status"] == "verified"
    assert payload["verified"] is True
    # No re-derivation keys leak into the today-keys-only path.
    assert "rederived" not in payload
    assert "rederivation_status" not in payload


def test_cli_replay_tamper_argument_hash_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, side_path, bundle_path, event_id = _seed_chain_and_side_store(
        tmp_path, args={"content": "safe"}, path="repo/public/file"
    )
    # Mutate the side-store record's args only; the chain stays intact.
    record = ReplaySideStore(side_path).get(event_id)
    assert record is not None
    record["args"] = {"content": "tampered"}
    side_path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    rc = main(
        [
            "replay",
            "--event",
            event_id,
            "--audit",
            str(audit_path),
            "--side-store",
            str(side_path),
            "--policy-bundle",
            str(bundle_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["rederivation_status"] == "argument-hash-mismatch"
    assert payload["rederived"] is False
    assert rc != 0


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """--version is part of complete CLI surface (PR 1 acceptance)."""
    from gove_zone import __version__

    # action=version causes SystemExit(0) after printing to stdout
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0

    out = capsys.readouterr().out
    assert f"gove-zone {__version__}" in out


# --- verify-ledger: tamper-evidence verification surface ----------------------


class _LedgerReceipt:
    """Minimal stand-in exposing only what ``consume`` reads."""

    def __init__(self, anchor: str) -> None:
        self.audit_event_hash = anchor
        self.request_id = "req"
        self.tenant_id = "tenant"
        self.actor = "agent"
        self.proposed_action = "write_file"

    def compute_hash(self) -> str:
        return "rh-" + self.audit_event_hash[:8]


def _seed_ledger(path: Path, n: int):
    from gove_zone import ReceiptConsumptionLedger

    ledger = ReceiptConsumptionLedger(path)
    for i in range(n):
        ledger.consume(_LedgerReceipt(str(i).ljust(64, "0")))
    return ledger


def test_cli_verify_ledger_registered() -> None:
    # Handler-wiring: the verb must be registered on the parser, not just defined.
    from gove_zone.cli import build_parser

    parser = build_parser()
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert "verify-ledger" in subparsers_action.choices


def test_cli_verify_ledger_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "consumed.jsonl"
    _seed_ledger(path, 3)
    rc = main(["verify-ledger", "--ledger", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["valid"] is True
    assert payload["checked"] == 3
    assert payload["unverified_legacy"] == 0


def test_cli_verify_ledger_detects_tamper(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "consumed.jsonl"
    _seed_ledger(path, 3)
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    # Drop the middle entry: a non-zero exit and a recorded failure.
    path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in [records[0], records[2]]),
        encoding="utf-8",
    )
    rc = main(["verify-ledger", "--ledger", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["valid"] is False
    assert payload["failures"]


def test_cli_verify_ledger_corrupt_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "consumed.jsonl"
    path.write_text("this is not json\n", encoding="utf-8")
    rc = main(["verify-ledger", "--ledger", str(path)])
    assert rc == 2
    assert "verify-ledger" in capsys.readouterr().err


def test_cli_verify_ledger_missing_file_is_empty_valid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "never-written.jsonl"
    rc = main(["verify-ledger", "--ledger", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["checked"] == 0
    assert payload["valid"] is True


def _seed_audit_and_ledger(tmp_path: Path, forged: bool):
    from gove_zone import ChainHashAuditStore, ReceiptConsumptionLedger

    audit_path = tmp_path / "audit.jsonl"
    ledger_path = tmp_path / "consumed.jsonl"
    audit = ChainHashAuditStore(audit_path)
    real = [audit.append(_record(f"ev{i}"))["event_hash"] for i in range(2)]
    ledger = ReceiptConsumptionLedger(ledger_path)
    ledger.consume(_LedgerReceipt(real[0]))
    ledger.consume(_LedgerReceipt("f" * 64 if forged else real[1]))
    return audit_path, ledger_path


def test_cli_verify_ledger_reconcile_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, ledger_path = _seed_audit_and_ledger(tmp_path, forged=False)
    rc = main(["verify-ledger", "--ledger", str(ledger_path), "--audit", str(audit_path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["reconcile"]["valid"] is True
    assert payload["reconcile"]["checked"] == 2
    assert payload["reconcile"]["unmatched"] == []


def test_cli_verify_ledger_reconcile_detects_forged_burn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit_path, ledger_path = _seed_audit_and_ledger(tmp_path, forged=True)
    rc = main(["verify-ledger", "--ledger", str(ledger_path), "--audit", str(audit_path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["reconcile"]["valid"] is False
    assert any(u["consumed_key"] == "f" * 64 for u in payload["reconcile"]["unmatched"])


def _generate_proofpacks(dest: Path) -> Path:
    import importlib.util

    gen_path = Path(__file__).parent / "fixtures" / "_generate_proofpacks.py"
    spec = importlib.util.spec_from_file_location("_proofpack_gen_cli", gen_path)
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.write_proofpacks(dest)
    return dest


def test_cli_verify_proofpack_valid_pack_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("cryptography")
    packs = _generate_proofpacks(tmp_path / "packs")
    # valid-replay ships unsigned (dev-posture) receipts, so the CLI's no-verifier
    # path accepts it. A SIGNED pack from the CLI is covered separately, with an
    # out-of-band --verifier-key, in test_cli_verify_proofpack_signed_with_key.
    rc = main(["verify-proofpack", str(packs / "valid-replay")])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["valid"] is True
    assert payload["reasons"] == []


def test_cli_verify_proofpack_signed_with_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A SIGNED proof-pack verifies from the CLI when the relying party supplies the
    public key OUT-OF-BAND (--verifier-key). The same pack without a key fails closed
    (SIGNED_RECEIPT_NO_VERIFIER) — proving the trust anchor is load-bearing, not cosmetic.
    """
    import hashlib

    from gove_zone import Ed25519Signer

    pytest.importorskip("cryptography")
    packs = _generate_proofpacks(tmp_path / "packs")
    # Reconstruct the committed fixture public key from its known seed (NOT shipped
    # in the pack — that would be the trust-anchor circularity of docs/PROOF_PATH.md).
    seed = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
    pub = Ed25519Signer.from_private_bytes(seed, key_id="fixture-key-1").public_bytes()
    keyfile = tmp_path / "trusted.pub"
    keyfile.write_bytes(pub)

    # With the out-of-band key → valid, exit 0.
    rc = main(
        [
            "verify-proofpack",
            str(packs / "valid-allow"),
            "--verifier-key",
            str(keyfile),
            "--key-id",
            "fixture-key-1",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload
    assert payload["valid"] is True
    assert payload["signature_verified"] is True

    # Without the key → fail closed.
    rc = main(["verify-proofpack", str(packs / "valid-allow")])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["valid"] is False
    assert "SIGNED_RECEIPT_NO_VERIFIER" in payload["reasons"]


def test_cli_verify_proofpack_revoked_key_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A signed pack whose signing key is on an out-of-band --revoked-keys list fails
    closed (SIGNING_KEY_REVOKED, exit 1), even though the signature itself is valid —
    proving revocation is applied OFFLINE by the verify-proofpack CLI (B4-c).
    """
    import hashlib

    from gove_zone import Ed25519Signer

    pytest.importorskip("cryptography")
    packs = _generate_proofpacks(tmp_path / "packs")
    seed = hashlib.sha256(b"gove-zone fixture corpus v1 :: trusted").digest()
    pub = Ed25519Signer.from_private_bytes(seed, key_id="fixture-key-1").public_bytes()
    keyfile = tmp_path / "trusted.pub"
    keyfile.write_bytes(pub)
    revoked = tmp_path / "revoked.json"
    revoked.write_text(json.dumps(["fixture-key-1"]), encoding="utf-8")

    # Same valid signed pack as test_cli_verify_proofpack_signed_with_key, now with the
    # signing key revoked → rejected.
    rc = main(
        [
            "verify-proofpack",
            str(packs / "valid-allow"),
            "--verifier-key",
            str(keyfile),
            "--key-id",
            "fixture-key-1",
            "--revoked-keys",
            str(revoked),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1, payload
    assert payload["valid"] is False
    assert "SIGNING_KEY_REVOKED" in payload["reasons"]

    # Sanity: WITHOUT --revoked-keys the same invocation is valid (off-by-default).
    rc = main(
        [
            "verify-proofpack",
            str(packs / "valid-allow"),
            "--verifier-key",
            str(keyfile),
            "--key-id",
            "fixture-key-1",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload
    assert payload["valid"] is True


def test_cli_verify_proofpack_malformed_revoked_keys_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A malformed --revoked-keys list must fail closed (exit 2), never silently
    degrade to 'no revocation applied' — same posture as a bad --verifier-key.
    """
    pytest.importorskip("cryptography")
    packs = _generate_proofpacks(tmp_path / "packs")
    bad = tmp_path / "bad-revoked.json"
    bad.write_text("{ not a json array", encoding="utf-8")

    rc = main(["verify-proofpack", str(packs / "valid-replay"), "--revoked-keys", str(bad)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "cannot load --revoked-keys" in captured.err


def test_cli_verify_proofpack_tampered_pack_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("cryptography")
    packs = _generate_proofpacks(tmp_path / "packs")
    rc = main(["verify-proofpack", str(packs / "tampered-receipt")])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["valid"] is False
    assert "RECEIPT_HASH_MISMATCH" in payload["reasons"]
