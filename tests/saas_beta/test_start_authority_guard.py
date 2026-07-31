"""Focused tests for the clean-sibling P3C start-authority guard.

These tests use synthetic owner-issued capabilities only. They never request,
write, log, or derive the production private key, and they must not launch the
authoritative P3C proof corpus.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest

CRYPTO_SERIALIZATION: Any = None
CRYPTO_ED25519_PRIVATE_KEY: Any = None
try:
    from cryptography.hazmat.primitives import serialization as _cryptography_serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _cryptography_ed25519_private_key,
    )
except ModuleNotFoundError:  # pragma: no cover - exercised when root uv env omits cryptography.
    pass
else:
    CRYPTO_SERIALIZATION = _cryptography_serialization
    CRYPTO_ED25519_PRIVATE_KEY = _cryptography_ed25519_private_key

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/evidence/start_authority_guard.py"
LAUNCHER = ROOT / "scripts/evidence/prove_clean_sibling"
sys.path.insert(0, str(HELPER.parent))

import start_authority_guard  # noqa: E402

P = "a2299d510d792dd04646204653e405e0485204a6"
T = "b" * 40
NODE_ID = "P3-APPROVAL-003C"


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity(path: Path) -> dict[str, Any]:
    return start_authority_guard._identity_from_stat(path.resolve(strict=True), os.lstat(path))


def _key_material() -> dict[str, str | bytes]:
    seed = hashlib.sha256(b"synthetic start authority fixture key").digest()
    public_key = _public_key(seed)
    return {
        "private": seed,
        "public_hex": public_key.hex(),
        "issuer_key_id": hashlib.sha256(public_key).hexdigest(),
    }


def _cryptography_subprocess(operation: str, private_key: bytes, message: bytes = b"") -> bytes:
    script = r"""
import json
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

request = json.load(sys.stdin)
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(request["private_key"]))
if request["operation"] == "public":
    result = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
elif request["operation"] == "sign":
    result = key.sign(bytes.fromhex(request["message"]))
else:
    raise SystemExit("unsupported operation")
print(result.hex())
"""
    completed = subprocess.run(
        ["uv", "run", "--with", "cryptography", "python", "-c", script],
        input=json.dumps(
            {
                "operation": operation,
                "private_key": private_key.hex(),
                "message": message.hex(),
            }
        ),
        text=True,
        capture_output=True,
        check=True,
    )
    return bytes.fromhex(completed.stdout.strip())


def _public_key(private_key: bytes) -> bytes:
    if CRYPTO_ED25519_PRIVATE_KEY is None or CRYPTO_SERIALIZATION is None:
        return _cryptography_subprocess("public", private_key)
    key = CRYPTO_ED25519_PRIVATE_KEY.from_private_bytes(private_key)
    return key.public_key().public_bytes(
        encoding=CRYPTO_SERIALIZATION.Encoding.Raw,
        format=CRYPTO_SERIALIZATION.PublicFormat.Raw,
    )


def _sign(private_key: bytes, message: bytes) -> bytes:
    if CRYPTO_ED25519_PRIVATE_KEY is None:
        return _cryptography_subprocess("sign", private_key, message)
    return CRYPTO_ED25519_PRIVATE_KEY.from_private_bytes(private_key).sign(message)


def _authority_fixture(
    tmp_path: Path,
    *,
    authority_id: str = "auth.p3c.test",
    attempt_id: str = "attempt-1",
    claims_mutation: Any | None = None,
    envelope_mutation: Any | None = None,
    test_faults_allowed: bool = False,
) -> dict[str, Any]:
    key = _key_material()
    authority_root = (tmp_path / "owner-authority").resolve()
    tmpdir = (tmp_path / "caller-tmpdir").resolve()
    authority_root.mkdir(mode=0o700, parents=True)
    tmpdir.mkdir(mode=0o700, parents=True)
    for dirname in ("issued", "spent", "outcomes"):
        (authority_root / dirname).mkdir(mode=0o700)
    now = int(time.time())
    root_identity = _identity(authority_root)
    tmpdir_identity = _identity(tmpdir)
    claims: dict[str, Any] = {
        "schema": start_authority_guard.SCHEMA,
        "version": 1,
        "authority_id": authority_id,
        "nonce": "nonce-for-start-authority-test",
        "approval_id": start_authority_guard.OWNER_APPROVAL_ID,
        "issuer_key_id": key["issuer_key_id"],
        "action": "start-proof",
        "node_id": NODE_ID,
        "p": P,
        "t": T,
        "authority_root_path": str(authority_root),
        "authority_root_identity": root_identity,
        "tmpdir_path": str(tmpdir),
        "tmpdir_identity": tmpdir_identity,
        "repo_path": str(ROOT.resolve()),
        "git_identity": start_authority_guard._git_identity(ROOT),
        "launcher_path": str(LAUNCHER.resolve()),
        "launcher_sha256": _sha256(LAUNCHER),
        "helper_path": str(HELPER.resolve()),
        "helper_sha256": _sha256(HELPER),
        "issued_at": now - 5,
        "expires_at": now + start_authority_guard.MAX_CAPABILITY_LIFETIME_SECONDS - 5,
        "expected_uid": os.getuid(),
        "expected_gid": os.getgid(),
        "attempt_id": attempt_id,
        "expected_terminal_artifact": str(
            authority_root / "outcomes" / f"{authority_id}.terminal.json"
        ),
        "scope": "supported-current-clean-sibling-launcher-only",
    }
    if test_faults_allowed:
        claims["test_faults_allowed"] = True
    if claims_mutation is not None:
        claims_mutation(claims)
    signature = _sign(cast(bytes, key["private"]), _canonical_json(claims)).hex()
    document = {"claims": claims, "signature": signature}
    if envelope_mutation is not None:
        envelope_mutation(document)
    capability = authority_root / "issued" / f"{authority_id}.json"
    capability.write_bytes(_canonical_json(document) + b"\n")
    capability.chmod(0o600)
    return {
        "authority_root": authority_root,
        "tmpdir": tmpdir,
        "authority_id": authority_id,
        "attempt_id": attempt_id,
        "capability": capability,
        "public_hex": key["public_hex"],
        "issuer_key_id": key["issuer_key_id"],
        "root_identity": root_identity,
    }


def _consume(context: dict[str, Any], *, attempt_id: str | None = None) -> dict[str, Any]:
    return start_authority_guard.consume_authority(
        authority_id=context["authority_id"],
        authority_root=context["authority_root"],
        repo_path=ROOT,
        tmpdir=context["tmpdir"],
        node_id=NODE_ID,
        p_commit=P,
        t_commit=T,
        launcher_path=LAUNCHER,
        helper_path=HELPER,
        attempt_id=attempt_id or context["attempt_id"],
        public_key_raw_hex=context["public_hex"],
        issuer_key_id=context["issuer_key_id"],
    )


def _assert_guard_rejects(context: dict[str, Any], reason: str) -> None:
    with pytest.raises(start_authority_guard.GuardError, match=reason):
        _consume(context)
    assert not list((context["tmpdir"]).rglob("*proof*"))


def _record_terminal(
    context: dict[str, Any], consume_result: dict[str, Any], **overrides: Any
) -> None:
    kwargs = {
        "authority_id": context["authority_id"],
        "authority_root": consume_result["authority_root_path"],
        "authority_root_identity": consume_result["authority_root_identity"],
        "attempt_id": consume_result["attempt_id"],
        "outcome": "SUCCEEDED",
        "exit_code": 0,
        "reason": "synthetic success",
        "spent_record_sha256": consume_result["spent_record_sha256"],
    }
    kwargs.update(overrides)
    start_authority_guard.record_terminal(**kwargs)


def test_start_authority_guard_libcrypto_verifies_independent_ed25519_signature() -> None:
    key = _key_material()
    message = b"RFC8032-style independent signing oracle"
    signature = _sign(cast(bytes, key["private"]), message)
    public_key = bytes.fromhex(cast(str, key["public_hex"]))

    verifier = start_authority_guard._LibCrypto()
    assert verifier.verify_ed25519(public_key, signature, message)

    bad_signature = bytearray(signature)
    bad_signature[0] ^= 1
    assert not verifier.verify_ed25519(public_key, bytes(bad_signature), message)

    bad_message = bytearray(message)
    bad_message[-1] ^= 1
    assert not verifier.verify_ed25519(public_key, signature, bytes(bad_message))

    bad_public_key = bytearray(public_key)
    bad_public_key[0] ^= 1
    assert not verifier.verify_ed25519(bytes(bad_public_key), signature, message)


def test_start_authority_guard_production_issuer_key_id_is_public_key_sha256() -> None:
    assert (
        hashlib.sha256(
            bytes.fromhex(start_authority_guard.PRODUCTION_PUBLIC_KEY_RAW_HEX)
        ).hexdigest()
        == start_authority_guard.PRODUCTION_ISSUER_KEY_ID
    )


def test_start_authority_guard_consumes_once_and_records_terminal(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    result = _consume(context)
    spent = context["authority_root"] / "spent" / f"{context['authority_id']}.spent.json"
    spent_record = json.loads(spent.read_text(encoding="ascii"))
    assert spent_record["schema"] == start_authority_guard.SPENT_SCHEMA
    assert spent_record["approval_id"] == start_authority_guard.OWNER_APPROVAL_ID
    assert spent_record["issuer_key_id"] == context["issuer_key_id"]
    assert spent_record["attempt_id"] == "attempt-1"
    assert spent_record["promise"] == "at-most-once-authorized-attempt"
    assert result["spent_record_sha256"] == hashlib.sha256(spent.read_bytes()).hexdigest()

    _record_terminal(context, result)
    terminal = context["authority_root"] / "outcomes" / f"{context['authority_id']}.terminal.json"
    terminal_record = json.loads(terminal.read_text(encoding="ascii"))
    assert terminal_record["outcome"] == "SUCCEEDED"
    assert terminal_record["spent_record_sha256"] == result["spent_record_sha256"]


def test_start_authority_guard_concurrent_double_start_has_one_winner(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)

    def run(index: int) -> str:
        try:
            _consume(context, attempt_id=f"attempt-{index}")
            return "winner"
        except start_authority_guard.GuardError as exc:
            assert "attempt" in str(exc) or "already spent" in str(exc)
            return "loser"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run, (1, 1)))
    assert sorted(results) == ["loser", "winner"]
    assert len(list((context["authority_root"] / "spent").glob("*.spent.json"))) == 1


@pytest.mark.parametrize("outcome", ["SUCCEEDED", "FAILED"])
def test_start_authority_guard_replay_after_terminal_result_stays_spent(
    tmp_path: Path,
    outcome: str,
) -> None:
    context = _authority_fixture(tmp_path)
    result = _consume(context)
    _record_terminal(
        context,
        result,
        outcome=outcome,
        exit_code=0 if outcome == "SUCCEEDED" else 2,
    )
    _assert_guard_rejects(context, "already spent")


def test_start_authority_guard_absent_terminal_after_kill_stays_spent(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    _consume(context)
    assert not list((context["authority_root"] / "outcomes").glob("*.terminal.json"))
    _assert_guard_rejects(context, "already spent")


@pytest.mark.parametrize(
    "fault",
    ["after-spent-create", "after-spent-write", "after-spent-file-fsync"],
)
def test_start_authority_guard_fault_after_consume_never_rearms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    context = _authority_fixture(tmp_path, test_faults_allowed=True)
    monkeypatch.setenv(start_authority_guard.FAULT_ENV, fault)
    _assert_guard_rejects(context, "injected fault")
    monkeypatch.delenv(start_authority_guard.FAULT_ENV)
    _assert_guard_rejects(context, "already spent")


@pytest.mark.parametrize(
    ("case_name", "mutate", "reason"),
    [
        (
            "wrong-approval",
            lambda claims: claims.__setitem__("approval_id", "P3-APPROVAL-003C"),
            "approval",
        ),
        ("wrong-action", lambda claims: claims.__setitem__("action", "run-proof"), "action"),
        ("wrong-issuer", lambda claims: claims.__setitem__("issuer_key_id", "0" * 64), "issuer"),
        ("wrong-node", lambda claims: claims.__setitem__("node_id", "P3-APPROVAL-003B"), "node"),
        ("wrong-p", lambda claims: claims.__setitem__("p", "c" * 40), "P binding"),
        ("wrong-t", lambda claims: claims.__setitem__("t", "d" * 40), "T binding"),
        ("wrong-worktree", lambda claims: claims.__setitem__("repo_path", "/"), "worktree"),
        ("wrong-git", lambda claims: claims.__setitem__("git_identity", {}), "git"),
        ("wrong-root-id", lambda claims: claims.__setitem__("authority_root_identity", {}), "root"),
        ("wrong-tmp", lambda claims: claims.__setitem__("tmpdir_identity", {}), "TMPDIR"),
        (
            "wrong-launcher",
            lambda claims: claims.__setitem__("launcher_sha256", "0" * 64),
            "launcher",
        ),
        ("wrong-helper", lambda claims: claims.__setitem__("helper_sha256", "0" * 64), "helper"),
        (
            "future-issued",
            lambda claims: claims.__setitem__(
                "issued_at",
                int(time.time()) + start_authority_guard.MAX_ISSUED_AT_FUTURE_SKEW_SECONDS + 1,
            ),
            "future",
        ),
        (
            "expired",
            lambda claims: claims.__setitem__("expires_at", int(time.time()) - 1),
            "expiry",
        ),
        (
            "overlong-lifetime",
            lambda claims: claims.__setitem__(
                "expires_at",
                claims["issued_at"] + start_authority_guard.MAX_CAPABILITY_LIFETIME_SECONDS + 1,
            ),
            "lifetime",
        ),
        (
            "wrong-uid",
            lambda claims: claims.__setitem__("expected_uid", os.getuid() + 1000),
            "uid/gid",
        ),
        ("wrong-attempt", lambda claims: claims.__setitem__("attempt_id", "attempt-2"), "attempt"),
        (
            "wrong-terminal",
            lambda claims: claims.__setitem__(
                "expected_terminal_artifact", "/outside/terminal.json"
            ),
            "terminal",
        ),
        (
            "wrong-scope",
            lambda claims: claims.__setitem__("scope", "global-hard-boundary"),
            "scope",
        ),
    ],
)
def test_start_authority_guard_rejects_binding_mismatch(
    tmp_path: Path,
    case_name: str,
    mutate: Any,
    reason: str,
) -> None:
    context = _authority_fixture(tmp_path, claims_mutation=mutate)
    _assert_guard_rejects(context, reason)


def test_start_authority_guard_accepts_small_future_clock_skew(tmp_path: Path) -> None:
    now = int(time.time())
    context = _authority_fixture(
        tmp_path,
        claims_mutation=lambda claims: (
            claims.__setitem__("issued_at", now + 30),
            claims.__setitem__("expires_at", now + 3600),
        ),
    )
    result = _consume(context)
    assert result["authority_id"] == context["authority_id"]


def test_start_authority_guard_rejects_override_issuer_key_id_mismatch(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    with pytest.raises(start_authority_guard.GuardError, match="issuer key id"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=context["authority_root"],
            repo_path=ROOT,
            tmpdir=context["tmpdir"],
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id="0" * 64,
        )


def test_start_authority_guard_rejects_valid_alternate_tmpdir_and_worktree(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    alternate_tmp = tmp_path / "alternate-tmp"
    alternate_tmp.mkdir(mode=0o700)
    with pytest.raises(start_authority_guard.GuardError, match="TMPDIR"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=context["authority_root"],
            repo_path=ROOT,
            tmpdir=alternate_tmp,
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id=context["issuer_key_id"],
        )
    alternate_repo = tmp_path / "alternate-repo"
    alternate_repo.mkdir(mode=0o700)
    (alternate_repo / ".git").write_text("gitdir: /nowhere\n", encoding="ascii")
    with pytest.raises(start_authority_guard.GuardError, match="worktree"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=context["authority_root"],
            repo_path=alternate_repo,
            tmpdir=context["tmpdir"],
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id=context["issuer_key_id"],
        )


@pytest.mark.parametrize(
    ("case_name", "mutate", "reason"),
    [
        (
            "bad-envelope",
            lambda context: context["capability"].write_text("{}", encoding="ascii"),
            "envelope",
        ),
        (
            "bad-signature",
            lambda context: context["capability"].write_text(
                json.dumps({"claims": {}, "signature": "0" * 128}),
                encoding="ascii",
            ),
            "signature",
        ),
        (
            "hardlinked-capability",
            lambda context: os.link(
                context["capability"], context["capability"].with_suffix(".link")
            ),
            "single-link",
        ),
        (
            "symlink-capability",
            lambda context: (
                context["capability"].unlink(),
                context["capability"].symlink_to("/dev/null"),
            ),
            "capability",
        ),
        ("writable-capability", lambda context: context["capability"].chmod(0o660), "mode"),
        ("writable-root", lambda context: context["authority_root"].chmod(0o770), "root"),
    ],
)
def test_start_authority_guard_rejects_tampered_or_unsafe_authority_files(
    tmp_path: Path,
    case_name: str,
    mutate: Any,
    reason: str,
) -> None:
    context = _authority_fixture(tmp_path)
    mutate(context)
    _assert_guard_rejects(context, reason)


def test_start_authority_guard_rejects_root_symlink_before_open(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    symlink = tmp_path / "authority-link"
    symlink.symlink_to(context["authority_root"])
    with pytest.raises(start_authority_guard.GuardError, match="canonical absolute"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=symlink,
            repo_path=ROOT,
            tmpdir=context["tmpdir"],
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id=context["issuer_key_id"],
        )


def test_start_authority_guard_rejects_authority_root_and_tmpdir_aliases(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(tmp_path, target_is_directory=True)
    authority_alias = alias_parent / "owner-authority"
    with pytest.raises(start_authority_guard.GuardError, match="canonical absolute"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=authority_alias,
            repo_path=ROOT,
            tmpdir=context["tmpdir"],
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id=context["issuer_key_id"],
        )

    context = _authority_fixture(tmp_path / "tmpdir-alias")
    tmp_alias_parent = tmp_path / "tmp-alias-parent"
    tmp_alias_parent.symlink_to(tmp_path / "tmpdir-alias", target_is_directory=True)
    tmpdir_alias = tmp_alias_parent / "caller-tmpdir"
    with pytest.raises(start_authority_guard.GuardError, match="canonical absolute"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=context["authority_root"],
            repo_path=ROOT,
            tmpdir=tmpdir_alias,
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id=context["issuer_key_id"],
        )

    context = _authority_fixture(tmp_path / "relative")
    with pytest.raises(start_authority_guard.GuardError, match="canonical absolute"):
        start_authority_guard.consume_authority(
            authority_id=context["authority_id"],
            authority_root=Path("relative-authority"),
            repo_path=ROOT,
            tmpdir=context["tmpdir"],
            node_id=NODE_ID,
            p_commit=P,
            t_commit=T,
            launcher_path=LAUNCHER,
            helper_path=HELPER,
            attempt_id=context["attempt_id"],
            public_key_raw_hex=context["public_hex"],
            issuer_key_id=context["issuer_key_id"],
        )


def test_start_authority_guard_rejects_duplicate_key_and_partial_spent(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    payload = context["capability"].read_text(encoding="ascii")
    context["capability"].write_text(payload[:-2] + ', "claims": {}}\n', encoding="ascii")
    _assert_guard_rejects(context, "duplicate")

    context = _authority_fixture(tmp_path / "partial")
    spent = context["authority_root"] / "spent" / f"{context['authority_id']}.spent.json"
    spent.write_text("{", encoding="ascii")
    spent.chmod(0o600)
    _assert_guard_rejects(context, "already spent")


def test_start_authority_guard_terminal_requires_matching_spent_and_attempt(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    result = _consume(context)
    _record_terminal(context, result)
    _record_terminal(context, result)
    with pytest.raises(start_authority_guard.GuardError, match="preexisting terminal"):
        _record_terminal(context, result, outcome="FAILED", exit_code=2)
    with pytest.raises(start_authority_guard.GuardError, match="attempt"):
        _record_terminal(context, result, attempt_id="attempt-2")
    with pytest.raises(start_authority_guard.GuardError, match="spent record"):
        _record_terminal(context, result, spent_record_sha256="0" * 64)


def test_start_authority_guard_terminal_rejects_preconsume_and_root_replacement(
    tmp_path: Path,
) -> None:
    context = _authority_fixture(tmp_path)
    with pytest.raises(start_authority_guard.GuardError, match="spent record"):
        start_authority_guard.record_terminal(
            authority_id=context["authority_id"],
            authority_root=context["authority_root"],
            authority_root_identity=context["root_identity"],
            attempt_id=context["attempt_id"],
            outcome="UNKNOWN",
            exit_code=130,
            reason="synthetic kill",
            spent_record_sha256="0" * 64,
        )
    result = _consume(context)
    moved = tmp_path / "moved-authority"
    context["authority_root"].rename(moved)
    replacement = context["authority_root"]
    replacement.mkdir(mode=0o700)
    for dirname in ("issued", "spent", "outcomes"):
        (replacement / dirname).mkdir(mode=0o700)
    with pytest.raises(start_authority_guard.GuardError, match="replacement"):
        _record_terminal(context, result)


def test_start_authority_guard_cli_uses_pinned_key_and_rejects_traversal(tmp_path: Path) -> None:
    context = _authority_fixture(tmp_path)
    completed = subprocess.run(
        [
            sys.executable,
            str(HELPER),
            "consume",
            "--authority-id",
            "../bad",
            "--authority-root",
            str(context["authority_root"]),
            "--repo-path",
            str(ROOT),
            "--tmpdir",
            str(context["tmpdir"]),
            "--node-id",
            NODE_ID,
            "--p",
            P,
            "--t",
            T,
            "--launcher-path",
            str(LAUNCHER),
            "--helper-path",
            str(HELPER),
            "--attempt-id",
            context["attempt_id"],
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "authority id is invalid" in completed.stderr
    source = HELPER.read_text(encoding="utf-8")
    assert "--public-key" not in source
    assert "PRODUCTION_PUBLIC_KEY_RAW_HEX" in source


def test_clean_sibling_launcher_reaches_loaded_guard_before_proof_setup(tmp_path: Path) -> None:
    proof_tmp = tmp_path / "proof-tmp"
    proof_tmp.mkdir(mode=0o700)
    completed = subprocess.run(
        [str(LAUNCHER), T],
        env={
            "PATH": "/usr/bin:/bin",
            "P": P,
            "NODE_ID": NODE_ID,
            "TMPDIR": str(proof_tmp),
            "ACGS_START_AUTHORITY_ROOT": str(tmp_path / "missing-authority"),
            "ACGS_START_AUTHORITY_ID": "auth.p3c.test",
            "ACGS_START_AUTHORITY_ATTEMPT_ID": "attempt-1",
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    combined = completed.stdout + completed.stderr
    assert completed.returncode == 2, combined
    assert "start authority rejected: authority root unavailable" in combined
    assert "loader unavailable" not in combined
    assert "guardian child exec failed" not in combined
    assert "CLEAN_SIBLING_TECHNICAL=PASS" not in combined
    assert not list(proof_tmp.rglob("*"))


def test_clean_sibling_launcher_source_orders_p3c_guard_before_setup_and_pins_loader() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")
    guard_index = source.index(
        "start_authority_context = start_authority_guard.consume_from_launcher()"
    )
    for marker in [
        "memfd = os.memfd_create(",
        "systemd_env = user_bus_env()",
        "pid = os.fork()",
        "os.execve(\n            SYSTEMD_RUN,",
    ]:
        assert source.index(marker, guard_index) > guard_index
    assert source.count('if os.environ.get("NODE_ID") == "P3-APPROVAL-003C":') == 1
    assert "types.ModuleType" in source
    assert "compile(helper_source, helper_path" in source
    assert "hashlib.sha256(helper_source).hexdigest()" in source
    assert source.index("pass_payload = (") < source.index("terminal_from_launcher(")
    assert source.index("write_all(attest_fd, pass_payload)") > source.index(
        "terminal_from_launcher("
    )
    assert "spec_from_file_location" not in source
    helper_source = HELPER.read_text(encoding="utf-8")
    assert "import hmac" not in helper_source
    assert "token" not in helper_source.lower()
    assert start_authority_guard.PRODUCTION_PUBLIC_KEY_RAW_HEX in helper_source
