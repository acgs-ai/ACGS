"""Clean-room contract for the dependency-minimal ACGS proof-pack verifier.

The load-bearing property of this package is that a proof pack verifies
**offline, without gove-zone installed**. These in-process tests pin the
behavioural half of that contract:

  a. the ``acgs-verify`` CLI verifies a golden pack and exits 0 (valid);
  b. a signed pack presented WITHOUT a verifier key fails **closed** (exit 1,
     reason ``SIGNED_RECEIPT_NO_VERIFIER``) — fail-closed is never weakened;
  c. no source module imports ``gove_zone`` (the namespace is fully vendored);
  d. the unavailable decision-replay tier fails closed, and offline verification
     never reaches it.

The environmental half — "the wheel installs and runs with gove-zone absent and
zero third-party deps" — is proved by ``scripts/cleanroom_verify.sh`` in CI.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from acgs_proofpack_verifier import verify_pack
from acgs_proofpack_verifier.cli import main as cli_main

_TESTS = Path(__file__).parent
_SRC = _TESTS.parents[1] / "src"
_FIXTURES = _TESTS / "fixtures"
GOLDEN = _FIXTURES / "golden"
SIGNED_NO_VERIFIER = _FIXTURES / "signed-no-verifier"
NOW_ISO = "2026-01-01T00:00:00+00:00"


# --- (a) golden pack verifies, exit 0 -----------------------------------------


def test_cli_verifies_golden_pack_exit_zero(capsys) -> None:
    rc = cli_main(["proofpack", "verify", str(GOLDEN), "--now-iso", NOW_ISO])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] is True
    assert out["reasons"] == []


def test_golden_pack_verifies_programmatically() -> None:
    result = verify_pack(GOLDEN, now_iso=NOW_ISO)
    assert result.valid, result.reasons
    assert result.integrity_status == "intact"
    assert result.receipt_and_chain is not None
    assert result.receipt_and_chain.audit_chain_verified
    assert result.reasons == []


# --- (b) signed pack without a verifier key fails CLOSED -----------------------


def test_cli_signed_pack_without_verifier_key_fails_closed(capsys) -> None:
    rc = cli_main(["proofpack", "verify", str(SIGNED_NO_VERIFIER), "--now-iso", NOW_ISO])
    assert rc == 1  # refused, not accepted
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] is False
    assert any("SIGNED_RECEIPT_NO_VERIFIER" in str(r) for r in out["reasons"]), out["reasons"]


def test_signed_pack_fail_closed_programmatically() -> None:
    result = verify_pack(SIGNED_NO_VERIFIER, now_iso=NOW_ISO)
    assert result.valid is False
    assert any(str(r) == "SIGNED_RECEIPT_NO_VERIFIER" for r in result.reasons), result.reasons


# --- (c) static guard: the namespace is fully vendored, no gove_zone import ----


def test_no_source_module_imports_gove_zone() -> None:
    """AST-level: no module-scope OR lazy import resolves to gove_zone.

    Stronger than a text grep — it ignores docstrings/comments and catches both
    ``import gove_zone`` and ``from gove_zone... import``.
    """
    offenders: list[str] = []
    for py in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{py.name}: import {a.name}"
                    for a in node.names
                    if a.name == "gove_zone" or a.name.startswith("gove_zone.")
                ]
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module
                and (node.module == "gove_zone" or node.module.startswith("gove_zone."))
            ):
                offenders.append(f"{py.name}: from {node.module} import ...")
    assert not offenders, "vendored source must not import gove_zone:\n" + "\n".join(offenders)


def test_no_source_text_contains_gove_zone_import_statement() -> None:
    """Literal belt-and-braces check for the exact substrings in the criterion."""
    for py in sorted(_SRC.rglob("*.py")):
        text = py.read_text(encoding="utf-8")
        assert "import gove_zone" not in text, py.name
        assert "from gove_zone" not in text, py.name


# --- (d) replay tier is unavailable and fails closed --------------------------


def test_replay_tier_unavailable_fails_closed(tmp_path: Path) -> None:
    """Re-derivation needs the policy engine, which this package does not vendor.

    Asking for it must fail CLOSED (never silently accept). This also documents
    that the removed engine code path is genuinely unreachable from offline
    verification: the golden pack verifies valid WITHOUT replay material (above),
    and only an explicit replay request trips the fail-closed guard here.
    """
    policy_bundle = tmp_path / "policy_bundle.json"
    policy_bundle.write_text("{}", encoding="utf-8")
    side_store = tmp_path / "side_store.jsonl"
    side_store.write_text("", encoding="utf-8")

    result = verify_pack(
        GOLDEN, now_iso=NOW_ISO, policy_bundle=policy_bundle, side_store=side_store
    )
    assert result.valid is False
    assert any("REPLAY" in str(r) for r in result.reasons), result.reasons
