"""Deterministic verification harness: regression attack suite A–F plus
structural checks (chain integrity, expiry, provenance, determinism).

Each check builds a fresh sandbox (governed repo + governance root +
keystore + ledger) so checks are independent and order-insensitive. Time
is a logical clock — no wall-clock reads — so the whole suite is
deterministic.
"""

from __future__ import annotations

import os
import shutil
import stat
import threading
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

from . import effect as effect_module
from .canonical import hash_file, sha256_hex
from .effect import ACCEPTED, REJECTED, EffectBinder, EffectRecordingError
from .engine import ALLOW, DENY, DecisionEngine
from .intent import MutationIntent, SignedIntent
from .ledger import AuditLedger, LedgerIntegrityError
from .receipt import MutationDecisionReceipt, ReceiptFormatError
from .root import GovernanceRoot, RootIntegrityError
from .state import ABSENT, RepositoryScanError, repository_violations


class CheckFailure(Exception):
    pass


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

POLICY = {
    "governed_prefixes": ["src", "governance"],
    "protected_prefixes": ["governance"],
    "receipt_ttl": 8,
    "task_authorities": {"TASK-*": ["agent-alpha", "agent-beta", "agent-gamma"]},
}

ACTORS = {
    "agent-alpha": {"status": "active", "scopes": ["src/*"]},
    "agent-beta": {"status": "active", "scopes": ["src/*"]},
    "agent-gamma": {"status": "active", "scopes": ["docs/*"]},
}

SEED_FILES = {
    "src/verify_readiness.py": b"print('readiness v1')\n",
    "src/module_a.py": b"VALUE = 1\n",
}


@dataclass
class Sandbox:
    base: Path
    repo: Path
    root: GovernanceRoot
    ledger: AuditLedger
    engine: DecisionEngine
    binder: EffectBinder
    now: int = 1
    _nonce: int = field(default=0)

    @classmethod
    def build(cls, base: Path) -> Sandbox:
        if base.exists():
            shutil.rmtree(base)
        repo = base / "repo"
        for rel, content in SEED_FILES.items():
            path = repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        root = GovernanceRoot.initialize(
            root_dir=repo / "governance",
            keystore_dir=base / "keystore",
            policy=POLICY,
            actors=ACTORS,
        )
        baseline = {rel: sha256_hex(content) for rel, content in SEED_FILES.items()}
        for name in ("policy.json", "actors.json", "manifest.json"):
            baseline[f"governance/{name}"] = hash_file(repo / "governance" / name)
        ledger = AuditLedger.initialize(
            base / "mutation_ledger.jsonl",
            root_manifest_hash=root.manifest_hash(),
            baseline=baseline,
            timestamp=0,
            # Anchor lives with the keystore: outside the governed tree,
            # outside the reach of an attacker who can write the ledger file.
            anchor_path=base / "keystore" / "ledger.head",
        )
        return cls(
            base=base,
            repo=repo,
            root=root,
            ledger=ledger,
            engine=DecisionEngine(root, ledger, repo),
            binder=EffectBinder(root, ledger, repo),
        )

    def tick(self) -> int:
        self.now += 1
        return self.now

    def intent(
        self,
        actor: str,
        resource: str,
        operation: str = "UPDATE",
        scope: str | None = None,
        expected_pre_hash: str | None = None,
        new_content: bytes | None = b"VALUE = 2\n",
        task: str = "TASK-1",
    ) -> SignedIntent:
        self._nonce += 1
        if expected_pre_hash is None:
            expected_pre_hash = hash_file(self.repo / resource)
        expected_post_hash = ABSENT if operation == "DELETE" else sha256_hex(new_content or b"")
        intent = MutationIntent(
            actor_identity=actor,
            resource_path=resource,
            operation=operation,
            expected_pre_hash=expected_pre_hash,
            expected_post_hash=expected_post_hash,
            requested_change_scope=scope if scope is not None else resource,
            timestamp=self.now,
            task_reference=task,
            nonce=f"n{self._nonce}",
        )
        return SignedIntent.create(intent, self.root.actor_key(actor))

    def governed_mutation(
        self, actor: str, resource: str, content: bytes
    ) -> MutationDecisionReceipt:
        """Happy-path helper: intent -> ALLOW -> commit ACCEPTED."""
        decision = self.engine.decide(
            self.intent(actor, resource, new_content=content), self.tick()
        )
        if decision.decision != ALLOW or decision.receipt is None:
            raise CheckFailure(f"expected ALLOW, got {decision.decision}: {decision.reason}")
        result = self.binder.commit(decision.receipt, content, self.tick())
        if result.status != ACCEPTED:
            raise CheckFailure(f"expected ACCEPTED, got {result.status}: {result.reason}")
        return decision.receipt


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------


def check_happy_path(base: Path) -> str:
    sb = Sandbox.build(base)
    resource = "src/verify_readiness.py"
    new_content = b"print('readiness v2')\n"
    receipt = sb.governed_mutation("agent-alpha", resource, new_content)
    _expect((sb.repo / resource).read_bytes() == new_content, "content not applied")
    sb.ledger.verify_chain()
    _expect(
        sb.ledger.authorized_state(resource) == sha256_hex(new_content),
        "ledger authorized state not updated",
    )
    _expect(
        repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes()) == [],
        "clean repo reported violations",
    )
    return f"receipt {receipt.receipt_id[:12]}… issued, committed, chain verified"


def check_deterministic_verifier(base: Path) -> str:
    sb = Sandbox.build(base)
    signed = sb.intent("agent-alpha", "src/module_a.py")
    h1, h2 = signed.intent.intent_hash(), signed.intent.intent_hash()
    _expect(h1 == h2, "intent hash not stable")
    v1 = sb.engine._first_violation(signed, sb.now)
    v2 = sb.engine._first_violation(signed, sb.now)
    _expect(v1 == v2 == None, f"verifier not deterministic: {v1!r} vs {v2!r}")  # noqa: E711
    bad = sb.intent("agent-gamma", "src/module_a.py")
    _expect(
        sb.engine._first_violation(bad, sb.now) == sb.engine._first_violation(bad, sb.now),
        "verifier not deterministic on DENY path",
    )
    return "identical intent + identical state ⇒ identical verdict and hashes"


def check_ledger_tamper_evident(base: Path) -> str:
    sb = Sandbox.build(base)
    sb.governed_mutation("agent-alpha", "src/module_a.py", b"VALUE = 2\n")
    lines = sb.ledger.path.read_text().splitlines()
    _expect(len(lines) >= 3, "expected genesis + decision + commit")
    tampered = lines[1].replace("ALLOW", "DENY", 1)
    _expect(tampered != lines[1], "tamper target not found")
    sb.ledger.path.write_text("\n".join([lines[0], tampered, *lines[2:]]) + "\n")
    try:
        sb.ledger.verify_chain()
    except LedgerIntegrityError as exc:
        return f"retroactive ledger edit detected: {exc}"
    raise CheckFailure("tampered ledger passed chain verification")


def check_receipt_expiry(base: Path) -> str:
    sb = Sandbox.build(base)
    decision = sb.engine.decide(sb.intent("agent-alpha", "src/module_a.py"), sb.tick())
    assert decision.receipt is not None
    sb.now = decision.receipt.expiry + 1  # logical clock passes the deadline
    result = sb.binder.commit(decision.receipt, b"VALUE = 2\n", sb.now)
    _expect(result.status == REJECTED, "expired receipt was accepted")
    _expect("expired" in result.reason, f"unexpected reason: {result.reason}")
    return f"receipt expired at t={decision.receipt.expiry}, commit at t={sb.now} rejected"


def check_provenance(base: Path) -> str:
    sb = Sandbox.build(base)
    sb.governed_mutation("agent-alpha", "src/module_a.py", b"VALUE = 2\n")
    sb.governed_mutation("agent-beta", "src/module_a.py", b"VALUE = 3\n")
    sb.ledger.verify_chain()
    issued = sb.ledger.issued_receipts()
    decisions = {e.payload["intent_hash"] for e in sb.ledger.events() if e.type == "DECISION"}
    commits = [e for e in sb.ledger.events() if e.type == "COMMIT"]
    _expect(len(commits) == 2, "expected exactly two commits")
    prev_after = sb.ledger.genesis().payload["baseline"]["src/module_a.py"]
    for event in commits:
        receipt = issued.get(event.payload["receipt_id"])
        _expect(receipt is not None, "commit without an issued receipt")
        assert receipt is not None
        _expect(receipt["intent_hash"] in decisions, "receipt without recorded intent")
        _expect(
            event.payload["before_hash"] == receipt["previous_state_hash"] == prev_after,
            "before-hash does not chain to prior authorized state",
        )
        prev_after = event.payload["after_hash"]
    return "every commit chains: intent_hash → receipt → before/after state hashes"


# ---------------------------------------------------------------------------
# Attack suite
# ---------------------------------------------------------------------------


def attack_a_direct_bypass(base: Path) -> str:
    """Agent bypasses the decision engine and writes the file directly."""
    sb = Sandbox.build(base)
    target = sb.repo / "src/verify_readiness.py"
    target.write_bytes(b"print('rogue edit')\n")  # no intent, no receipt

    violations = repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes())
    _expect(len(violations) == 1, f"bypass not detected: {violations}")
    _expect(violations[0]["kind"] == "unauthorized_modify", "wrong violation kind")

    # Laundering attempt: submit an intent whose expected_pre_hash matches
    # the rogue disk state. The engine compares disk against the LEDGER,
    # so the rogue state is unmistakable.
    launder = sb.intent("agent-alpha", "src/verify_readiness.py")
    decision = sb.engine.decide(launder, sb.tick())
    _expect(decision.decision == DENY, "laundered bypass was allowed")
    _expect("diverged from audit chain" in decision.reason, decision.reason)
    return "direct write detected as unauthorized_modify; laundering intent DENIED"


def attack_b_valid_signature_wrong_scope(base: Path) -> str:
    """Correctly signed intent from an actor without scope on the resource."""
    sb = Sandbox.build(base)
    signed = sb.intent("agent-gamma", "src/verify_readiness.py")  # gamma owns docs/* only
    decision = sb.engine.decide(signed, sb.tick())
    _expect(decision.decision == DENY, "out-of-scope actor was allowed")
    _expect("scope does not permit" in decision.reason, decision.reason)
    _expect(decision.receipt is None, "DENY produced a receipt")
    return "valid signature, unauthorized scope ⇒ DENY (no receipt issued)"


def attack_c_concurrent_writers(base: Path) -> str:
    """Two agents race to mutate the same resource."""
    sb = Sandbox.build(base)
    resource = "src/verify_readiness.py"
    first = sb.engine.decide(
        sb.intent("agent-alpha", resource, new_content=b"print('winner')\n"), sb.tick()
    )
    _expect(first.decision == ALLOW, f"first writer denied: {first.reason}")
    second = sb.engine.decide(sb.intent("agent-beta", resource), sb.tick())
    _expect(second.decision == DENY, "second concurrent writer was allowed")
    _expect("in flight" in second.reason, second.reason)
    assert first.receipt is not None
    result = sb.binder.commit(first.receipt, b"print('winner')\n", sb.tick())
    _expect(result.status == ACCEPTED, f"winner commit rejected: {result.reason}")

    # Post-commit retry by the loser with a stale pre-hash also fails.
    stale = sb.intent("agent-beta", resource, expected_pre_hash=first.receipt.previous_state_hash)
    retry = sb.engine.decide(stale, sb.tick())
    _expect(retry.decision == DENY, "stale retry was allowed")
    return "one writer ACCEPTED, one DENIED (conflict), stale retry DENIED"


def attack_d_modify_governance_root(base: Path) -> str:
    """Governed path AND out-of-band tamper both fail closed."""
    sb = Sandbox.build(base)
    # (1) Through the front door: intent targeting the governance root.
    signed = sb.intent("agent-alpha", "governance/policy.json", scope="governance/*")
    decision = sb.engine.decide(signed, sb.tick())
    _expect(decision.decision == DENY, "governance root mutation was allowed")
    _expect("immutable governance root" in decision.reason, decision.reason)

    # (2) Around the back: raw write to policy.json. The engine must then
    # refuse to make ANY decision (fail closed), not just this one.
    policy_path = sb.repo / "governance/policy.json"
    original = policy_path.read_bytes()
    policy_path.write_bytes(original.replace(b'"src"', b'"anything"'))
    try:
        sb.engine.decide(sb.intent("agent-alpha", "src/module_a.py"), sb.tick())
    except RootIntegrityError:
        return "front-door DENY; back-door tamper ⇒ engine fails closed entirely"
    raise CheckFailure("engine kept deciding on a tampered governance root")


def attack_e_replay_receipt(base: Path) -> str:
    """Replay a receipt that has already been consumed."""
    sb = Sandbox.build(base)
    receipt = sb.governed_mutation("agent-alpha", "src/module_a.py", b"VALUE = 2\n")
    replay = sb.binder.commit(receipt, b"VALUE = 666\n", sb.tick())
    _expect(replay.status == REJECTED, "replayed receipt was accepted")
    _expect("already consumed" in replay.reason, replay.reason)
    _expect(
        (sb.repo / "src/module_a.py").read_bytes() == b"VALUE = 2\n",
        "replay changed the file",
    )
    return "consumed receipt replay REJECTED; file untouched"


def attack_f_change_after_approval(base: Path) -> str:
    """File mutated between approval and commit."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    decision = sb.engine.decide(sb.intent("agent-alpha", resource), sb.tick())
    assert decision.receipt is not None
    (sb.repo / resource).write_bytes(b"VALUE = 999  # sneaked in\n")
    result = sb.binder.commit(decision.receipt, b"VALUE = 2\n", sb.tick())
    _expect(result.status == REJECTED, "post-approval change was committed over")
    _expect("changed after approval" in result.reason, result.reason)
    violations = repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes())
    _expect(len(violations) == 1, "post-approval tamper not visible in state check")
    return "pre-state hash mismatch ⇒ commit REJECTED; tamper flagged by state check"


def attack_h_ledger_truncation(base: Path) -> str:
    """Drop the ledger tail to un-consume a receipt, then replay it."""
    sb = Sandbox.build(base)
    resource = sb.repo / "src/module_a.py"
    original = resource.read_bytes()
    receipt = sb.governed_mutation("agent-alpha", "src/module_a.py", b"VALUE = 2\n")
    # Attacker with ledger-file write access: revert the file bytes and
    # delete the consuming COMMIT event. The remaining chain is still
    # internally self-consistent — only the anchor exposes the truncation.
    resource.write_bytes(original)
    lines = sb.ledger.path.read_text().splitlines()
    sb.ledger.path.write_text("\n".join(lines[:-1]) + "\n")
    try:
        sb.binder.commit(receipt, b"VALUE = 999\n", sb.tick())
    except LedgerIntegrityError as exc:
        _expect("anchor" in str(exc), f"unexpected reason: {exc}")
        _expect(resource.read_bytes() == original, "truncation replay changed the file")
        return "tail truncation detected via out-of-tree anchor ⇒ fail closed"
    raise CheckFailure("truncated ledger accepted a replayed receipt (double-spend)")


def attack_i_genesis_regeneration(base: Path) -> str:
    """Delete the ledger and mint a fresh genesis to wipe audit history."""
    sb = Sandbox.build(base)
    sb.governed_mutation("agent-alpha", "src/module_a.py", b"VALUE = 2\n")
    sb.ledger.path.unlink()
    try:
        AuditLedger.initialize(
            sb.ledger.path,
            root_manifest_hash=sb.root.manifest_hash(),
            baseline={},
            timestamp=0,
            anchor_path=sb.ledger.anchor_path,
        )
    except LedgerIntegrityError:
        pass
    else:
        raise CheckFailure("history wipe: genesis was regenerated over an anchored chain")
    # And the engine refuses to operate on the wiped chain.
    try:
        sb.engine.decide(sb.intent("agent-alpha", "src/verify_readiness.py"), sb.tick())
    except LedgerIntegrityError:
        return "re-genesis refused; engine fails closed on the wiped chain"
    raise CheckFailure("engine kept deciding after ledger wipe")


def check_ledger_root_binding(base: Path) -> str:
    """An engine must refuse a ledger initialized against a different root."""
    sb_a = Sandbox.build(base / "a")
    sb_b = Sandbox.build(base / "b")
    mispaired = DecisionEngine(sb_a.root, sb_b.ledger, sb_b.repo)
    try:
        mispaired.decide(sb_b.intent("agent-alpha", "src/module_a.py"), 2)
    except LedgerIntegrityError as exc:
        _expect("not bound" in str(exc), str(exc))
        return "genesis root_manifest_hash is enforced, not just recorded"
    raise CheckFailure("engine accepted a ledger bound to a different governance root")


def attack_forged_receipt(base: Path) -> str:
    """Receipt fields, including the parent identity, are root-signed."""
    sb = Sandbox.build(base)
    decision = sb.engine.decide(sb.intent("agent-alpha", "src/module_a.py"), sb.tick())
    assert decision.receipt is not None
    for receipt_field, value in (
        ("resource", "src/verify_readiness.py"),
        ("parent_ancestor_inode", decision.receipt.parent_ancestor_inode + 1),
    ):
        forged = MutationDecisionReceipt.from_dict(
            {**decision.receipt.to_dict(), receipt_field: value}
        )
        result = sb.binder.commit(forged, b"pwn\n", sb.tick())
        _expect(result.status == REJECTED, f"forged {receipt_field} was accepted")
        _expect("signature invalid" in result.reason, result.reason)
    return "altered resource or parent identity fails root-key signature check ⇒ REJECTED"


def attack_j_symlink_escape(base: Path) -> str:
    """A symlinked directory must not let a governed-looking path write
    outside the repository — at decide time or between approval and commit."""
    sb = Sandbox.build(base)
    outside = sb.base / "outside"
    outside.mkdir(parents=True, exist_ok=True)

    # (1) Decide time: the hostile symlink already exists.
    (sb.repo / "src" / "sub").symlink_to(outside)
    signed = sb.intent("agent-alpha", "src/sub/leak.txt", operation="CREATE")
    decision = sb.engine.decide(signed, sb.tick())
    _expect(decision.decision == DENY, "symlink-escaping path was allowed")
    _expect("outside the governed repository" in decision.reason, decision.reason)

    # (2) Effect time: symlink introduced AFTER approval.
    signed2 = sb.intent(
        "agent-alpha",
        "src/sub2/leak.txt",
        operation="CREATE",
        new_content=b"leak\n",
    )
    decision2 = sb.engine.decide(signed2, sb.tick())
    _expect(decision2.decision == ALLOW, f"clean CREATE denied: {decision2.reason}")
    assert decision2.receipt is not None
    (sb.repo / "src" / "sub2").symlink_to(outside)
    result = sb.binder.commit(decision2.receipt, b"leak\n", sb.tick())
    _expect(result.status == REJECTED, "post-approval symlink escape was committed")
    _expect(not (outside / "leak.txt").exists(), "bytes escaped the governed repository")
    return "symlink escape DENIED at decide time and REJECTED at effect time"


def attack_k_metadata_swap(base: Path) -> str:
    """Byte-identical content with changed file metadata is a state change:
    file-to-symlink swaps and exec-bit flips must be visible divergence."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    content = b"VALUE = 2\n"
    sb.governed_mutation("agent-alpha", resource, content)
    target = sb.repo / resource

    # (1) Replace the file with a symlink to a byte-identical copy.
    copy = sb.base / "copy_module_a.py"
    copy.write_bytes(content)
    target.unlink()
    target.symlink_to(copy)
    violations = repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes())
    _expect(len(violations) == 1, f"symlink swap not detected: {violations}")
    _expect(violations[0]["kind"] == "unauthorized_modify", "wrong violation kind")

    # (2) Restore, then flip the exec bit on byte-identical content.
    target.unlink()
    target.write_bytes(content)
    _expect(
        repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes()) == [],
        "restored file still reported divergent",
    )
    target.chmod(0o755)
    violations = repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes())
    _expect(len(violations) == 1, "exec-bit flip not detected")
    return "file→symlink swap and exec-bit flip both surface as unauthorized_modify"


def attack_l_unrecordable_effect_rolled_back(base: Path) -> str:
    """If the COMMIT event cannot be appended, the filesystem effect must not
    persist — otherwise an accepted mutation would be unauditable."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    original = (sb.repo / resource).read_bytes()
    decision = sb.engine.decide(sb.intent("agent-alpha", resource), sb.tick())
    _expect(decision.decision == ALLOW, f"setup ALLOW failed: {decision.reason}")
    assert decision.receipt is not None

    class RecordingFailure(Exception):
        pass

    class FailingLedger:
        """Delegates everything to the real ledger; append always fails."""

        def __init__(self, inner: AuditLedger):
            self._inner = inner

        def __getattr__(self, name: str):
            if name == "append":

                def _fail(*_a: object, **_k: object) -> None:
                    raise RecordingFailure("simulated audit-chain append failure")

                return _fail
            return getattr(self._inner, name)

    sb.binder.ledger = FailingLedger(sb.ledger)  # type: ignore[assignment]
    try:
        sb.binder.commit(decision.receipt, b"VALUE = 2\n", sb.tick())
    except EffectRecordingError:
        _expect((sb.repo / resource).read_bytes() == original, "rolled-back effect persisted")
        sb.ledger.verify_chain()
        _expect(
            repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes()) == [],
            "rollback left the repository diverged from the chain",
        )
        return "append failure ⇒ EffectRecordingError; file restored, chain still clean"
    raise CheckFailure("recording failure did not raise EffectRecordingError")


def attack_m_reinitialize_governance_root(base: Path) -> str:
    """Re-running the bootstrap ceremony over an existing root must be
    refused: initialize() rewrites policy/actors and re-signs a fresh
    manifest, so a silent re-run would replace the governance contract in
    place — the exact mutation the sealed root exists to prevent."""
    sb = Sandbox.build(base)
    policy_path = sb.repo / "governance" / "policy.json"
    before = policy_path.read_bytes()
    hostile_policy = {**POLICY, "governed_prefixes": []}  # ungovern everything
    try:
        GovernanceRoot.initialize(
            root_dir=sb.repo / "governance",
            keystore_dir=sb.base / "keystore",
            policy=hostile_policy,
            actors=ACTORS,
        )
    except RootIntegrityError as exc:
        _expect("already initialized" in str(exc), str(exc))
        _expect(policy_path.read_bytes() == before, "reinit altered sealed policy bytes")
        sb.root.verify_integrity()  # the original root still stands
        return "second initialize() refused; sealed root bytes untouched"
    raise CheckFailure("bootstrap ceremony re-ran over an existing governance root")


def attack_n_glob_prefix_rogue_artifacts(base: Path) -> str:
    """Artifacts planted under a GLOB governed prefix — including dangling
    symlinks — must surface as unauthorized creations. The scan must apply
    the engine's own governed predicate (src/*.py is a pattern, not a
    directory) and must not follow symlinks (is_file() on a broken link is
    False, so a follow-the-link walk would never enumerate it)."""
    sb = Sandbox.build(base)
    prefixes = ["src/*.py"]
    _expect(
        repository_violations(sb.ledger, sb.repo, prefixes) == [],
        "clean repo reported violations under a glob prefix",
    )

    # (1) Rogue regular file matching the glob prefix.
    rogue = sb.repo / "src" / "rogue_new.py"
    rogue.write_bytes(b"print('rogue')\n")
    violations = repository_violations(sb.ledger, sb.repo, prefixes)
    _expect(len(violations) == 1, f"glob-prefix rogue file not detected: {violations}")
    _expect(violations[0]["resource"] == "src/rogue_new.py", str(violations[0]))
    _expect(violations[0]["kind"] == "unauthorized_create", "wrong violation kind")
    rogue.unlink()

    # (2) Dangling symlink planted under the governed prefix.
    dangle = sb.repo / "src" / "dangling.py"
    dangle.symlink_to(sb.base / "no-such-target")
    violations = repository_violations(sb.ledger, sb.repo, prefixes)
    _expect(len(violations) == 1, f"dangling symlink not detected: {violations}")
    _expect(violations[0]["resource"] == "src/dangling.py", str(violations[0]))
    _expect(violations[0]["kind"] == "unauthorized_create", "wrong violation kind")
    return "glob-prefix rogue file and dangling symlink surface as unauthorized_create"


def attack_p_temp_symlink_race(base: Path) -> str:
    """A pre-planted temporary symlink must never be followed or replaced."""
    for label, victim_kind in (("external", "external"), ("protected", "protected")):
        sb = Sandbox.build(base / label)
        resource = "src/module_a.py"
        target = sb.repo / resource
        original = target.read_bytes()
        decision = sb.engine.decide(
            sb.intent("agent-alpha", resource, new_content=b"attacker-controlled\n"),
            sb.tick(),
        )
        assert decision.receipt is not None
        if victim_kind == "external":
            victim = sb.base / "outside.txt"
            victim.write_bytes(b"outside-original\n")
        else:
            victim = sb.repo / "governance" / "policy.json"
        victim_before = victim.read_bytes()
        hostile = target.parent / ".module_a.py.mutation-authority.deadbeef.tmp"
        hostile.symlink_to(victim)
        with patch("mutation_authority.effect.secrets.token_hex", return_value="deadbeef"):
            result = sb.binder.commit(decision.receipt, b"attacker-controlled\n", sb.tick())
        _expect(result.status == REJECTED, f"{label} temp symlink race was accepted")
        _expect(target.read_bytes() == original, f"{label} race changed governed target")
        _expect(victim.read_bytes() == victim_before, f"{label} race changed protected victim")
        _expect(hostile.is_symlink(), f"{label} hostile symlink was unexpectedly replaced")
    return "unique O_EXCL|O_NOFOLLOW temp creation left external/protected files unchanged"


def attack_pre_state_path_swap(base: Path) -> str:
    """A byte-identical parent replacement after receipt mint must be rejected."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    original_src = sb.repo / "src"
    original_bytes = (original_src / "module_a.py").read_bytes()
    replacement_src = sb.base / "replacement-src"
    replacement_src.mkdir()
    replacement_target = replacement_src / "module_a.py"
    replacement_target.write_bytes(original_bytes)
    replacement_before = replacement_target.read_bytes()
    moved_src = sb.base / "original-src"
    decision = sb.engine.decide(
        sb.intent("agent-alpha", resource, new_content=b"attacker-controlled\n"), sb.tick()
    )
    assert decision.receipt is not None

    original_src.rename(moved_src)
    replacement_src.rename(original_src)
    result = sb.binder.commit(decision.receipt, b"attacker-controlled\n", sb.tick())

    _expect(result.status == REJECTED, "replacement tree inherited authorization")
    _expect(
        moved_src.joinpath("module_a.py").read_bytes() == original_bytes,
        "original pinned tree changed",
    )
    _expect(
        original_src.joinpath("module_a.py").read_bytes() == replacement_before,
        "replacement lexical tree changed",
    )
    _expect(
        decision.receipt.receipt_id not in sb.ledger.committed_receipt_ids(),
        "pre-state tree swap left a COMMIT",
    )
    sb.ledger.verify_chain()
    return "post-mint parent replacement rejected; both trees unchanged and no COMMIT"


def attack_post_open_parent_swap(base: Path) -> str:
    """A replacement after the signed ancestor is pinned must be rejected."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    original_src = sb.repo / "src"
    original_bytes = (original_src / "module_a.py").read_bytes()
    replacement_src = sb.base / "replacement-src"
    replacement_src.mkdir()
    replacement_target = replacement_src / "module_a.py"
    replacement_target.write_bytes(original_bytes)
    replacement_before = replacement_target.read_bytes()
    moved_src = sb.base / "original-src"
    decision = sb.engine.decide(
        sb.intent("agent-alpha", resource, new_content=b"attacker-controlled\n"), sb.tick()
    )
    assert decision.receipt is not None
    real_open = effect_module._open_bound_ancestor
    swapped = False

    def open_then_swap(
        repo_dir: Path, receipt: MutationDecisionReceipt
    ) -> tuple[int, str, tuple[str, ...]]:
        nonlocal swapped
        opened = real_open(repo_dir, receipt)
        if not swapped:
            swapped = True
            original_src.rename(moved_src)
            replacement_src.rename(original_src)
        return opened

    with patch("mutation_authority.effect._open_bound_ancestor", side_effect=open_then_swap):
        result = sb.binder.commit(decision.receipt, b"attacker-controlled\n", sb.tick())

    _expect(swapped, "deterministic post-open tree swap did not run")
    _expect(result.status == REJECTED, "post-open replacement inherited authorization")
    _expect(
        moved_src.joinpath("module_a.py").read_bytes() == original_bytes,
        "pinned original tree changed",
    )
    _expect(
        original_src.joinpath("module_a.py").read_bytes() == replacement_before,
        "replacement lexical tree changed",
    )
    _expect(
        decision.receipt.receipt_id not in sb.ledger.committed_receipt_ids(),
        "post-open tree swap left a COMMIT",
    )
    sb.ledger.verify_chain()
    return "post-open parent replacement rejected; both trees unchanged and no COMMIT"


def attack_q_parent_rename_during_effect(base: Path) -> str:
    """Renaming the verified parent during mutation must roll back via dirfd."""

    def make_rename_after_effect(
        real_replace: Callable[[int, str, bytes, int], None],
        repo: Path,
        moved_parent: Path,
        destination: Path,
    ) -> Callable[[int, str, bytes, int], None]:
        renamed = False

        def rename_after_effect(parent_fd: int, name: str, content: bytes, mode: int) -> None:
            nonlocal renamed
            real_replace(parent_fd, name, content, mode)
            if not renamed:
                renamed = True
                (repo / "src").rename(moved_parent)
                (repo / "src").symlink_to(destination, target_is_directory=True)

        return rename_after_effect

    for label in ("external", "protected"):
        sb = Sandbox.build(base / label)
        resource = "src/module_a.py"
        original = (sb.repo / resource).read_bytes()
        protected = sb.repo / "governance" / "policy.json"
        protected_before = protected.read_bytes()
        outside = sb.base / "outside"
        outside.mkdir()
        outside_victim = outside / "module_a.py"
        outside_victim.write_bytes(b"outside-original\n")
        decision = sb.engine.decide(
            sb.intent("agent-alpha", resource, new_content=b"attacker-controlled\n"),
            sb.tick(),
        )
        assert decision.receipt is not None

        moved_parent = sb.base / "moved-src"
        destination = outside if label == "external" else protected.parent
        rename_after_effect = make_rename_after_effect(
            effect_module._atomic_replace_at,
            sb.repo,
            moved_parent,
            destination,
        )

        with patch(
            "mutation_authority.effect._atomic_replace_at",
            side_effect=rename_after_effect,
        ):
            result = sb.binder.commit(decision.receipt, b"attacker-controlled\n", sb.tick())

        _expect(result.status == REJECTED, f"{label} ancestor rename was accepted")
        _expect(
            moved_parent.joinpath("module_a.py").read_bytes() == original,
            f"{label} rollback did not restore the pinned target",
        )
        _expect(
            outside_victim.read_bytes() == b"outside-original\n",
            f"{label} race changed external content",
        )
        _expect(
            protected.read_bytes() == protected_before, f"{label} race changed protected content"
        )
        _expect(
            decision.receipt.receipt_id not in sb.ledger.committed_receipt_ids(),
            f"{label} race recorded a COMMIT",
        )
    return "ancestor rename rolled back through pinned fd; no external/protected write or COMMIT"


def attack_r_parent_rename_at_audit_append(base: Path) -> str:
    """A rename injected at append must rewind both effect and COMMIT."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    original = (sb.repo / resource).read_bytes()
    outside = sb.base / "outside"
    outside.mkdir()
    outside_victim = outside / "module_a.py"
    outside_victim.write_bytes(b"outside-original\n")
    decision = sb.engine.decide(
        sb.intent("agent-alpha", resource, new_content=b"attacker-controlled\n"), sb.tick()
    )
    assert decision.receipt is not None
    real_append = sb.ledger.append
    moved_parent = sb.base / "moved-src"

    def append_then_rename(*args: object, **kwargs: object):
        event = real_append(*args, **kwargs)
        (sb.repo / "src").rename(moved_parent)
        (sb.repo / "src").symlink_to(outside, target_is_directory=True)
        return event

    with patch.object(sb.ledger, "append", side_effect=append_then_rename):
        result = sb.binder.commit(decision.receipt, b"attacker-controlled\n", sb.tick())

    _expect(result.status == REJECTED, "append-boundary ancestor rename was accepted")
    _expect(
        moved_parent.joinpath("module_a.py").read_bytes() == original,
        "append-boundary rollback did not restore the pinned target",
    )
    _expect(
        outside_victim.read_bytes() == b"outside-original\n",
        "append-boundary race changed external content",
    )
    _expect(
        decision.receipt.receipt_id not in sb.ledger.committed_receipt_ids(),
        "append-boundary race left a COMMIT event",
    )
    sb.ledger.verify_chain()
    return "append-boundary rename rewound effect and COMMIT; external content unchanged"


def check_nested_create_uses_bound_ancestor(base: Path) -> str:
    """Nested CREATE is pinned to its nearest existing ancestor and rolls back."""
    success = Sandbox.build(base / "success")
    resource = "src/nested/deep/private.py"
    decision = success.engine.decide(
        success.intent("agent-alpha", resource, operation="CREATE", new_content=b"SECRET = True\n"),
        success.tick(),
    )
    assert decision.receipt is not None
    src_stat = (success.repo / "src").stat()
    _expect(
        decision.receipt.parent_ancestor_path == "src",
        "nested CREATE did not bind the nearest existing ancestor",
    )
    _expect(
        (
            decision.receipt.parent_ancestor_device,
            decision.receipt.parent_ancestor_inode,
        )
        == (src_stat.st_dev, src_stat.st_ino),
        "nested CREATE receipt ancestor identity is not the approved src directory",
    )
    result = success.binder.commit(decision.receipt, b"SECRET = True\n", success.tick())
    _expect(result.status == ACCEPTED, f"nested CREATE failed: {result.reason}")
    _expect(
        (success.repo / resource).read_bytes() == b"SECRET = True\n",
        "nested CREATE content mismatch",
    )

    rollback = Sandbox.build(base / "rollback")
    rollback_decision = rollback.engine.decide(
        rollback.intent(
            "agent-alpha", resource, operation="CREATE", new_content=b"SECRET = True\n"
        ),
        rollback.tick(),
    )
    assert rollback_decision.receipt is not None
    with patch.object(rollback.ledger, "append", side_effect=OSError("disk full")):
        try:
            rollback.binder.commit(rollback_decision.receipt, b"SECRET = True\n", rollback.tick())
        except EffectRecordingError:
            pass
        else:
            raise CheckFailure("unrecordable nested CREATE did not fail loudly")
    _expect(
        not (rollback.repo / "src" / "nested").exists(),
        "nested CREATE rollback left target or parent directories",
    )
    _expect(
        rollback_decision.receipt.receipt_id not in rollback.ledger.committed_receipt_ids(),
        "nested CREATE rollback left a COMMIT",
    )
    rollback.ledger.verify_chain()
    return "nested CREATE used signed ancestor and rolled back target plus parents"


def check_create_respects_restrictive_umask(base: Path) -> str:
    """CREATE binds the fixed secure mode; a restrictive umask is never widened."""
    sb = Sandbox.build(base)
    resource = "src/private.py"
    previous_umask = os.umask(0o077)
    try:
        decision = sb.engine.decide(
            sb.intent(
                "agent-alpha",
                resource,
                operation="CREATE",
                new_content=b"SECRET = True\n",
            ),
            sb.tick(),
        )
        assert decision.receipt is not None
        result = sb.binder.commit(decision.receipt, b"SECRET = True\n", sb.tick())
    finally:
        os.umask(previous_umask)
    _expect(result.status == ACCEPTED, f"restrictive-umask CREATE failed: {result.reason}")
    mode = stat.S_IMODE((sb.repo / resource).stat().st_mode)
    _expect(mode == 0o600, f"CREATE widened umask 077 mode to {mode:o}")
    return "CREATE under umask 077 produced mode 0600"


def attack_s_post_write_replacement(base: Path) -> str:
    """Bytes substituted after the atomic write must be rolled back."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    target = sb.repo / resource
    original = target.read_bytes()
    authorized = b"VALUE = 2\n"
    rogue = b"ROGUE = True\n"
    decision = sb.engine.decide(
        sb.intent("agent-alpha", resource, new_content=authorized), sb.tick()
    )
    assert decision.receipt is not None
    real_replace = effect_module._atomic_replace_at
    replaced = False

    def replace_then_substitute(parent_fd: int, name: str, content: bytes, mode: int) -> None:
        nonlocal replaced
        real_replace(parent_fd, name, content, mode)
        if not replaced:
            replaced = True
            real_replace(parent_fd, name, rogue, mode)

    with patch(
        "mutation_authority.effect._atomic_replace_at",
        side_effect=replace_then_substitute,
    ):
        result = sb.binder.commit(decision.receipt, authorized, sb.tick())

    _expect(replaced, "deterministic post-write substitution did not run")
    _expect(result.status == REJECTED, "rogue post-write state was accepted")
    _expect(target.read_bytes() == original, "post-write mismatch was not rolled back")
    _expect(
        decision.receipt.receipt_id not in sb.ledger.committed_receipt_ids(),
        "post-write mismatch left a COMMIT",
    )
    sb.ledger.verify_chain()
    return "post-write substituted bytes rejected; prior state restored and no COMMIT"


def check_mutation_receipt_schema_v2_rejects_legacy(base: Path) -> str:
    """Persisted legacy receipts fail closed with a typed format error."""
    sb = Sandbox.build(base)
    decision = sb.engine.decide(
        sb.intent("agent-alpha", "src/module_a.py", new_content=b"VALUE = 2\n"),
        sb.tick(),
    )
    assert decision.receipt is not None
    legacy = decision.receipt.to_dict()
    for field_name in (
        "schema",
        "expected_state_hash",
        "expected_state_mode",
        "parent_ancestor_path",
        "parent_ancestor_device",
        "parent_ancestor_inode",
    ):
        legacy.pop(field_name, None)
    try:
        MutationDecisionReceipt.from_dict(legacy)
    except ReceiptFormatError as exc:
        _expect("legacy unversioned" in str(exc), str(exc))
    else:
        raise CheckFailure("legacy unversioned mutation receipt was accepted")

    malformed = decision.receipt.to_dict()
    malformed.pop("expected_state_hash")
    try:
        MutationDecisionReceipt.from_dict(malformed)
    except ReceiptFormatError as exc:
        _expect("missing=" in str(exc), str(exc))
        return "v2 receipt parser rejects legacy/malformed state bindings with typed errors"
    raise CheckFailure("malformed v2 mutation receipt was accepted")


def attack_o_in_memory_root_mutation(base: Path) -> str:
    """Mutating the CACHED policy/actors dicts (the dataclass is frozen, its
    dict fields are not) must fail closed at the next decision exactly like a
    disk tamper: decisions consult root.policy/root.actors, so an in-memory
    grant would authorize what the sealed, signed files never did."""
    sb = Sandbox.build(base / "actors")
    sb.root.actors["agent-gamma"]["scopes"] = ["src/*"]  # in-memory scope grant
    try:
        sb.engine.decide(sb.intent("agent-gamma", "src/module_a.py"), sb.tick())
    except RootIntegrityError:
        pass
    else:
        raise CheckFailure("engine decided on an in-memory-tampered actor registry")

    sb2 = Sandbox.build(base / "policy")
    sb2.root.policy["protected_prefixes"] = []  # in-memory unprotect
    try:
        sb2.engine.decide(sb2.intent("agent-alpha", "src/module_a.py"), sb2.tick())
    except RootIntegrityError:
        return "in-memory actors/policy tamper ⇒ engine fails closed entirely"
    raise CheckFailure("engine decided on an in-memory-tampered policy")


def attack_t_content_substitution(base: Path) -> str:
    """A receipt approves specific bytes, not just a resource: an executor
    holding a valid receipt must not be able to commit DIFFERENT content —
    the expected post-state hash is part of what was authorized."""
    sb = Sandbox.build(base)
    resource = "src/module_a.py"
    original = (sb.repo / resource).read_bytes()
    decision = sb.engine.decide(
        sb.intent("agent-alpha", resource, new_content=b"VALUE = 2\n"), sb.tick()
    )
    _expect(decision.decision == ALLOW, f"setup ALLOW failed: {decision.reason}")
    assert decision.receipt is not None
    swapped = sb.binder.commit(decision.receipt, b"import os  # pwn\n", sb.tick())
    _expect(swapped.status == REJECTED, "substituted content was committed")
    _expect("not authorized by receipt" in swapped.reason, swapped.reason)
    _expect((sb.repo / resource).read_bytes() == original, "substitution touched the file")
    # The same receipt still authorizes exactly the approved bytes.
    approved = sb.binder.commit(decision.receipt, b"VALUE = 2\n", sb.tick())
    _expect(approved.status == ACCEPTED, f"approved bytes rejected: {approved.reason}")
    return "substituted bytes REJECTED (post-state bound); approved bytes ACCEPTED"


def attack_u_inflated_clock_receipt(base: Path) -> str:
    """decide() takes a caller-supplied `now`. An inflated value must not
    mint a receipt whose expiry outlives the TTL measured from the audit
    chain's own clock — such a receipt would block the resource (via
    open_receipts_for) or stay committable arbitrarily far into the future."""
    sb = Sandbox.build(base)
    ttl = sb.root.receipt_ttl()
    decision = sb.engine.decide(sb.intent("agent-alpha", "src/module_a.py"), 999_999_999)
    _expect(decision.decision == ALLOW, f"setup ALLOW failed: {decision.reason}")
    assert decision.receipt is not None
    # At issuance the chain holds only genesis (timestamp 0, one event), so
    # the clamp pins the issue tick to 2 regardless of the caller's clock.
    _expect(
        decision.receipt.expiry <= 2 + ttl,
        f"inflated now minted far-future expiry {decision.receipt.expiry}",
    )
    _expect(
        sb.ledger.open_receipts_for("src/module_a.py", decision.receipt.expiry + 1) == [],
        "inflated-clock receipt still blocks the resource past its clamped expiry",
    )
    return "inflated caller clock cannot extend a receipt past the ledger clock + TTL"


def check_unanchored_ledger_refused(base: Path) -> str:
    """Constructing a ledger without an anchor must be an explicit, loud
    opt-in — never a silent default that disables truncation detection."""
    base.mkdir(parents=True, exist_ok=True)
    try:
        AuditLedger(base / "ledger.jsonl")
    except LedgerIntegrityError:
        pass
    else:
        raise CheckFailure("unanchored ledger constructed without explicit opt-in")
    AuditLedger(base / "ledger.jsonl", allow_unanchored=True)  # insecure dev mode
    return "anchorless construction refused unless allow_unanchored=True"


def attack_v_unreadable_governed_subtree(base: Path) -> str:
    """Hide an unauthorized file by dropping traversal permission on its
    directory: the scan must fail closed, never report a clean repository."""
    sb = Sandbox.build(base)
    hidden = sb.repo / "src" / "hidden"
    hidden.mkdir()
    (hidden / "rogue.py").write_bytes(b"ROGUE = True\n")
    if os.geteuid() == 0:
        # root ignores directory modes; inject the identical enumeration
        # failure the kernel would see as an unprivileged scanner.
        real_iterdir = Path.iterdir

        def deny(self: Path):
            if self == hidden:
                raise PermissionError(13, "Permission denied", str(self))
            return real_iterdir(self)

        guard = patch.object(Path, "iterdir", deny)
    else:
        hidden.chmod(0o000)
        guard = nullcontext()
    try:
        with guard:
            try:
                repository_violations(sb.ledger, sb.repo, sb.root.governed_prefixes())
            except RepositoryScanError:
                pass
            else:
                raise CheckFailure(
                    "unreadable governed subtree was silently skipped — the hidden "
                    "unauthorized file would pass the CI gate undetected"
                )
    finally:
        if os.geteuid() != 0:
            hidden.chmod(0o755)
    return "unreadable governed directory ⇒ scan fails closed (RepositoryScanError)"


def check_concurrent_ledger_appends_serialized(base: Path) -> str:
    """Two writers appending concurrently must serialize on the ledger lock:
    unique seqs, an intact chain, and an anchor that matches the head —
    never two events built from the same snapshotted tail."""
    sb = Sandbox.build(base)
    start = threading.Barrier(2)
    errors: list[Exception] = []

    def writer(offset: int) -> None:
        # A separate AuditLedger instance per writer, as two processes would have.
        ledger = AuditLedger(sb.ledger.path, anchor_path=sb.ledger.anchor_path)
        start.wait()
        try:
            for i in range(8):
                ledger.append(
                    "DECISION",
                    {"decision": "DENY", "reason": f"race-{offset}-{i}"},
                    100 + offset,
                )
        except Exception as exc:  # surfaced below as a check failure
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(k,)) for k in (1, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _expect(not errors, f"concurrent append raised: {errors}")
    sb.ledger.verify_chain()  # unique seqs, linked chain, anchor == head
    events = list(sb.ledger.events())
    _expect(len(events) == 1 + 16, f"expected 17 events, found {len(events)} (lost append)")
    return "16 racing appends from 2 writers ⇒ intact chain, anchored head, none lost"


def check_concurrent_decisions_serialized(base: Path) -> str:
    """Two decide() calls for the same resource racing through the open-receipt
    conflict check must serialize: the check and the ALLOW append are one
    ledger transaction, so exactly one receipt is minted and the loser is
    DENIED as an in-flight conflict — never two live receipts bound to the
    same pre-state."""
    sb = Sandbox.build(base)
    resource = "src/verify_readiness.py"
    intents = [
        sb.intent("agent-alpha", resource, new_content=b"print('alpha')\n"),
        sb.intent("agent-beta", resource, new_content=b"print('beta')\n"),
    ]
    now = sb.tick()
    start = threading.Barrier(2)
    decisions: list = [None, None]
    errors: list[Exception] = []

    def racer(k: int) -> None:
        # A separate ledger/engine instance per racer, as two processes would have.
        ledger = AuditLedger(sb.ledger.path, anchor_path=sb.ledger.anchor_path)
        engine = DecisionEngine(sb.root, ledger, sb.repo)
        start.wait()
        try:
            decisions[k] = engine.decide(intents[k], now)
        except Exception as exc:  # surfaced below as a check failure
            errors.append(exc)

    threads = [threading.Thread(target=racer, args=(k,)) for k in (0, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _expect(not errors, f"concurrent decide raised: {errors}")
    verdicts = sorted(d.decision for d in decisions if d is not None)
    _expect(verdicts == [ALLOW, DENY], f"expected one ALLOW and one DENY, got {verdicts}")
    loser = next(d for d in decisions if d.decision == DENY)
    _expect("in flight" in loser.reason, loser.reason)
    sb.ledger.verify_chain()
    _expect(
        len(sb.ledger.open_receipts_for(resource, now)) == 1,
        "race minted more than one live receipt for the resource",
    )
    return "racing decisions serialized ⇒ one ALLOW receipt, one in-flight DENY"


CHECKS: list[tuple[str, Callable[[Path], str]]] = [
    ("happy-path: intent → decision → receipt → effect → audit", check_happy_path),
    ("deterministic verifier", check_deterministic_verifier),
    ("ledger is tamper-evident (hash chain)", check_ledger_tamper_evident),
    ("receipt expiry enforced", check_receipt_expiry),
    ("cryptographic provenance of every accepted change", check_provenance),
    ("ATTACK A: direct filesystem bypass", attack_a_direct_bypass),
    ("ATTACK B: valid signature, unauthorized scope", attack_b_valid_signature_wrong_scope),
    ("ATTACK C: concurrent writers on one resource", attack_c_concurrent_writers),
    ("ATTACK D: mutate governance root", attack_d_modify_governance_root),
    ("ATTACK E: replay consumed receipt", attack_e_replay_receipt),
    ("ATTACK F: change file after approval, before commit", attack_f_change_after_approval),
    ("ATTACK G (bonus): forged/altered receipt", attack_forged_receipt),
    ("ATTACK H (bonus): truncate ledger tail, replay receipt", attack_h_ledger_truncation),
    ("ATTACK I (bonus): delete ledger, regenerate genesis", attack_i_genesis_regeneration),
    ("ATTACK J (bonus): symlink escape from the governed repository", attack_j_symlink_escape),
    ("ATTACK K (bonus): metadata-only mutation (symlink swap, exec bit)", attack_k_metadata_swap),
    (
        "ATTACK L (bonus): effect applied but unrecordable is rolled back",
        attack_l_unrecordable_effect_rolled_back,
    ),
    (
        "ATTACK M (bonus): re-initialize the governance root in place",
        attack_m_reinitialize_governance_root,
    ),
    (
        "ATTACK N (bonus): rogue artifacts under a glob governed prefix",
        attack_n_glob_prefix_rogue_artifacts,
    ),
    (
        "ATTACK O (bonus): in-memory governance root mutation",
        attack_o_in_memory_root_mutation,
    ),
    ("ATTACK M: effect-time temporary symlink race", attack_p_temp_symlink_race),
    ("ATTACK M2: post-mint parent replacement", attack_pre_state_path_swap),
    ("ATTACK M3: post-open parent replacement", attack_post_open_parent_swap),
    ("ATTACK N: ancestor rename during effect", attack_q_parent_rename_during_effect),
    ("ATTACK O: ancestor rename at audit append", attack_r_parent_rename_at_audit_append),
    (
        "nested CREATE uses signed ancestor and transactional rollback",
        check_nested_create_uses_bound_ancestor,
    ),
    ("CREATE respects restrictive umask", check_create_respects_restrictive_umask),
    ("ATTACK P: post-write state substitution", attack_s_post_write_replacement),
    (
        "ATTACK T: content substitution against a valid receipt",
        attack_t_content_substitution,
    ),
    (
        "ATTACK U: inflated caller clock at receipt issuance",
        attack_u_inflated_clock_receipt,
    ),
    (
        "mutation receipt v2 rejects legacy state bindings",
        check_mutation_receipt_schema_v2_rejects_legacy,
    ),
    ("ledger is bound to its governance root", check_ledger_root_binding),
    ("unanchored ledger construction is refused", check_unanchored_ledger_refused),
    (
        "ATTACK V: unreadable governed subtree hides a rogue file",
        attack_v_unreadable_governed_subtree,
    ),
    ("concurrent ledger appends are serialized", check_concurrent_ledger_appends_serialized),
    ("concurrent decisions on one resource are serialized", check_concurrent_decisions_serialized),
]


def run_all_checks(work_dir: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    for index, (name, fn) in enumerate(CHECKS):
        sandbox_dir = work_dir / f"check-{index:02d}"
        try:
            detail = fn(sandbox_dir)
            results.append(CheckResult(name=name, passed=True, detail=detail))
        except (CheckFailure, AssertionError) as exc:
            results.append(CheckResult(name=name, passed=False, detail=str(exc)))
        except Exception as exc:  # unexpected error is a failure, not a crash
            results.append(
                CheckResult(name=name, passed=False, detail=f"{type(exc).__name__}: {exc}")
            )
    return results
