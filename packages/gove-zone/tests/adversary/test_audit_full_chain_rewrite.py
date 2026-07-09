"""Adversary class: AUDIT MANIPULATION via self-consistent full-chain rewrite.

``verify_chain()`` (audit.py) is keyless and self-referential: it recomputes every
``event_hash`` and checks ``previous_hash`` linkage, but there is NO signature or external
anchor over the chain head. An attacker with filesystem write access can delete/alter an
event and regenerate a fully self-consistent chain from genesis — ``verify_chain()`` then
reports ``valid=True``. Existing tamper tests only catch single-line edits that DON'T
re-derive downstream hashes, which is not the real threat.

See threat-model-v2.md §7. Tamper-evidence holds only relative to an independently held
copy of the trusted head.
"""

from __future__ import annotations

import json
from pathlib import Path

from gove_zone import ChainHashAuditStore, Decision, DecisionRecord
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import sha256_json


def _seed(path: Path, n: int) -> ChainHashAuditStore:
    store = ChainHashAuditStore(path)
    for i in range(n):
        store.append(
            DecisionRecord(
                decision=Decision.ALLOW,
                tool=f"tool-{i}",
                argument_hash="h",
                policy_version="v1",
                event_id=f"ev{i}",
            )
        )
    return store


def test_verify_chain_accepts_self_consistent_full_rewrite_KNOWN_GAP(tmp_path: Path) -> None:
    """Delete the middle event and regenerate a fully self-consistent chain; the keyless
    verifier accepts it with no trace of the deletion — the attack succeeds today."""
    path = tmp_path / "audit.jsonl"
    store = _seed(path, 3)
    assert store.verify_chain()["valid"] is True

    events = list(store.iter_events())
    kept = [events[0], events[2]]  # drop the middle event entirely

    previous = GENESIS_HASH
    rewritten: list[dict] = []
    for ev in kept:
        payload = dict(ev)
        payload["previous_hash"] = previous
        payload.pop("event_hash", None)
        payload["event_hash"] = sha256_json(payload)
        rewritten.append(payload)
        previous = payload["event_hash"]

    path.write_text(
        "\n".join(json.dumps(p, sort_keys=True) for p in rewritten) + "\n",
        encoding="utf-8",
    )

    result = ChainHashAuditStore(path).verify_chain()
    assert result["valid"] is True, (
        "a self-consistent full rewrite passes internal verification because the chain is "
        "keyless with no external anchor. If this fails, an anchor/checkpoint was added "
        "(good — update the manifest)."
    )
    assert result["checked"] == 2  # the deleted event left no trace


def test_single_field_edit_still_detected_HELD(tmp_path: Path) -> None:
    """The existing guarantee: editing one line WITHOUT re-deriving downstream hashes is
    caught. This is the boundary of the current defense — self-consistency is all it
    checks."""
    path = tmp_path / "audit.jsonl"
    _seed(path, 2)

    lines = path.read_text(encoding="utf-8").splitlines()
    ev0 = json.loads(lines[0])
    ev0["tool"] = "TAMPERED"  # edit a field, leave event_hash stale
    lines[0] = json.dumps(ev0, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = ChainHashAuditStore(path).verify_chain()
    assert result["valid"] is False
