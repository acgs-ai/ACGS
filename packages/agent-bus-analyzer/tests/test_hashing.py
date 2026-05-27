"""Unit tests for canonical_json + compute_event_hash."""

from __future__ import annotations

import hashlib

from agent_bus_analyzer.hashing import canonical_json, compute_event_hash


def test_canonical_json_is_deterministic_under_key_order() -> None:
    a = {"z": 1, "a": 2, "m": 3}
    b = {"a": 2, "m": 3, "z": 1}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_json_has_no_whitespace() -> None:
    assert canonical_json({"a": 1, "b": [2, 3]}) == '{"a":1,"b":[2,3]}'


def test_canonical_json_handles_nested_keys() -> None:
    payload = {"outer": {"z": 1, "a": 2}, "list": [{"b": 1, "a": 2}]}
    assert canonical_json(payload) == '{"list":[{"a":2,"b":1}],"outer":{"a":2,"z":1}}'


def test_compute_event_hash_excludes_event_hash_field() -> None:
    event_a = {"prev_hash": "ab" * 32, "payload": "x", "event_hash": "ignored"}
    event_b = {"prev_hash": "ab" * 32, "payload": "x"}
    assert compute_event_hash(event_a) == compute_event_hash(event_b)


def test_compute_event_hash_differs_when_prev_hash_differs() -> None:
    event_a = {"prev_hash": "ab" * 32, "payload": "x"}
    event_b = {"prev_hash": "cd" * 32, "payload": "x"}
    assert compute_event_hash(event_a) != compute_event_hash(event_b)


def test_compute_event_hash_matches_manual_sha256() -> None:
    event = {"prev_hash": None, "payload": "x", "causal_index": 0}
    expected = hashlib.sha256(canonical_json(event).encode("utf-8")).hexdigest()
    assert compute_event_hash(event) == expected


def test_compute_event_hash_does_not_mutate_input() -> None:
    event = {"prev_hash": "00" * 32, "payload": "x", "event_hash": "irrelevant"}
    before = dict(event)
    compute_event_hash(event)
    assert event == before
