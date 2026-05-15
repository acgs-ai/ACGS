"""Unit tests for config loader + constitutional-hash resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bus_analyzer.config import load_config, resolve_constitutional_hash
from agent_bus_analyzer.errors import IntegrityStoreUnavailable


def test_resolve_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSTITUTIONAL_HASH", "608508a9bd224290")
    assert resolve_constitutional_hash() == "608508a9bd224290"


def test_unset_env_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONSTITUTIONAL_HASH", raising=False)
    with pytest.raises(IntegrityStoreUnavailable, match="unset"):
        resolve_constitutional_hash()


def test_bad_hex_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSTITUTIONAL_HASH", "not-hex-chars!!")
    with pytest.raises(IntegrityStoreUnavailable, match="16 lowercase hex"):
        resolve_constitutional_hash()


def test_uppercase_hash_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSTITUTIONAL_HASH", "608508A9BD224290")
    with pytest.raises(IntegrityStoreUnavailable):
        resolve_constitutional_hash()


def test_wrong_length_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONSTITUTIONAL_HASH", "608508a9bd224")
    with pytest.raises(IntegrityStoreUnavailable):
        resolve_constitutional_hash()


def test_load_config_basic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CONSTITUTIONAL_HASH", "608508a9bd224290")
    cfg = load_config(
        bus_endpoint="local:default",
        audit_file=tmp_path / "audit.jsonl",
        store_dir=tmp_path / "traces",
    )
    assert cfg.constitutional_hash == "608508a9bd224290"
    assert cfg.queue_capacity == 10_000
    assert cfg.retention_days == 90
    assert cfg.audit_file == tmp_path / "audit.jsonl"
    assert cfg.store_dir == tmp_path / "traces"


def test_load_config_is_frozen(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CONSTITUTIONAL_HASH", "608508a9bd224290")
    cfg = load_config(
        bus_endpoint="local:default",
        audit_file=tmp_path / "audit.jsonl",
        store_dir=tmp_path / "traces",
    )
    with pytest.raises((AttributeError, TypeError)):
        cfg.queue_capacity = 1  # type: ignore[misc]
