"""Regression tests for backend.auth.dependencies SECRET_KEY validation.

Codex adversarial-review finding #2: SECRET_KEY had a public placeholder
default, letting any deploy without the env var sign JWTs with a known
string. The fix wraps the lookup in `_load_secret_key()` which raises
unless either a real secret is set OR ACGS_BOOTSTRAP_DEV_AUTH=1 opts in.

These tests target the helper directly rather than reimporting the module,
because module reload swaps the identity of get_current_user and breaks
other tests that compare router dependencies by identity (notably
test_p0_contract_hardening.test_business_routers_are_protected_*).
"""

from __future__ import annotations

import os

import pytest

# Ensure SECRET_KEY is set before any test or conftest fixture pulls in
# backend.auth.dependencies. Per-test fixtures below monkeypatch it for
# the specific scenario under test.
os.environ.setdefault("SECRET_KEY", "test-secret-" + "x" * 16)

from backend.auth.dependencies import _PLACEHOLDER_SECRET_KEY, _load_secret_key


def test_missing_secret_key_raises_in_production(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("ACGS_BOOTSTRAP_DEV_AUTH", raising=False)

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        _load_secret_key()


def test_placeholder_secret_key_raises_in_production(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", _PLACEHOLDER_SECRET_KEY)
    monkeypatch.delenv("ACGS_BOOTSTRAP_DEV_AUTH", raising=False)

    with pytest.raises(RuntimeError, match="placeholder"):
        _load_secret_key()


def test_missing_secret_key_allowed_in_dev_mode(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("ACGS_BOOTSTRAP_DEV_AUTH", "1")

    assert _load_secret_key() == _PLACEHOLDER_SECRET_KEY


def test_placeholder_secret_key_allowed_in_dev_mode(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", _PLACEHOLDER_SECRET_KEY)
    monkeypatch.setenv("ACGS_BOOTSTRAP_DEV_AUTH", "1")

    assert _load_secret_key() == _PLACEHOLDER_SECRET_KEY


def test_real_secret_key_accepted(monkeypatch):
    real = "a" * 32
    monkeypatch.setenv("SECRET_KEY", real)
    monkeypatch.delenv("ACGS_BOOTSTRAP_DEV_AUTH", raising=False)

    assert _load_secret_key() == real
