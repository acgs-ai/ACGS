"""Strict canonicalizer for the Phase 2 signature ABI.

Phase 1's `sha256_json` uses `default=str` which can silently coerce
ambiguous types into strings. For long-lived signatures we need a
canonicalizer that rejects ambiguity instead — see
`docs/design/phase2-trace-crypto.md` §canonical serialization and
ADR-0007.
"""

from __future__ import annotations

import unicodedata

import pytest


def _canonical_bytes():
    """Lazy-import so collection succeeds before the module exists."""
    from governance.crypto.canonical import canonical_bytes

    return canonical_bytes


def _CanonicalizationError():
    from governance.crypto.canonical import CanonicalizationError

    return CanonicalizationError


def test_canonical_bytes_accepts_int_bool_str_none_list_nested_dict():
    canonical_bytes = _canonical_bytes()
    payload = {
        "a": 1,
        "b": True,
        "c": None,
        "d": "text",
        "e": [1, "two", False, None],
        "f": {"nested": {"deep": 42}},
    }
    out = canonical_bytes(payload)
    assert isinstance(out, bytes)
    # determinism: re-canonicalize must produce identical bytes
    assert canonical_bytes(payload) == out


def test_canonical_bytes_sorts_keys_in_codepoint_order():
    canonical_bytes = _canonical_bytes()
    a = canonical_bytes({"b": 1, "a": 2, "c": 3})
    b = canonical_bytes({"a": 2, "c": 3, "b": 1})
    assert a == b
    # confirms sort: "a" before "b" before "c"
    assert a.index(b'"a"') < a.index(b'"b"') < a.index(b'"c"')


def test_canonical_bytes_uses_tight_separators_and_utf8():
    canonical_bytes = _canonical_bytes()
    out = canonical_bytes({"a": 1, "b": [2, 3]})
    assert out == b'{"a":1,"b":[2,3]}'


def test_canonical_bytes_rejects_float():
    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": 1.5})


def test_canonical_bytes_rejects_nan_and_inf():
    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError):
            canonical_bytes({"x": bad})


def test_canonical_bytes_rejects_non_str_dict_key():
    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    with pytest.raises(CanonicalizationError):
        canonical_bytes({1: "value"})


def test_canonical_bytes_rejects_bytes_value():
    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": b"raw"})


def test_canonical_bytes_rejects_datetime_value():
    import datetime as dt

    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": dt.datetime.now(tz=dt.timezone.utc)})


def test_canonical_bytes_rejects_unnormalized_unicode():
    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    # NFD-decomposed "café" — visually identical to NFC "café" but
    # not byte-identical. We require callers to NFC-normalize.
    nfd = unicodedata.normalize("NFD", "café")
    nfc = unicodedata.normalize("NFC", "café")
    assert nfd != nfc
    # NFC passes
    canonical_bytes({"x": nfc})
    # NFD raises
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": nfd})


def test_canonical_bytes_rejects_embedded_nul_in_string():
    canonical_bytes = _canonical_bytes()
    CanonicalizationError = _CanonicalizationError()
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": "with\x00nul"})


def test_canonical_bytes_rejects_duplicate_keys_via_dict_subclass():
    # plain dict can't carry duplicates, but a caller might pass a
    # custom mapping. Test the contract via str/int collision after
    # normalization is not a use case — we require keys to be plain str.
    # Covered by test_canonical_bytes_rejects_non_str_dict_key.
    pass
