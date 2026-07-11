"""Characterization tests pinning the TWO divergent ``sha256_json`` byte formats.

This package ships two same-named canonicalizers that emit DIFFERENT bytes:

- ``governance.models.sha256_json``
  ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)``
  — non-ASCII passes through as raw UTF-8; non-JSON-serializable values are
  silently coerced to ``str``.
- ``governed_mcp_v0._io.sha256_json``
  ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)``
  — non-ASCII is ``\\uXXXX``-escaped; non-JSON-serializable values raise
  ``TypeError``.

They agree on pure-ASCII JSON-native payloads and NOWHERE else. A payload
hashed by one and verified by the other mismatches as soon as it contains
non-ASCII text — a receipt/verify landmine if a value ever crosses the
module boundary.

Call-site analysis (2026-07-07, this worktree): every producer/verifier pair
stays inside its own module. All ``governance/*`` hashing (admission gate,
replay, audit chains, dspy, evaluation) imports from ``governance.models``;
all ``governed_mcp_v0/*`` hashing (server receipts, verify.py replay,
constitution registry) imports from ``governed_mcp_v0._io``. The only
cross-boundary import in ``governed_mcp_v0`` is
``governance.audit.refuse_unreliable_fs`` (not a hasher), and no
``governance`` module imports ``governed_mcp_v0``. Zero cross-module hash
verification exists today, so unification remains POSSIBLE — but it is
deferred: persisted receipts and audit chains were hashed with these exact
byte formats, and changing either format breaks verification of existing
artifacts.

These are characterization tests, not aspirations: the golden hashes below
pin the CURRENT behavior of each function. If either test fails, someone
changed a hash format that persisted artifacts depend on — stop and read
``docs/solutions/logic-errors/two-divergent-sha256-json-canonicalizers.md``
before "fixing" the test. New code that needs strict, unambiguous hashing
should use ``governance.crypto.canonical.canonical_bytes`` (Phase 2 ABI)
instead of either of these.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from governance.models import sha256_json as models_sha256_json
from governed_mcp_v0._io import sha256_json as io_sha256_json

ASCII_PAYLOAD = {"tool": "send_email", "amount_cents": 5000, "nested": {"ok": True, "ids": [1, 2, 3]}}
ASCII_GOLDEN = "63d64aac2ecb6334e2ad112d76a1e38303d2c9060ea7489c6e0bbe87034071f5"

NON_ASCII_PAYLOAD = {"reviewer": "Müller", "note": "café ☕", "tenant": "默认"}
NON_ASCII_GOLDEN_MODELS = "2c45cb97cc0a9b34d03a6cfe2ae338cc41b34ee72ea0dcfc7047a1d7632fc547"
NON_ASCII_GOLDEN_IO = "3946dd8a4fbfd9ad4ef16567c1a5dfee1f77736a4fe95610817e8df603fba7e1"

NON_SERIALIZABLE_PAYLOAD = {"when": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)}
NON_SERIALIZABLE_GOLDEN_MODELS = "01939be5ee4bb45d1ab4fe1bc836363b6763e2e21b60f659c7051840b70ced50"


@pytest.mark.regression(
    pr="maint/p1-sha256-json-divergence",
    severity="HIGH",
    issue="divergent_sha256_json_canonicalizers",
    coverage_angle="ascii_payloads_hash_identically",
)
def test_ascii_payload_hashes_identically_in_both_modules():
    """Pure-ASCII JSON-native payloads are the ONLY inputs both agree on."""
    assert models_sha256_json(ASCII_PAYLOAD) == ASCII_GOLDEN
    assert io_sha256_json(ASCII_PAYLOAD) == ASCII_GOLDEN


@pytest.mark.regression(
    pr="maint/p1-sha256-json-divergence",
    severity="HIGH",
    issue="divergent_sha256_json_canonicalizers",
    coverage_angle="non_ascii_payloads_diverge",
)
def test_non_ascii_payload_diverges_between_modules():
    """ensure_ascii=False (models) vs ensure_ascii=True (_io) yield different
    bytes for the same payload. This divergence is EXPECTED CURRENT BEHAVIOR,
    pinned so it can never change silently."""
    models_hash = models_sha256_json(NON_ASCII_PAYLOAD)
    io_hash = io_sha256_json(NON_ASCII_PAYLOAD)
    assert models_hash == NON_ASCII_GOLDEN_MODELS
    assert io_hash == NON_ASCII_GOLDEN_IO
    assert models_hash != io_hash


@pytest.mark.regression(
    pr="maint/p1-sha256-json-divergence",
    severity="HIGH",
    issue="divergent_sha256_json_canonicalizers",
    coverage_angle="non_serializable_coerce_vs_raise",
)
def test_non_serializable_value_coerces_in_models_but_raises_in_io():
    """models: default=str silently coerces (can never raise — see
    test_canonicalizer_failure_deny.py); _io: no default, raises TypeError."""
    assert models_sha256_json(NON_SERIALIZABLE_PAYLOAD) == NON_SERIALIZABLE_GOLDEN_MODELS
    with pytest.raises(TypeError):
        io_sha256_json(NON_SERIALIZABLE_PAYLOAD)
