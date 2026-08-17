"""Phase 2 entry-gate hardening tests (H1 transition, H2 adversarial, H3 version, H4 secret tiers)."""

from __future__ import annotations

import pytest

from acgs_trajectory import secrets_scan as ss
from acgs_trajectory.adapter import SourceAdapter, read_jsonl, version_supported
from acgs_trajectory.git_evidence import git_transition
from acgs_trajectory.ingest import ingest_text
from acgs_trajectory.validate import v1_causal_graph

CAP = "1970-01-01T00:00:00Z"
GIT = {"head_sha": "a" * 40, "dirty": False, "branch": "master"}


def parse(read_fixture, name):
    return SourceAdapter().parse(read_jsonl(read_fixture(name)))


def ingest(read_fixture, name, **kw):
    return ingest_text(read_fixture(name), store=None, captured_at=CAP, **kw)


# ---- H4: secret-scanner policy tiers ---------------------------------------

# Synthetic, non-functional AWS-shaped keys, assembled from split literals so the
# full AKIA[0-9A-Z]{16} pattern never appears in source (no scanner flags this file).
_FAKE_AWS = "AKIA" + "QZ7X2LMWORKER9QT"          # matches the pattern at runtime only
_FAKE_AWS_EXAMPLEISH = "AKIA" + "000000000EXAMPLE"  # substring EXAMPLE, not the exact allowlist value


def test_h4_confirmed_secret_tier():
    f = ss.scan_text(f"AWS_KEY={_FAKE_AWS}")  # non-example, high-precision
    assert f and f[0].tier == ss.CONFIRMED_SECRET
    assert f[0].quarantine_worthy
    assert ss.has_secrets(f"{_FAKE_AWS} is here")


def test_h4_example_placeholder_allowed():
    f = ss.scan_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert f and f[0].tier == ss.EXAMPLE_PLACEHOLDER
    assert not f[0].quarantine_worthy
    assert ss.has_secrets("AKIAIOSFODNN7EXAMPLE") is False  # placeholder not quarantined


def test_h4_pragma_does_not_downgrade_on_untrusted_content():
    # SECURITY: a pragma in untrusted transcript content must NOT exempt a real secret.
    probe = f"{_FAKE_AWS}  pragma: allowlist secret"
    f = ss.scan_text(probe)
    assert ss.has_secrets(probe)
    assert any(x.tier == ss.CONFIRMED_SECRET for x in f)


def test_h4_id_prefix_cannot_hide_secret():
    # long high-entropy body behind a known id prefix must still be flagged
    wrapped = "toolu_aB3xK9mP2qR7sT1uV5wY8zC4dE6fG0hJ2kL4nM6pQ8rS"
    assert ss.has_secrets(wrapped)
    # an AWS key smuggled behind a prefix must be caught (body re-checked)
    assert ss.has_secrets(f"prefix toolu_ then {_FAKE_AWS} alone")


def test_h4_crafted_example_suffix_still_confirmed():
    # only the EXACT published example is a placeholder; a crafted ...EXAMPLE key is real
    f = ss.scan_text(f"AWS={_FAKE_AWS_EXAMPLEISH}")  # substring EXAMPLE, not the exact allowlist value
    assert f and f[0].tier == ss.CONFIRMED_SECRET


def test_h4_assigned_secret_is_pattern_match():
    f = ss.scan_text("password=Sup3rSecretValue1234567")
    assert f and f[0].tier == ss.SECRET_PATTERN_MATCH
    assert f[0].quarantine_worthy


def test_h4_non_secret_identifiers_not_flagged():
    # Anthropic tool ids, sha256 digests, and UUIDs must not trip the scanner.
    samples = [
        "toolu_01Dza6X5qLRsFJefUVBVP8gZ",
        "9e9d2530132a3d5e99c163846846ab82a583a4c2bbcfe404a1a034bffc2e3a56",  # sha256
        "f91157f5-9536-ce64-71bf-10c94539a771",  # uuid-shaped
    ]
    for s in samples:
        assert ss.scan_text(s) == [], f"false positive on {s[:12]}..."


def test_h4_reason_carries_tier_not_value():
    f = ss.scan_text(f"AWS_KEY={_FAKE_AWS}")
    r = f[0].as_reason()
    assert r.startswith("secret:confirmed_secret:")
    assert "AKIA" not in r


def test_h4_placeholder_session_not_quarantined(read_fixture):
    res = ingest(read_fixture, "placeholder_session.jsonl", repo_git=GIT)
    assert res.status != "quarantined", res.reasons
    assert any(r.startswith("note:secret:example_placeholder") for r in res.reasons)


def test_h4_generic_secret_still_quarantines(read_fixture):
    res = ingest(read_fixture, "secret_session.jsonl")
    assert res.status == "quarantined"
    assert any(r.startswith("secret:secret_pattern_match") for r in res.reasons)


# ---- H2: adversarial fixtures ----------------------------------------------


def test_h2_mixed_session_ids(read_fixture):
    res = ingest(read_fixture, "mixed_session_ids.jsonl", repo_git=GIT)
    assert res.status != "complete"
    assert any("multiple_session_ids" in r for r in res.reasons)


def test_h2_cyclic_parent_detected(read_fixture):
    reasons = v1_causal_graph(parse(read_fixture, "cyclic_parent_session.jsonl"))
    assert "V1:cycle" in reasons
    # and it must surface through the real ingest path (wiring regression guard)
    res = ingest(read_fixture, "cyclic_parent_session.jsonl", repo_git=GIT)
    assert res.status != "complete" and "V1:cycle" in res.reasons


def test_h2_result_before_use_detected(read_fixture):
    reasons = v1_causal_graph(parse(read_fixture, "result_before_use_session.jsonl"))
    assert any("tool_result_before_use" in r for r in reasons)
    res = ingest(read_fixture, "result_before_use_session.jsonl", repo_git=GIT)
    assert res.status != "complete"
    assert any("tool_result_before_use" in r for r in res.reasons)


def test_h2_dangling_tool_use_represented(read_fixture):
    p = parse(read_fixture, "dangling_tool_use_session.jsonl")
    ev = [t for t in p.tool_events if t.tool_use_id == "toolu_D1"]
    assert ev and ev[0].result_ref is None  # represented, not dropped


def test_h2_missing_session_id(read_fixture):
    res = ingest(read_fixture, "missing_session_id_session.jsonl", repo_git=GIT)
    assert res.status != "complete"
    assert "V3:missing_session_id" in res.reasons


def test_h2_missing_version_quarantined(read_fixture):
    res = ingest(read_fixture, "missing_version_session.jsonl")
    assert res.status == "quarantined"
    assert any("unsupported_version" in r for r in res.reasons)


# ---- H3: version-drift matrix ----------------------------------------------


@pytest.mark.parametrize(
    "version,ok",
    [
        ("2.1.170", True),
        ("2.0.0", True),
        ("2.99.5", True),
        ("2.", True),
        ("3.0.0", False),
        ("1.9.9", False),
        ("", False),
        (None, False),
        ("2", False),        # malformed: no dotted prefix
        (2.1, False),        # non-string metadata
        (2, False),
        ({"v": 1}, False),
    ],
)
def test_h3_version_matrix(version, ok):
    assert version_supported(version) is ok


# ---- H1: git transition capture --------------------------------------------


def test_h1_git_transition_with_fake_runner():
    canned = {
        "diff --shortstat P..H --": " 3 files changed, 40 insertions(+), 2 deletions(-)\n",
        "diff --name-status P..H --": "M\tacgs_trajectory/adapter.py\nA\ttests/test_hardening.py\n"
        "R100\told/path.py\tnew/path.py\n",
        "status --porcelain=v1": "",
        "ls-files -s": "100644 abc 0\tfile_a\n100644 def 0\tfile_b\n",
    }

    def fake(args):
        return canned[" ".join(args)]

    block = git_transition("P", "H", fake)
    assert block["parent"] == "P" and block["head"] == "H"
    assert "3 files changed" in block["diff_shortstat"]
    assert {"change": "M", "path": "acgs_trajectory/adapter.py"} in block["changed_files"]
    assert block["working_tree_clean"] is True
    assert block["tracked_file_count"] == 2
    # rename R100 old\tnew -> new path is 'new/path.py', old captured as 'from'
    rn = [c for c in block["changed_files"] if c["change"].startswith("R")]
    assert rn and rn[0]["path"] == "new/path.py" and rn[0]["from"] == "old/path.py"
