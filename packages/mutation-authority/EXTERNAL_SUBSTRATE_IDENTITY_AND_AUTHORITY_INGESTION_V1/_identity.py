"""Substrate identity: build and verify a deterministic cryptographic manifest.

Identity binds the *bytes of a fixed critical-object set* plus the *structural
counts re-derived from the live registries*. It deliberately does NOT bind the
absolute pathname (Section 6): a substrate relocated to a new path whose
critical objects are byte-identical still verifies. Path binding is recorded as
corroborating evidence (verify_readiness.py hardcodes its ROOT), not as the
identity itself.

Fail-closed semantics (Section 16):
  * any critical object present but with a different hash  -> IDENTITY_MISMATCH
  * any critical object absent                             -> IDENTITY_UNVERIFIABLE
  * critical objects match but counts drift                -> SUBSTRATE_DRIFT
  * all match                                              -> IDENTITY_CONFIRMED
Verification NEVER regenerates the manifest (that would mask drift); rebinding
is a separate explicit build.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from _canonical import ABSENT, hash_file, hash_obj, sha256_hex
from _substrate import (
    CRITICAL_OBJECTS,
    compute_critical_objects,
    derive_counts,
)

SCHEMA = "acgs_substrate_identity/v1"
MANIFEST_NAME = "substrate_identity.json"

# The identity_class enum (mirrors SUBSTRATE_IDENTITY_SCHEMA.json). A typo'd
# class would silently mislabel the trust level of the whole manifest.
IDENTITY_CLASSES = (
    "EXACT_PRIOR_SUBSTRATE",
    "COMPATIBLE_BUT_UNPROVEN",
    "DIVERGED_SUBSTRATE",
    "TEST_SUBSTRATE",
)

# Coreutils sha256sum line: "<64 hex>  <name>" (two-space separator; a leading
# "*" on the name means binary mode and is equivalent).
_SUMS_LINE_RE = re.compile(r"^([0-9a-f]{64})  (\*?)(.+)$")

# Redact operator home paths from the committed manifest. The substrate's own
# verifier fails on any "/home/<user>/" or "/Users/<user>/" string; identity does
# not depend on the literal path (it matches by bytes), so we store a redacted
# display plus a hash of the full path for corroboration.
_HOME_RE = re.compile(r"^/(home|Users)/[^/]+")


def _redact_home(path: str) -> str:
    return _HOME_RE.sub("~", path)


# States
IDENTITY_CONFIRMED = "IDENTITY_CONFIRMED"
IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
IDENTITY_UNVERIFIABLE = "IDENTITY_UNVERIFIABLE"
SUBSTRATE_DRIFT = "SUBSTRATE_DRIFT"


def critical_set_digest(critical: dict[str, dict[str, Any]]) -> str:
    """Deterministic digest over {relpath: sha256}. Path-independent: uses
    relative paths only, so relocation does not change it."""
    return hash_obj({rel: v["sha256"] for rel, v in sorted(critical.items())})


def _path_binding(root: Path) -> dict[str, Any]:
    """Record whether verify_readiness.py hardcodes a ROOT under this tree.

    Corroborating evidence only. Read-only; never fails the build on its own.
    """
    vr = root / "verify_readiness.py"
    real_parent = str(root.parent)
    bound = False
    if vr.is_file():
        try:
            text = vr.read_text(encoding="utf-8", errors="replace")
            bound = ("ROOT" in text) and (real_parent in text)
        except OSError:
            bound = False
    return {
        "type": "verify_readiness.py hardcodes ROOT to the substrate parent",
        "observed_parent": _redact_home(real_parent),
        "verified": bound,
    }


def build_manifest(root: Path, identity_class: str) -> dict[str, Any]:
    """Build the identity manifest. Fails closed if any critical object is
    absent — an incomplete substrate has no bindable identity."""
    if identity_class not in IDENTITY_CLASSES:
        raise ValueError(
            f"unknown identity_class: {identity_class!r} — must be one of "
            + ", ".join(IDENTITY_CLASSES)
        )
    critical = compute_critical_objects(root)
    absent = sorted(rel for rel, v in critical.items() if v["sha256"] == ABSENT)
    if absent:
        raise ValueError("cannot build identity: critical objects absent: " + ", ".join(absent))
    irregular = sorted(
        rel for rel, v in critical.items() if str(v["sha256"]).startswith("UNHASHABLE:")
    )
    if irregular:
        # A manifest carrying a marker "digest" would re-verify against the
        # same symlinked object — identity must bind regular in-tree bytes.
        raise ValueError(
            "cannot build identity: critical objects are not regular files "
            "(symlinked?): " + ", ".join(irregular)
        )
    counts = derive_counts(root)
    digest = critical_set_digest(critical)
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "substrate_id": digest[:16],
        "substrate_type": "COMMERCIAL_BUYER_READINESS_V1",
        "canonical_observed_path": _redact_home(str(root)),
        "canonical_observed_path_sha256": sha256_hex(str(root).encode("utf-8")),
        "path_binding": _path_binding(root),
        "source_bundle_identity": {
            "bundle_dir": root.parents[1].name if len(root.parents) >= 2 else str(root),
            "note": "downloaded trajectory bundle; extraction of the sibling .zip",
        },
        "critical_object_count": len(critical),
        "critical_objects": critical,
        "critical_set_digest": digest,
        "expected_counts": counts,
        "identity_generated_from": [
            "sha256 of a fixed 15-object critical set",
            "structural counts re-derived from the live registries",
        ],
        "generation_basis": "deterministic (critical_set_digest); no wall-clock embedded",
        "identity_strength": {
            "path_binding": "strong" if _path_binding(root)["verified"] else "weak",
            "structural_fingerprint": "exact",
            "cryptographic_binding": "critical_objects",
            "vcs_lineage": "unavailable",
        },
        "identity_class": identity_class,
        "limitations": [
            "No VCS lineage exists; identity is authorship path-binding + exact "
            "critical-object hashes + exact count fingerprint, not commit ancestry.",
            "Binds a critical subset, not all 232 GB; the two layers carrying the "
            "340 requests / 408 mappings / 12 requirements plus each layer's own "
            "sha256sums.txt (which transitively pins its files) and the top verifier.",
            "Identity proves this is the same artifact; it proves nothing about "
            "any real-world legal authority, right, or recipient.",
        ],
    }


def _verify_checksum_manifest(sums_rel: str, sums_path: Path) -> tuple[list[str], list[str]]:
    """Verify every entry of one layer's sha256sums.txt against the files it
    names (coreutils format: '<64 hex>  <name>'). The identity claims each
    layer's checksum manifest "transitively pins its files", so those pins must
    actually be checked: a listed file altered or removed fails identity even
    though the sums file's own bytes are unchanged.

    Returns (mismatched, absent) entry labels. A sums file that cannot be
    parsed, carries a malformed line, or names a path escaping its layer
    directory is itself reported as mismatched (fail closed)."""
    mismatched: list[str] = []
    absent: list[str] = []
    layer_dir = sums_path.parent
    try:
        lines = sums_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return [sums_rel], []
    for line in lines:
        if not line.strip():
            continue
        m = _SUMS_LINE_RE.match(line)
        if m is None:
            return [sums_rel], []  # malformed checksum manifest — unverifiable pin
        expected_digest, _mode, name = m.group(1), m.group(2), m.group(3)
        parts = name.replace("\\", "/").split("/")
        if name.startswith("/") or ".." in parts:
            return [sums_rel], []  # traversal name — refuse to follow it
        entry_rel = f"{sums_rel.rsplit('/', 1)[0]}/{name}" if "/" in sums_rel else name
        digest = hash_file(layer_dir / name)
        if digest == ABSENT:
            absent.append(entry_rel)
        elif digest != expected_digest:
            mismatched.append(entry_rel)
    return mismatched, absent


def verify_manifest(manifest: dict[str, Any], candidate_root: Path) -> dict[str, Any]:
    """Re-verify a candidate substrate against a bound manifest. Read-only.

    Returns {state, mismatched[], absent[], count_drift{}, candidate_root,
    critical_set_digest_matches}.
    """
    expected = manifest.get("critical_objects", {})
    mismatched: list[str] = []
    absent: list[str] = []
    live: dict[str, dict[str, Any]] = {}
    for rel in CRITICAL_OBJECTS:
        p = candidate_root / rel
        digest = hash_file(p)
        is_content = digest != ABSENT and not digest.startswith("UNHASHABLE:")
        live[rel] = {
            "sha256": digest,
            "bytes": (p.stat().st_size if (is_content and p.is_file()) else None),
        }
        exp = expected.get(rel, {}).get("sha256")
        if digest == ABSENT:
            absent.append(rel)
        elif exp is not None and digest != exp:
            mismatched.append(rel)
        elif rel.endswith("sha256sums.txt"):
            # The sums file's own bytes match the manifest; now honor the
            # transitive pin — every file it names must still hash to its
            # recorded digest.
            entry_mismatched, entry_absent = _verify_checksum_manifest(rel, p)
            mismatched.extend(e for e in entry_mismatched if e not in mismatched)
            absent.extend(e for e in entry_absent if e not in absent)

    digest_matches = critical_set_digest(live) == manifest.get("critical_set_digest")

    # Determine state, fail-closed order: mismatch > absent > drift > confirmed.
    if mismatched:
        state = IDENTITY_MISMATCH
    elif absent:
        state = IDENTITY_UNVERIFIABLE
    else:
        # All critical objects present and byte-matching. Counts must still agree.
        try:
            live_counts = derive_counts(candidate_root)
        except Exception:
            live_counts = {}
        drift = {
            k: {"expected": v, "live": live_counts.get(k)}
            for k, v in manifest.get("expected_counts", {}).items()
            if live_counts.get(k) != v
        }
        if drift or not digest_matches:
            state = SUBSTRATE_DRIFT
            return {
                "state": state,
                "mismatched": mismatched,
                "absent": absent,
                "count_drift": drift,
                "critical_set_digest_matches": digest_matches,
                "candidate_root": str(candidate_root),
            }
        state = IDENTITY_CONFIRMED

    return {
        "state": state,
        "mismatched": mismatched,
        "absent": absent,
        "count_drift": {},
        "critical_set_digest_matches": digest_matches,
        "candidate_root": str(candidate_root),
    }
