#!/usr/bin/env python3
"""Phase 1.1 Evidence Freeze generator.

Deterministically produces the Phase 1 evidence manifest and the freeze report.
Does NOT evaluate, score, label, or package (Phase 2+ remain out of scope). It
only records reproducible, auditable facts about the ingestion foundation.

Usage:
    python scripts/evidence_freeze.py --commit <SHA> --branch <B> \
        --dirty <true|false> --pytest "38 passed" [--out docs/evidence]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from acgs_trajectory.canonical import canonical_bytes, sha256_hex  # noqa: E402
from acgs_trajectory.ingest import ingest_text  # noqa: E402
from acgs_trajectory.raw_store import RawStore  # noqa: E402
from acgs_trajectory.replay import replay  # noqa: E402

IMPL_FILES = [
    "acgs_trajectory/__init__.py",
    "acgs_trajectory/canonical.py",
    "acgs_trajectory/errors.py",
    "acgs_trajectory/adapter.py",
    "acgs_trajectory/secrets_scan.py",
    "acgs_trajectory/raw_store.py",
    "acgs_trajectory/materialize.py",
    "acgs_trajectory/validate.py",
    "acgs_trajectory/ingest.py",
    "acgs_trajectory/replay.py",
    "acgs_trajectory/cli.py",
    "acgs_trajectory/schemas/governance_trajectory_v2.schema.json",
]
SCHEMA_FILE = "acgs_trajectory/schemas/governance_trajectory_v2.schema.json"

FIXTURES = {
    "complete_session.jsonl": "real-shape passing session (golden replay input)",
    "subagent_session.jsonl": "sidechain / subagent nesting",
    "hook_prevented_session.jsonl": "governance hook evidence (preventedContinuation)",
    "missing_parent_session.jsonl": "V1 orphan",
    "broken_tool_ref_session.jsonl": "V2 broken tool reference",
    "secret_session.jsonl": "V5 secret boundary (AWS canonical example key)",
    "unsupported_version_session.jsonl": "V6 unsupported version quarantine",
    "unknown_type_session.jsonl": "V6 unknown record type quarantine",
    "malformed_session.jsonl": "malformed JSON -> ParseError",
}

# Phase 1.1 validation-coverage labels (as requested) -> implementing symbol + tests.
VALIDATION_COVERAGE = {
    "V1 causal integrity": {
        "impl": "validate.v1_causal_graph",
        "tests": ["test_v1_clean_on_complete", "test_v1_orphan_detected",
                  "test_v1_sidechain_linked", "test_subagent_relationship_and_edges"],
    },
    "V2 block/tool linkage": {
        "impl": "adapter.SourceAdapter.parse (tool join) + validate.v2_block_integrity",
        "tests": ["test_tool_use_result_linkage", "test_v1_broken_tool_ref",
                  "test_v2_block_integrity_clean", "test_block_separation_thinking_text_tooluse"],
    },
    "V3 tamper detection": {
        "impl": "validate.v4_tamper + raw_store.verify_raw + raw_store.verify_chain",
        "tests": ["test_tamper_detection_v4", "test_verify_raw_detects_tamper",
                  "test_manifest_chain_detects_modification"],
    },
    "V4 provenance completeness": {
        "impl": "validate.v3_provenance",
        "tests": ["test_missing_git_head_is_incomplete_not_complete",
                  "test_environment_and_leaf"],
    },
    "V5 secret boundary": {
        "impl": "secrets_scan.scan_text + ingest quarantine routing",
        "tests": ["test_v5_secret_detection", "test_v5_git_sha_whitelisted",
                  "test_secret_session_quarantined_and_not_in_shared_archive"],
    },
    "V6 unsupported input handling": {
        "impl": "adapter version boundary + ingest quarantine + validate.v6_schema",
        "tests": ["test_unsupported_version_quarantined", "test_unknown_record_type_quarantined_but_retained",
                  "test_malformed_line_raises", "test_v6_rejects_derived_values"],
    },
}

# A1-A9 acceptance mapping (docs/phase1/acceptance-criteria.md) -> evidence.
ACCEPTANCE_MAPPING = {
    "A1 schema contract valid": "jsonschema check_schema + sample validates (test_v6_schema_loads_and_is_draft2020)",
    "A2 golden round-trip": "replay byte-identical (test_replay_byte_identical_across_runs)",
    "A3 orphan=0 on golden": "test_v1_clean_on_complete",
    "A4 tamper detection": "test_tamper_detection_v4 + test_verify_raw_detects_tamper",
    "A5 missing-field fail-closed": "test_missing_git_head_is_incomplete_not_complete",
    "A6 unknown-type quarantine": "test_unknown_record_type_quarantined_but_retained",
    "A7 secret boundary": "test_secret_session_quarantined_and_not_in_shared_archive",
    "A8 raw immutability": "test_content_addressed_worm + test_manifest_hash_chain",
    "A9 determinism": "test_determinism_identical_input_identical_output + test_replay_byte_identical_across_runs",
}

KNOWN_LIMITATIONS_REF = "docs/phase1/implementation-summary.md#6-known-limitations"
SUPPORTED_VERSIONS = ["2.1.170"]
SUPPORTED_PREFIXES = ["2."]


def file_sha(rel: str) -> str:
    return sha256_hex((ROOT / rel).read_bytes())


def run_checks() -> dict:
    """Perform the deterministic Phase 1.1 checks and return a results dict."""
    results: dict = {}

    # deterministic replay twice
    fx = "tests/fixtures/complete_session.jsonl"
    a = replay(ROOT / fx)
    b = replay(ROOT / fx)
    results["replay"] = {
        "fixture": fx,
        "runs": 2,
        "status": a.status,
        "canonical_sha256": a.canonical_sha256,
        "normalized_sha256": a.normalized_sha256,
        "trajectory_id": a.trajectory_id,
        "byte_identical": a.canonical == b.canonical and a.canonical_sha256 == b.canonical_sha256,
        "fixture_unmutated": True,  # replay() raises if the source changed
    }

    # schema validation of the committed sample
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / SCHEMA_FILE).read_text())
    Draft202012Validator.check_schema(schema)
    sample = json.loads((ROOT / "docs/examples/sample_trajectory.json").read_text())
    sample_errors = [e.message for e in Draft202012Validator(schema).iter_errors(sample)]
    results["schema_validation"] = {
        "schema_is_draft2020": True,
        "sample_valid": not sample_errors,
        "sample_errors": sample_errors,
    }

    # manifest chain verification via a throwaway store
    with tempfile.TemporaryDirectory() as td:
        store = RawStore(td)
        ingest_text((ROOT / fx).read_text(), store=store, captured_at="1970-01-01T00:00:00Z",
                    repo_git={"head_sha": "0" * 40, "dirty": False})
        ingest_text((ROOT / "tests/fixtures/secret_session.jsonl").read_text(), store=store,
                    captured_at="1970-01-01T00:00:01Z")
        ok, errors = store.verify_chain()
    results["manifest_chain"] = {"verified": ok, "errors": errors}

    return results


def build_manifest(args, checks: dict) -> dict:
    manifest = {
        "manifest_version": "phase1-evidence/1",
        "phase": "1.1 Evidence Freeze",
        "scope": "ingestion foundation only (no evaluator/scoring/labels/annotation/tiering/packaging)",
        "repository": {
            "commit": args.commit,
            "branch": args.branch,
            "dirty": args.dirty == "true",
        },
        "schema": {"file": SCHEMA_FILE, "sha256": file_sha(SCHEMA_FILE),
                   "schema_version": "governance_trajectory/v2"},
        "implementation_files": [{"path": p, "sha256": file_sha(p)} for p in IMPL_FILES],
        "fixtures": [{"path": f"tests/fixtures/{n}", "sha256": file_sha(f"tests/fixtures/{n}"),
                      "purpose": purpose} for n, purpose in FIXTURES.items()],
        "supported_claude_code_versions": {"exact": SUPPORTED_VERSIONS, "prefixes": SUPPORTED_PREFIXES,
                                           "unknown_policy": "quarantine + adapter review (docs/evidence/version-boundary.md)"},
        "test_suite_result": args.pytest,
        "validation_coverage": VALIDATION_COVERAGE,
        "acceptance_mapping": ACCEPTANCE_MAPPING,
        "checks": checks,
        "known_limitations_ref": KNOWN_LIMITATIONS_REF,
    }
    return manifest


def render_report(manifest: dict, manifest_sha: str) -> str:
    c = manifest["checks"]
    verdict = "PASS" if (
        c["replay"]["byte_identical"]
        and c["schema_validation"]["sample_valid"]
        and c["manifest_chain"]["verified"]
        and "passed" in manifest["test_suite_result"]
    ) else "FAIL"
    repo = manifest["repository"]
    lines = [
        "# Phase 1.1 Evidence Freeze Report",
        "",
        f"**Verdict: {verdict}**",
        "",
        f"- Commit SHA: `{repo['commit']}`",
        f"- Branch: `{repo['branch']}`  |  Dirty: `{repo['dirty']}`",
        f"- Schema: `{manifest['schema']['sha256']}` (`{manifest['schema']['file']}`)",
        f"- Manifest SHA-256: `{manifest_sha}`",
        "",
        "## Test results",
        f"- pytest: **{manifest['test_suite_result']}**",
        "",
        "## Deterministic replay",
        f"- fixture: `{c['replay']['fixture']}` (status `{c['replay']['status']}`)",
        f"- canonical SHA-256: `{c['replay']['canonical_sha256']}`",
        f"- normalized SHA-256: `{c['replay']['normalized_sha256']}`",
        f"- trajectory_id: `{c['replay']['trajectory_id']}`",
        f"- byte-identical across 2 runs: **{c['replay']['byte_identical']}**",
        f"- source fixture unmutated: **{c['replay']['fixture_unmutated']}**",
        "",
        "## Schema + provenance",
        f"- schema is Draft 2020-12: {c['schema_validation']['schema_is_draft2020']}",
        f"- sample artifact valid: {c['schema_validation']['sample_valid']}",
        f"- manifest hash-chain verified: {c['manifest_chain']['verified']}",
        "",
        "## Validation coverage (V1–V6)",
    ]
    for k, v in manifest["validation_coverage"].items():
        lines.append(f"- **{k}** — {v['impl']} — tests: {', '.join(v['tests'])}")
    lines += ["", "## Acceptance mapping (A1–A9)"]
    for k, v in manifest["acceptance_mapping"].items():
        lines.append(f"- **{k}** — {v}")
    lines += [
        "",
        "## Supported versions",
        f"- exact: {', '.join(manifest['supported_claude_code_versions']['exact'])}"
        f"  |  prefixes: {', '.join(manifest['supported_claude_code_versions']['prefixes'])}",
        "- unknown → quarantine + adapter review (no silent schema drift)",
        "",
        "## Remaining risks",
        "- R1/R9 version drift: only 2.1.170 block-verified; other 2.x by prefix.",
        "- R2 secret-scanner precision: fail-closed over-quarantine (noisy on high-entropy tokens).",
        "- R4 git-join fidelity bounded by capture; diff not yet auto-captured.",
        "- Fixture corpus small (synthetic + shapes); expand before production.",
        "",
        f"_Known limitations: {manifest['known_limitations_ref']}._",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", required=True)
    ap.add_argument("--branch", default="master")
    ap.add_argument("--dirty", default="false", choices=["true", "false"])
    ap.add_argument("--pytest", required=True, help="literal pytest summary, e.g. '38 passed'")
    ap.add_argument("--out", default="docs/evidence")
    args = ap.parse_args(argv)

    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)

    checks = run_checks()
    manifest = build_manifest(args, checks)

    manifest_bytes = canonical_bytes(manifest)
    manifest_sha = sha256_hex(manifest_bytes)
    (out / "phase1_evidence_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = render_report(manifest, manifest_sha)
    (out / "PHASE1_1_EVIDENCE_FREEZE.md").write_text(report, encoding="utf-8")

    print(report)
    print(f"manifest_sha256={manifest_sha}")
    verdict_pass = "**Verdict: PASS**" in report
    return 0 if verdict_pass else 1


if __name__ == "__main__":
    sys.exit(main())
