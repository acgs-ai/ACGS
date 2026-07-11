#!/usr/bin/env python3
"""ACGS Compliance Evidence Pack generator.

Assembles one auditor-facing bundle that ties each mapped framework requirement
(EU AI Act Art. 12, ISO/IEC 42001 Annex A, SOC 2 Trust Services Criteria) to
concrete runtime evidence from a real governed action: a Decision Receipt
anchored in a hash-chained audit log, packaged as an offline-verifiable ACGS
proof pack.

The framework rows are read from ``compliance/control-mapping.json`` (the single
source of truth, validated by ``compliance/engine.py``); the runtime evidence is
produced by ``gove_zone.proofpack.generate_proof_pack`` over a committed,
already-verified governed action. Nothing in this bundle is hand-authored — it
re-derives from the mapping and from the receipt/audit inputs on every run.

This is a **self-assessment evidence bundle, not a certification, attestation,
or audit result.** A row means gove-zone produces evidence toward the
requirement at the executor boundary; it does not make an adopting system
compliant. See the disclaimer embedded in the mapping and in every file below.

Usage::

    # generate the committed pack (byte-reproducible with the pinned clock)
    uv run --package gove-zone python compliance/evidence_pack.py generate \
        --out compliance/evidence-pack

    # verify a pack: manifest integrity + inner proof-pack offline verification
    uv run --package gove-zone python compliance/evidence_pack.py verify \
        compliance/evidence-pack

Stdlib only at module scope (matches gove-zone's zero-runtime-deps posture);
``gove_zone.proofpack`` is imported lazily inside the generate/verify paths so
this module never contaminates the published gove-zone import surface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MAPPING_PATH = REPO_ROOT / "compliance" / "control-mapping.json"
DEFAULT_INPUTS = REPO_ROOT / "compliance" / "evidence-inputs"
DEFAULT_OUT = REPO_ROOT / "compliance" / "evidence-pack"

# Pinned generation clock so the committed pack is byte-reproducible: same
# mapping + same governed-action inputs + same clock -> identical bytes ->
# identical manifest digests. tests/docs asserts this.
PINNED_NOW_ISO = "2026-01-01T00:00:00+00:00"

SCHEMA_VERSION = "acgs/compliance-evidence-pack/v1"

# The frameworks presented as auditor-facing evidence sheets, in pack order, with
# their output filenames. NIST AI RMF is intentionally excluded — the three here
# are the ones an external auditor/regulator asks for (EU AI Act record-keeping,
# ISO 42001 AIMS controls, SOC 2 TSC); NIST stays in the readiness report.
PACK_FRAMEWORKS: tuple[tuple[str, str], ...] = (
    ("eu_ai_act", "eu-ai-act-article-12.md"),
    ("iso_42001", "iso-42001.md"),
    ("soc2", "soc2.md"),
)

# Location of the inner proof pack, relative to the pack root. Fixed by the pack
# schema — verification checks THIS path, never a value read out of the (unsigned)
# manifest, so a tampered manifest cannot skip inner verification.
EXPECTED_PROOFPACK_REL = "runtime-evidence/proofpack"

# Controls that the OFFLINE pack actually demonstrates for a single ALLOW governed
# action: recording, binding, and cryptographic integrity — each independently
# re-derivable from the packaged receipt + audit chain by `acgs proofpack verify`
# with no system access and no out-of-band material.
#
# Deliberately EXCLUDED (each sheet states why):
#   - REPLAY-VERIFY — the pack omits the policy bundle + side store (out-of-band
#     by design), so offline `acgs proofpack verify` reports replay_status
#     "recorded" (a generation-time generator attestation), NOT an independent
#     re-derivation ("reverified"). Claiming it is demonstrated offline overstates.
#   - DECISION-GATE's refusal path, FAILCLOSED, ESCALATE-HUMAN — a single ALLOW
#     action never exercises blocking/deny/escalation.
#   - SIG-VERIFY / SIG-REQUIRED / EXPIRY / ANTI-REPLAY — signing/expiry/anti-replay.
# This partition is pinned by tests/docs/test_compliance_evidence_pack.py.
DEMONSTRATED_BY_ALLOW_ACTION: frozenset[str] = frozenset(
    {
        "RECEIPT-REQUIRED",
        "HASH-INTEGRITY",
        "ACTOR-ANCHOR",
        "ARG-BIND",
        "POLICY-TENANT-BIND",
        "MACI-VALIDATOR-SEP",
        "POLICY-BEFORE-EXEC",
        "AUDIT-HASHCHAIN",
    }
)

# Controls a reader might expect but which this ALLOW-only offline pack does NOT
# independently demonstrate — surfaced explicitly in every sheet so the evidence
# boundary is never implied away. Pinned by the test partition.
NOT_DEMONSTRATED_OFFLINE: frozenset[str] = frozenset(
    {
        "REPLAY-VERIFY",
        "DECISION-GATE",
        "FAILCLOSED",
        "ESCALATE-HUMAN",
        "SIG-VERIFY",
        "SIG-REQUIRED",
        "EXPIRY",
        "ANTI-REPLAY",
    }
)

NOT_CERTIFIED_BANNER = (
    "**Not compliance-certified. Not regulator-approved. Not an audit result.** "
    "This is a self-assessment mapping backed by runtime evidence: each row means "
    "gove-zone produces evidence toward the requirement at the executor boundary "
    "— it does not make an adopting system compliant."
)

EVIDENCE_BEARING = ("implemented", "opt-in", "partial")


class EvidencePackError(Exception):
    """Raised when a pack cannot be generated or fails verification."""


# --- data helpers -------------------------------------------------------------


def load_mapping(path: Path = MAPPING_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _summarize_framework(fw: dict[str, Any]) -> dict[str, Any]:
    """Per-framework status counts + evidence-bearing ratio (mirrors engine)."""
    counts: dict[str, int] = {}
    for entry in fw["requirements"]:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    total = sum(counts.values())
    applicable = total - counts.get("not-applicable", 0)
    evidence = sum(counts.get(s, 0) for s in EVIDENCE_BEARING)
    return {
        "total": total,
        "applicable": applicable,
        "evidence_bearing": evidence,
        "ratio": (evidence / applicable) if applicable else 0.0,
        "counts": counts,
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- runtime evidence ---------------------------------------------------------


def _generate_runtime_evidence(out_root: Path, inputs_dir: Path, now_iso: str) -> dict[str, Any]:
    """Produce the offline proof pack for the canonical governed action.

    Returns a small, deterministic ``runtime_meta`` dict read back out of the
    generated artifacts so the sheets/README/manifest describe exactly what was
    packaged (no second source of truth).
    """
    from gove_zone.proofpack import PackGenerationError, generate_proof_pack

    receipt = inputs_dir / "decision-receipt.json"
    audit = inputs_dir / "audit.jsonl"
    policy_bundle = inputs_dir / "policy-bundle.json"
    side_store = inputs_dir / "side-store.jsonl"
    for required in (receipt, audit, policy_bundle, side_store):
        if not required.exists():
            raise EvidencePackError(f"missing governed-action input: {required}")

    proofpack_dir = out_root / "runtime-evidence" / "proofpack"
    try:
        generate_proof_pack(
            proofpack_dir,
            receipt_path=receipt,
            audit_path=audit,
            policy_bundle=policy_bundle,
            side_store=side_store,
            now_iso=now_iso,
            force=True,
        )
    except PackGenerationError as exc:
        raise EvidencePackError(f"runtime evidence generation refused: {exc}") from exc

    receipt_doc = json.loads((proofpack_dir / "decision-receipt.json").read_text(encoding="utf-8"))
    chain_doc = json.loads((proofpack_dir / "audit-chain.json").read_text(encoding="utf-8"))
    replay_doc = json.loads((proofpack_dir / "replay-report.json").read_text(encoding="utf-8"))
    return {
        "receipt_id": receipt_doc.get("receipt_id", ""),
        "actor": receipt_doc.get("actor", ""),
        "decision": receipt_doc.get("decision", ""),
        "proposed_action": receipt_doc.get("proposed_action", ""),
        "signature_algorithm": receipt_doc.get("signature_algorithm", "none"),
        "signed": receipt_doc.get("signature_algorithm", "none") != "none",
        "audit_event_count": chain_doc.get("event_count", 0),
        "audit_last_hash": chain_doc.get("last_hash", ""),
        "replay_status": replay_doc.get("status", ""),
        "proofpack_rel": "runtime-evidence/proofpack",
    }


# --- rendering ----------------------------------------------------------------


def _status_vocab_block(mapping: dict[str, Any]) -> list[str]:
    lines = ["## Status vocabulary", ""]
    for status, meaning in mapping["status_vocabulary"].items():
        lines.append(f"- **{status}** — {meaning}")
    lines.append("")
    return lines


def _runtime_evidence_block(fw: dict[str, Any], runtime: dict[str, Any]) -> list[str]:
    """Per-sheet section tying framework controls to the included governed action."""
    cited: dict[str, list[str]] = {}
    for entry in fw["requirements"]:
        for ctrl in entry.get("acgs_controls", []):
            cited.setdefault(ctrl, []).append(entry["id"])

    demonstrated = {c: ids for c, ids in cited.items() if c in DEMONSTRATED_BY_ALLOW_ACTION}
    not_demonstrated = sorted(c for c in cited if c not in DEMONSTRATED_BY_ALLOW_ACTION)

    decision = runtime["decision"].upper()
    signed = "signed" if runtime["signed"] else "unsigned (development posture)"
    lines = [
        "## Runtime evidence in this pack",
        "",
        (
            f"`{runtime['proofpack_rel']}/` is one real governed action — actor "
            f"`{runtime['actor']}` proposing `{runtime['proposed_action']}`, decided "
            f"**{decision}** (receipt `{runtime['receipt_id']}`, {signed}) and anchored in a "
            f"{runtime['audit_event_count']}-event hash-chained audit log. It is "
            "independently re-derivable offline — receipt-hash binding and audit-chain "
            "integrity, with no system access — using:"
        ),
        "",
        "```",
        f"acgs proofpack verify compliance/evidence-pack/{runtime['proofpack_rel']}",
        "```",
        "",
        (
            "It is a single reference governed action, not production traffic. An ALLOW "
            "action with an integrity-verified receipt and audit chain demonstrates the "
            "**recording, binding, and integrity** controls the rows above cite:"
        ),
        "",
    ]
    if demonstrated:
        lines.append("| Control demonstrated offline | Requirement rows it substantiates |")
        lines.append("|---|---|")
        for ctrl in sorted(demonstrated):
            lines.append(f"| {ctrl} | {', '.join(sorted(demonstrated[ctrl]))} |")
        lines.append("")
    if not_demonstrated:
        lines.append(
            "Controls this framework cites that this offline ALLOW-only pack does **not** "
            "independently demonstrate (evidence boundary — verify separately): "
            + ", ".join(f"`{c}`" for c in not_demonstrated)
            + "."
        )
        if "REPLAY-VERIFY" in not_demonstrated:
            lines.append("")
            lines.append(
                "> Decision replay was verified at generation time, but the pack omits "
                "the policy bundle and side store (retained out-of-band), so offline "
                "`acgs proofpack verify` reports the replay as `recorded` — a generator "
                "attestation, not an independent re-derivation. Supply the material from "
                "`compliance/evidence-inputs/` with `--policy-bundle`/`--side-store` to "
                "re-derive it yourself."
            )
        lines.append("")
        lines.append(
            "Blocking/deny, escalation, signing, expiry, and anti-replay controls require "
            "their own governed actions to demonstrate."
        )
        lines.append("")
    return lines


def render_framework_sheet(fw_key: str, mapping: dict[str, Any], runtime: dict[str, Any]) -> str:
    fw = mapping["frameworks"][fw_key]
    summary = _summarize_framework(fw)
    lines: list[str] = []
    lines.append(f"# {fw['name']}")
    lines.append("")
    lines.append(
        f"> Part of the ACGS Compliance Evidence Pack (`{SCHEMA_VERSION}`). "
        "Generated from `compliance/control-mapping.json` — do not hand-edit; "
        "regenerate with `compliance/evidence_pack.py`."
    )
    lines.append("")
    if fw.get("scope_note"):
        lines.append(f"> {fw['scope_note']}")
        lines.append("")
    lines.append(mapping["disclaimer"])
    lines.append("")
    lines.append(NOT_CERTIFIED_BANNER)
    lines.append("")
    lines.append(
        f"**Coverage:** {summary['evidence_bearing']}/{summary['applicable']} applicable "
        f"requirements are evidence-bearing ({summary['ratio']:.0%}); "
        f"{summary['total']} requirements mapped."
    )
    lines.append("")
    lines.append("## Requirement → control → status")
    lines.append("")
    lines.append("| ID | Requirement | ACGS controls | Status | Limitation |")
    lines.append("|---|---|---|---|---|")
    for entry in fw["requirements"]:
        ctrls = ", ".join(entry.get("acgs_controls", [])) or "—"
        lines.append(
            f"| {entry['id']} | {entry['requirement']} | {ctrls} "
            f"| {entry['status']} | {entry.get('limitation', '')} |"
        )
    lines.append("")
    lines.extend(_runtime_evidence_block(fw, runtime))
    lines.append("## How to verify these rows")
    lines.append("")
    lines.append(
        "Each row's `verification_method` in `compliance/control-mapping.json` is a "
        "runnable test command or a named documentation review. Re-run the mapping's "
        "own gate with:"
    )
    lines.append("")
    lines.append("```")
    lines.append("python3 compliance/engine.py validate")
    lines.append("python3 compliance/engine.py report --run   # executes every row's tests")
    lines.append("```")
    lines.append("")
    lines.extend(_status_vocab_block(mapping))
    return "\n".join(lines) + "\n"


def render_readme(mapping: dict[str, Any], runtime: dict[str, Any], now_iso: str) -> str:
    lines: list[str] = []
    lines.append("# ACGS Compliance Evidence Pack")
    lines.append("")
    lines.append(f"Schema: `{SCHEMA_VERSION}`  ·  Generated: `{now_iso}`")
    lines.append("")
    lines.append(mapping["disclaimer"])
    lines.append("")
    lines.append(NOT_CERTIFIED_BANNER)
    lines.append("")
    lines.append("## What this pack is")
    lines.append("")
    lines.append(
        "One self-contained, auditor-facing bundle. It ties mapped requirements from "
        "three governance frameworks to concrete runtime evidence from a real governed "
        "action. The runtime receipt and audit chain are cryptographically hash-bound "
        "(independently re-derivable offline); the framework sheets are indexed by an "
        "unsigned SHA-256 manifest that detects corruption and casual edits (see the "
        "manifest limitation below)."
    )
    lines.append("")
    lines.append("## Contents")
    lines.append("")
    lines.append("| Artifact | Path | What it is |")
    lines.append("|---|---|---|")
    lines.append(
        "| EU AI Act Article 12 mapping | `frameworks/eu-ai-act-article-12.md` "
        "| Record-keeping (Art. 12 / 19 / 26(6)) requirements → ACGS controls → status |"
    )
    lines.append(
        "| ISO/IEC 42001 mapping | `frameworks/iso-42001.md` "
        "| Annex A AI-management-system controls → ACGS controls → status |"
    )
    lines.append(
        "| SOC 2 evidence | `frameworks/soc2.md` "
        "| Trust Services Criteria → ACGS controls → status → runtime evidence |"
    )
    lines.append(
        "| Audit export | `runtime-evidence/proofpack/audit-chain.json` "
        "| The hash-chained, append-only decision log for the governed action |"
    )
    lines.append(
        "| Decision receipt report | `runtime-evidence/proofpack/decision-receipt.json` "
        "+ `verification-summary.md` | The Decision Receipt and its human-readable report |"
    )
    lines.append(
        "| Offline proof pack | `runtime-evidence/proofpack/` "
        "| Verify with `acgs proofpack verify <dir>` — no system access needed |"
    )
    lines.append(
        "| Integrity manifest | `manifest.json` | SHA-256 + byte length of every file above |"
    )
    lines.append("")
    lines.append("## Readiness at a glance")
    lines.append("")
    lines.append("| Framework | Requirements | Evidence-bearing |")
    lines.append("|---|---|---|")
    for fw_key, _ in PACK_FRAMEWORKS:
        fw = mapping["frameworks"][fw_key]
        s = _summarize_framework(fw)
        name = fw["name"].split(" — ")[0].split(" (")[0]
        lines.append(
            f"| {name} | {s['total']} | {s['evidence_bearing']}/{s['applicable']} "
            f"({s['ratio']:.0%}) |"
        )
    lines.append("")
    lines.append("## The governed action")
    lines.append("")
    decision = runtime["decision"].upper()
    signed = "signed" if runtime["signed"] else "UNSIGNED (development posture)"
    lines.append(
        f"- **Actor**: `{runtime['actor']}`  ·  **Action**: `{runtime['proposed_action']}`"
    )
    lines.append(
        f"- **Decision**: **{decision}**  ·  **Receipt**: `{runtime['receipt_id']}`  "
        f"·  **Signature**: {signed}"
    )
    lines.append(
        f"- **Audit chain**: {runtime['audit_event_count']} event(s), last hash "
        f"`{runtime['audit_last_hash'][:16]}…`"
    )
    lines.append(
        f"- **Replay**: {runtime['replay_status']} at generation (generator attestation); "
        "offline `acgs proofpack verify` reports it as `recorded` unless the out-of-band "
        "policy bundle + side store are supplied to re-derive it"
    )
    lines.append("")
    lines.append("## How to verify this pack")
    lines.append("")
    lines.append("```")
    lines.append("# 1. runtime evidence — offline, no system access")
    lines.append(f"acgs proofpack verify compliance/evidence-pack/{runtime['proofpack_rel']}")
    lines.append("# 2. pack integrity — every file matches its manifest digest")
    lines.append("python3 compliance/evidence_pack.py verify compliance/evidence-pack")
    lines.append("# 3. mapping schema + evidence paths")
    lines.append("python3 compliance/engine.py validate")
    lines.append("```")
    lines.append("")
    lines.append("## Provenance and limitations")
    lines.append("")
    lines.append(
        "- The runtime evidence is a **single reference governed action**, committed "
        "under `compliance/evidence-inputs/`, not a sample of production traffic."
    )
    lines.append(
        "- An ALLOW action with an integrity-verified receipt + audit chain demonstrates "
        "the recording/binding/integrity controls offline. Decision replay was verified "
        "at generation time only (a generator attestation): the pack omits the policy "
        "bundle + side store, so offline verify reports it as `recorded`, not re-derived. "
        "The DENY/ESCALATE fail-closed path, signing, expiry, and anti-replay controls "
        "require their own governed actions."
    )
    lines.append(
        "- The `manifest.json` is an **unsigned** integrity index: it detects accidental "
        "corruption and casual edits, but a motivated forger who edits a framework sheet "
        "and recomputes its manifest entry is not stopped by the manifest alone. The "
        "cryptographic anchor is the receipt-hash binding + audit hash-chain inside the "
        "proof pack; signing the manifest is a follow-up."
    )
    lines.append(
        "- Audit is local, append-only JSONL: tamper-evident, not tamper-proof. "
        "Retention, off-host/WORM durability, and custody (EU AI Act Art. 19 / 26(6)) "
        "are operator responsibilities."
    )
    lines.append(
        "- This pack is regenerated, never hand-edited. See "
        "`compliance/COMPLIANCE_READINESS_REPORT.md`, `docs/COMPLIANCE_CROSSWALK.md`, "
        "and `docs/CLAIMS.md` rows 27-33 for the full standing limitations."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


# --- generation ---------------------------------------------------------------


def build_evidence_pack(
    out_dir: str | Path = DEFAULT_OUT,
    *,
    inputs_dir: str | Path = DEFAULT_INPUTS,
    mapping_path: str | Path = MAPPING_PATH,
    now_iso: str = PINNED_NOW_ISO,
    force: bool = False,
) -> dict[str, Any]:
    """Build the Compliance Evidence Pack into *out_dir*; return a summary dict."""
    out = Path(out_dir)
    inputs = Path(inputs_dir)
    mapping = load_mapping(Path(mapping_path))

    if out.exists() and any(out.iterdir()) and not force:
        raise EvidencePackError(
            f"refusing to overwrite non-empty pack directory {out} (pass force=True / --force)"
        )
    if out.exists():
        _rmtree(out)
    (out / "frameworks").mkdir(parents=True, exist_ok=True)

    runtime = _generate_runtime_evidence(out, inputs, now_iso)

    for fw_key, filename in PACK_FRAMEWORKS:
        (out / "frameworks" / filename).write_text(
            render_framework_sheet(fw_key, mapping, runtime), encoding="utf-8"
        )
    (out / "README.md").write_text(render_readme(mapping, runtime, now_iso), encoding="utf-8")

    manifest = _build_manifest(out, mapping, runtime, now_iso)
    _dump_json(out / "manifest.json", manifest)

    return {
        "status": "pass",
        "output_directory": str(out),
        "schema_version": SCHEMA_VERSION,
        "frameworks": [k for k, _ in PACK_FRAMEWORKS],
        "runtime_evidence": runtime,
        "file_count": len(manifest["files"]),
    }


def _build_manifest(
    out: Path, mapping: dict[str, Any], runtime: dict[str, Any], now_iso: str
) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for path in sorted(out.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(out).as_posix()
        if rel == "manifest.json":  # only the pack's own top-level manifest is self-excluded
            continue
        files[rel] = {"sha256": _sha256_file(path), "bytes": path.stat().st_size}
    return {
        "schema_version": SCHEMA_VERSION,
        "title": "ACGS Compliance Evidence Pack",
        "generated_at": now_iso,
        "generated_with": "compliance/evidence_pack.py",
        "disclaimer": mapping["disclaimer"],
        "not_certified": ("Not compliance-certified. Not regulator-approved. Not an audit result."),
        "frameworks": [k for k, _ in PACK_FRAMEWORKS],
        "runtime_evidence": runtime,
        "files": files,
        "how_to_verify": "python3 compliance/evidence_pack.py verify <pack-dir>",
    }


def _rmtree(path: Path) -> None:
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file() or child.is_symlink():
            child.unlink()
        elif child.is_dir():
            child.rmdir()
    path.rmdir()


# --- verification -------------------------------------------------------------


def verify_evidence_pack(pack_dir: str | Path) -> dict[str, Any]:
    """Verify pack integrity (manifest digests) + inner proof-pack offline.

    Returns ``{"valid": bool, "reasons": [...], "checks": {...}}``. Never raises
    on a *bad pack* — a tampered file is a verdict, not an exception; only a
    missing/malformed manifest raises.
    """
    pack = Path(pack_dir)
    manifest_path = pack / "manifest.json"
    if not manifest_path.exists():
        raise EvidencePackError(f"no manifest.json in {pack}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    reasons: list[str] = []
    listed = manifest.get("files", {})

    # 1. every listed file present + digest matches
    for rel, meta in sorted(listed.items()):
        target = pack / rel
        if not target.exists():
            reasons.append(f"missing file listed in manifest: {rel}")
            continue
        actual = _sha256_file(target)
        if actual != meta.get("sha256"):
            reasons.append(f"digest mismatch: {rel}")

    # 2. no unlisted files smuggled into the pack. Only the pack's own top-level
    #    manifest.json is exempt — a nested file *named* manifest.json (e.g.
    #    frameworks/manifest.json) must still be covered, or it is a smuggled file.
    for path in sorted(pack.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(pack).as_posix()
        if rel == "manifest.json":
            continue
        if rel not in listed:
            reasons.append(f"file not covered by manifest: {rel}")

    # 3. inner proof pack verifies offline at its FIXED location. We never trust a
    #    proofpack path read out of the (unsigned) manifest — a tampered manifest
    #    must not be able to blank the field and skip inner verification (fail-closed).
    from gove_zone.proofpack import verify_pack

    inner_dir = pack / EXPECTED_PROOFPACK_REL
    inner_valid: bool | None = None
    if not inner_dir.is_dir():
        reasons.append(f"missing inner proof pack at {EXPECTED_PROOFPACK_REL}")
    else:
        inner = verify_pack(inner_dir)
        inner_valid = inner.valid
        if not inner.valid:
            reasons.append(f"inner proof pack failed verification: {EXPECTED_PROOFPACK_REL}")
    # defense-in-depth: the manifest must actually point at that location
    if manifest.get("runtime_evidence", {}).get("proofpack_rel") != EXPECTED_PROOFPACK_REL:
        reasons.append("manifest runtime_evidence.proofpack_rel does not match the pack schema")

    integrity_prefixes = ("missing file", "digest mismatch", "file not covered")
    return {
        "valid": not reasons,
        "reasons": reasons,
        "checks": {
            "files_listed": len(listed),
            "manifest_integrity": not any(r.startswith(integrity_prefixes) for r in reasons),
            "inner_proofpack_valid": inner_valid,
        },
    }


# --- CLI ----------------------------------------------------------------------


def _cmd_generate(args: argparse.Namespace) -> int:
    try:
        summary = build_evidence_pack(
            args.out,
            inputs_dir=args.inputs,
            now_iso=args.now_iso,
            force=args.force,
        )
    except EvidencePackError as exc:
        print(f"evidence_pack generate: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_evidence_pack(args.pack_dir)
    except EvidencePackError as exc:
        print(f"evidence_pack verify: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence_pack",
        description="Generate or verify the ACGS Compliance Evidence Pack.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="assemble the evidence pack")
    gen.add_argument("--out", default=str(DEFAULT_OUT), help="output pack directory")
    gen.add_argument(
        "--inputs", default=str(DEFAULT_INPUTS), help="governed-action inputs directory"
    )
    gen.add_argument(
        "--now-iso",
        default=PINNED_NOW_ISO,
        help="generation timestamp (pinned for byte-reproducible output)",
    )
    gen.add_argument("--force", action="store_true", help="overwrite an existing pack directory")
    gen.set_defaults(func=_cmd_generate)

    ver = sub.add_parser("verify", help="verify pack integrity + inner proof pack")
    ver.add_argument("pack_dir", help="evidence pack directory to verify")
    ver.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
