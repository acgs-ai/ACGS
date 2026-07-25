from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_DOCS = [
    "README.md",
    "AGENTS.md",
    "llms.txt",
    "docs/START_HERE.md",
    "docs/HUMAN_GUIDE.md",
    "docs/ARCHITECTURE.md",
    "docs/DECISION_RECEIPT_SPEC.md",
    "docs/SECURITY_MODEL.md",
    "docs/CLAIMS.md",
    "docs/QUICKSTART.md",
    "docs/DEMO_SCRIPT.md",
    "docs/INTEGRATION_GUIDE.md",
    "docs/INTEGRATION_MATRIX.md",
    "docs/COMPARISON.md",
    "docs/POSITIONING.md",
    "docs/ROADMAP.md",
    "docs/GLOSSARY.md",
    "docs/REVIEW_CHECKLIST.md",
    "docs/ADOPTION_GUIDE.md",
    "docs/PROOF_PATH.md",
]

EXAMPLE_SCRIPTS = [
    "examples/python_tool_gate/demo.py",
    "examples/mcp_tool_gate/demo.py",
    "examples/agent_framework_gate/demo.py",
    "examples/ci_deploy_gate/demo.py",
    "examples/tamper_demo/demo.py",
    "examples/dynamic_swarm/demo.py",
    "examples/mcp-governed-agent/demo.py",
    "examples/governed_aml_screening/demo.py",
    "examples/governed_legal_drafting/demo.py",
]

EXAMPLE_READMES = [
    "examples/python_tool_gate/README.md",
    "examples/mcp_tool_gate/README.md",
    "examples/agent_framework_gate/README.md",
    "examples/ci_deploy_gate/README.md",
    "examples/tamper_demo/README.md",
    "examples/dynamic_swarm/README.md",
    "examples/mcp-governed-agent/README.md",
    "examples/governed_aml_screening/README.md",
    "examples/governed_legal_drafting/README.md",
]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_required_docs_exist_and_carry_core_invariant() -> None:
    for rel in REQUIRED_DOCS:
        path = ROOT / rel
        assert path.is_file(), f"missing required doc: {rel}"
        text = path.read_text(encoding="utf-8")
        assert "No valid Decision Receipt, no side effect" in text, rel


def test_readme_opening_and_non_claims() -> None:
    text = _read("README.md")
    assert text.startswith(
        "ACGS / gove-zone is a vendor-neutral, receipt-gated governance layer "
        "for AI-agent side effects."
    )
    for phrase in (
        "not production-certified",
        "not compliance-certified",
        "not regulator-approved",
        "not a replacement for content moderation",
        "not a replacement for sandboxing",
        "not a complete IAM/PKI system",
        "not a full formal-verification system",
    ):
        assert phrase.lower() in text.lower()


def test_neutrality_wording_stays_claim_safe() -> None:
    """Guard the repositioning: neutrality copy must scope to supported tiers and
    must not reintroduce present-tense universal portability overclaims.

    Cross-host receipt portability is roadmap (docs/CLAIMS.md), so blanket
    "any platform / no matter which runtime" wording would overclaim it.
    """
    surfaces = ("README.md", "docs/introduction.md", "docs/POSITIONING.md")
    banned = (
        "no matter which runtime",
        "any agent — on any platform",
        "any agent - on any platform",
        "any agent on any platform",
    )
    for rel in surfaces:
        lowered = _read(rel).lower()
        for phrase in banned:
            assert phrase not in lowered, f"{rel}: overbroad portability claim '{phrase}'"
    # Neutrality copy must point readers at the tier/claim evidence, not just assert.
    for rel in ("README.md", "docs/introduction.md"):
        assert "integration_matrix.md" in _read(rel).lower(), rel


def _claim_ledger_rows() -> list[list[str]]:
    """Data rows of the claim-ledger table, as trimmed cell lists."""
    rows: list[list[str]] = []
    for line in _read("docs/CLAIMS.md").splitlines():
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 6 or cells[0] == "Claim" or set(cells[0]) <= {"-"}:
            continue  # header / separator
        rows.append(cells)
    return rows


def test_claim_ledger_evidence_exists() -> None:
    """No dangling citations: evidence a claim names must exist in the tree.

    Mirrors ``test_on_master_evidence_files_exist`` in ``test_adversary_model.py``.
    A claim whose cited test or example does not exist is an overclaim, and the
    ledger is the file that is supposed to stop overclaiming. Rows with status
    ``not claimed`` / ``roadmap`` cite no evidence and are skipped.
    """
    test_files = {p.name for p in ROOT.rglob("test_*.py")}
    test_defs = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (ROOT / "packages" / "gove-zone" / "tests").rglob("test_*.py")
    )
    missing: list[str] = []
    for cells in _claim_ledger_rows():
        claim, status, evidence, eatest = cells[0], cells[1], cells[2], cells[3]
        if status in {"not claimed", "roadmap"}:
            continue
        cited = f"{evidence} {eatest}"
        label = claim[:60]
        for name in set(re.findall(r"`(test_[A-Za-z0-9_]+)`", cited)):
            # A citation may name a test module or a single test function.
            if f"{name}.py" not in test_files and f"def {name}(" not in test_defs:
                missing.append(f"{label} -> {name}")
        for rel in set(re.findall(r"`((?:packages|examples|docs)/[\w./-]+)`", cited)):
            if not (ROOT / rel).exists():
                missing.append(f"{label} -> {rel}")
    assert not missing, "claim ledger cites evidence not present in the tree:\n  " + "\n  ".join(
        missing
    )


def test_claim_ledger_has_explicit_non_claims() -> None:
    text = _read("docs/CLAIMS.md").lower()
    for phrase in (
        "production-certified",
        "compliance-certified",
        "regulator-approved",
        "content moderation",
        "sandboxing",
        "iam/rbac/pki",
        "formal verification",
    ):
        assert phrase in text


def test_architecture_has_required_mermaid_flow() -> None:
    text = _read("docs/ARCHITECTURE.md")
    assert "```mermaid" in text
    for phrase in (
        "Agent request",
        "Governance check",
        "Decision Receipt",
        "Executor validation",
        "Side effect",
        "Fail-closed denial",
        "Audit evidence",
        "Replay verification",
    ):
        assert phrase in text


def test_examples_have_readmes_and_run_successfully() -> None:
    env = os.environ.copy()
    src = str(ROOT / "packages" / "gove-zone" / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

    for rel in EXAMPLE_READMES:
        text = _read(rel)
        assert "Run:" in text
        assert "Expected output" in text
        assert "Failure case" in text
        assert "What is proven" in text

    for rel in EXAMPLE_SCRIPTS:
        # The dynamic_swarm example imports `acgs_lite`, which lives in the
        # `packages/acgs-lite` git submodule. On a fresh/documented checkout the
        # submodule is uninitialized, so `acgs_lite` is unimportable and the
        # script exits non-zero. Skip ONLY this example in that case (a clear,
        # explicit skip), without weakening the other example checks.
        if (
            rel == "examples/dynamic_swarm/demo.py"
            and importlib.util.find_spec("acgs_lite") is None
        ):
            warnings.warn(
                f"skipping {rel}: acgs_lite submodule not initialized "
                "(run `git submodule update --init packages/acgs-lite` to exercise it)",
                stacklevel=2,
            )
            continue
        proc = subprocess.run(
            [sys.executable, rel],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert proc.returncode == 0, f"{rel}\nSTDOUT={proc.stdout}\nSTDERR={proc.stderr}"
        payload = json.loads(proc.stdout)
        assert payload["status"] == "pass", rel


def test_new_markdown_links_resolve() -> None:
    docs = [*REQUIRED_DOCS, *EXAMPLE_READMES]
    pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for rel in docs:
        base = (ROOT / rel).parent
        for target in pattern.findall(_read(rel)):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean = target.split("#", 1)[0]
            if not clean or clean.startswith("<"):
                continue
            assert (base / clean).exists(), f"broken link in {rel}: {target}"
