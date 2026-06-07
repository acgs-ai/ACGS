from __future__ import annotations

import json
import os
import re
import subprocess
import sys
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
]

EXAMPLE_READMES = [
    "examples/python_tool_gate/README.md",
    "examples/mcp_tool_gate/README.md",
    "examples/agent_framework_gate/README.md",
    "examples/ci_deploy_gate/README.md",
    "examples/tamper_demo/README.md",
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
        "ACGS is a vendor-neutral, receipt-gated governance layer for AI-agent side effects."
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
