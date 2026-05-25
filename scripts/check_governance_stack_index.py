"""Validate the governance stack index stays claim-safe and complete.

The index is a routing surface for reviewers and deployment operators. This
check intentionally validates stable evidence contracts and known caveats
without trying to prove live deployment.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "governance-stack-index.md"

REQUIRED_PATHS = (
    "packages/gove-zone/",
    "packages/acgs-lite/",
    "packages/Acgs-Swarm/",
    "packages/agent-bus-analyzer/",
    "acgs_governance_eval_mvp/",
    "acgi-ai/",
    "acgs-cft-governance-pack/",
    "hermes_acgs_bundle/",
    "ca-legal-agent-skills/",
    "clinicalguard-privacy-hardening/",
    "packages/clinicalguard/",
    "ACGS/packages/legalguard/",
    "acgs-enterprise-ai-manager/frontend/",
)

REQUIRED_CONCEPTS = (
    "fail-closed",
    "hash-chain",
    "claim-safe",
    "source-tagged",
    "policy/evidence contract",
    "live deployment proof is not complete",
    "external credentials",
    "ignored adjacent checkout",
    "not parent-tracked",
)

FORBIDDEN_CLAIMS = (
    "compliance-certified",
    "regulator-grade",
    "production-ready",
    "full upstream benchmark execution complete",
    "TBD package-local gate",
)

MAIN_TABLE_HEADER = (
    "| Layer | Package/path | Policy/evidence contract | "
    "Primary local gate | Live/deploy proof status |"
)


def main() -> int:
    if not INDEX.exists():
        print(f"missing {INDEX.relative_to(ROOT)}")
        return 1

    text = INDEX.read_text(encoding="utf-8")
    failures: list[str] = []

    if not text.startswith("# Governance stack index"):
        failures.append("index must start with the expected H1")

    for path in REQUIRED_PATHS:
        if f"`{path}`" not in text:
            failures.append(f"missing package/path row: {path}")

    for concept in REQUIRED_CONCEPTS:
        if concept not in text:
            failures.append(f"missing required concept: {concept}")

    lowered = text.lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim in lowered:
            failures.append(f"forbidden overclaim present: {claim}")

    if MAIN_TABLE_HEADER not in text:
        failures.append("main routing table header is missing or drifted")

    if failures:
        print("Governance stack index check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Governance stack index check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
