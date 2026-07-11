"""Validate the governance stack index stays claim-safe and complete.

The index is a routing surface for reviewers and deployment operators. This
check intentionally validates stable evidence contracts and known caveats
without trying to prove live deployment.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs" / "governance-stack-index.md"
INTEGRATION_MAP = ROOT / "docs" / "integration-readiness-task-map.md"

REQUIRED_PATHS = (
    "packages/gove-zone/",
    "packages/acgs-lite/",
    "packages/Acgs-Swarm/",
    "packages/agent-bus-analyzer/",
    "acgs_governance_eval_mvp/",
    "acgi-ai/",
    "acgs-cft-governance-pack/",
    "acgs_governance_eval_mvp/governance/adapters/hermes/",
    "ca-legal-agent-skills/",
    "clinicalguard-privacy-hardening/",
    "packages/clinicalguard/",
    "ACGS/packages/legalguard/",
    "docs/archive/acgs-enterprise-ai-manager/frontend/",
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

INTEGRATION_MAP_REQUIRED_CONCEPTS = (
    "make release-evidence",
    "make platform-readiness",
    "make production-launch-preflight",
    "branch or deployment proof",
    "Valid deferrals / external blockers",
    "Hosted Storybook buyer evidence",
    "Node 22 warning is not readiness evidence",
    "make production-blocker-evidence",
    "gove-zone smoke",
)

INTEGRATION_MAP_FORBIDDEN_STALE_SCOPE = (
    "feat/acgs-conductor-adapter-spike",
    "Scope: current checkout at",
)

MAIN_TABLE_HEADER = (
    "| Layer | Package/path | Policy/evidence contract | "
    "Primary local gate | Live/deploy proof status |"
)


def main() -> int:
    if not INDEX.exists():
        print(f"missing {INDEX.relative_to(ROOT)}")
        return 1
    if not INTEGRATION_MAP.exists():
        print(f"missing {INTEGRATION_MAP.relative_to(ROOT)}")
        return 1

    text = INDEX.read_text(encoding="utf-8")
    readiness_map = INTEGRATION_MAP.read_text(encoding="utf-8")
    failures: list[str] = []

    if not text.startswith("# Governance stack index"):
        failures.append("index must start with the expected H1")

    if not readiness_map.startswith("# Integration readiness task map"):
        failures.append("integration readiness map must start with the expected H1")

    for concept in INTEGRATION_MAP_REQUIRED_CONCEPTS:
        if concept not in readiness_map:
            failures.append(f"integration readiness map missing required concept: {concept}")

    for stale_scope in INTEGRATION_MAP_FORBIDDEN_STALE_SCOPE:
        if stale_scope in readiness_map:
            failures.append(f"integration readiness map has stale scope wording: {stale_scope}")

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
