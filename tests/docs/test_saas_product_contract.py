from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAAS = ROOT / "docs" / "saas"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalized(path: Path) -> str:
    return " ".join(_text(path).split())


def test_each_product_contract_is_explicitly_target_only_and_tied_to_g006() -> None:
    names = {
        "PRODUCT_REQUIREMENTS.md",
        "ASSURANCE_CLASSES.md",
        "OPEN_CORE_BOUNDARY.md",
        "ENTITLEMENT_AND_METERING_MATRIX.md",
    }
    for name in names:
        document = SAAS / name
        contents = _text(document)
        assert "**Status:** Phase-0 target beta contract (G007)." in contents
        assert "**Not an implementation claim:**" in contents
        assert "## Current-state boundary" in contents
        assert "CURRENT_STATE_SURVEY.md" in contents
        assert "ROADMAP.md" in contents
        assert "## Evidence and next gate" in contents


def test_assurance_classes_preserve_provenance_and_cannot_be_promoted() -> None:
    assurance = _normalized(SAAS / "ASSURANCE_CLASSES.md")
    assert (
        "Observed evidence is post-execution evidence, never pre-execution authorization proof."
    ) in assurance
    assert "must not silently upgrade federated or observed evidence to native" in assurance
    assert "project/environment binding is a target requirement" in assurance
    assert "source decision digest" in assurance
    assert "rather than raw secrets, credentials, unnecessary tool arguments" in assurance
    assert "planned interoperability work" in assurance
    assert (
        "does not mean an adapter is shipped, trusted, interoperable, or "
        "eligible to issue native assurance"
    ) in assurance
    assert "policy identifier/version/canonical content hash" in assurance
    assert "canonical, content-addressed, signed, tenant/project/environment-bound" in assurance


def test_open_core_and_entitlement_contracts_preserve_local_safety() -> None:
    open_core = _normalized(SAAS / "OPEN_CORE_BOUNDARY.md")
    entitlement = _normalized(SAAS / "ENTITLEMENT_AND_METERING_MATRIX.md")

    assert "without a hosted entitlement or network dependency" in open_core
    assert (
        "No plan, entitlement, billing failure, account suspension, hosted outage, "
        "or retention limit may disable the local gate"
    ) in open_core
    assert "it cannot create allow-by-default behavior locally" in open_core
    assert (
        "does not assert a current billing/usage ledger, live charge, published price"
    ) in entitlement
    assert "must not charge for local authorization calls or model tokens" in entitlement
    assert "Observed evidence must not be metered as a verified governed action" in entitlement
    assert "must never disable local signing, verification, anti-replay" in entitlement
    assert "must not be silently discarded" in entitlement
    assert "No real charges, published pricing, legal commitments, license changes" in entitlement


def test_competitor_language_is_fair_and_target_bound() -> None:
    comparison = _normalized(ROOT / "docs" / "COMPARISON.md")
    strategy = _normalized(ROOT / "docs" / "PRODUCT_STRATEGY.md")

    assert "Enforcement-capable" in comparison
    assert "AWS AgentCore Policy in `ENFORCE` mode" in comparison
    assert "Microsoft ACS/AGT" in comparison
    assert "Galileo Agent Control" in comparison
    assert "NVIDIA NeMo Guardrails" in comparison
    assert "ACGS does not claim to be the only option that enforces before an action" in comparison
    assert "This repository does not frame it as audit-only" in comparison
    assert (
        "Adapter profiles for those systems are roadmap work, not shipped interoperability claims"
    ) in comparison
    assert "logs *after* the action" not in comparison
    assert "a trail you read after harm" not in comparison
    assert "receipt-centric vs audit-centric" not in comparison
    assert "竞品最弱" not in strategy
    assert "以**审计为中心**" not in strategy
    assert "不声称它只做事后审计" in strategy
    assert "竞争差异假设" in strategy
    assert "待真实接入验证" in strategy


def test_g007_progress_record_links_the_actual_contract_surface() -> None:
    dag = json.loads(_text(SAAS / "DELIVERY_DAG.yaml"))
    g007 = next(node for node in dag["nodes"] if node["id"] == "G007")

    assert (g007["status"], g007["implementation_state"], g007["evidence_state"]) == (
        "completed",
        "built",
        "independently_reviewed",
    )
    assert g007["branch"] == "beta/p0-product-contract-007"
    assert g007["worktree"] == "saas-beta/p0-product-contract-007"
    assert g007["pr"] == 320
    assert {
        "docs/saas/PRODUCT_REQUIREMENTS.md",
        "docs/saas/ASSURANCE_CLASSES.md",
        "docs/saas/OPEN_CORE_BOUNDARY.md",
        "docs/saas/ENTITLEMENT_AND_METERING_MATRIX.md",
        "docs/COMPARISON.md",
        "docs/PRODUCT_STRATEGY.md",
        "docs/README.md",
        "docs/ROADMAP.md",
        "tests/docs/test_saas_product_contract.py",
    } <= set(g007["likely_interfaces_files"])
    assert "G008" in g007["next_safe_action"]

    matrix = _text(SAAS / "ACCEPTANCE_MATRIX.md")
    assert (
        "| AM-002 | Frozen current-state and product-contract reconciliation | partial | "
        "current_local | G006, G007, G008 |"
    ) in matrix


def test_native_policy_and_approval_contracts_are_explicit() -> None:
    requirements = _normalized(SAAS / "PRODUCT_REQUIREMENTS.md")

    assert "policy identifier, version, canonical content hash" in requirements
    assert "canonical, content-addressed, signed, tenant/project/environment-bound" in requirements
    assert "draft, review, active, stale, superseded, and revoked lifecycle states" in requirements
    assert "separates requester, policy validator, and authorized approver" in requirements
    assert "self-approval is rejected" in requirements
    assert "Policy can require quorum and role constraints" in requirements
    assert "cannot resume the same side effect more than once" in requirements


def test_docs_index_and_roadmap_expose_the_target_contract_without_promotion() -> None:
    docs_index = _text(ROOT / "docs" / "README.md")
    roadmap = _text(ROOT / "docs" / "ROADMAP.md")

    for link in (
        "saas/PRODUCT_REQUIREMENTS.md",
        "saas/ASSURANCE_CLASSES.md",
        "saas/OPEN_CORE_BOUNDARY.md",
        "saas/ENTITLEMENT_AND_METERING_MATRIX.md",
    ):
        assert link in docs_index
        assert link in roadmap
    assert "not evidence that the managed service" in roadmap
