from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAAS = ROOT / "docs" / "saas"
ADR = ROOT / "docs" / "adr"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalized(path: Path) -> str:
    return " ".join(_text(path).split())


def test_g008_contracts_are_target_only_and_grounded_in_g006_g007() -> None:
    names = {
        "ARCHITECTURE.md",
        "THREAT_MODEL.md",
        "API_AND_DATA_CONTRACT.md",
        "MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md",
    }
    for name in names:
        document = SAAS / name
        contents = _text(document)
        assert "**Status:** Phase-0 target beta contract (G008)." in contents
        assert "**Not an implementation claim:**" in contents
        assert "CURRENT_STATE_SURVEY.md" in contents
        assert "ROADMAP.md" in contents
        assert "G008" in contents

    architecture = _normalized(SAAS / "ARCHITECTURE.md")
    assert "no mandatory network call in the side-effect hot path" in architecture
    assert "last-known-good (LKG) policy" in architecture
    assert "high-risk path fails closed" in architecture
    assert "provisional planning assumptions" in architecture
    assert "operational owner must ratify" in architecture
    assert "BYPASSRLS roles must not be treated as tenant-isolated access" in architecture
    assert "never from an agent-controlled tool/API body" in architecture
    assert (
        "does not turn federated or observed records into native authorization proof"
        in architecture
    )
    assert "Authentication secrets, credentials, access tokens, private keys" in architecture
    assert "durably persists a pre-effect issuance/audit-anchor record" in architecture
    assert (
        "Audit append/anchor verification, receipt validation, canonicalization, or" in architecture
    )
    assert "canonicalization algorithm/version and canonical argument digest" in architecture
    assert (
        "remote revocation instantly; it must fail closed when signed trust-material"
        in architecture
    )


def test_threat_model_covers_stride_agent_boundaries_and_zero_side_effects() -> None:
    threat = _normalized(SAAS / "THREAT_MODEL.md")
    for term in (
        "STRIDE and agent-specific threat analysis",
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information disclosure",
        "Denial of service",
        "Elevation of privilege",
        "Agent-specific TOCTOU",
    ):
        assert term in threat
    assert "DENY and ESCALATE are never executable" in threat
    assert "original ESCALATE artifact" in threat
    assert "class-invalid evidence" in threat
    assert "full self-consistent rewrite" in threat.lower()
    assert "must not silently upgrade federated or observed evidence to native" in threat
    assert "calls the protected tool zero times" in threat
    assert "default evidence, telemetry, errors, billing, and exports omit seeded" in threat.lower()
    assert "Pre-effect audit append/issuance-anchor persistence or digest verification" in threat
    assert "unknown/mismatched canonicalization algorithm/version" in threat
    assert "revocation after last sync once signed trust freshness expires" in threat


def test_api_contract_freezes_authenticity_provenance_and_data_rules() -> None:
    api = _normalized(SAAS / "API_AND_DATA_CONTRACT.md")
    assert "future public management and evidence API is rooted at **/v1**" in api
    assert "server-side session to the BFF" in api
    assert "never receives or stores a service API key" in api
    assert "authenticated principal and the resource relationship are the authority" in api
    assert "Idempotency-Key" in api
    assert "same key with a different digest returns a conflict" in api
    assert "All mutating management, gate, and evidence requests require an" in api
    assert "have no non-idempotent opt-out" in api
    assert "opaque, tenant-scoped cursor pagination" in api
    assert (
        "No endpoint, worker, export, dashboard, alert, or usage calculation "
        "may silently promote an assurance class"
    ) in api
    assert "never return after creation" in api.lower()
    assert "do not use raw arguments or credentials as analytics/billing dimensions" in api
    assert "unknown version or mismatch fails before effect" in api
    assert "generated TypeScript client or bidirectional contract tests" in api


def test_migration_policy_requires_safe_evolution_and_preserves_verifiability() -> None:
    policy = _normalized(SAAS / "MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md")
    assert "uses create-all rather than an Alembic migration surface" in policy
    assert "explicit, reviewed Alembic migration history" in policy
    assert "backup before execution" in policy
    assert all(
        stage in policy for stage in ("Expand.", "Migrate/backfill.", "Validate.", "Contract.")
    )
    assert "Backfills do not manufacture signatures, native assurance" in policy
    assert (
        "Original schema/version/canonical bytes/digest/signature/bindings remain verifiable"
    ) in policy
    assert (
        "Reclassifying, countersigning, importing, or exporting it as native authorization evidence"
    ) in policy
    assert "clean-install migration from empty supported PostgreSQL" in policy
    assert "backup/PITR/restore drill" in policy


ADR_FILES = {
    "saas-identity-oidc-saml-scim-build-vs-buy.md",
    "saas-kms-build-vs-buy.md",
    "saas-object-retention-build-vs-buy.md",
    "saas-independent-witness-build-vs-buy.md",
    "saas-billing-build-vs-buy.md",
    "saas-commercial-module-boundary.md",
}


def test_each_build_vs_buy_adr_is_proposed_owner_gated_and_noncommercial() -> None:
    for name in ADR_FILES:
        document = ADR / name
        contents = _text(document)
        normalized = _normalized(document)
        assert "**Proposed — decision required.**" in contents
        assert "## Decision required" in contents
        assert "## Safe fallback" in contents
        assert "## Evidence required after approval" in contents
        assert "## Downstream nodes and validation after unblock" in contents
        assert "Accountable owners:" in contents
        assert "does not" in normalized.lower()
        assert "selected vendor" not in normalized.lower()
        assert "live charge" not in normalized.lower()
        assert "commercial commitment" not in normalized.lower()

    identity = _normalized(ADR / "saas-identity-oidc-saml-scim-build-vs-buy.md")
    kms = _normalized(ADR / "saas-kms-build-vs-buy.md")
    storage = _normalized(ADR / "saas-object-retention-build-vs-buy.md")
    witness = _normalized(ADR / "saas-independent-witness-build-vs-buy.md")
    billing = _normalized(ADR / "saas-billing-build-vs-buy.md")
    commercial = _normalized(ADR / "saas-commercial-module-boundary.md")

    assert "OIDC as the first federation protocol to evaluate" in identity
    assert "provider interface" in kms and "side-effect hot path" in kms
    assert "retention capability" in storage
    assert "database hash chain as a retention or witness substitute" in storage
    assert "cannot silently rewrite evidence and its only trust anchor" in witness
    assert "does not charge for local authorization calls or model tokens" in billing
    assert (
        "Existing Apache-2.0 code cannot be retroactively represented as an "
        "exclusive paid feature boundary"
    ) in commercial


def test_docs_indexes_expose_target_architecture_without_promoting_it() -> None:
    docs_index = _text(ROOT / "docs" / "README.md")
    roadmap = _text(ROOT / "docs" / "ROADMAP.md")

    for link in (
        "saas/ARCHITECTURE.md",
        "saas/THREAT_MODEL.md",
        "saas/API_AND_DATA_CONTRACT.md",
        "saas/MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md",
        "adr/saas-identity-oidc-saml-scim-build-vs-buy.md",
    ):
        assert link in docs_index
        assert link in roadmap
    assert "not managed-service evidence" in docs_index
    assert "not evidence that a managed plane" in " ".join(roadmap.split())


def test_g008_remains_tied_to_the_conservative_program_record() -> None:
    dag = json.loads(_text(SAAS / "DELIVERY_DAG.yaml"))
    g008 = next(node for node in dag["nodes"] if node["id"] == "G008")

    assert set(g008["dependencies"]) == {"G006", "G007"}
    assert g008["risk_class"] == "red"
    assert (
        g008["status"],
        g008["implementation_state"],
        g008["evidence_state"],
    ) == ("completed", "built", "independently_reviewed")
    assert g008["branch"] == "beta/p0-architecture-008"
    assert g008["worktree"] == "saas-beta/p0-architecture-008"
    assert g008["pr"] == 321
    assert {
        "docs/saas/ARCHITECTURE.md",
        "docs/saas/THREAT_MODEL.md",
        "docs/saas/API_AND_DATA_CONTRACT.md",
        "docs/saas/MIGRATION_VERSIONING_COMPATIBILITY_POLICY.md",
        "tests/docs/test_saas_architecture_contract.py",
    } <= set(g008["likely_interfaces_files"])

    matrix = _text(SAAS / "ACCEPTANCE_MATRIX.md")
    assert (
        "| AM-002 | Frozen current-state and product-contract reconciliation | partial | "
        "current_local | G006, G007, G008 |"
    ) in matrix
    assert (
        "owner-only provider, legal, licensing, spend, and deployment decisions remain proposed"
    ) in matrix

    g101 = next(node for node in dag["nodes"] if node["id"] == "G101")
    assert (
        g101["status"],
        g101["implementation_state"],
        g101["evidence_state"],
    ) == ("in_progress", "partial", "local_verified")
    assert g101["branch"] == "beta/p1-g101-postgres-advisory-lock"
    assert g101["worktree"] == "saas-beta/p1-g101-postgres-advisory-lock"
    assert g101["pr"] == 324
    assert g101["status"] != "completed"
    assert g101["implementation_state"] != "built"
    assert g101["evidence_state"] not in {"accepted", "ci_verified"}
    assert {
        "packages/acgs-control-plane/src/acgs_control_plane/migrations.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migrations/versions/0001_legacy_v0.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migrations/versions/0002_project_environment.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migration_recovery.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migration_cli.py",
        "packages/acgs-control-plane/MIGRATION_RECOVERY.md",
        "packages/acgs-control-plane/tests/test_migrations.py",
        "packages/acgs-control-plane/tests/test_project_environment_scope.py",
        "packages/acgs-control-plane/tests/test_postgresql_migrations.py",
        "packages/acgs-control-plane/tests/_postgresql_migration_worker.py",
        "packages/acgs-control-plane/tests/test_migration_recovery.py",
        "packages/acgs-control-plane/tests/test_postgresql_migration_recovery.py",
        "packages/acgs-control-plane/tests/test_migration_cli.py",
        "packages/acgs-control-plane/tests/test_postgresql_migration_cli.py",
        ".github/workflows/python-acgs-control-plane.yml",
        "requirements/saas-beta/cp-test.lock",
    } <= set(g101["likely_interfaces_files"])
    assert "PostgreSQL 17.10-bookworm" in " ".join(g101["positive_tests"])

    increment_rows = g101["local_evidence_increments"]
    increment_prs = [item["pr"] for item in increment_rows]
    assert len(increment_prs) == len(set(increment_prs))
    assert {329, 330, 331, 332, 334, 335, 336, 338} <= set(increment_prs)
    increments = {item["pr"]: item for item in increment_rows}
    for increment in increment_rows:
        assert increment["state"] == "open_draft"
        assert increment["merged"] is False
        assert increment["evidence_state"] == "local_verified"
        assert increment["ci_backed"] is False
        assert increment["review_state"] in {
            "independently_reviewed",
            "independently_approved",
        }
        assert increment["proves"]
        assert increment["does_not_prove"]

    integrated = increments[338]
    repaired_head = "1e7aa033bb5a2b8ee0984e98b148e0c14b94622d"
    rejected_predecessor = "952186c5039504c7be4d086c5d2eb806beecb3b8"
    assert integrated["branch"] == "beta/p1-g101-integrated-candidate"
    assert integrated["base_pr"] == 337
    assert integrated["head"] == repaired_head
    assert integrated["review_state"] == "independently_approved"
    assert integrated["verification_state"] == "passed"
    assert integrated["state"] == "open_draft"
    assert integrated["merged"] is False
    assert integrated["ci_backed"] is False
    predecessor = integrated["security_rejected_predecessor"]
    assert predecessor == {
        "head": rejected_predecessor,
        "disposition": "security_rejected_predecessor_in_draft_pr_338_history",
        "relationship": f"immediate_ancestor_of_{repaired_head}",
        "standalone_publication": ("never_published_as_a_standalone_accepted_pr_or_head"),
        "remote_history": "present_only_as_an_ancestor_in_draft_pr_338",
        "superseded_and_repaired_by": repaired_head,
        "accepted_evidence": False,
        "reason": (
            "Recovery preflight was not bound to canonical PostgreSQL public and the "
            "workflow acquired an unpinned PostgreSQL client trust root."
        ),
    }

    g101_truth = " ".join((g101["evidence_artifact"], g101["blocker"], g101["next_safe_action"]))
    for required_truth in (
        "PR #338",
        repaired_head,
        "PR #337",
        "open drafts",
        "unmerged",
        "repository-unaccepted",
        "failed before any step",
        "billing lock",
        "Windows",
        "not accepted evidence",
        "Do not start G102",
        "Keep G105 planned and deferred",
    ):
        assert required_truth in g101_truth
    assert rejected_predecessor in g101_truth
    assert "production startup remains deliberately blocked" in g101_truth.lower()

    remote_ci = g101["remote_ci"]
    assert remote_ci["state"] == "externally_blocked"
    assert remote_ci["ci_backed"] is False
    assert "failed before any step" in remote_ci["annotation"]
    assert "billing" in remote_ci["annotation"].lower()
    remote_candidate = remote_ci["integrated_candidate"]
    assert remote_candidate["source_pr"] == 338
    assert remote_candidate["head"] == repaired_head
    assert remote_candidate["base_pr"] == 337
    assert remote_candidate["state"] == "open_draft"
    assert set(remote_candidate["self_hosted_passes"]) == {
        "test (3.11)",
        "test (3.12)",
    }
    zero_step = remote_candidate["billing_blocked_zero_step"]
    assert {item["name"] for item in zero_step} == {
        "postgresql-migrations",
        "codex-review",
    }
    assert all(item["run_id"] > 0 and item["job_id"] > 0 for item in zero_step)
    assert remote_candidate["windows"] == "unavailable"
    assert "do not make the migration evidence fully CI-backed" in remote_ci["impact"]

    g102 = next(node for node in dag["nodes"] if node["id"] == "G102")
    assert (
        g102["status"],
        g102["implementation_state"],
        g102["evidence_state"],
    ) == ("blocked", "missing", "unverified")
    assert g102["dependencies"] == ["G101"]
    assert "must not start" in g102["blocker"]

    g103 = next(node for node in dag["nodes"] if node["id"] == "G103")
    assert (
        g103["status"],
        g103["implementation_state"],
        g103["evidence_state"],
    ) == ("planned", "missing", "unverified")
    assert g103["dependencies"] == ["G101", "G102"]
    g103_isolation_contract = " ".join(
        [
            *g103["likely_interfaces_files"],
            *g103["positive_tests"],
            g103["next_safe_action"],
        ]
    )
    for requirement in (
        "tenant context",
        "composite constraints",
        "RLS",
        "schema/search_path",
        "role hardening",
        "After G101 and G102 are completed",
        "before implementation",
    ):
        assert requirement in g103_isolation_contract

    g105 = next(node for node in dag["nodes"] if node["id"] == "G105")
    assert (
        g105["status"],
        g105["implementation_state"],
        g105["evidence_state"],
    ) == ("planned", "missing", "unverified")
    assert set(g105["dependencies"]) == {"G103", "G104", "G004"}
    assert "Deferred" in g105["blocker"]
    assert "must not start" in g105["blocker"]
    assert "Keep G105 planned and deferred" in g105["next_safe_action"]

    assert (
        "| AM-005 | Tenant-scoped managed control-plane foundation | partial | "
        "current_local | G101, G102, G103, G104, G105, G106 |"
    ) in matrix
    am_005 = next(line for line in matrix.splitlines() if line.startswith("| AM-005 |"))
    for current_fact in (
        "PR #338",
        repaired_head,
        "PR #337",
        "191 package passes with 19 skips",
        "53 main PostgreSQL passes with one Windows-only skip",
        "8 recovery passes",
        "3 bytea passes",
        "7 rolling-upgrade passes",
        "self-hosted remote Python 3.11 and 3.12 checks pass",
        "failed with zero steps",
        "GitHub billing lock",
        "Windows remains unavailable",
        rejected_predecessor,
        "present in remote history only as the immediate ancestor",
        "not accepted evidence",
        "open drafts and unmerged",
        "G101 therefore remains `in_progress`/`partial`/`local_verified`",
        "G102 remains blocked",
        "G105 remains planned and deferred",
    ):
        assert current_fact in am_005
    for unsupported_upgrade in (
        "| built |",
        "production-ready",
        "repository-accepted",
        "G101 is complete",
        "G102 may start",
        "CI-backed evidence",
    ):
        assert unsupported_upgrade not in am_005
