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
    ) == ("blocked", "built", "local_verified")
    assert g101["branch"] == "beta/p1-g101-tool-provenance"
    assert g101["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g101["pr"] == 355
    assert {
        "packages/acgs-control-plane/pyproject.toml",
        "packages/acgs-control-plane/src/acgs_control_plane/db.py",
        "packages/acgs-control-plane/src/acgs_control_plane/models.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migrations.py",
        "packages/acgs-control-plane/src/acgs_control_plane/alembic.ini",
        "packages/acgs-control-plane/src/acgs_control_plane/migrations/env.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migrations/versions/0001_legacy_v0.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migrations/versions/0002_project_environment.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migration_cli.py",
        "packages/acgs-control-plane/src/acgs_control_plane/migration_recovery.py",
        "packages/acgs-control-plane/tests/test_migrations.py",
        "packages/acgs-control-plane/tests/test_project_environment_scope.py",
        "packages/acgs-control-plane/tests/test_postgresql_migrations.py",
        "packages/acgs-control-plane/tests/test_postgresql_migration_cli.py",
        "packages/acgs-control-plane/tests/test_postgresql_migration_recovery.py",
        "packages/acgs-control-plane/tests/test_postgresql_migration_recovery_bytea.py",
        "packages/acgs-control-plane/tests/test_postgresql_rolling_upgrade.py",
        ".github/workflows/python-acgs-control-plane.yml",
    } <= set(g101["likely_interfaces_files"])
    positive_tests = " ".join(g101["positive_tests"])
    for evidence in (
        "PostgreSQL 17.10-bookworm",
        "advisory-lock contention",
        "raw Alembic command denial",
        "startup exact-schema classification",
        "CLI forward-only acknowledgement",
        "rolling-upgrade compatibility",
        "migration recovery tool provenance",
    ):
        assert evidence in positive_tests
    for evidence in (
        "draft PR #354 plus draft PR #355",
        "full control-plane package 214 passed/32 skipped",
        "real disposable PostgreSQL migration recovery 8 passed",
        ".github/workflows/python-acgs-control-plane.yml",
        "ACP_TEST_RECOVERY_SOURCE_URL",
        "ACP_TEST_RECOVERY_TARGET_URL",
        "explicit absolute pg_dump/pg_restore wrapper paths",
        "EXT-GITHUB-BILLING",
        "not G603 production DR/PITR/object/witness recovery",
    ):
        assert evidence in g101["evidence_artifact"]
    for gap in (
        "#354 based on #353",
        "#355 based on #354",
        "EXT-GITHUB-BILLING",
        "G603 production backup/PITR/object/witness DR",
        "G103 tenant database isolation",
    ):
        assert gap in g101["blocker"]
    for retired_gap in (
        "#308 startup integration",
        "CI-backed PostgreSQL migration",
        "multi-instance migration",
        "migration backup/restore",
        "forward-only rollback",
    ):
        assert retired_gap not in g101["blocker"]
    assert "G103 tenant database isolation remains planned after G101 and G102" in g101["blocker"]
    assert "observe #354/#355 hosted PostgreSQL and review checks" in g101["next_safe_action"]
    assert "before accepting aggregate G102" in g101["next_safe_action"]
    assert "Keep production DR/PITR/object/witness recovery in G603" in g101["next_safe_action"]

    assert (
        "| AM-005 | Tenant-scoped managed control-plane foundation | partial | "
        "current_local | G101, G102, G102A, G102B, G103, G104, G105, G106 |"
    ) in matrix
    am_005 = next(line for line in matrix.splitlines() if line.startswith("| AM-005 |"))
    for evidence in (
        "214 passed/32 skipped",
        "bounded request-admission/redacted-error contract evidence",
        "PR #357 branch `beta/p1-g102-request-admission`",
        "commit `4d60fb4a0a16be06a2a9957dea91dc2bf429c57d`",
        "focused `cd packages/acgs-control-plane && uv run pytest "
        "tests/test_api_contract.py -q` at 14 passed",
        "full control-plane 228 passed/32 skipped",
        "Ruff and mypy pass",
        "independent security/code approve/verifier pass",
        "hosted Python 3.11/3.12 pass",
        "receipt-only bounded opaque cursor pagination",
        "PR #359 branch `beta/p1-g102b-receipt-cursors`",
        "commit `262c7bd8f408cef81333ae53591113960d78a32a`",
        (
            "focused `cd packages/acgs-control-plane && uv run pytest "
            "tests/test_receipt_cursor_pagination.py -q` at 32 passed"
        ),
        "full control-plane 260 passed/32 skipped",
        "deterministic generated CP lock",
        "Python 3.11 hash-locked offline import pass",
        "receipt-route pagination only",
        "not complete all-collections pagination",
        "no PostgreSQL/schema change or capacity claim",
        "real disposable PostgreSQL migration recovery at 8 passed",
        "focused migration, CLI, startup, rolling-upgrade, and recovery-tool-provenance tests",
        ".github/workflows/python-acgs-control-plane.yml",
        "ACP_TEST_RECOVERY_SOURCE_URL",
        "ACP_TEST_RECOVERY_TARGET_URL",
        "explicit absolute `pg_dump`/`pg_restore` wrapper paths",
        "unmerged #353/#354/#355/#357/#359 draft stack",
        "EXT-GITHUB-BILLING",
        "hosted PostgreSQL migration/codex-review check-start failures",
        "aggregate G102 remains in_progress/partial/current-local",
        "completed `/v1` root",
        "complete all-collections cursor pagination",
        "durable idempotency",
        "async export jobs",
        "OpenAPI drift evidence",
        "G103 tenant isolation remains planned",
        "G603 production DR/PITR/object/witness recovery remains separate",
    ):
        assert evidence in am_005
    for retired_gap in (
        "#308 startup integration",
        "CI-backed PostgreSQL",
        "multi-instance",
        "backup/restore",
        "forward-only rollback",
        "API/policy/backfill",
    ):
        assert retired_gap not in am_005
    assert "No row declares beta code-complete or production-ready" in matrix
    assert "Production launch remains a separate human-authorized decision" in matrix

    g102 = next(node for node in dag["nodes"] if node["id"] == "G102")
    assert g102["dependencies"] == ["G101", "G102A", "G102B"]
    assert (
        g102["status"],
        g102["implementation_state"],
        g102["evidence_state"],
    ) == ("in_progress", "partial", "local_verified")
    assert "EXT-GITHUB-BILLING" in g102["blocker"]
    for missing_contract in (
        "/v1 root",
        "complete all-collections cursor pagination",
        "durable idempotency",
        "async export jobs",
        "OpenAPI drift",
    ):
        assert missing_contract in g102["blocker"]
    actual_g102a_files = {
        "packages/acgs-control-plane/README.md",
        "packages/acgs-control-plane/src/acgs_control_plane/api_contract.py",
        "packages/acgs-control-plane/src/acgs_control_plane/app.py",
        "packages/acgs-control-plane/src/acgs_control_plane/config.py",
        "packages/acgs-control-plane/tests/test_api_contract.py",
    }
    assert actual_g102a_files <= set(g102["likely_interfaces_files"])
    assert all((ROOT / path).is_file() for path in actual_g102a_files)
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_api_contract.py -q"
        in g102["validation_commands"]
    )
    actual_g102b_files = {
        "packages/acgs-control-plane/README.md",
        "packages/acgs-control-plane/pyproject.toml",
        "packages/acgs-control-plane/src/acgs_control_plane/app.py",
        "packages/acgs-control-plane/src/acgs_control_plane/config.py",
        "packages/acgs-control-plane/src/acgs_control_plane/governance.py",
        "packages/acgs-control-plane/src/acgs_control_plane/pagination.py",
        "packages/acgs-control-plane/src/acgs_control_plane/schemas.py",
        "packages/acgs-control-plane/tests/test_receipt_cursor_pagination.py",
        "requirements/saas-beta/cp-test.in",
        "requirements/saas-beta/cp-test.lock",
    }
    assert actual_g102b_files <= set(g102["likely_interfaces_files"])
    assert all((ROOT / path).is_file() for path in actual_g102b_files)
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_receipt_cursor_pagination.py -q"
        in g102["validation_commands"]
    )

    g102a = next(node for node in dag["nodes"] if node["id"] == "G102A")
    assert g102a["title"] == "Bounded request admission and redacted error contract"
    assert set(g102a["dependencies"]) == {"G101"}
    assert g102a["consumers"] == ["G102"]
    assert (
        g102a["status"],
        g102a["implementation_state"],
        g102a["evidence_state"],
    ) == ("blocked", "built", "local_verified")
    assert g102a["branch"] == "beta/p1-g102-request-admission"
    assert g102a["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g102a["pr"] == 357
    assert actual_g102a_files <= set(g102a["likely_interfaces_files"])
    combined_g102a = " ".join(
        [
            *g102a["likely_interfaces_files"],
            *g102a["positive_tests"],
            *g102a["validation_commands"],
            g102a["evidence_artifact"],
            g102a["blocker"],
            g102a["next_safe_action"],
        ]
    )
    for evidence in (
        "4d60fb4a0a16be06a2a9957dea91dc2bf429c57d",
        "bounded request-admission and redacted-error contract evidence",
        "focused 14 passed",
        "full control-plane package evidence at 228 passed and 32 skipped",
        "Ruff pass",
        "mypy pass",
        "independent security/code approve/verifier pass",
        "hosted Python 3.11",
        "Python 3.12 pass",
        "Hosted PostgreSQL migrations and codex-review did not start",
        "EXT-GITHUB-BILLING",
        "/v1 root",
        "G102B separately covers receipt-route cursor pagination",
        "complete all-collections cursor pagination",
        "durable idempotency",
        "async export jobs",
        "OpenAPI drift",
    ):
        assert evidence in combined_g102a
    assert "until /v1, cursor pagination," not in combined_g102a
    assert "lacks /v1 root, cursor pagination," not in combined_g102a
    assert "partial until /v1 root, cursor pagination," not in combined_g102a
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_api_contract.py -q"
        in combined_g102a
    )
    assert "tests/test_request_admission.py" not in combined_g102a
    assert "tests/test_api_program_reconcile.py" not in combined_g102a

    g102b = next(node for node in dag["nodes"] if node["id"] == "G102B")
    assert g102b["title"] == "Bounded opaque receipt cursor pagination"
    assert set(g102b["dependencies"]) == {"G101"}
    assert g102b["consumers"] == ["G102"]
    assert (
        g102b["status"],
        g102b["implementation_state"],
        g102b["evidence_state"],
    ) == ("blocked", "built", "local_verified")
    assert g102b["branch"] == "beta/p1-g102b-receipt-cursors"
    assert g102b["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g102b["pr"] == 359
    assert actual_g102b_files <= set(g102b["likely_interfaces_files"])
    combined_g102b = " ".join(
        [
            *g102b["likely_interfaces_files"],
            *g102b["positive_tests"],
            *g102b["forbidden_side_effect_negative_tests"],
            *g102b["validation_commands"],
            g102b["evidence_artifact"],
            g102b["blocker"],
            g102b["next_safe_action"],
        ]
    )
    for evidence in (
        "262c7bd8f408cef81333ae53591113960d78a32a",
        "receipt cursor pagination evidence at 32 passed",
        "full control-plane package evidence at 260 passed and 32 skipped",
        "Ruff pass",
        "mypy pass",
        "deterministic generated CP lock",
        "Python 3.11 hash-locked offline import pass",
        "independent security/code approve/verifier pass",
        "hosted Python 3.11",
        "Python 3.12 pass",
        "Hosted PostgreSQL migrations and codex-review did not start",
        "EXT-GITHUB-BILLING",
        "receipt-route cursor pagination only",
        "no PostgreSQL/schema change or capacity claim",
    ):
        assert evidence in combined_g102b
    for forbidden_promotion in (
        "aggregate G102",
        "all-collections pagination",
        "/v1 root",
        "durable idempotency",
        "async export jobs",
        "OpenAPI drift",
        "PostgreSQL/schema change",
        "capacity claims",
    ):
        assert forbidden_promotion in combined_g102b

    for downstream_node_id in ("G103",):
        downstream_node = next(node for node in dag["nodes"] if node["id"] == downstream_node_id)
        assert (
            downstream_node["status"],
            downstream_node["implementation_state"],
            downstream_node["evidence_state"],
        ) == ("planned", "missing", "unverified")

    g103 = next(node for node in dag["nodes"] if node["id"] == "G103")
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

    g603 = next(node for node in dag["nodes"] if node["id"] == "G603")
    assert (
        g603["status"],
        g603["implementation_state"],
        g603["evidence_state"],
    ) == ("planned", "missing", "unverified")
    assert "backup, PITR, object, witness, and migration rollback" in " ".join(
        [*g603["likely_interfaces_files"], *g603["positive_tests"], g603["evidence_artifact"]]
    )
