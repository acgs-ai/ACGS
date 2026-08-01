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


def _node_text(node: dict[str, object]) -> str:
    parts: list[str] = []
    for key in (
        "likely_interfaces_files",
        "positive_tests",
        "forbidden_side_effect_negative_tests",
        "validation_commands",
    ):
        value = node.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
    for key in ("evidence_artifact", "blocker", "next_safe_action"):
        value = node.get(key)
        if value:
            parts.append(str(value))
    return " ".join(parts)


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
    ) == ("completed", "built", "independently_reviewed")
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
        "#354/#355 merged migration/recovery foundation",
        "#369 scope-attachment precursor",
        "current master",
        "hosted PostgreSQL/codex-review/test checks passing",
        "83afdbd7d5b8ae2c9f043fa13488cda739ac1e2b",
        "67f7e3062e9b3745f3a44d16c3c660b6884b670a",
        "not production DR/PITR/object/witness recovery",
    ):
        assert evidence in g101["evidence_artifact"]
    assert g101["blocker"] is None
    for retired_gap in (
        "#308 startup integration",
        "CI-backed PostgreSQL migration",
        "multi-instance migration",
        "migration backup/restore",
        "forward-only rollback",
        "EXT-GITHUB-BILLING",
    ):
        assert retired_gap not in g101["evidence_artifact"]
    assert "Use this slice as completed dependency evidence" in g101["next_safe_action"]
    assert "remaining aggregate G102" in g101["next_safe_action"]

    assert (
        "| AM-005 | Tenant-scoped managed control-plane foundation | partial | "
        "current_local | G101, G102, G102A, G102B, G102C, G102D, G102E, G102F, "
        "G103, G104, G105, G106 |"
    ) in matrix
    am_005 = next(line for line in matrix.splitlines() if line.startswith("| AM-005 |"))
    for evidence in (
        "G101 and slices G102A-D are completed/built/independently reviewed",
        "merged PRs #354/#355/#357/#359/#361/#363",
        "hosted checks green",
        "Mandatory G102F remains missing",
        "before any staging, production, capacity, or latency claim",
        "Aggregate G102 therefore remains in_progress/partial/current-local",
        "durable idempotency beyond native `agent.register`",
        "async export jobs",
        "production provider wiring",
        "complete tenant isolation",
        "policy signing/distribution",
        "external exactly-once delivery",
        "full native cutover from legacy unsigned route aliases",
        "PR #369 provides partial project/environment scope attachment",
        "PR #370 provides a partial signed native agent-create transaction spine",
        "PR #371 provides partial route-scoped idempotency/outbox evidence",
        "G104 service credential/browser BFF work remains missing",
    ):
        assert evidence in am_005
    for retired_gap in (
        "#308 startup integration",
        "CI-backed PostgreSQL",
        "multi-instance",
        "backup/restore",
        "forward-only rollback",
        "API/policy/backfill",
        "EXT-GITHUB-BILLING",
        "unmerged #353/#354/#355/#357/#359/#361/#363 draft stack",
        "hosted PostgreSQL migration/codex-review check-start failures",
    ):
        assert retired_gap not in am_005
    assert "No row declares beta code-complete or production-ready" in matrix
    assert "Production launch remains a separate human-authorized decision" in matrix

    g102 = next(node for node in dag["nodes"] if node["id"] == "G102")
    assert g102["dependencies"] == [
        "G101",
        "G102A",
        "G102B",
        "G102C",
        "G102D",
        "G102E",
        "G102F",
    ]
    assert (
        g102["status"],
        g102["implementation_state"],
        g102["evidence_state"],
    ) == ("in_progress", "partial", "local_verified")
    assert "EXT-GITHUB-BILLING" not in g102["blocker"]
    for missing_contract in (
        "mandatory G102F migration-managed composite (org_id, created_at, id) collection indexes",
        "cursor coverage beyond the four dedicated collections",
        "durable idempotency for mutating routes beyond native agent.register",
        "async export jobs",
        "policy signing/distribution",
        "external exactly-once delivery",
        "full native cutover from legacy unsigned route aliases",
    ):
        assert missing_contract in g102["blocker"]
    assert "OpenAPI drift verification remain missing" not in g102["blocker"]
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
    actual_g102c_files = {
        "packages/acgs-control-plane/tests/test_openapi_drift.py",
    }
    assert actual_g102c_files <= set(g102["likely_interfaces_files"])
    assert all((ROOT / path).is_file() for path in actual_g102c_files)
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_openapi_drift.py -q"
        in g102["validation_commands"]
    )
    actual_g102d_files = {
        "packages/acgs-control-plane/src/acgs_control_plane/app.py",
        "packages/acgs-control-plane/src/acgs_control_plane/governance.py",
        "packages/acgs-control-plane/src/acgs_control_plane/schemas.py",
        "packages/acgs-control-plane/tests/integration/test_production_posture.py",
        "packages/acgs-control-plane/tests/test_openapi_drift.py",
        "packages/acgs-control-plane/tests/test_startup_preflight.py",
        "packages/acgs-control-plane/tests/test_v1_api_contract.py",
    }
    assert actual_g102d_files <= set(g102["likely_interfaces_files"])
    assert all((ROOT / path).is_file() for path in actual_g102d_files)
    assert (
        "cd packages/acgs-control-plane && uv run pytest tests/test_v1_api_contract.py "
        "tests/test_openapi_drift.py tests/test_startup_preflight.py "
        "tests/integration/test_production_posture.py -q" in g102["validation_commands"]
    )

    g102a = next(node for node in dag["nodes"] if node["id"] == "G102A")
    assert g102a["title"] == "Bounded request admission and redacted error contract"
    assert set(g102a["dependencies"]) == {"G101"}
    assert g102a["consumers"] == ["G102"]
    assert (
        g102a["status"],
        g102a["implementation_state"],
        g102a["evidence_state"],
    ) == ("completed", "built", "independently_reviewed")
    assert g102a["branch"] == "beta/p1-g102-request-admission"
    assert g102a["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g102a["pr"] == 357
    assert actual_g102a_files <= set(g102a["likely_interfaces_files"])
    combined_g102a = _node_text(g102a)
    for evidence in (
        "4d60fb4a0a16be06a2a9957dea91dc2bf429c57d",
        "bounded request-admission and redacted-error contract evidence",
        "evidence at 14 passed",
        "full control-plane package evidence at 228 passed and 32 skipped",
        "Ruff and mypy pass",
        "independent security/code approve/verifier pass",
        "hosted Python 3.11/3.12 pass",
        "PR #357 merged into current master",
        "hosted codex-review",
        "postgresql-migrations",
        "G102B separately covers receipt-route cursor pagination",
        "G102C separately covers the current-v0 OpenAPI drift sentinel",
        "G102D separately covers additive legacy-v0 /v1 aliases",
        "complete all-collections cursor pagination",
        "async export jobs",
    ):
        assert evidence in combined_g102a
    assert "OpenAPI drift acceptance evidence" not in combined_g102a
    assert "OpenAPI drift gates are completed" not in combined_g102a
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
    assert g102b["consumers"] == ["G102", "G102E"]
    assert (
        g102b["status"],
        g102b["implementation_state"],
        g102b["evidence_state"],
    ) == ("completed", "built", "independently_reviewed")
    assert g102b["branch"] == "beta/p1-g102b-receipt-cursors"
    assert g102b["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g102b["pr"] == 359
    assert actual_g102b_files <= set(g102b["likely_interfaces_files"])
    combined_g102b = _node_text(g102b)
    for evidence in (
        "262c7bd8f408cef81333ae53591113960d78a32a",
        "receipt cursor pagination evidence at 32 passed",
        "full control-plane package evidence at 260 passed and 32 skipped",
        "Ruff pass",
        "mypy pass",
        "deterministic generated CP lock",
        "Python 3.11 hash-locked offline import pass",
        "independent security/code approve/verifier pass",
        "hosted Python 3.11/3.12 pass",
        "PR #359 merged into current master",
        "hosted codex-review",
        "postgresql-migrations",
        "all-collections pagination remains an aggregate G102 gap",
        "PostgreSQL/schema change",
    ):
        assert evidence in combined_g102b
    for forbidden_promotion in (
        "aggregate G102",
        "all-collections pagination",
        "G102D /v1 alias evidence",
        "durable idempotency",
        "async export jobs",
        "PostgreSQL/schema change",
        "capacity claims",
        "G102C OpenAPI drift sentinel evidence",
    ):
        assert forbidden_promotion in combined_g102b

    g102c = next(node for node in dag["nodes"] if node["id"] == "G102C")
    assert g102c["title"] == "Current-v0 OpenAPI drift sentinel"
    assert set(g102c["dependencies"]) == {"G101"}
    assert g102c["consumers"] == ["G102"]
    assert (
        g102c["status"],
        g102c["implementation_state"],
        g102c["evidence_state"],
    ) == ("completed", "built", "independently_reviewed")
    assert g102c["branch"] == "beta/p1-g102c-openapi-drift"
    assert g102c["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g102c["pr"] == 361
    assert actual_g102c_files <= set(g102c["likely_interfaces_files"])
    combined_g102c = _node_text(g102c)
    for evidence in (
        "a6faf49a7b5f947b592f4be8372a85b173251090",
        "current-v0 OpenAPI drift sentinel evidence at 5 passed",
        "full control-plane package evidence at 265 passed and 32 skipped",
        "Ruff pass",
        "package-local mypy pass",
        "independent review finding repaired then APPROVE",
        "verifier PASS",
        "hosted Python 3.11/3.12 pass",
        "PR #361 merged into current master",
        "hosted codex-review",
        "postgresql-migrations",
        "runtime/API aggregate gaps remain",
    ):
        assert evidence in combined_g102c
    for forbidden_promotion in (
        "runtime behavior",
        "schema migration",
        "production readiness",
        "beta completion",
        "G102D /v1 alias",
        "async-export",
        "all-collections cursor capability",
    ):
        assert forbidden_promotion in combined_g102c

    g102d = next(node for node in dag["nodes"] if node["id"] == "G102D")
    assert g102d["title"] == "Additive legacy-v0 /v1 API aliases"
    assert set(g102d["dependencies"]) == {"G101"}
    assert g102d["consumers"] == ["G102", "G102E"]
    assert (
        g102d["status"],
        g102d["implementation_state"],
        g102d["evidence_state"],
    ) == ("completed", "built", "independently_reviewed")
    assert g102d["branch"] == "beta/p1-g102d-v1-api-contract"
    assert g102d["worktree"] == "saas-beta/p1-g101-tool-provenance"
    assert g102d["pr"] == 363
    assert actual_g102d_files <= set(g102d["likely_interfaces_files"])
    combined_g102d = _node_text(g102d)
    for evidence in (
        "047ddcf89530dc488ab6a2f4dd3bc00fe0211c5d",
        "focused v1/OpenAPI/startup/production-posture evidence at 42 passed",
        "full control-plane package evidence at 272 passed and 32 skipped",
        "Ruff pass",
        "package-local mypy pass",
        "independent code and security APPROVE",
        "verifier PASS",
        "hosted Python 3.11/3.12 pass",
        "PR #363 merged into current master",
        "hosted codex-review",
        "postgresql-migrations",
        "additive legacy-v0 /v1 alias slice",
        "typed GET /v1 metadata",
        "preserving v0 behavior",
        "14 LEGACY_UNSIGNED_WRITE blockers",
    ):
        assert evidence in combined_g102d
    for forbidden_promotion in (
        "signed production governance",
        "database schema",
        "migration",
        "generated client",
        "production readiness",
        "beta completion",
        "complete all-collections pagination",
        "durable idempotency",
        "async export job",
    ):
        assert forbidden_promotion in combined_g102d

    for completed_leaf_id in ("G102A", "G102B", "G102C", "G102D"):
        completed_leaf = next(node for node in dag["nodes"] if node["id"] == completed_leaf_id)
        completed_leaf_text = _node_text(completed_leaf)
        assert "Hosted PostgreSQL migrations and codex-review did not start" not in completed_leaf_text
        assert "hosted PostgreSQL migration, and codex-review evidence remain missing" not in completed_leaf_text
        assert "hosted PostgreSQL migration/codex-review evidence remain missing" not in completed_leaf_text

    for downstream_node_id in ("G103",):
        downstream_node = next(node for node in dag["nodes"] if node["id"] == downstream_node_id)
        assert (
            downstream_node["status"],
            downstream_node["implementation_state"],
            downstream_node["evidence_state"],
        ) == ("blocked", "partial", "local_verified")

    g103 = next(node for node in dag["nodes"] if node["id"] == "G103")
    assert g103["dependencies"] == ["G101", "G102"]
    assert g103["pr"] == 369
    g103_isolation_contract = _node_text(g103)
    for requirement in (
        "scope-attachment precursor",
        "project/environment attachment",
        "not complete tenant isolation",
        "tenant context",
        "composite constraints",
        "RLS",
        "schema/search_path",
        "role hardening",
        "workers",
        "exports",
        "caches/logs/metrics/support tooling",
        "cross-tenant inference denial",
        "Complete the named missing dependency",
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
