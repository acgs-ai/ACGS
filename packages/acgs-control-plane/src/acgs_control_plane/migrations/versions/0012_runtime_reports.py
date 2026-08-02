"""Add authenticated append-only runtime reports and wiring attestations."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from acgs_control_plane.runtime_lineage_schema import (
    POSTGRES_RUNTIME_LINEAGE_FUNCTIONS,
    POSTGRES_RUNTIME_LINEAGE_TRIGGERS,
    SQLITE_RUNTIME_LINEAGE_OBJECTS,
)

JSONVariant = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runtime_identities") as batch_op:
        batch_op.create_unique_constraint(
            "uq_runtime_identities_scope_gate_id",
            ["org_id", "project_id", "environment_id", "gate_id", "id"],
        )
    with op.batch_alter_table("runtime_credential_generations") as batch_op:
        batch_op.create_unique_constraint(
            "uq_runtime_credential_scope_generation_id",
            ["org_id", "project_id", "environment_id", "identity_id", "generation", "id"],
        )
    op.create_table(
        "runtime_reports",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("gate_id", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=240), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("credential_id", sa.String(length=64), nullable=False),
        sa.Column("credential_generation", sa.Integer(), nullable=False),
        sa.Column("workload_key_id", sa.String(length=128), nullable=False),
        sa.Column("public_key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("policy_version_id", sa.String(length=64), nullable=False),
        sa.Column("policy_head_generation", sa.Integer(), nullable=False),
        sa.Column("policy_content_hash", sa.String(length=64), nullable=False),
        sa.Column("runtime_build_digest", sa.String(length=64), nullable=False),
        sa.Column("configuration_digest", sa.String(length=64), nullable=False),
        sa.Column("policy_snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_provenance_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_revocation_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_fresh_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("report_hash", sa.String(length=64), nullable=False),
        sa.Column("projection_commitment", sa.String(length=64), nullable=False),
        sa.Column("request_projection", JSONVariant, nullable=False),
        sa.Column("request_signature", sa.Text(), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('status', 'wiring')", name="ck_runtime_reports_kind"),
        sa.CheckConstraint(
            "sequence >= 1 AND sequence <= 9007199254740991",
            name="ck_runtime_reports_sequence_positive",
        ),
        sa.CheckConstraint("expires_at > observed_at", name="ck_runtime_reports_expiry_order"),
        sa.CheckConstraint(
            "policy_issued_at <= policy_revocation_checked_at AND "
            "policy_revocation_checked_at <= policy_fresh_until AND "
            "policy_fresh_until <= policy_expires_at",
            name="ck_runtime_reports_policy_time_order",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name="fk_runtime_reports_organization",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "gate_id", "identity_id"],
            [
                "runtime_identities.org_id",
                "runtime_identities.project_id",
                "runtime_identities.environment_id",
                "runtime_identities.gate_id",
                "runtime_identities.id",
            ],
            name="fk_runtime_reports_identity_gate_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "gate_id"],
            [
                "runtime_identity_gates.org_id",
                "runtime_identity_gates.project_id",
                "runtime_identity_gates.environment_id",
                "runtime_identity_gates.id",
            ],
            name="fk_runtime_reports_gate_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            [
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "credential_generation",
                "credential_id",
            ],
            [
                "runtime_credential_generations.org_id",
                "runtime_credential_generations.project_id",
                "runtime_credential_generations.environment_id",
                "runtime_credential_generations.identity_id",
                "runtime_credential_generations.generation",
                "runtime_credential_generations.id",
            ],
            name="fk_runtime_reports_credential_scope_generation_id",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "policy_version_id"],
            [
                "policy_versions.org_id",
                "policy_versions.project_id",
                "policy_versions.environment_id",
                "policy_versions.id",
            ],
            name="fk_runtime_reports_policy_version",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_runtime_reports_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "gate_id",
            "identity_id",
            "kind",
            "id",
            name="uq_runtime_reports_scope_gate_identity_id",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "receipt_id",
            name="uq_runtime_reports_scope_receipt",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "sequence",
            name="uq_runtime_reports_identity_sequence",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "sequence",
            "id",
            name="uq_runtime_reports_identity_sequence_id",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "kind",
            "sequence",
            "id",
            name="uq_runtime_reports_identity_kind_sequence_id",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "kind",
            "id",
            name="uq_runtime_reports_identity_kind_id",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "nonce",
            name="uq_runtime_reports_identity_nonce",
        ),
    )
    op.create_index("ix_runtime_reports_org_id", "runtime_reports", ["org_id"])
    op.create_table(
        "runtime_report_heads",
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False),
        sa.Column("latest_report_id", sa.String(length=64), nullable=False),
        sa.Column("latest_report_hash", sa.String(length=64), nullable=False),
        sa.Column("latest_projection_commitment", sa.String(length=64), nullable=False),
        sa.Column("history_count", sa.BigInteger(), nullable=False),
        sa.Column("history_accumulator", sa.String(length=64), nullable=False),
        sa.Column("latest_wiring_kind", sa.String(length=16), nullable=True),
        sa.Column("latest_wiring_sequence", sa.BigInteger(), nullable=True),
        sa.Column("latest_wiring_report_id", sa.String(length=64), nullable=True),
        sa.Column("latest_wiring_report_hash", sa.String(length=64), nullable=True),
        sa.Column("latest_wiring_projection_commitment", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "last_sequence >= 1 AND last_sequence <= 9007199254740991",
            name="ck_runtime_report_heads_sequence_positive",
        ),
        sa.CheckConstraint(
            "history_count = last_sequence",
            name="ck_runtime_report_heads_history_count",
        ),
        sa.CheckConstraint(
            "latest_wiring_sequence IS NULL OR "
            "(latest_wiring_sequence >= 1 AND latest_wiring_sequence <= 9007199254740991)",
            name="ck_runtime_report_heads_wiring_sequence_bounds",
        ),
        sa.CheckConstraint(
            "latest_wiring_sequence IS NULL OR latest_wiring_sequence <= last_sequence",
            name="ck_runtime_report_heads_wiring_sequence_order",
        ),
        sa.CheckConstraint(
            "(latest_wiring_report_id IS NULL AND latest_wiring_kind IS NULL "
            "AND latest_wiring_sequence IS NULL AND latest_wiring_report_hash IS NULL "
            "AND latest_wiring_projection_commitment IS NULL) OR "
            "(latest_wiring_report_id IS NOT NULL AND latest_wiring_kind = 'wiring' "
            "AND latest_wiring_sequence IS NOT NULL AND latest_wiring_report_hash IS NOT NULL "
            "AND latest_wiring_projection_commitment IS NOT NULL)",
            name="ck_runtime_report_heads_wiring_tuple",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            name="fk_runtime_report_heads_organization",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "identity_id"],
            [
                "runtime_identities.org_id",
                "runtime_identities.project_id",
                "runtime_identities.environment_id",
                "runtime_identities.id",
            ],
            name="fk_runtime_report_heads_identity_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            [
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "last_sequence",
                "latest_report_id",
            ],
            [
                "runtime_reports.org_id",
                "runtime_reports.project_id",
                "runtime_reports.environment_id",
                "runtime_reports.identity_id",
                "runtime_reports.sequence",
                "runtime_reports.id",
            ],
            name="fk_runtime_report_heads_latest_report",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            [
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "latest_wiring_kind",
                "latest_wiring_sequence",
                "latest_wiring_report_id",
            ],
            [
                "runtime_reports.org_id",
                "runtime_reports.project_id",
                "runtime_reports.environment_id",
                "runtime_reports.identity_id",
                "runtime_reports.kind",
                "runtime_reports.sequence",
                "runtime_reports.id",
            ],
            name="fk_runtime_report_heads_latest_wiring_report",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("identity_id"),
    )
    op.create_index("ix_runtime_report_heads_org_id", "runtime_report_heads", ["org_id"])
    op.create_table(
        "runtime_wiring_challenge_consumptions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("credential_id", sa.String(length=64), nullable=False),
        sa.Column("credential_generation", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("expected_sequence", sa.BigInteger(), nullable=False),
        sa.Column("report_kind", sa.String(length=16), nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("challenge_nonce", sa.String(length=128), nullable=False),
        sa.Column("namespace_digest", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("projection_commitment", sa.String(length=64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("report_kind = 'wiring'", name="ck_runtime_wiring_challenge_kind"),
        sa.CheckConstraint(
            "sequence >= 1 AND sequence <= 9007199254740991",
            name="ck_runtime_wiring_challenge_sequence_bounds",
        ),
        sa.CheckConstraint(
            "expected_sequence >= 1 AND expected_sequence <= 9007199254740991",
            name="ck_runtime_wiring_challenge_expected_sequence_bounds",
        ),
        sa.CheckConstraint(
            "expected_sequence = sequence",
            name="ck_runtime_wiring_challenge_expected_sequence_binding",
        ),
        sa.ForeignKeyConstraint(
            [
                "org_id",
                "project_id",
                "environment_id",
                "identity_id",
                "report_kind",
                "sequence",
                "report_id",
            ],
            [
                "runtime_reports.org_id",
                "runtime_reports.project_id",
                "runtime_reports.environment_id",
                "runtime_reports.identity_id",
                "runtime_reports.kind",
                "runtime_reports.sequence",
                "runtime_reports.id",
            ],
            name="fk_runtime_wiring_challenge_report_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_runtime_wiring_challenge_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "challenge_nonce",
            name="uq_runtime_wiring_challenge_identity_nonce",
        ),
        sa.UniqueConstraint("report_id", name="uq_runtime_wiring_challenge_report"),
    )
    op.create_index(
        "ix_runtime_wiring_challenge_consumptions_org_id",
        "runtime_wiring_challenge_consumptions",
        ["org_id"],
    )
    op.create_table(
        "runtime_wiring_attestations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("gate_id", sa.String(length=64), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("report_kind", sa.String(length=16), nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("attestation_hash", sa.String(length=64), nullable=False),
        sa.Column("assurance_class", sa.String(length=64), nullable=False),
        sa.Column("evidence_kind", sa.String(length=64), nullable=False),
        sa.Column("suite_id", sa.String(length=128), nullable=False),
        sa.Column("suite_hash", sa.String(length=64), nullable=False),
        sa.Column("artifact", JSONVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "assurance_class = 'observed'",
            name="ck_runtime_wiring_attestations_assurance",
        ),
        sa.CheckConstraint(
            "evidence_kind = 'in_process_public_surface_conformance'",
            name="ck_runtime_wiring_attestations_evidence_kind",
        ),
        sa.CheckConstraint(
            "report_kind = 'wiring'",
            name="ck_runtime_wiring_attestations_report_kind",
        ),
        sa.ForeignKeyConstraint(
            [
                "org_id",
                "project_id",
                "environment_id",
                "gate_id",
                "identity_id",
                "report_kind",
                "report_id",
            ],
            [
                "runtime_reports.org_id",
                "runtime_reports.project_id",
                "runtime_reports.environment_id",
                "runtime_reports.gate_id",
                "runtime_reports.identity_id",
                "runtime_reports.kind",
                "runtime_reports.id",
            ],
            name="fk_runtime_wiring_attestations_report_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "attestation_hash", name="uq_runtime_wiring_attestations_attestation_hash"
        ),
        sa.UniqueConstraint("report_id", name="uq_runtime_wiring_attestations_report"),
    )
    op.create_index(
        "ix_runtime_wiring_attestations_scope_identity",
        "runtime_wiring_attestations",
        ["org_id", "project_id", "environment_id", "identity_id"],
    )
    _create_runtime_report_lineage_triggers()


def downgrade() -> None:
    """Fail closed instead of deleting runtime report provenance."""

    raise NotImplementedError(
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back runtime reports."
    )


def _create_runtime_report_lineage_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for statement in POSTGRES_RUNTIME_LINEAGE_FUNCTIONS.values():
            op.execute(statement)
        for statement in POSTGRES_RUNTIME_LINEAGE_TRIGGERS.values():
            op.execute(statement)
    elif dialect == "sqlite":
        for statement in SQLITE_RUNTIME_LINEAGE_OBJECTS.values():
            op.execute(statement)
