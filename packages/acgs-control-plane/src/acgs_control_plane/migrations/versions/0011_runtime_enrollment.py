"""Add hosted runtime enrollment identity state.

Revision 0011 adds the control-plane tables used for governed runtime
bootstrap issuance, proof-of-possession enrollment, signed renewal, and
governed revocation.
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

JSONVariant = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def _timestamps() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "runtime_identity_gates",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name="ck_runtime_identity_gate_status"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_runtime_identity_gates_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id", "project_id", "environment_id", name="uq_runtime_identity_gate_scope"
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "id",
            name="uq_runtime_identity_gate_scope_id",
        ),
    )
    op.create_index("ix_runtime_identity_gates_org_id", "runtime_identity_gates", ["org_id"])

    op.create_table(
        "runtime_identities",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("gate_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("actor", sa.String(length=240), nullable=False),
        sa.Column("workload_key_id", sa.String(length=128), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("public_key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("descriptor", JSONVariant, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("current_generation", sa.Integer(), nullable=False),
        *_timestamps(),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_runtime_identities_status"),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_runtime_identities_environment",
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
            name="fk_runtime_identities_gate_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id", "project_id", "environment_id", "id", name="uq_runtime_identities_scope_id"
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "name",
            name="uq_runtime_identities_scope_name",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "public_key_thumbprint",
            name="uq_runtime_identities_scope_thumbprint",
        ),
    )
    op.create_index("ix_runtime_identities_org_id", "runtime_identities", ["org_id"])

    op.create_table(
        "runtime_enrollment_bootstraps",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("gate_id", sa.String(length=64), nullable=False),
        sa.Column("bootstrap_digest", sa.String(length=64), nullable=False),
        sa.Column("bootstrap_locator", sa.String(length=64), nullable=False),
        sa.Column("pepper_key_id", sa.String(length=128), nullable=False),
        sa.Column("server_challenge", sa.String(length=256), nullable=False),
        sa.Column("runtime_identity_id", sa.String(length=64), nullable=False),
        sa.Column("audience", sa.String(length=128), nullable=False),
        sa.Column("workload_key_id", sa.String(length=128), nullable=False),
        sa.Column("public_key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_by_actor", sa.String(length=200), nullable=False),
        sa.Column("consumed_by_identity_id", sa.String(length=64), nullable=True),
        sa.Column("policy_head_generation", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'consumed', 'revoked', 'expired')",
            name="ck_runtime_enrollment_bootstrap_status",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_runtime_enrollment_bootstraps_environment",
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
            name="fk_runtime_enrollment_bootstraps_gate_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "consumed_by_identity_id"],
            [
                "runtime_identities.org_id",
                "runtime_identities.project_id",
                "runtime_identities.environment_id",
                "runtime_identities.id",
            ],
            name="fk_runtime_enrollment_bootstraps_consumed_identity_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("bootstrap_digest", name="uq_runtime_enrollment_bootstrap_digest"),
        sa.UniqueConstraint("bootstrap_locator", name="uq_runtime_enrollment_bootstrap_locator"),
    )
    op.create_index(
        "ix_runtime_enrollment_bootstraps_org_id", "runtime_enrollment_bootstraps", ["org_id"]
    )
    op.create_index(
        "uq_runtime_enrollment_active_bootstrap_scope",
        "runtime_enrollment_bootstraps",
        ["org_id", "project_id", "environment_id", "gate_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "runtime_credential_generations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("workload_key_id", sa.String(length=128), nullable=False),
        sa.Column("public_key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("descriptor", JSONVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'superseded', 'revoked', 'expired')",
            name="ck_runtime_credential_generation_status",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "identity_id"],
            [
                "runtime_identities.org_id",
                "runtime_identities.project_id",
                "runtime_identities.environment_id",
                "runtime_identities.id",
            ],
            name="fk_runtime_credential_generations_identity_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "generation",
            name="uq_runtime_credential_generation",
        ),
    )
    op.create_index(
        "ix_runtime_credential_generations_org_id", "runtime_credential_generations", ["org_id"]
    )
    op.create_index(
        "uq_runtime_credential_active_identity",
        "runtime_credential_generations",
        ["org_id", "project_id", "environment_id", "identity_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "runtime_enrollment_idempotency",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("response", JSONVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "identity_id"],
            [
                "runtime_identities.org_id",
                "runtime_identities.project_id",
                "runtime_identities.environment_id",
                "runtime_identities.id",
            ],
            name="fk_runtime_enrollment_idempotency_identity_scope",
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
            name="fk_runtime_enrollment_idempotency_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "idempotency_key_hash",
            name="uq_runtime_enrollment_idempotency_scope_key",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            name="uq_runtime_enrollment_idempotency_identity",
        ),
    )
    op.create_index(
        "ix_runtime_enrollment_idempotency_org_id", "runtime_enrollment_idempotency", ["org_id"]
    )

    op.create_table(
        "runtime_request_nonces",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=True),
        sa.Column("response", JSONVariant, nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "identity_id"],
            [
                "runtime_identities.org_id",
                "runtime_identities.project_id",
                "runtime_identities.environment_id",
                "runtime_identities.id",
            ],
            name="fk_runtime_request_nonces_identity_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "nonce",
            name="uq_runtime_request_nonce_identity",
        ),
    )
    op.create_index("ix_runtime_request_nonces_org_id", "runtime_request_nonces", ["org_id"])

    op.create_table(
        "runtime_operation_idempotency",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("identity_id", sa.String(length=64), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("response", JSONVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["organizations.id"], deferrable=True, initially="DEFERRED"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "receipt_id"],
            [
                "managed_decision_receipts.org_id",
                "managed_decision_receipts.project_id",
                "managed_decision_receipts.environment_id",
                "managed_decision_receipts.receipt_id",
            ],
            name="fk_runtime_operation_idempotency_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "identity_id",
            "operation",
            "idempotency_key_hash",
            name="uq_runtime_operation_idempotency_scope_operation_key",
        ),
    )
    op.create_index(
        "ix_runtime_operation_idempotency_org_id", "runtime_operation_idempotency", ["org_id"]
    )


def downgrade() -> None:
    """Fail closed instead of deleting runtime identity provenance."""

    raise NotImplementedError(
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back runtime enrollment."
    )
