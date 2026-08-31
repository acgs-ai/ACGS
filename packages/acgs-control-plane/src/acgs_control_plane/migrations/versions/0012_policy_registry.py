"""Add environment-scoped immutable managed policy registry.

Revision ``0012`` is additive. Legacy org-scoped ``policy_bundles`` remain
historical/local compatibility data; this migration does not infer
project/environment scope from those rows.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

JSONVariant = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("policy_id", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("document", JSONVariant, nullable=False),
        sa.Column("rules", JSONVariant, nullable=False),
        sa.Column("canonical_envelope", JSONVariant, nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=200), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=32), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("trust_epoch", sa.Integer(), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("purpose = 'acgs.policy-envelope/v1'", name="ck_pv_purpose"),
        sa.CheckConstraint("signature_algorithm = 'ed25519'", name="ck_pv_signature_algorithm"),
        sa.CheckConstraint("trust_epoch > 0", name="ck_pv_trust_epoch_positive"),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_policy_versions_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "project_id", "environment_id", "id", name="uq_pv_scope_id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "policy_id",
            "version",
            name="uq_pv_scope_policy_version",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "content_hash",
            name="uq_pv_scope_content_hash",
        ),
    )
    op.create_index("ix_policy_versions_org_id", "policy_versions", ["org_id"])
    _create_policy_versions_immutability_trigger()

    op.create_table(
        "environment_policy_heads",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("active_policy_version_id", sa.String(length=64), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("generation >= 0", name="ck_eph_generation_nonnegative"),
        sa.CheckConstraint("status IN ('active')", name="ck_eph_status"),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_environment_policy_heads_environment",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "active_policy_version_id"],
            [
                "policy_versions.org_id",
                "policy_versions.project_id",
                "policy_versions.environment_id",
                "policy_versions.id",
            ],
            name="fk_environment_policy_heads_active_version",
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
            name="fk_environment_policy_heads_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id", "project_id", "environment_id", name="uq_environment_policy_heads_scope"
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "generation",
            name="uq_environment_policy_heads_scope_generation",
        ),
    )
    op.create_index("ix_environment_policy_heads_org_id", "environment_policy_heads", ["org_id"])
    _create_environment_policy_heads_monotonic_trigger()

    op.create_table(
        "policy_registry_idempotency",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("actor_hash", sa.String(length=64), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=200), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("response", JSONVariant, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["organizations.id"],
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id"],
            ["environments.org_id", "environments.project_id", "environments.id"],
            name="fk_policy_registry_idempotency_environment",
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
            name="fk_policy_registry_idempotency_receipt_scope",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key_hash", name="uq_policy_registry_idempotency_key_hash"),
    )
    op.create_index(
        "ix_policy_registry_idempotency_org_id", "policy_registry_idempotency", ["org_id"]
    )


def downgrade() -> None:
    """Fail closed instead of deleting policy registry evidence."""

    raise NotImplementedError(
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back policy registry evidence."
    )


def _create_policy_versions_immutability_trigger() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION acgs_policy_versions_immutable()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'policy_versions are immutable';
            END;
            $$;
            """
        )
        op.execute(
            """
            CREATE TRIGGER policy_versions_immutable_update
            BEFORE UPDATE ON policy_versions
            FOR EACH ROW
            EXECUTE FUNCTION acgs_policy_versions_immutable();
            """
        )
        op.execute(
            """
            CREATE TRIGGER policy_versions_immutable_delete
            BEFORE DELETE ON policy_versions
            FOR EACH ROW
            EXECUTE FUNCTION acgs_policy_versions_immutable();
            """
        )
    elif dialect == "sqlite":
        op.execute(
            """
            CREATE TRIGGER policy_versions_immutable_update
            BEFORE UPDATE ON policy_versions
            BEGIN
                SELECT RAISE(ABORT, 'policy_versions are immutable');
            END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER policy_versions_immutable_delete
            BEFORE DELETE ON policy_versions
            BEGIN
                SELECT RAISE(ABORT, 'policy_versions are immutable');
            END;
            """
        )


def _drop_policy_versions_immutability_trigger() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS policy_versions_immutable_delete ON policy_versions")
        op.execute("DROP TRIGGER IF EXISTS policy_versions_immutable_update ON policy_versions")
        op.execute("DROP FUNCTION IF EXISTS acgs_policy_versions_immutable()")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS policy_versions_immutable_delete")
        op.execute("DROP TRIGGER IF EXISTS policy_versions_immutable_update")


def _create_environment_policy_heads_monotonic_trigger() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION acgs_environment_policy_heads_monotonic()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF NEW.org_id <> OLD.org_id
                   OR NEW.project_id <> OLD.project_id
                   OR NEW.environment_id <> OLD.environment_id
                   OR NEW.generation <> OLD.generation + 1 THEN
                    RAISE EXCEPTION 'environment_policy_heads must advance monotonically';
                END IF;
                RETURN NEW;
            END;
            $$;
            """
        )
        op.execute(
            """
            CREATE TRIGGER environment_policy_heads_monotonic_update
            BEFORE UPDATE ON environment_policy_heads
            FOR EACH ROW
            EXECUTE FUNCTION acgs_environment_policy_heads_monotonic();
            """
        )
    elif dialect == "sqlite":
        op.execute(
            """
            CREATE TRIGGER environment_policy_heads_monotonic_update
            BEFORE UPDATE ON environment_policy_heads
            WHEN NEW.org_id <> OLD.org_id
              OR NEW.project_id <> OLD.project_id
              OR NEW.environment_id <> OLD.environment_id
              OR NEW.generation <> OLD.generation + 1
            BEGIN
                SELECT RAISE(ABORT, 'environment_policy_heads must advance monotonically');
            END;
            """
        )
