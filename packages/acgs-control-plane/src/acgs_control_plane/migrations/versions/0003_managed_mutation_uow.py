"""Add managed SQL mutation ledger and outbox foundation.

Revision ``0003`` is additive. It does not rewrite legacy receipts, expose
routes, deliver outbox rows, or infer project/environment provenance for old
organization-scoped evidence.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _scope_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["org_id", "project_id", "environment_id"],
        ["environments.org_id", "environments.project_id", "environments.id"],
        name=name,
    )


def _receipt_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["org_id", "project_id", "environment_id", "managed_receipt_id"],
        [
            "managed_decision_receipts.org_id",
            "managed_decision_receipts.project_id",
            "managed_decision_receipts.environment_id",
            "managed_decision_receipts.id",
        ],
        name=name,
    )


def upgrade() -> None:
    with op.batch_alter_table("environments") as batch_op:
        batch_op.create_unique_constraint(
            "uq_environments_org_project_id",
            ["org_id", "project_id", "id"],
        )

    op.create_table(
        "managed_decision_receipts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_id", sa.String(length=200), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("proposed_action", sa.String(length=200), nullable=False),
        sa.Column("execution_boundary", sa.String(length=200), nullable=False),
        sa.Column("policy_bundle_id", sa.String(length=200), nullable=False),
        sa.Column("policy_version", sa.String(length=200), nullable=False),
        sa.Column("policy_hash", sa.String(length=128), nullable=False),
        sa.Column("argument_hash", sa.String(length=128), nullable=False),
        sa.Column("signing_key_id", sa.String(length=200), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=32), nullable=False),
        sa.Column("assurance_class", sa.String(length=32), nullable=False),
        sa.Column("source_system", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("projection", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_receipts_scope_environment"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("assurance_class = 'native'", name="ck_mdr_assurance_native"),
        sa.CheckConstraint("source_system = 'gove-zone'", name="ck_mdr_source_gove_zone"),
        sa.UniqueConstraint("org_id", "project_id", "environment_id", "id", name="uq_mdr_scope_id"),
        sa.UniqueConstraint(
            "org_id", "project_id", "environment_id", "receipt_id", name="uq_mdr_scope_receipt_id"
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "receipt_hash",
            name="uq_mdr_scope_receipt_hash",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "audit_event_hash",
            name="uq_mdr_scope_audit_event_hash",
        ),
        sa.UniqueConstraint("org_id", "receipt_hash", name="uq_mdr_org_receipt_hash"),
        sa.UniqueConstraint("org_id", "audit_event_hash", name="uq_mdr_org_audit_event_hash"),
    )
    op.create_index("ix_managed_decision_receipts_org_id", "managed_decision_receipts", ["org_id"])

    op.create_table(
        "managed_mutation_attempts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=200), nullable=False),
        sa.Column("actor_hash", sa.String(length=64), nullable=False),
        sa.Column("argument_hash", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failure_class_hash", sa.String(length=64), nullable=True),
        sa.Column("failure_digest", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_attempts_scope_environment"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "status IN ('in_progress', 'succeeded', 'failed')",
            name="ck_mma_terminal_status",
        ),
        sa.UniqueConstraint("org_id", "receipt_hash", name="uq_mma_org_receipt_hash"),
        sa.UniqueConstraint("org_id", "audit_event_hash", name="uq_mma_org_audit_event_hash"),
    )
    op.create_index("ix_managed_mutation_attempts_org_id", "managed_mutation_attempts", ["org_id"])

    op.create_table(
        "managed_receipt_consumptions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("managed_receipt_id", sa.String(length=64), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False),
        sa.Column("audit_event_hash", sa.String(length=64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_consumptions_scope_environment"),
        _receipt_fk("fk_managed_consumptions_scope_receipt"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "managed_receipt_id",
            name="uq_mrc_scope_receipt",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "receipt_hash",
            name="uq_mrc_scope_receipt_hash",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "audit_event_hash",
            name="uq_mrc_scope_audit_event_hash",
        ),
        sa.UniqueConstraint("org_id", "receipt_hash", name="uq_mrc_org_receipt_hash"),
        sa.UniqueConstraint("org_id", "audit_event_hash", name="uq_mrc_org_audit_event_hash"),
    )
    op.create_index(
        "ix_managed_receipt_consumptions_org_id",
        "managed_receipt_consumptions",
        ["org_id"],
    )

    op.create_table(
        "managed_governance_event_heads",
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("last_event_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_event_heads_scope_environment"),
        sa.PrimaryKeyConstraint("org_id", "project_id", "environment_id"),
    )

    op.create_table(
        "managed_governance_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("managed_receipt_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("proposed_action", sa.String(length=200), nullable=False),
        sa.Column("policy_version", sa.String(length=200), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("payload", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_events_scope_environment"),
        _receipt_fk("fk_managed_events_scope_receipt"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "project_id", "environment_id", "id", name="uq_mge_scope_id"),
        sa.UniqueConstraint(
            "org_id", "project_id", "environment_id", "sequence", name="uq_mge_scope_sequence"
        ),
        sa.UniqueConstraint(
            "org_id", "project_id", "environment_id", "event_hash", name="uq_mge_scope_event_hash"
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "managed_receipt_id",
            name="uq_mge_scope_receipt",
        ),
    )
    op.create_index("ix_managed_governance_events_org_id", "managed_governance_events", ["org_id"])

    op.create_table(
        "managed_outbox",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("environment_id", sa.String(length=64), nullable=False),
        sa.Column("managed_receipt_id", sa.String(length=64), nullable=False),
        sa.Column("managed_event_id", sa.String(length=64), nullable=False),
        sa.Column("delivery_key", sa.String(length=200), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("payload", _JSON, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        _scope_fk("fk_managed_outbox_scope_environment"),
        _receipt_fk("fk_managed_outbox_scope_receipt"),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "environment_id", "managed_event_id"],
            [
                "managed_governance_events.org_id",
                "managed_governance_events.project_id",
                "managed_governance_events.environment_id",
                "managed_governance_events.id",
            ],
            name="fk_managed_outbox_scope_event",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "delivery_key",
            name="uq_managed_outbox_scope_delivery_key",
        ),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "environment_id",
            "payload_digest",
            name="uq_managed_outbox_scope_payload_digest",
        ),
    )
    op.create_index("ix_managed_outbox_org_id", "managed_outbox", ["org_id"])


def downgrade() -> None:
    """Fail closed instead of deleting receipt, consumption, event, or outbox evidence."""
    msg = (
        "The control-plane migration history is forward-only; "
        "restore a verified backup to roll back."
    )
    raise NotImplementedError(msg)
