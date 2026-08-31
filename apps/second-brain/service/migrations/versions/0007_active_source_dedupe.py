"""Scope source dedupe uniqueness to live rows.

Revision ID: 0007_active_source_dedupe
Revises: 0006_answer_adequacy
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007_active_source_dedupe"
down_revision: str | None = "0006_answer_adequacy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE public.sources
            DROP CONSTRAINT sources_owner_id_workspace_id_normalized_dedup_sha256_key,
            DROP CONSTRAINT sources_owner_id_workspace_id_idempotency_key_key;

        CREATE UNIQUE INDEX sources_active_normalized_dedup_sha256
            ON public.sources (owner_id, workspace_id, normalized_dedup_sha256)
            WHERE deleted_at IS NULL;

        CREATE UNIQUE INDEX sources_active_idempotency_key
            ON public.sources (owner_id, workspace_id, idempotency_key)
            WHERE deleted_at IS NULL AND idempotency_key IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX public.sources_active_idempotency_key;
        DROP INDEX public.sources_active_normalized_dedup_sha256;

        ALTER TABLE public.sources
            ADD CONSTRAINT sources_owner_id_workspace_id_normalized_dedup_sha256_key
                UNIQUE (owner_id, workspace_id, normalized_dedup_sha256),
            ADD CONSTRAINT sources_owner_id_workspace_id_idempotency_key_key
                UNIQUE (owner_id, workspace_id, idempotency_key);
        """
    )
