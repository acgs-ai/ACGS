"""Add calibrated semantic-only answer adequacy threshold.

Revision ID: 0006_answer_adequacy
Revises: 0005_organization_today_policy
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006_answer_adequacy"
down_revision: str | None = "0005_organization_today_policy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE public.embedding_profiles
            ADD COLUMN answer_min_similarity double precision,
            ADD CONSTRAINT embedding_profiles_answer_min_similarity_bounded CHECK (
                answer_min_similarity IS NULL
                OR answer_min_similarity BETWEEN -1.0 AND 1.0
            );

        COMMENT ON COLUMN public.embedding_profiles.answer_min_similarity IS
            'Calibrated semantic-only answer threshold; NULL fails closed.';

        CREATE TRIGGER embedding_profiles_threshold_immutable
            BEFORE UPDATE OF answer_min_similarity ON public.embedding_profiles
            FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation();
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TRIGGER embedding_profiles_threshold_immutable
            ON public.embedding_profiles;
        ALTER TABLE public.embedding_profiles
            DROP CONSTRAINT embedding_profiles_answer_min_similarity_bounded,
            DROP COLUMN answer_min_similarity;
        """
    )
