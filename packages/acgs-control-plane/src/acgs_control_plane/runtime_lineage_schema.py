"""Canonical database objects enforcing append-only runtime report lineage."""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

SQLITE_RUNTIME_LINEAGE_OBJECTS_0012: Final = MappingProxyType(
    {
        "runtime_reports_immutable_update": """
            CREATE TRIGGER runtime_reports_immutable_update
            BEFORE UPDATE ON runtime_reports
            BEGIN
                SELECT RAISE(ABORT, 'runtime_reports are immutable');
            END;
        """,
        "runtime_reports_immutable_delete": """
            CREATE TRIGGER runtime_reports_immutable_delete
            BEFORE DELETE ON runtime_reports
            BEGIN
                SELECT RAISE(ABORT, 'runtime_reports are immutable');
            END;
        """,
        "runtime_wiring_attestations_immutable_update": """
            CREATE TRIGGER runtime_wiring_attestations_immutable_update
            BEFORE UPDATE ON runtime_wiring_attestations
            BEGIN
                SELECT RAISE(ABORT, 'runtime_wiring_attestations are immutable');
            END;
        """,
        "runtime_wiring_attestations_immutable_delete": """
            CREATE TRIGGER runtime_wiring_attestations_immutable_delete
            BEFORE DELETE ON runtime_wiring_attestations
            BEGIN
                SELECT RAISE(ABORT, 'runtime_wiring_attestations are immutable');
            END;
        """,
        "runtime_report_heads_monotonic_update": """
            CREATE TRIGGER runtime_report_heads_monotonic_update
            BEFORE UPDATE ON runtime_report_heads
            WHEN NEW.identity_id IS NOT OLD.identity_id
              OR NEW.org_id IS NOT OLD.org_id
              OR NEW.project_id IS NOT OLD.project_id
              OR NEW.environment_id IS NOT OLD.environment_id
              OR NEW.last_sequence < OLD.last_sequence
              OR NEW.history_count <> NEW.last_sequence
              OR NEW.history_count < OLD.history_count
              OR (NEW.history_count = OLD.history_count
                  AND NEW.history_accumulator IS NOT OLD.history_accumulator)
              OR (NEW.last_sequence = OLD.last_sequence AND (
                  NEW.latest_report_id IS NOT OLD.latest_report_id
                  OR NEW.latest_report_hash IS NOT OLD.latest_report_hash
                  OR NEW.latest_projection_commitment IS NOT OLD.latest_projection_commitment
              ))
              OR (OLD.latest_wiring_sequence IS NOT NULL
                  AND NEW.latest_wiring_sequence IS NULL)
              OR NEW.latest_wiring_sequence < OLD.latest_wiring_sequence
              OR (NEW.latest_wiring_sequence = OLD.latest_wiring_sequence AND (
                  NEW.latest_wiring_kind IS NOT OLD.latest_wiring_kind
                  OR NEW.latest_wiring_report_id IS NOT OLD.latest_wiring_report_id
                  OR NEW.latest_wiring_report_hash IS NOT OLD.latest_wiring_report_hash
                  OR NEW.latest_wiring_projection_commitment
                     IS NOT OLD.latest_wiring_projection_commitment
              ))
            BEGIN
                SELECT RAISE(ABORT, 'runtime_report_heads must be non-decreasing');
            END;
        """,
        "runtime_report_heads_monotonic_delete": """
            CREATE TRIGGER runtime_report_heads_monotonic_delete
            BEFORE DELETE ON runtime_report_heads
            BEGIN
                SELECT RAISE(ABORT, 'runtime_report_heads cannot be deleted');
            END;
        """,
    }
)

SQLITE_RUNTIME_LINEAGE_OBJECTS_0013_DELTA: Final = MappingProxyType(
    {
        "runtime_wiring_challenge_consumptions_immutable_update": """
            CREATE TRIGGER runtime_wiring_challenge_consumptions_immutable_update
            BEFORE UPDATE ON runtime_wiring_challenge_consumptions
            BEGIN
                SELECT RAISE(ABORT, 'runtime_wiring_challenge_consumptions are immutable');
            END;
        """,
        "runtime_wiring_challenge_consumptions_immutable_delete": """
            CREATE TRIGGER runtime_wiring_challenge_consumptions_immutable_delete
            BEFORE DELETE ON runtime_wiring_challenge_consumptions
            BEGIN
                SELECT RAISE(ABORT, 'runtime_wiring_challenge_consumptions are immutable');
            END;
        """,
    }
)

SQLITE_RUNTIME_LINEAGE_OBJECTS: Final = MappingProxyType(
    {**SQLITE_RUNTIME_LINEAGE_OBJECTS_0012, **SQLITE_RUNTIME_LINEAGE_OBJECTS_0013_DELTA}
)

POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0012: Final = MappingProxyType(
    {
        "acgs_runtime_reports_immutable": """
            CREATE OR REPLACE FUNCTION acgs_runtime_reports_immutable()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'runtime_reports are immutable';
            END;
            $$;
        """,
        "acgs_runtime_wiring_attestations_immutable": """
            CREATE OR REPLACE FUNCTION acgs_runtime_wiring_attestations_immutable()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'runtime_wiring_attestations are immutable';
            END;
            $$;
        """,
        "acgs_runtime_report_heads_monotonic": """
            CREATE OR REPLACE FUNCTION acgs_runtime_report_heads_monotonic()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'runtime_report_heads cannot be deleted';
                END IF;
                IF NEW.identity_id IS DISTINCT FROM OLD.identity_id
                   OR NEW.org_id IS DISTINCT FROM OLD.org_id
                   OR NEW.project_id IS DISTINCT FROM OLD.project_id
                   OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
                   OR NEW.last_sequence < OLD.last_sequence
                   OR NEW.history_count <> NEW.last_sequence
                   OR NEW.history_count < OLD.history_count
                   OR (NEW.history_count = OLD.history_count
                       AND NEW.history_accumulator IS DISTINCT FROM OLD.history_accumulator)
                   OR (NEW.last_sequence = OLD.last_sequence AND (
                       NEW.latest_report_id IS DISTINCT FROM OLD.latest_report_id
                       OR NEW.latest_report_hash IS DISTINCT FROM OLD.latest_report_hash
                       OR NEW.latest_projection_commitment
                          IS DISTINCT FROM OLD.latest_projection_commitment
                   ))
                   OR (OLD.latest_wiring_sequence IS NOT NULL
                       AND NEW.latest_wiring_sequence IS NULL)
                   OR NEW.latest_wiring_sequence < OLD.latest_wiring_sequence
                   OR (NEW.latest_wiring_sequence = OLD.latest_wiring_sequence AND (
                       NEW.latest_wiring_kind IS DISTINCT FROM OLD.latest_wiring_kind
                       OR NEW.latest_wiring_report_id IS DISTINCT FROM OLD.latest_wiring_report_id
                       OR NEW.latest_wiring_report_hash
                          IS DISTINCT FROM OLD.latest_wiring_report_hash
                       OR NEW.latest_wiring_projection_commitment
                          IS DISTINCT FROM OLD.latest_wiring_projection_commitment
                   )) THEN
                    RAISE EXCEPTION 'runtime_report_heads must be non-decreasing';
                END IF;
                RETURN NEW;
            END;
            $$;
        """,
    }
)

POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0013_DELTA: Final = MappingProxyType(
    {
        "acgs_runtime_wiring_challenge_consumptions_immutable": """
            CREATE OR REPLACE FUNCTION acgs_runtime_wiring_challenge_consumptions_immutable()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'runtime_wiring_challenge_consumptions are immutable';
            END;
            $$;
        """,
    }
)

POSTGRES_RUNTIME_LINEAGE_FUNCTIONS: Final = MappingProxyType(
    {
        **POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0012,
        **POSTGRES_RUNTIME_LINEAGE_FUNCTIONS_0013_DELTA,
    }
)

POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0012: Final = MappingProxyType(
    {
        "runtime_reports_immutable_update": """
            CREATE TRIGGER runtime_reports_immutable_update
            BEFORE UPDATE ON runtime_reports
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_reports_immutable();
        """,
        "runtime_reports_immutable_delete": """
            CREATE TRIGGER runtime_reports_immutable_delete
            BEFORE DELETE ON runtime_reports
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_reports_immutable();
        """,
        "runtime_wiring_attestations_immutable_update": """
            CREATE TRIGGER runtime_wiring_attestations_immutable_update
            BEFORE UPDATE ON runtime_wiring_attestations
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_wiring_attestations_immutable();
        """,
        "runtime_wiring_attestations_immutable_delete": """
            CREATE TRIGGER runtime_wiring_attestations_immutable_delete
            BEFORE DELETE ON runtime_wiring_attestations
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_wiring_attestations_immutable();
        """,
        "runtime_report_heads_monotonic_update": """
            CREATE TRIGGER runtime_report_heads_monotonic_update
            BEFORE UPDATE ON runtime_report_heads
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_report_heads_monotonic();
        """,
        "runtime_report_heads_monotonic_delete": """
            CREATE TRIGGER runtime_report_heads_monotonic_delete
            BEFORE DELETE ON runtime_report_heads
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_report_heads_monotonic();
        """,
    }
)

POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0013_DELTA: Final = MappingProxyType(
    {
        "runtime_wiring_challenge_consumptions_immutable_update": """
            CREATE TRIGGER runtime_wiring_challenge_consumptions_immutable_update
            BEFORE UPDATE ON runtime_wiring_challenge_consumptions
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_wiring_challenge_consumptions_immutable();
        """,
        "runtime_wiring_challenge_consumptions_immutable_delete": """
            CREATE TRIGGER runtime_wiring_challenge_consumptions_immutable_delete
            BEFORE DELETE ON runtime_wiring_challenge_consumptions
            FOR EACH ROW EXECUTE FUNCTION acgs_runtime_wiring_challenge_consumptions_immutable();
        """,
        "runtime_wiring_challenge_consumptions_immutable_truncate": """
            CREATE TRIGGER runtime_wiring_challenge_consumptions_immutable_truncate
            BEFORE TRUNCATE ON runtime_wiring_challenge_consumptions
            FOR EACH STATEMENT
            EXECUTE FUNCTION acgs_runtime_wiring_challenge_consumptions_immutable();
        """,
    }
)

POSTGRES_RUNTIME_LINEAGE_TRIGGERS: Final = MappingProxyType(
    {**POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0012, **POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0013_DELTA}
)

POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES_0012: Final = MappingProxyType(
    {name: "O" for name in POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0012}
)
POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES_0013_DELTA: Final = MappingProxyType(
    {name: "O" for name in POSTGRES_RUNTIME_LINEAGE_TRIGGERS_0013_DELTA}
)
POSTGRES_RUNTIME_LINEAGE_TRIGGER_ENABLED_STATES: Final = MappingProxyType(
    {name: "O" for name in POSTGRES_RUNTIME_LINEAGE_TRIGGERS}
)
