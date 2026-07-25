"""Opt-in PostgreSQL evidence for the local disposable recovery drill.

Both URLs must identify the exact dedicated databases named below. Nothing is
inferred from an application URL, and the public schemas are reset only after
the explicit destructive-test acknowledgement.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa

from acgs_control_plane.db import make_engine
from acgs_control_plane.migration_recovery import (
    RecoveryRefused,
    _pg_environment,
    _run_command,
    create_recovery_bundle,
    restore_recovery_bundle,
    verify_recovery_bundle,
)
from acgs_control_plane.migrations import (
    _POSTGRES_MIGRATION_LOCK_CLASS_ID,
    _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
    DatabaseSchemaState,
    inspect_schema,
    upgrade_database,
)

SOURCE_DATABASE = "acgs_control_plane_recovery_source_test"
TARGET_DATABASE = "acgs_control_plane_recovery_target_test"
SOURCE_ENV = "ACP_TEST_RECOVERY_SOURCE_URL"
TARGET_ENV = "ACP_TEST_RECOVERY_TARGET_URL"

SOURCE_URL = os.environ.get(SOURCE_ENV)
TARGET_URL = os.environ.get(TARGET_ENV)
if not SOURCE_URL or not TARGET_URL:
    pytest.skip(
        f"set both {SOURCE_ENV} and {TARGET_ENV} to run PostgreSQL recovery tests",
        allow_module_level=True,
    )
if os.environ.get("ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE") != "1":
    raise RuntimeError(
        "Set ACP_TEST_POSTGRES_ALLOW_DESTRUCTIVE=1 to acknowledge that these tests "
        "reset two exactly named disposable PostgreSQL public schemas."
    )

pytest.importorskip("psycopg")


def _required_tool_path(name: str) -> Path:
    resolved = shutil.which(name)
    if resolved is None:
        pytest.skip(f"{name} is required to run PostgreSQL recovery integration tests")
    selected = Path(resolved)
    if not selected.is_absolute():
        selected = Path.cwd() / selected
    try:
        selected.stat()
    except OSError:
        pytest.skip(f"{name} resolved to an unavailable PostgreSQL client path: {selected}")
    return selected


PG_DUMP_PATH = _required_tool_path("pg_dump")
PG_RESTORE_PATH = _required_tool_path("pg_restore")
PSQL_PATH = _required_tool_path("psql")


def _validated_url(raw: str, expected_database: str, variable: str) -> str:
    url = sa.engine.make_url(raw)
    if url.get_backend_name() != "postgresql" or url.database != expected_database:
        raise RuntimeError(
            f"{variable} must use PostgreSQL and name exactly {expected_database!r}."
        )
    return raw


SOURCE_URL = _validated_url(SOURCE_URL, SOURCE_DATABASE, SOURCE_ENV)
TARGET_URL = _validated_url(TARGET_URL, TARGET_DATABASE, TARGET_ENV)


def _safe_admin_url(url: str) -> str:
    return (
        sa.engine.make_url(url)
        .update_query_dict({"options": "-csearch_path=pg_catalog,public"})
        .render_as_string(hide_password=False)
    )


def _alter_role_search_path(
    connection: sa.Connection, url: str, expected_database: str, clause: str
) -> None:
    username = sa.engine.make_url(url).username
    assert username is not None
    quote = connection.dialect.identifier_preparer.quote_identifier
    connection.exec_driver_sql(
        f"ALTER ROLE {quote(username)} IN DATABASE {quote(expected_database)} {clause}"
    )


def _reset(url: str, expected_database: str) -> None:
    engine = make_engine(_safe_admin_url(url))
    try:
        with engine.begin() as connection:
            current = connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
            if current != expected_database:
                raise RuntimeError("refusing to reset a database whose runtime name changed")
            _alter_role_search_path(connection, url, expected_database, "RESET search_path")
            connection.execute(sa.text("DROP SCHEMA IF EXISTS shadow CASCADE"))
            connection.execute(sa.text("DROP SCHEMA public CASCADE"))
            connection.execute(sa.text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _isolated_databases() -> Iterator[None]:
    _reset(SOURCE_URL, SOURCE_DATABASE)
    _reset(TARGET_URL, TARGET_DATABASE)
    try:
        yield
    finally:
        _reset(SOURCE_URL, SOURCE_DATABASE)
        _reset(TARGET_URL, TARGET_DATABASE)


def _seed_source() -> None:
    upgrade_database(SOURCE_URL)
    engine = make_engine(SOURCE_URL)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    """
                    INSERT INTO organizations (
                        id, name, created_at, audit_anchor_count, audit_anchor_hash
                    ) VALUES ('org-recovery', 'Recovery Drill', now(), 0, '')
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO projects (id, org_id, slug, name, created_at)
                    VALUES ('project-recovery', 'org-recovery', 'core', 'Core', now())
                    """
                )
            )
            connection.execute(
                sa.text(
                    """
                    INSERT INTO environments (
                        id, org_id, project_id, slug, name, created_at
                    ) VALUES (
                        'environment-recovery', 'org-recovery', 'project-recovery',
                        'local', 'Local', now()
                    )
                    """
                )
            )
    finally:
        engine.dispose()


def _install_shadow_hijacks(
    url: str,
    expected_database: str,
    *,
    create_public_marker: bool = False,
    public_first: bool = False,
) -> None:
    function_schema = "public" if public_first else "shadow"
    role_search_path = "public, pg_catalog" if public_first else "shadow, pg_catalog"
    engine = make_engine(_safe_admin_url(url))
    try:
        with engine.begin() as connection:
            assert (
                connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
                == expected_database
            )
            connection.execute(sa.text("CREATE SCHEMA shadow"))
            connection.execute(sa.text("CREATE TABLE shadow.sentinel (id INTEGER PRIMARY KEY)"))
            connection.execute(sa.text("INSERT INTO shadow.sentinel (id) VALUES (11)"))
            if create_public_marker:
                connection.execute(
                    sa.text("CREATE TABLE public.nonempty_marker (id INTEGER PRIMARY KEY)")
                )
                connection.execute(sa.text("INSERT INTO public.nonempty_marker (id) VALUES (17)"))
            connection.execute(
                sa.text(
                    f"""
                    CREATE FUNCTION {function_schema}.current_database()
                    RETURNS name LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 12 WHERE id = 11;
                        RETURN 'hijacked';
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    f"""
                    CREATE FUNCTION {function_schema}.current_schema()
                    RETURNS name LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 13 WHERE id = 11;
                        RETURN 'shadow';
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    f"""
                    CREATE FUNCTION {function_schema}.current_setting(setting_name text)
                    RETURNS text LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 14 WHERE id = 11;
                        RETURN setting_name;
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    f"""
                    CREATE FUNCTION {function_schema}.pg_export_snapshot()
                    RETURNS text LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 15 WHERE id = 11;
                        RETURN 'hijacked-snapshot';
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    f"""
                    CREATE FUNCTION {function_schema}.pg_try_advisory_lock(integer, integer)
                    RETURNS boolean LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 16 WHERE id = 11;
                        RETURN true;
                    END
                    $function$
                    """
                )
            )
            connection.execute(
                sa.text(
                    f"""
                    CREATE FUNCTION {function_schema}.pg_advisory_unlock(integer, integer)
                    RETURNS boolean LANGUAGE plpgsql AS $function$
                    BEGIN
                        UPDATE shadow.sentinel SET id = 18 WHERE id = 11;
                        RETURN true;
                    END
                    $function$
                    """
                )
            )
            _alter_role_search_path(
                connection,
                url,
                expected_database,
                f"SET search_path TO {role_search_path}",
            )
    finally:
        engine.dispose()


def _assert_shadow_and_public_unchanged(
    url: str, expected_database: str, *, public_marker: bool
) -> None:
    engine = make_engine(_safe_admin_url(url))
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT pg_catalog.current_database()"))
                == expected_database
            )
            assert connection.scalar(sa.text("SELECT id FROM shadow.sentinel")) == 11
            public_tables = set(sa.inspect(connection).get_table_names(schema="public"))
            if public_marker:
                assert public_tables == {"nonempty_marker"}
                assert connection.scalar(sa.text("SELECT id FROM public.nonempty_marker")) == 17
            else:
                assert public_tables == set()
    finally:
        engine.dispose()


def _create_valid_bundle(tmp_path: Path) -> Path:
    _seed_source()
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    bundle = tmp_path / "bundle"
    create_recovery_bundle(
        source_url_env=SOURCE_ENV,
        audit_dir=audit_source,
        output=bundle,
        pg_dump_path=PG_DUMP_PATH,
        pg_restore_path=PG_RESTORE_PATH,
    )
    return bundle


def test_source_shadow_default_and_function_hijacks_refuse_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_source()
    _install_shadow_hijacks(SOURCE_URL, SOURCE_DATABASE)
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    calls: list[list[str]] = []

    def forbidden_runner(command: list[str], _environment: dict[str, str]) -> None:
        calls.append(list(command))

    with pytest.raises(RecoveryRefused, match="canonical public schema"):
        create_recovery_bundle(
            source_url_env=SOURCE_ENV,
            audit_dir=audit_source,
            output=tmp_path / "bundle",
            runner=forbidden_runner,
        )

    assert calls == []
    engine = make_engine(_safe_admin_url(SOURCE_URL))
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT count(*) FROM public.organizations")) == 1
            assert connection.scalar(sa.text("SELECT id FROM shadow.sentinel")) == 11
    finally:
        engine.dispose()
    assert not (tmp_path / "bundle").exists()


def test_public_first_function_hijacks_refuse_before_subprocess(
    tmp_path: Path,
) -> None:
    # Revision-unowned functions in the public schema are rejected by the
    # migration head preflight before any client subprocess is spawned, so a
    # public-first hijack cannot be reached by pg_dump at all.
    _seed_source()
    _install_shadow_hijacks(SOURCE_URL, SOURCE_DATABASE, public_first=True)
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    bundle = tmp_path / "bundle"
    calls: list[list[str]] = []

    def forbidden_runner(command: list[str], _environment: dict[str, str]) -> None:
        calls.append(list(command))

    with pytest.raises(RecoveryRefused, match="exact supported migration head schema"):
        create_recovery_bundle(
            source_url_env=SOURCE_ENV,
            audit_dir=audit_source,
            output=bundle,
            pg_dump_path=PG_DUMP_PATH,
            pg_restore_path=PG_RESTORE_PATH,
            runner=forbidden_runner,
        )

    assert calls == []
    assert not bundle.exists()
    engine = make_engine(_safe_admin_url(SOURCE_URL))
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT id FROM shadow.sentinel")) == 11
            assert connection.scalar(sa.text("SELECT count(*) FROM public.organizations")) == 1
    finally:
        engine.dispose()
    assert not (tmp_path / "bundle").exists()


def test_pg_environment_overrides_ambient_pgoptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PGOPTIONS", "-csearch_path=shadow,public")
    url = sa.engine.make_url(
        "postgresql+psycopg://recovery:secret@127.0.0.1:5432/acgs_control_plane_recovery"
    )

    with _pg_environment(url, tmp_path) as environment:
        assert environment["PGOPTIONS"] == "-csearch_path=public"


@pytest.mark.parametrize(
    "public_marker",
    [False, True],
    ids=["shadow-empty", "public-behind-shadow"],
)
def test_target_shadow_default_refuses_before_any_pg_restore_or_mutation(
    public_marker: bool, tmp_path: Path
) -> None:
    bundle = _create_valid_bundle(tmp_path)
    _install_shadow_hijacks(
        TARGET_URL,
        TARGET_DATABASE,
        create_public_marker=public_marker,
    )
    calls: list[list[str]] = []

    def forbidden_runner(command: list[str], _environment: dict[str, str]) -> None:
        calls.append(list(command))

    with pytest.raises(RecoveryRefused, match="canonical public schema"):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env=TARGET_ENV,
            target_database_name=TARGET_DATABASE,
            target_audit_dir=tmp_path / "target-audit",
            acknowledge_operator_controlled_bundle=True,
            runner=forbidden_runner,
        )

    assert calls == []
    _assert_shadow_and_public_unchanged(
        TARGET_URL,
        TARGET_DATABASE,
        public_marker=public_marker,
    )
    assert not (tmp_path / "target-audit").exists()


def test_postgresql_bundle_restore_round_trip_equivalence(tmp_path: Path) -> None:
    _seed_source()
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    bundle = tmp_path / "bundle"

    created = create_recovery_bundle(
        source_url_env=SOURCE_ENV,
        audit_dir=audit_source,
        output=bundle,
        pg_dump_path=PG_DUMP_PATH,
        pg_restore_path=PG_RESTORE_PATH,
    )
    verified = verify_recovery_bundle(bundle=bundle, pg_restore_path=PG_RESTORE_PATH)
    restored = restore_recovery_bundle(
        bundle=bundle,
        target_url_env=TARGET_ENV,
        target_database_name=TARGET_DATABASE,
        target_audit_dir=tmp_path / "target-audit",
        acknowledge_operator_controlled_bundle=True,
        pg_restore_path=PG_RESTORE_PATH,
    )

    assert created == verified == restored
    assert inspect_schema(TARGET_URL).state is DatabaseSchemaState.VERSION_0005
    engine = make_engine(TARGET_URL)
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT count(*) FROM organizations")) == 1
            assert connection.scalar(sa.text("SELECT count(*) FROM projects")) == 1
            assert connection.scalar(sa.text("SELECT count(*) FROM environments")) == 1
    finally:
        engine.dispose()
    assert (tmp_path / "target-audit" / "org-recovery.audit.jsonl").read_bytes() == b""


def test_postgresql_nonempty_target_invokes_no_mutating_restore(tmp_path: Path) -> None:
    _seed_source()
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    bundle = tmp_path / "bundle"
    create_recovery_bundle(
        source_url_env=SOURCE_ENV,
        audit_dir=audit_source,
        output=bundle,
        pg_dump_path=PG_DUMP_PATH,
        pg_restore_path=PG_RESTORE_PATH,
    )
    upgrade_database(TARGET_URL)
    calls: list[list[str]] = []

    def forbidden_runner(command: list[str], _environment: dict[str, str]) -> None:
        calls.append(list(command))
        raise AssertionError("nonempty public target must refuse before pg_restore --list")

    with pytest.raises(RecoveryRefused, match="must have an exact empty"):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env=TARGET_ENV,
            target_database_name=TARGET_DATABASE,
            target_audit_dir=tmp_path / "target-audit",
            acknowledge_operator_controlled_bundle=True,
            runner=forbidden_runner,
        )

    assert calls == []
    assert inspect_schema(TARGET_URL).state is DatabaseSchemaState.VERSION_0005


def test_postgresql_restore_lock_contention_refuses_before_mutating_restore(
    tmp_path: Path,
) -> None:
    _seed_source()
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    bundle = tmp_path / "bundle"
    create_recovery_bundle(
        source_url_env=SOURCE_ENV,
        audit_dir=audit_source,
        output=bundle,
        pg_dump_path=PG_DUMP_PATH,
        pg_restore_path=PG_RESTORE_PATH,
    )
    mutating_commands: list[list[str]] = []

    def recording_runner(command: list[str], environment: dict[str, str]) -> None:
        if "--list" not in command:
            mutating_commands.append(list(command))
        _run_command(command, environment)

    holder_engine = make_engine(TARGET_URL)
    try:
        with holder_engine.connect() as holder:
            # PostgreSQL declares pg_advisory_lock as void. Drivers represent
            # that result differently (for example None or an empty string),
            # so the restore refusal below is the portable acquisition proof.
            holder.execute(
                sa.text("SELECT pg_advisory_lock(:class_id, :object_id)"),
                {
                    "class_id": _POSTGRES_MIGRATION_LOCK_CLASS_ID,
                    "object_id": _POSTGRES_MIGRATION_LOCK_OBJECT_ID,
                },
            )
            holder.commit()
            with pytest.raises(RecoveryRefused, match="lock is held"):
                restore_recovery_bundle(
                    bundle=bundle,
                    target_url_env=TARGET_ENV,
                    target_database_name=TARGET_DATABASE,
                    target_audit_dir=tmp_path / "target-audit",
                    acknowledge_operator_controlled_bundle=True,
                    pg_restore_path=PG_RESTORE_PATH,
                    runner=recording_runner,
                )
    finally:
        holder_engine.dispose()

    assert mutating_commands == []
    assert inspect_schema(TARGET_URL).state is DatabaseSchemaState.EMPTY


def test_postgresql_injected_pg_restore_failure_rolls_back_all_objects(
    tmp_path: Path,
) -> None:
    _seed_source()
    audit_source = tmp_path / "source-audit"
    audit_source.mkdir()
    bundle = tmp_path / "bundle"

    def archive_injection_runner(command: list[str], environment: dict[str, str]) -> None:
        if Path(command[0]).name != "pg_dump":
            _run_command(command, environment)
            return
        assert Path(command[0]) == PG_DUMP_PATH
        # First create the normal source snapshot, then use the dedicated
        # disposable target as an archive-rewrite fixture. This leaves the
        # source's exact supported schema untouched while producing a custom
        # archive whose final organizations COPY deterministically fails.
        _run_command(command, environment)
        archive = Path(
            next(item.removeprefix("--file=") for item in command if item.startswith("--file="))
        )
        target_credentials = tmp_path / "target-pg-credentials"
        target_credentials.mkdir(mode=0o700)
        target_engine = make_engine(TARGET_URL)
        try:
            with _pg_environment(
                sa.engine.make_url(TARGET_URL), target_credentials
            ) as target_environment:
                _run_command(
                    [
                        str(PG_RESTORE_PATH),
                        "--single-transaction",
                        "--exit-on-error",
                        "--no-owner",
                        "--no-acl",
                        "--schema=public",
                        f"--dbname={TARGET_DATABASE}",
                        str(archive),
                    ],
                    target_environment,
                )
            with target_engine.begin() as connection:
                connection.execute(
                    sa.text(
                        """
                        CREATE FUNCTION public.fail_during_pg_restore(value text)
                        RETURNS boolean
                        LANGUAGE plpgsql
                        AS $$
                        BEGIN
                            IF current_setting('application_name')
                               LIKE 'pg_restore%' THEN
                                RAISE EXCEPTION 'injected late pg_restore failure';
                            END IF;
                            RETURN true;
                        END;
                        $$
                        """
                    )
                )
                connection.execute(
                    sa.text(
                        """
                        ALTER TABLE organizations
                        ADD CONSTRAINT injected_late_restore_failure
                        CHECK (public.fail_during_pg_restore(id))
                        """
                    )
                )
            archive.unlink()
            with _pg_environment(
                sa.engine.make_url(TARGET_URL), target_credentials
            ) as target_environment:
                dump_command = [
                    argument for argument in command if not argument.startswith("--snapshot=")
                ]
                _run_command(dump_command, target_environment)
        finally:
            target_engine.dispose()
            _reset(TARGET_URL, TARGET_DATABASE)
            target_credentials.rmdir()

    create_recovery_bundle(
        source_url_env=SOURCE_ENV,
        audit_dir=audit_source,
        output=bundle,
        runner=archive_injection_runner,
        pg_dump_path=PG_DUMP_PATH,
        pg_restore_path=PG_RESTORE_PATH,
    )
    mutating_commands: list[list[str]] = []
    late_failure_output: list[str] = []

    def late_table_data_failure_runner(command: list[str], environment: dict[str, str]) -> None:
        if "--list" in command:
            assert Path(command[0]) == PG_RESTORE_PATH
            _run_command(command, environment)
            return
        mutating_commands.append(list(command))
        assert Path(command[0]) == PG_RESTORE_PATH
        archive = Path(command[-1])
        listed = subprocess.run(
            [str(PG_RESTORE_PATH), "--list", str(archive)],
            env=dict(environment),
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        ).stdout
        table_data = [
            line
            for line in listed.splitlines()
            if " TABLE DATA public organizations " in f"{line} "
        ]
        if len(table_data) != 1:
            raise RecoveryRefused(
                f"expected one organizations TABLE DATA entry, got {len(table_data)}"
            )
        # Make the deliberately failing organizations COPY the final TABLE
        # DATA operation, while leaving post-data constraints after all data.
        # Schema creation and all earlier table data therefore run before the
        # injected check constraint rejects this row.
        ordered_lines = [line for line in listed.splitlines() if line != table_data[0]]
        final_table_data = max(
            index for index, line in enumerate(ordered_lines) if " TABLE DATA " in f"{line} "
        )
        ordered_lines.insert(final_table_data + 1, table_data[0])
        injected_list = archive.with_name("late-table-data-failure.list")
        injected_list.write_text("\n".join([*ordered_lines, ""]), encoding="utf-8")
        failing_command = [
            *command[:-1],
            "--verbose",
            f"--use-list={injected_list}",
            str(archive),
        ]
        result = subprocess.run(
            failing_command,
            env=dict(environment),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        late_failure_output.append(result.stderr)
        if result.returncode == 0:
            raise RecoveryRefused("injected late TABLE DATA failure unexpectedly succeeded")
        raise RecoveryRefused("pg_restore failed during final TABLE DATA entry")

    with pytest.raises(RecoveryRefused, match="pg_restore failed"):
        restore_recovery_bundle(
            bundle=bundle,
            target_url_env=TARGET_ENV,
            target_database_name=TARGET_DATABASE,
            target_audit_dir=tmp_path / "target-audit",
            acknowledge_operator_controlled_bundle=True,
            pg_restore_path=PG_RESTORE_PATH,
            runner=late_table_data_failure_runner,
        )

    assert len(mutating_commands) == 1
    assert "--single-transaction" in mutating_commands[0]
    assert "--exit-on-error" in mutating_commands[0]
    assert len(late_failure_output) == 1
    assert "creating TABLE" in late_failure_output[0]
    assert "processing data for table" in late_failure_output[0]
    assert "injected late pg_restore failure" in late_failure_output[0]
    assert inspect_schema(TARGET_URL).state is DatabaseSchemaState.EMPTY
    target_engine = make_engine(TARGET_URL)
    try:
        with target_engine.connect() as connection:
            assert sa.inspect(connection).get_table_names(schema="public") == []
            public_relations = connection.scalar(
                sa.text(
                    """
                    SELECT count(*)
                    FROM pg_catalog.pg_class AS class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = class.relnamespace
                    WHERE namespace.nspname = 'public'
                    """
                )
            )
            public_functions = connection.scalar(
                sa.text(
                    """
                    SELECT count(*)
                    FROM pg_catalog.pg_proc AS procedure
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = procedure.pronamespace
                    WHERE namespace.nspname = 'public'
                    """
                )
            )
            assert public_relations == 0
            assert public_functions == 0
    finally:
        target_engine.dispose()
    assert not (tmp_path / "target-audit").exists()
