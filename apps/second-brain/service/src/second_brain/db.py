from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.config import Settings, WorkerSettings


class RuntimeRoleAttestationError(RuntimeError):
    """Raised when the API is not connected through the restricted runtime role."""


def create_database_engine(settings: Settings) -> Engine:
    return create_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        hide_parameters=True,
    )


def create_worker_content_engine(settings: WorkerSettings) -> Engine:
    return create_engine(
        settings.content_database_url.get_secret_value(),
        pool_pre_ping=True,
        hide_parameters=True,
    )


def create_worker_dispatcher_engine(settings: WorkerSettings) -> Engine:
    return create_engine(
        settings.dispatcher_database_url.get_secret_value(),
        pool_pre_ping=True,
        hide_parameters=True,
    )


def attest_runtime_role(engine: Engine) -> None:
    with engine.connect() as connection:
        role = connection.execute(
            text(
                "SELECT current_user, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one_or_none()
    if role is None:
        raise RuntimeRoleAttestationError("runtime database role could not be attested")
    username, is_superuser, bypasses_rls, creates_db, creates_role = role
    if username != "second_brain_app" or any(
        (is_superuser, bypasses_rls, creates_db, creates_role)
    ):
        raise RuntimeRoleAttestationError(
            "runtime database role must be restricted second_brain_app"
        )


def attest_worker_role(engine: Engine) -> None:
    with engine.connect() as connection:
        role = connection.execute(
            text(
                "SELECT current_user, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one_or_none()
    if role is None:
        raise RuntimeRoleAttestationError("worker database role could not be attested")
    username, is_superuser, bypasses_rls, creates_db, creates_role = role
    if username != "second_brain_worker" or any(
        (is_superuser, bypasses_rls, creates_db, creates_role)
    ):
        raise RuntimeRoleAttestationError(
            "worker database role must be restricted second_brain_worker"
        )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def scoped_session(
    session_factory: sessionmaker[Session], owner_id: UUID, workspace_id: UUID
) -> Iterator[Session]:
    with session_factory.begin() as session:
        session.execute(
            text("SELECT set_config('app.owner_id', :owner_id, true)"),
            {"owner_id": str(owner_id)},
        )
        session.execute(
            text("SELECT set_config('app.workspace_id', :workspace_id, true)"),
            {"workspace_id": str(workspace_id)},
        )
        yield session
