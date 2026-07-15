"""Runtime settings for the control plane.

Environment-driven, no config-framework dependency. Production deployments
point ``ACP_DATABASE_URL`` at PostgreSQL; tests inject a SQLite URL through
:func:`acgs_control_plane.app.create_app` directly.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

DEFAULT_DATABASE_URL = "postgresql+psycopg://acgs:acgs@localhost:5432/acgs_control_plane"


class RuntimePosture(StrEnum):
    """Explicit startup posture; production is never inferred from a URL."""

    LOCAL_DEV_LEGACY_UNSIGNED = "local-dev-legacy-unsigned"
    PRODUCTION = "production"


class RuntimePostureConfigurationError(RuntimeError):
    """Stable refusal raised before persistence construction."""

    code = "STARTUP_CONFIGURATION_BLOCKED"
    stage = "pre-persistence"

    def __init__(self, blocker: str) -> None:
        self.blocker = blocker
        super().__init__(
            json.dumps(
                {
                    "blocker": blocker,
                    "code": self.code,
                    "stage": self.stage,
                },
                sort_keys=True,
            )
        )


@dataclass(frozen=True)
class PostureBlocker:
    """One structured reason production cannot construct persistence."""

    code: str
    component: str
    route: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {"code": self.code, "component": self.component}
        if self.route is not None:
            payload["route"] = self.route
        return payload


class ProductionPostureBlocked(RuntimeError):
    """Fail-closed production refusal raised before engine construction."""

    code = "PRODUCTION_POSTURE_BLOCKED"
    stage = "pre-persistence"

    def __init__(self, blockers: tuple[PostureBlocker, ...]) -> None:
        if not blockers:
            raise ValueError("production posture refusal requires at least one blocker")
        self.blockers = blockers
        super().__init__(
            json.dumps(
                {
                    "blockers": [blocker.to_dict() for blocker in blockers],
                    "code": self.code,
                    "stage": self.stage,
                },
                sort_keys=True,
            )
        )


@dataclass(frozen=True)
class Settings:
    """Immutable process configuration.

    ``bootstrap_token`` gates organization creation (the only endpoint that
    exists before any tenant does). ``None`` means org creation is disabled —
    fail closed, never open.
    """

    database_url: str = DEFAULT_DATABASE_URL
    audit_dir: Path = Path("./acp-audit")
    bootstrap_token: str | None = None
    create_tables: bool = False
    runtime_posture: RuntimePosture | None = None

    @classmethod
    def from_env(cls) -> Settings:
        raw_posture = os.environ.get("ACP_RUNTIME_POSTURE")
        try:
            runtime_posture = RuntimePosture(raw_posture) if raw_posture is not None else None
        except ValueError as exc:
            raise RuntimePostureConfigurationError("RUNTIME_POSTURE_UNKNOWN") from exc
        return cls(
            database_url=os.environ.get("ACP_DATABASE_URL", DEFAULT_DATABASE_URL),
            audit_dir=Path(os.environ.get("ACP_AUDIT_DIR", "./acp-audit")),
            bootstrap_token=os.environ.get("ACP_BOOTSTRAP_TOKEN") or None,
            create_tables=os.environ.get("ACP_CREATE_TABLES", "0") == "1",
            runtime_posture=runtime_posture,
        )
