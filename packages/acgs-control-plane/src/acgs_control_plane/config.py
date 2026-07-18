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
    """Explicit runtime safety posture; it is never inferred."""

    LOCAL_DEV_LEGACY_UNSIGNED = "local-dev-legacy-unsigned"
    PRODUCTION = "production"


class RuntimePostureConfigurationError(RuntimeError):
    """Stable pre-persistence refusal for an unknown environment posture."""

    code = "PRODUCTION_POSTURE_BLOCKED"
    stage = "pre-persistence"

    def __init__(self) -> None:
        super().__init__(
            json.dumps(
                {
                    "code": self.code,
                    "stage": self.stage,
                    "blockers": [
                        {"code": "RUNTIME_POSTURE_UNKNOWN", "component": "runtime-posture"}
                    ],
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
    create_tables: bool = True
    runtime_posture: RuntimePosture | None = None

    @classmethod
    def from_env(cls) -> Settings:
        raw_posture = os.environ.get("ACP_RUNTIME_POSTURE")
        if raw_posture is None:
            posture = None
        elif raw_posture == "local-dev-legacy-unsigned":
            posture = RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED
        elif raw_posture == "production":
            posture = RuntimePosture.PRODUCTION
        else:
            # Parse with fixed literals rather than constructing the enum from
            # untrusted environment text.  Enum conversion includes the raw
            # value in ValueError, which can escape through exception chaining.
            raise RuntimePostureConfigurationError()
        return cls(
            database_url=os.environ.get("ACP_DATABASE_URL", DEFAULT_DATABASE_URL),
            audit_dir=Path(os.environ.get("ACP_AUDIT_DIR", "./acp-audit")),
            bootstrap_token=os.environ.get("ACP_BOOTSTRAP_TOKEN") or None,
            create_tables=os.environ.get("ACP_CREATE_TABLES", "1") == "1",
            runtime_posture=posture,
        )
