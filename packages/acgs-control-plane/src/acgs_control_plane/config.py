"""Runtime settings for the control plane.

Environment-driven, no config-framework dependency. Production deployments
point ``ACP_DATABASE_URL`` at PostgreSQL; tests inject a SQLite URL through
:func:`acgs_control_plane.app.create_app` directly.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from acgs_control_plane.pagination import (
    CursorConfigurationError,
    CursorKeyring,
    configured_cursor_keyring,
    local_ephemeral_cursor_keyring,
    parse_cursor_clock_skew_seconds,
    parse_cursor_ttl_seconds,
    validate_cursor_clock_skew_seconds,
    validate_cursor_ttl_seconds,
)

DEFAULT_DATABASE_URL = "postgresql+psycopg://acgs:acgs@localhost:5432/acgs_control_plane"
DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024
MIN_MAX_REQUEST_BODY_BYTES = 1
MAX_MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024


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


class RequestBodyLimitConfigurationError(RuntimeError):
    """Stable refusal for an unsafe request-body limit environment value."""

    code = "REQUEST_BODY_LIMIT_CONFIGURATION_INVALID"
    stage = "pre-persistence"

    def __init__(self) -> None:
        super().__init__(
            json.dumps(
                {
                    "code": self.code,
                    "stage": self.stage,
                    "setting": "ACP_MAX_REQUEST_BODY_BYTES",
                    "bounds": {
                        "min": MIN_MAX_REQUEST_BODY_BYTES,
                        "max": MAX_MAX_REQUEST_BODY_BYTES,
                    },
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
    bootstrap_token: str | None = field(default=None, repr=False)
    create_tables: bool = False
    runtime_posture: RuntimePosture | None = None
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    cursor_keyring: CursorKeyring | None = field(default=None, repr=False)
    cursor_ttl_seconds: int = 300
    cursor_clock_skew_seconds: int = 30

    def __post_init__(self) -> None:
        cursor_ttl_seconds = validate_cursor_ttl_seconds(self.cursor_ttl_seconds)
        cursor_clock_skew_seconds = validate_cursor_clock_skew_seconds(
            self.cursor_clock_skew_seconds
        )
        object.__setattr__(
            self,
            "max_request_body_bytes",
            validate_max_request_body_bytes(self.max_request_body_bytes),
        )
        object.__setattr__(self, "cursor_ttl_seconds", cursor_ttl_seconds)
        object.__setattr__(self, "cursor_clock_skew_seconds", cursor_clock_skew_seconds)
        if self.cursor_keyring is None:
            object.__setattr__(
                self,
                "cursor_keyring",
                local_ephemeral_cursor_keyring(cursor_ttl_seconds, cursor_clock_skew_seconds),
            )
        elif not isinstance(self.cursor_keyring, CursorKeyring):
            raise CursorConfigurationError()

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
        cursor_ttl_seconds = parse_cursor_ttl_seconds(os.environ.get("ACP_CURSOR_TTL_SECONDS"))
        cursor_clock_skew_seconds = parse_cursor_clock_skew_seconds(
            os.environ.get("ACP_CURSOR_CLOCK_SKEW_SECONDS")
        )
        cursor_keyring = configured_cursor_keyring(
            key_id=os.environ.get("ACP_CURSOR_KEY_ID") or None,
            key_b64=os.environ.get("ACP_CURSOR_KEY") or None,
            ttl_seconds=cursor_ttl_seconds,
            clock_skew_seconds=cursor_clock_skew_seconds,
        )
        return cls(
            database_url=os.environ.get("ACP_DATABASE_URL", DEFAULT_DATABASE_URL),
            audit_dir=Path(os.environ.get("ACP_AUDIT_DIR", "./acp-audit")),
            bootstrap_token=os.environ.get("ACP_BOOTSTRAP_TOKEN") or None,
            create_tables=os.environ.get("ACP_CREATE_TABLES", "0") == "1",
            runtime_posture=posture,
            max_request_body_bytes=parse_max_request_body_bytes(
                os.environ.get("ACP_MAX_REQUEST_BODY_BYTES")
            ),
            cursor_keyring=cursor_keyring,
            cursor_ttl_seconds=cursor_ttl_seconds,
            cursor_clock_skew_seconds=cursor_clock_skew_seconds,
        )


def parse_max_request_body_bytes(raw: str | None) -> int:
    if raw is None or raw == "":
        return DEFAULT_MAX_REQUEST_BODY_BYTES
    if not raw.isdecimal():
        raise RequestBodyLimitConfigurationError()
    if len(raw) > len(str(MAX_MAX_REQUEST_BODY_BYTES)):
        raise RequestBodyLimitConfigurationError()
    value = int(raw)
    return validate_max_request_body_bytes(value)


def validate_max_request_body_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequestBodyLimitConfigurationError()
    if not (MIN_MAX_REQUEST_BODY_BYTES <= value <= MAX_MAX_REQUEST_BODY_BYTES):
        raise RequestBodyLimitConfigurationError()
    return value
