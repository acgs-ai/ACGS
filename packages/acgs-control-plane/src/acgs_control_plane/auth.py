"""API-key authentication.

Keys are opaque bearer secrets (``acp_<token>``) presented in ``X-API-Key``.
Only the SHA-256 of the key is stored; a lost key is unrecoverable and must
be rotated. Principal resolution is tenant-scoped by construction — the key
row carries the org.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.models import User
from acgs_control_plane.rbac import Role

API_KEY_HEADER = "X-API-Key"
BOOTSTRAP_HEADER = "X-Bootstrap-Token"


@dataclass(frozen=True)
class Principal:
    user_id: str
    org_id: str
    name: str
    role: Role
    api_key_hash: str | None = None

    @property
    def actor_id(self) -> str:
        # Colon-delimited, injective: user ids are hex (no colons).
        return f"user:{self.user_id}"


def generate_api_key() -> tuple[str, str]:
    """Return ``(raw_key, sha256_hex)``. The raw key is shown exactly once."""
    raw = "acp_" + secrets.token_urlsafe(32)
    return raw, hash_api_key(raw)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def resolve_principal(session: Session, raw_key: str) -> Principal | None:
    key_hash = hash_api_key(raw_key)
    user = session.execute(
        select(User).where(User.api_key_hash == key_hash, User.active.is_(True))
    ).scalar_one_or_none()
    if user is None:
        return None
    try:
        role = Role(user.role)
    except ValueError:
        # Unknown role in storage: fail closed, treat as unauthenticated.
        return None
    return Principal(
        user_id=user.id,
        org_id=user.org_id,
        name=user.name,
        role=role,
        api_key_hash=key_hash,
    )
