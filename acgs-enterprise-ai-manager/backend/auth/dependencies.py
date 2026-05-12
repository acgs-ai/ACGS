"""
Authentication and Authorization Module
Basic JWT-based authentication with role-based access control
"""

from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from typing import Optional
from uuid import UUID
import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import os

from backend.database import get_db
from backend.models.user import User

# Security configuration
#
# SECRET_KEY must be set in the environment. The previous module-level default
# of "your-secret-key-change-in-production" silently let production deployments
# sign JWTs with a publicly-known string, which is a token-forgery bypass.
#
# Local development that genuinely needs the placeholder (smoke tests, demo
# scripts) must opt in with ACGS_BOOTSTRAP_DEV_AUTH=1; that same env var
# already gates the bootstrap-token path in get_current_user below, so the
# two relax together.
_PLACEHOLDER_SECRET_KEY = "your-secret-key-change-in-production"
_DEV_MODE_ENV = "ACGS_BOOTSTRAP_DEV_AUTH"


def _load_secret_key() -> str:
    secret = os.getenv("SECRET_KEY")
    dev_mode = os.getenv(_DEV_MODE_ENV) == "1"

    if not secret:
        if dev_mode:
            return _PLACEHOLDER_SECRET_KEY
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. Set a strong random "
            f"value, or set {_DEV_MODE_ENV}=1 to allow the development "
            "placeholder."
        )

    if secret == _PLACEHOLDER_SECRET_KEY and not dev_mode:
        raise RuntimeError(
            "SECRET_KEY is set to the public placeholder "
            f"'{_PLACEHOLDER_SECRET_KEY}'. Replace it with a strong random "
            f"value, or set {_DEV_MODE_ENV}=1 to allow it for local dev only."
        )

    return secret


SECRET_KEY = _load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)


# Password hashing — direct bcrypt calls rather than passlib's CryptContext.
# passlib has been unmaintained since 2020 and transitively imports the
# stdlib `crypt` module which Python 3.13 removes; calling bcrypt directly
# produces the same `$2b$…` hash format, so existing stored password hashes
# verify unchanged.
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except ValueError:
        # bcrypt.checkpw raises ValueError on malformed hashes; treat as a
        # mismatch rather than propagating, matching passlib's behavior.
        return False


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload data to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        expire = utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Dependency to get the current authenticated user from JWT token.

    Usage:
        @app.get("/protected")
        async def protected_route(user: dict = Depends(get_current_user)):
            return {"user": user}
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    # Dev bootstrap tokens are accepted only when explicitly enabled.
    if os.getenv("ACGS_BOOTSTRAP_DEV_AUTH") == "1" and payload.get("bootstrap") is True:
        return {
            "id": user_id,
            "email": payload.get("email"),
            "name": payload.get("name", "Development User"),
            "role": payload.get("role", "admin"),
            "team": None,
            "permissions": [],
        }

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user:
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user",
            )
        return {
            "id": str(user.id),
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "team": user.team,
            "permissions": user.permissions or [],
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="User not found",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(required_role: str):
    """
    Dependency factory to require a specific role.

    Usage:
        @app.get("/admin")
        async def admin_route(user: dict = Depends(require_role("admin"))):
            return {"message": "Admin access granted"}
    """

    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "user")

        # Role hierarchy: admin > manager > user > viewer
        role_hierarchy = {"admin": 3, "manager": 2, "user": 1, "viewer": 0}

        if role_hierarchy.get(user_role, 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}",
            )

        return user

    return role_checker
