"""
Authentication API routes.
"""

from datetime import datetime
from backend.utils.timeutil import utcnow
import os
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.dependencies import (
    create_access_token,
    get_current_user,
    verify_password,
)
from backend.database import get_db
from backend.models.user import User


router = APIRouter()


class LoginRequest(BaseModel):
    """Login payload expected by the current frontend."""

    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """JWT response with public user data."""

    access_token: str
    token_type: str = "bearer"
    user: dict


def _public_user(user: User) -> dict:
    return {
        "id": str(user.id),
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "team": user.team,
        "permissions": user.permissions or [],
        "is_active": user.is_active,
    }


def _dev_bootstrap_user(username: str, password: str) -> dict | None:
    if os.getenv("ACGS_BOOTSTRAP_DEV_AUTH") != "1":
        return None

    expected_email = os.getenv("ACGS_DEV_USER_EMAIL", "admin@example.com")
    expected_password = os.getenv("ACGS_DEV_USER_PASSWORD")
    if not expected_password:
        return None

    if username != expected_email or password != expected_password:
        return None

    return {
        "id": os.getenv("ACGS_DEV_USER_ID", "00000000-0000-0000-0000-000000000001"),
        "name": os.getenv("ACGS_DEV_USER_NAME", "Development Admin"),
        "email": expected_email,
        "role": os.getenv("ACGS_DEV_USER_ROLE", "admin"),
        "team": None,
        "permissions": [],
        "is_active": True,
    }


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and return a bearer token."""
    bootstrap_user = _dev_bootstrap_user(payload.username, payload.password)
    if bootstrap_user:
        token = create_access_token(
            {
                "sub": bootstrap_user["id"],
                "email": bootstrap_user["email"],
                "name": bootstrap_user["name"],
                "role": bootstrap_user["role"],
                "bootstrap": True,
            }
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": bootstrap_user,
        }

    result = await db.execute(select(User).where(User.email == payload.username))
    user = result.scalar_one_or_none()

    if user:
        if not user.is_active or not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not verify_password(payload.password, user.password_hash):
            user.failed_login_count = (user.failed_login_count or 0) + 1
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user.failed_login_count = 0
        user.last_login_at = utcnow()
        public_user = _public_user(user)
        token = create_access_token(
            {
                "sub": str(user.id),
                "email": user.email,
                "name": user.name,
                "role": user.role,
            }
        )
        return {"access_token": token, "token_type": "bearer", "user": public_user}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    """Return the current authenticated user."""
    return current_user
