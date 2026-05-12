"""
Pydantic schemas for request/response validation
Placeholder schemas until full domain implementation
"""

from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from uuid import UUID


# User schemas
class UserBase(BaseModel):
    """Base user schema."""

    name: str = Field(..., min_length=1, max_length=255)
    email: EmailStr
    role: str = Field(..., pattern="^(admin|manager|user|viewer)$")
    team: Optional[str] = Field(None, max_length=100)


class UserCreate(UserBase):
    """Schema for creating a new user."""

    password: str = Field(..., min_length=8)


class UserResponse(UserBase):
    """Schema for user response."""

    id: UUID
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Task schemas
class TaskBase(BaseModel):
    """Base task schema."""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    status: str = Field(
        default="todo", pattern="^(todo|in_progress|blocked|review|done|cancelled)$"
    )
    priority: str = Field(default="medium", pattern="^(low|medium|high|urgent)$")


class TaskCreate(TaskBase):
    """Schema for creating a new task."""

    pass


class TaskUpdate(BaseModel):
    """Schema for updating a task."""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(
        None, pattern="^(todo|in_progress|blocked|review|done|cancelled)$"
    )
    priority: Optional[str] = Field(None, pattern="^(low|medium|high|urgent)$")


class TaskResponse(TaskBase):
    """Schema for task response."""

    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Project schemas
class ProjectBase(BaseModel):
    """Base project schema."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    status: str = Field(
        default="planning", pattern="^(planning|active|on_hold|completed|cancelled)$"
    )


class ProjectCreate(ProjectBase):
    """Schema for creating a new project."""

    pass


class ProjectResponse(ProjectBase):
    """Schema for project response."""

    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Authentication schemas
class Token(BaseModel):
    """JWT token response schema."""

    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Token payload data schema."""

    email: Optional[str] = None
    role: Optional[str] = None


class LoginRequest(BaseModel):
    """Login request schema."""

    email: EmailStr
    password: str
