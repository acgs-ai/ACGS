"""
Task Schemas
Pydantic schemas for Task request/response validation
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from decimal import Decimal


# Base schemas
class TaskBase(BaseModel):
    """Base task schema with common fields."""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    status: str = Field(
        default="todo", pattern="^(todo|in_progress|blocked|review|done|cancelled)$"
    )
    priority: str = Field(default="medium", pattern="^(low|medium|high|urgent)$")
    assignee_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    due_date: Optional[datetime] = None
    estimated_hours: Optional[Decimal] = Field(None, ge=0, le=999.99)
    actual_hours: Optional[Decimal] = Field(None, ge=0, le=999.99)
    tags: Optional[List[str]] = Field(default_factory=list)


class TaskCreate(TaskBase):
    """Schema for creating a new task."""

    pass


class TaskUpdate(BaseModel):
    """Schema for updating a task (all fields optional)."""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(
        None, pattern="^(todo|in_progress|blocked|review|done|cancelled)$"
    )
    priority: Optional[str] = Field(None, pattern="^(low|medium|high|urgent)$")
    assignee_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    due_date: Optional[datetime] = None
    estimated_hours: Optional[Decimal] = Field(None, ge=0, le=999.99)
    actual_hours: Optional[Decimal] = Field(None, ge=0, le=999.99)
    tags: Optional[List[str]] = None


# Nested response schemas for related entities
class UserSummary(BaseModel):
    """Summary of user for nested responses."""

    id: UUID
    name: str
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class ProjectSummary(BaseModel):
    """Summary of project for nested responses."""

    id: UUID
    name: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class AssetSummary(BaseModel):
    """Summary of IT asset for nested responses."""

    id: UUID
    name: str
    type: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class InfrastructureSummary(BaseModel):
    """Summary of infrastructure for nested responses."""

    id: UUID
    name: str
    type: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class TaskResponse(TaskBase):
    """Schema for task response with all fields."""

    id: UUID
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TaskDetailResponse(TaskResponse):
    """Schema for detailed task response with related entities."""

    assignee: Optional[UserSummary] = None
    project: Optional[ProjectSummary] = None
    assets: List[AssetSummary] = Field(default_factory=list)
    infrastructure: List[InfrastructureSummary] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class TaskFilter(BaseModel):
    """Schema for filtering tasks."""

    status: Optional[str] = Field(
        None, pattern="^(todo|in_progress|blocked|review|done|cancelled)$"
    )
    priority: Optional[str] = Field(None, pattern="^(low|medium|high|urgent)$")
    assignee_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    search: Optional[str] = Field(None, max_length=255)
    tags: Optional[List[str]] = None
    due_before: Optional[datetime] = None
    due_after: Optional[datetime] = None


class PaginatedTaskResponse(BaseModel):
    """Schema for paginated task list response."""

    items: List[TaskResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

    model_config = ConfigDict(from_attributes=True)


class TaskLinkRequest(BaseModel):
    """Schema for linking tasks to assets/infrastructure."""

    entity_id: UUID
    relationship_type: Optional[str] = Field(
        None, pattern="^(uses|requires|configures|maintains|deploys_to|monitors)$"
    )
