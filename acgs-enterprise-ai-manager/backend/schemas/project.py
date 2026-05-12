"""
Project Pydantic Schemas
Request/response validation schemas for Project CRUD operations
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime, date
from uuid import UUID
from decimal import Decimal


class ProjectBase(BaseModel):
    """Base project schema with common fields."""

    name: str = Field(..., min_length=1, max_length=255, description="Project name")
    description: Optional[str] = Field(None, description="Project description")
    status: str = Field(
        default="planning",
        pattern="^(planning|active|on_hold|completed|cancelled)$",
        description="Project status",
    )
    start_date: Optional[date] = Field(None, description="Project start date")
    end_date: Optional[date] = Field(None, description="Project end date")
    budget: Optional[Decimal] = Field(None, ge=0, description="Project budget")
    actual_cost: Optional[Decimal] = Field(
        None, ge=0, description="Actual cost incurred"
    )
    team: List[Dict[str, Any]] = Field(default_factory=list, description="Team members")
    owner_id: Optional[UUID] = Field(None, description="Project owner user ID")


class ProjectCreate(ProjectBase):
    """Schema for creating a new project."""

    pass


class ProjectUpdate(BaseModel):
    """Schema for updating a project (all fields optional)."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(
        None, pattern="^(planning|active|on_hold|completed|cancelled)$"
    )
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    budget: Optional[Decimal] = Field(None, ge=0)
    actual_cost: Optional[Decimal] = Field(None, ge=0)
    team: Optional[List[Dict[str, Any]]] = None
    owner_id: Optional[UUID] = None


class ProjectResponse(ProjectBase):
    """Schema for project response."""

    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectFilter(BaseModel):
    """Schema for project filtering parameters."""

    status: Optional[str] = Field(
        None, pattern="^(planning|active|on_hold|completed|cancelled)$"
    )
    owner_id: Optional[UUID] = None
    search: Optional[str] = Field(None, description="Search in name and description")
    start_after: Optional[date] = Field(None, description="Start date after")
    end_before: Optional[date] = Field(None, description="End date before")


class PaginatedProjectResponse(BaseModel):
    """Schema for paginated project list response."""

    items: List[ProjectResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
