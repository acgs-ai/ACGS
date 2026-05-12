"""
IT Asset Schemas
Pydantic schemas for IT Asset request/response validation
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime, date
from uuid import UUID
from decimal import Decimal


# Base schemas
class ITAssetBase(BaseModel):
    """Base IT asset schema with common fields."""

    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(
        ...,
        pattern="^(server|workstation|laptop|network_device|storage|software_license|other)$",
    )
    status: str = Field(
        default="active", pattern="^(active|maintenance|retired|disposed)$"
    )
    location: Optional[str] = Field(None, max_length=255)
    owner_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    purchase_date: Optional[date] = None
    purchase_cost: Optional[Decimal] = Field(None, ge=0, le=9999999999.99)
    lifecycle_stage: Optional[str] = Field(
        None, pattern="^(new|operational|aging|end_of_life)$"
    )
    warranty_expiry: Optional[date] = None
    specifications: Optional[dict] = Field(default_factory=dict)


class ITAssetCreate(ITAssetBase):
    """Schema for creating a new IT asset."""

    pass


class ITAssetUpdate(BaseModel):
    """Schema for updating an IT asset (all fields optional)."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[str] = Field(
        None,
        pattern="^(server|workstation|laptop|network_device|storage|software_license|other)$",
    )
    status: Optional[str] = Field(
        None, pattern="^(active|maintenance|retired|disposed)$"
    )
    location: Optional[str] = Field(None, max_length=255)
    owner_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    purchase_date: Optional[date] = None
    purchase_cost: Optional[Decimal] = Field(None, ge=0, le=9999999999.99)
    lifecycle_stage: Optional[str] = Field(
        None, pattern="^(new|operational|aging|end_of_life)$"
    )
    warranty_expiry: Optional[date] = None
    specifications: Optional[dict] = None


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


class TaskSummary(BaseModel):
    """Summary of task for nested responses."""

    id: UUID
    title: str
    status: str
    priority: str

    model_config = ConfigDict(from_attributes=True)


class ITAssetResponse(ITAssetBase):
    """Schema for IT asset response with all fields."""

    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ITAssetDetailResponse(ITAssetResponse):
    """Schema for detailed IT asset response with related entities."""

    owner: Optional[UserSummary] = None
    project: Optional[ProjectSummary] = None
    tasks: List[TaskSummary] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ITAssetFilter(BaseModel):
    """Schema for filtering IT assets."""

    type: Optional[str] = Field(
        None,
        pattern="^(server|workstation|laptop|network_device|storage|software_license|other)$",
    )
    status: Optional[str] = Field(
        None, pattern="^(active|maintenance|retired|disposed)$"
    )
    lifecycle_stage: Optional[str] = Field(
        None, pattern="^(new|operational|aging|end_of_life)$"
    )
    owner_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    location: Optional[str] = Field(None, max_length=255)
    search: Optional[str] = Field(None, max_length=255)


class PaginatedITAssetResponse(BaseModel):
    """Schema for paginated IT asset list response."""

    items: List[ITAssetResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

    model_config = ConfigDict(from_attributes=True)
