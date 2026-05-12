"""
Infrastructure Pydantic Schemas
Request/response validation schemas for Infrastructure CRUD operations
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID


class InfrastructureBase(BaseModel):
    """Base infrastructure schema with common fields."""

    name: str = Field(
        ..., min_length=1, max_length=255, description="Infrastructure name"
    )
    type: str = Field(
        ...,
        pattern="^(compute|network|storage|database|security|monitoring)$",
        description="Infrastructure type",
    )
    status: str = Field(
        default="operational",
        pattern="^(operational|degraded|down|maintenance)$",
        description="Infrastructure status",
    )
    capacity: Optional[Dict[str, Any]] = Field(None, description="Capacity metrics")
    location: Optional[str] = Field(
        None, max_length=255, description="Physical/logical location"
    )
    dependencies: List[str] = Field(
        default_factory=list, description="Dependency identifiers"
    )
    configuration: Optional[Dict[str, Any]] = Field(
        None, description="Configuration details"
    )


class InfrastructureCreate(InfrastructureBase):
    """Schema for creating new infrastructure."""

    pass


class InfrastructureUpdate(BaseModel):
    """Schema for updating infrastructure (all fields optional)."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[str] = Field(
        None, pattern="^(compute|network|storage|database|security|monitoring)$"
    )
    status: Optional[str] = Field(
        None, pattern="^(operational|degraded|down|maintenance)$"
    )
    capacity: Optional[Dict[str, Any]] = None
    location: Optional[str] = Field(None, max_length=255)
    dependencies: Optional[List[str]] = None
    configuration: Optional[Dict[str, Any]] = None


class InfrastructureResponse(InfrastructureBase):
    """Schema for infrastructure response."""

    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InfrastructureFilter(BaseModel):
    """Schema for infrastructure filtering parameters."""

    type: Optional[str] = Field(
        None, pattern="^(compute|network|storage|database|security|monitoring)$"
    )
    status: Optional[str] = Field(
        None, pattern="^(operational|degraded|down|maintenance)$"
    )
    location: Optional[str] = None
    search: Optional[str] = Field(None, description="Search in name and configuration")


class PaginatedInfrastructureResponse(BaseModel):
    """Schema for paginated infrastructure list response."""

    items: List[InfrastructureResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
