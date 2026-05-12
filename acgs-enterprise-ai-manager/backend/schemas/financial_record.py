"""
Financial Record Pydantic Schemas
Request/response validation schemas for Financial Record CRUD operations
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from datetime import date as DateType
from uuid import UUID
from decimal import Decimal


class FinancialRecordBase(BaseModel):
    """Base financial record schema with common fields."""

    type: str = Field(
        ...,
        pattern="^(expense|revenue|budget_allocation|invoice|payment)$",
        description="Financial record type",
    )
    amount: Decimal = Field(..., description="Transaction amount")
    currency: str = Field(
        default="USD", min_length=3, max_length=3, description="Currency code"
    )
    date: DateType = Field(..., description="Transaction date")
    category: str = Field(
        ..., min_length=1, max_length=100, description="Financial category"
    )
    project_id: Optional[UUID] = Field(None, description="Associated project ID")
    approval_status: str = Field(
        default="pending",
        pattern="^(pending|approved|rejected)$",
        description="Approval status",
    )
    approved_by: Optional[UUID] = Field(None, description="Approver user ID")
    description: Optional[str] = Field(None, description="Transaction description")
    additional_data: Optional[Dict[str, Any]] = Field(
        None, description="Additional metadata"
    )


class FinancialRecordCreate(FinancialRecordBase):
    """Schema for creating a new financial record."""

    pass


class FinancialRecordUpdate(BaseModel):
    """Schema for updating a financial record (all fields optional)."""

    type: Optional[str] = Field(
        None, pattern="^(expense|revenue|budget_allocation|invoice|payment)$"
    )
    amount: Optional[Decimal] = None
    currency: Optional[str] = Field(None, min_length=3, max_length=3)
    date: Optional[DateType] = None
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    project_id: Optional[UUID] = None
    approval_status: Optional[str] = Field(
        None, pattern="^(pending|approved|rejected)$"
    )
    approved_by: Optional[UUID] = None
    description: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


class FinancialRecordResponse(FinancialRecordBase):
    """Schema for financial record response."""

    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FinancialRecordFilter(BaseModel):
    """Schema for financial record filtering parameters."""

    type: Optional[str] = Field(
        None, pattern="^(expense|revenue|budget_allocation|invoice|payment)$"
    )
    approval_status: Optional[str] = Field(
        None, pattern="^(pending|approved|rejected)$"
    )
    project_id: Optional[UUID] = None
    category: Optional[str] = None
    date_from: Optional[DateType] = Field(None, description="Date from")
    date_to: Optional[DateType] = Field(None, description="Date to")
    min_amount: Optional[Decimal] = Field(None, ge=0, description="Minimum amount")
    max_amount: Optional[Decimal] = Field(None, ge=0, description="Maximum amount")


class PaginatedFinancialRecordResponse(BaseModel):
    """Schema for paginated financial record list response."""

    items: List[FinancialRecordResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
