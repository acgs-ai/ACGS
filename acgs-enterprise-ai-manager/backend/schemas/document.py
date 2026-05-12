"""
Document Pydantic Schemas
Request/response validation schemas for Document CRUD operations
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from uuid import UUID


class DocumentBase(BaseModel):
    """Base document schema with common fields."""

    title: str = Field(..., min_length=1, max_length=255, description="Document title")
    content: Optional[str] = Field(None, description="Document content")
    type: str = Field(
        ...,
        pattern="^(specification|report|policy|procedure|contract|other)$",
        description="Document type",
    )
    tags: List[str] = Field(default_factory=list, description="Document tags")
    owner_id: Optional[UUID] = Field(None, description="Document owner user ID")
    version: int = Field(default=1, ge=1, description="Document version")
    file_path: Optional[str] = Field(None, max_length=500, description="File path")
    file_size: Optional[int] = Field(None, ge=0, description="File size in bytes")
    mime_type: Optional[str] = Field(None, max_length=100, description="MIME type")


class DocumentCreate(DocumentBase):
    """Schema for creating a new document."""

    pass


class DocumentUpdate(BaseModel):
    """Schema for updating a document (all fields optional)."""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    content: Optional[str] = None
    type: Optional[str] = Field(
        None, pattern="^(specification|report|policy|procedure|contract|other)$"
    )
    tags: Optional[List[str]] = None
    owner_id: Optional[UUID] = None
    version: Optional[int] = Field(None, ge=1)
    file_path: Optional[str] = Field(None, max_length=500)
    file_size: Optional[int] = Field(None, ge=0)
    mime_type: Optional[str] = Field(None, max_length=100)


class DocumentResponse(DocumentBase):
    """Schema for document response."""

    id: UUID
    created_date: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DocumentFilter(BaseModel):
    """Schema for document filtering parameters."""

    type: Optional[str] = Field(
        None, pattern="^(specification|report|policy|procedure|contract|other)$"
    )
    owner_id: Optional[UUID] = None
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    search: Optional[str] = Field(None, description="Search in title and content")


class DocumentLinkRequest(BaseModel):
    """Schema for linking a document to an entity."""

    entity_type: str = Field(
        ...,
        pattern="^(project|task|asset|infrastructure|financial_record)$",
        description="Entity type to link",
    )
    entity_id: UUID = Field(..., description="Entity ID to link")
    link_type: str = Field(
        default="reference",
        pattern="^(attachment|reference|specification|report)$",
        description="Link type",
    )


class PaginatedDocumentResponse(BaseModel):
    """Schema for paginated document list response."""

    items: List[DocumentResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
