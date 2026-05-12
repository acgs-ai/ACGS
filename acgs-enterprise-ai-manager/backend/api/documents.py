"""
Documents API Endpoints
REST API for Document CRUD operations with tagging and linking
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID
import logging
import math

from backend.database import get_db
from backend.services.document_service import DocumentService
from backend.schemas.document import (
    DocumentCreate,
    DocumentUpdate,
    DocumentResponse,
    DocumentFilter,
    PaginatedDocumentResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_document(doc_data: DocumentCreate, db: AsyncSession = Depends(get_db)):
    """Create a new document."""
    try:
        doc = await DocumentService.create_document(db, doc_data)
        logger.info(f"Created document: {doc.id}")
        return doc
    except Exception as e:
        logger.error(f"Failed to create document: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create document",
        )


@router.get("/{doc_id}", response_model=DocumentResponse)
async def get_document(doc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get document by ID."""
    doc = await DocumentService.get_document(db, doc_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Document {doc_id} not found"
        )
    return doc


@router.get("/", response_model=PaginatedDocumentResponse)
async def list_documents(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    type_filter: Optional[str] = Query(None, alias="type"),
    owner_id: Optional[UUID] = Query(None),
    tags: Optional[List[str]] = Query(None),
    search: Optional[str] = Query(None, max_length=255),
    db: AsyncSession = Depends(get_db),
):
    """List documents with filtering and pagination."""
    try:
        filters = DocumentFilter(
            type=type_filter, owner_id=owner_id, tags=tags, search=search
        )

        items, total = await DocumentService.list_documents(
            db, filters=filters, page=page, page_size=page_size
        )

        total_pages = math.ceil(total / page_size) if total > 0 else 0

        return PaginatedDocumentResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )
    except Exception as e:
        logger.error(f"Failed to list documents: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list documents",
        )


@router.put("/{doc_id}", response_model=DocumentResponse)
async def update_document(
    doc_id: UUID, doc_data: DocumentUpdate, db: AsyncSession = Depends(get_db)
):
    """Update document."""
    doc = await DocumentService.update_document(db, doc_id, doc_data)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Document {doc_id} not found"
        )
    logger.info(f"Updated document: {doc_id}")
    return doc


@router.delete("/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(doc_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete document."""
    deleted = await DocumentService.delete_document(db, doc_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Document {doc_id} not found"
        )
    logger.info(f"Deleted document: {doc_id}")
