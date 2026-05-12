"""
Document Service Layer
Business logic for Document CRUD operations with tagging and linking
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import Optional, List
from uuid import UUID

from backend.models.document import Document
from backend.schemas.document import DocumentCreate, DocumentUpdate, DocumentFilter


class DocumentService:
    """Service class for Document business logic."""

    @staticmethod
    async def create_document(db: AsyncSession, doc_data: DocumentCreate) -> Document:
        """Create a new document."""
        doc = Document(**doc_data.model_dump())
        db.add(doc)
        await db.commit()
        await db.refresh(doc, ["owner"])
        return doc

    @staticmethod
    async def get_document(db: AsyncSession, doc_id: UUID) -> Optional[Document]:
        """Get document by ID."""
        result = await db.execute(select(Document).where(Document.id == doc_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_documents(
        db: AsyncSession,
        filters: Optional[DocumentFilter] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[List[Document], int]:
        """List documents with filtering and pagination."""
        query = select(Document)

        if filters:
            conditions = []
            if filters.type:
                conditions.append(Document.type == filters.type)
            if filters.owner_id:
                conditions.append(Document.owner_id == filters.owner_id)
            if filters.tags:
                for tag in filters.tags:
                    conditions.append(Document.tags.contains([tag]))
            if filters.search:
                search_term = f"%{filters.search}%"
                conditions.append(
                    or_(
                        Document.title.ilike(search_term),
                        Document.content.ilike(search_term),
                    )
                )
            if conditions:
                query = query.where(and_(*conditions))

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        query = query.offset((page - 1) * page_size).limit(page_size)
        query = query.order_by(Document.created_date.desc())

        result = await db.execute(query)
        items = result.scalars().all()
        return list(items), total

    @staticmethod
    async def update_document(
        db: AsyncSession, doc_id: UUID, doc_data: DocumentUpdate
    ) -> Optional[Document]:
        """Update document."""
        doc = await DocumentService.get_document(db, doc_id)
        if not doc:
            return None

        update_data = doc_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(doc, field, value)

        await db.commit()
        await db.refresh(doc, ["owner"])
        return doc

    @staticmethod
    async def delete_document(db: AsyncSession, doc_id: UUID) -> bool:
        """Delete document."""
        doc = await DocumentService.get_document(db, doc_id)
        if not doc:
            return False
        await db.delete(doc)
        await db.commit()
        return True
