"""
Search Index Model
SQLAlchemy model for unified search across all domains
"""

from sqlalchemy import Column, String, DateTime, Text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, TSVECTOR
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base


class SearchIndex(Base):
    """Search index model for unified cross-domain search."""

    __tablename__ = "search_index"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(UUID(as_uuid=True), nullable=False)
    domain = Column(String(50), nullable=False)
    title = Column(String(255))
    content = Column(Text)
    tags = Column(JSONB, default=[])
    extra_data = Column(
        "metadata", JSONB
    )  # SQL column is metadata; attribute avoids SQLAlchemy reserved name.
    search_vector = Column(TSVECTOR)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    __table_args__ = (
        Index("idx_search_index_entity", "entity_type", "entity_id", unique=True),
        Index("idx_search_index_domain", "domain"),
        Index(
            "idx_search_index_search_vector", "search_vector", postgresql_using="gin"
        ),
        Index("idx_search_index_tags", "tags", postgresql_using="gin"),
    )

    def __repr__(self):
        return f"<SearchIndex(domain='{self.domain}', entity_type='{self.entity_type}', title='{self.title}')>"
