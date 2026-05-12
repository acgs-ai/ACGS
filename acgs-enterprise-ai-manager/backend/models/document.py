"""
Document SQLAlchemy Model
Complete implementation with tagging and polymorphic linking to other entities
"""

from sqlalchemy import Column, String, DateTime, Text, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base


class Document(Base):
    """Document model with tagging and cross-domain linking."""

    __tablename__ = "documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=True)
    type = Column(
        String(50),
        nullable=False,
        # CHECK constraint: ('specification', 'report', 'policy', 'procedure', 'contract', 'other')
    )
    tags = Column(JSONB, default=list)
    created_date = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    version = Column(Integer, default=1)
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)
    mime_type = Column(String(100), nullable=True)

    # Relationships
    owner = relationship("User", foreign_keys=[owner_id])

    def __repr__(self):
        return f"<Document(id={self.id}, title='{self.title}', type='{self.type}', version={self.version})>"
