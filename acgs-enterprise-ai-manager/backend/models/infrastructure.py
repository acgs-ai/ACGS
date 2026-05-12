"""
Infrastructure Model
SQLAlchemy model for Infrastructure entity
"""

from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base
from backend.models.task import task_infrastructure


class Infrastructure(Base):
    """Infrastructure model."""

    __tablename__ = "infrastructure"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default="operational")
    capacity = Column(JSONB)
    location = Column(String(255))
    dependencies = Column(JSONB, default=[])
    configuration = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    tasks = relationship(
        "Task", secondary=task_infrastructure, back_populates="infrastructure"
    )

    def __repr__(self):
        return f"<Infrastructure(id={self.id}, name='{self.name}', type='{self.type}')>"
