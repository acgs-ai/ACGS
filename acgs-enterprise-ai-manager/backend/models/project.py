"""
Project Model
SQLAlchemy model for Project entity
"""

from sqlalchemy import Column, String, DateTime, Text, Date, Numeric, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base


class Project(Base):
    """Project model."""

    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(50), nullable=False, default="planning")
    start_date = Column(Date)
    end_date = Column(Date)
    budget = Column(Numeric(15, 2))
    actual_cost = Column(Numeric(15, 2), default=0)
    team = Column(JSONB, default=[])
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    owner = relationship("User", back_populates="projects")
    tasks = relationship("Task", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}', status='{self.status}')>"
