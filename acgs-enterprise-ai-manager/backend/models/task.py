"""
Task Model
SQLAlchemy model for Task entity with cross-domain relationships
"""

from sqlalchemy import Column, String, DateTime, Text, Numeric, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base

# Association table for Task-Asset many-to-many relationship
task_assets = Table(
    "task_assets",
    Base.metadata,
    Column(
        "task_id",
        UUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "asset_id",
        UUID(as_uuid=True),
        ForeignKey("it_assets.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("relationship_type", String(50)),
    Column("created_at", DateTime(timezone=True), default=utcnow),
)


# Association table for Task-Infrastructure many-to-many relationship
task_infrastructure = Table(
    "task_infrastructure",
    Base.metadata,
    Column(
        "task_id",
        UUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "infrastructure_id",
        UUID(as_uuid=True),
        ForeignKey("infrastructure.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("relationship_type", String(50)),
    Column("created_at", DateTime(timezone=True), default=utcnow),
)


class Task(Base):
    """Task model with cross-domain relationships."""

    __tablename__ = "tasks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(50), nullable=False, default="todo")
    priority = Column(String(20), nullable=False, default="medium")
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    project_id = Column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE")
    )
    due_date = Column(DateTime(timezone=True))
    estimated_hours = Column(Numeric(5, 2))
    actual_hours = Column(Numeric(5, 2))
    tags = Column(JSONB, default=[])
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    completed_at = Column(DateTime(timezone=True))

    # Relationships
    assignee = relationship("User", back_populates="tasks", lazy="selectin")
    project = relationship("Project", back_populates="tasks", lazy="selectin")
    assets = relationship(
        "ITAsset", secondary=task_assets, back_populates="tasks", lazy="selectin"
    )
    infrastructure = relationship(
        "Infrastructure",
        secondary=task_infrastructure,
        back_populates="tasks",
        lazy="selectin",
    )

    def __repr__(self):
        return f"<Task(id={self.id}, title='{self.title}', status='{self.status}')>"
