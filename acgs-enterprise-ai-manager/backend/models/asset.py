"""
IT Asset Model
SQLAlchemy model for IT Asset entity
"""

from sqlalchemy import Column, String, DateTime, Date, Numeric, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base
from backend.models.task import task_assets


class ITAsset(Base):
    """IT Asset model."""

    __tablename__ = "it_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default="active")
    location = Column(String(255))
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"))
    purchase_date = Column(Date)
    purchase_cost = Column(Numeric(12, 2))
    lifecycle_stage = Column(String(50))
    warranty_expiry = Column(Date)
    specifications = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    owner = relationship("User", foreign_keys=[owner_id], lazy="select")
    project = relationship("Project", foreign_keys=[project_id], lazy="select")
    tasks = relationship("Task", secondary=task_assets, back_populates="assets")

    def __repr__(self):
        return f"<ITAsset(id={self.id}, name='{self.name}', type='{self.type}')>"
