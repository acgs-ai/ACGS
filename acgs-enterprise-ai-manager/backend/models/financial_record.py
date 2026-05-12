"""
Financial Record SQLAlchemy Model
Complete implementation with approval workflow and project relationships
"""

from sqlalchemy import Column, String, DateTime, Text, Date, Numeric, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.utils.timeutil import utcnow
import uuid

from backend.database import Base


class FinancialRecord(Base):
    """Financial Record model with approval workflow."""

    __tablename__ = "financial_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(
        String(50),
        nullable=False,
        # CHECK constraint: ('expense', 'revenue', 'budget_allocation', 'invoice', 'payment')
    )
    amount = Column(Numeric(15, 2), nullable=False)
    currency = Column(String(3), default="USD")
    date = Column(Date, nullable=False)
    category = Column(String(100), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True)
    approval_status = Column(
        String(20),
        default="pending",
        # CHECK constraint: ('pending', 'approved', 'rejected')
    )
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    description = Column(Text, nullable=True)
    additional_data = Column("metadata", JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    project = relationship("Project", foreign_keys=[project_id])
    approver = relationship("User", foreign_keys=[approved_by])

    def __repr__(self):
        return f"<FinancialRecord(id={self.id}, type='{self.type}', amount={self.amount}, status='{self.approval_status}')>"
