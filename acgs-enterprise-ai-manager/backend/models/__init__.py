"""
SQLAlchemy Models
Import all models here to ensure they are registered with SQLAlchemy
"""

from backend.database import Base
from backend.models.user import User
from backend.models.project import Project
from backend.models.task import Task
from backend.models.asset import ITAsset
from backend.models.infrastructure import Infrastructure
from backend.models.search_index import SearchIndex

__all__ = [
    "Base",
    "User",
    "Project",
    "Task",
    "ITAsset",
    "Infrastructure",
    "SearchIndex",
]
