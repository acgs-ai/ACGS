"""
API Routers
Import all API routers here
"""

from backend.api import (
    tasks,
    recommendations,
    search,
    projects,
    assets,
    infrastructure,
    documents,
    financial,
    reports,
)

__all__ = [
    "tasks",
    "recommendations",
    "search",
    "projects",
    "assets",
    "infrastructure",
    "documents",
    "financial",
    "reports",
]
