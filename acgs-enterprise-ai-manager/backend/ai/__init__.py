"""
AI Module for ACGS Enterprise Manager
Provides recommendation engine, learning capabilities, and autonomous operations
"""

from .recommendation_engine import RecommendationEngine
from .autonomous_ops import (
    AutonomousOperationsEngine,
    get_autonomous_engine,
    initialize_autonomous_engine,
)

__all__ = [
    "RecommendationEngine",
    "AutonomousOperationsEngine",
    "get_autonomous_engine",
    "initialize_autonomous_engine",
]
