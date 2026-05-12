"""
Autonomous Operations Handlers
Domain-specific handlers for autonomous AI operations
"""

from .task_assignment import TaskAssignmentHandler
from .asset_maintenance import AssetMaintenanceHandler

__all__ = ["TaskAssignmentHandler", "AssetMaintenanceHandler"]
