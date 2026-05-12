"""
Middleware package initialization
"""

from backend.middleware.governance_interceptor import GovernanceMiddleware

__all__ = ["GovernanceMiddleware"]
