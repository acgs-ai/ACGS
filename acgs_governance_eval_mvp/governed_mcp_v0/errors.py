"""Typed exceptions raised by the governed MCP v0 runtime."""
from __future__ import annotations


class GovernanceDenied(RuntimeError):
    """Raised when deterministic governance denies a side effect."""


class GovernanceStorageError(RuntimeError):
    """Raised when receipt or audit persistence fails closed."""
