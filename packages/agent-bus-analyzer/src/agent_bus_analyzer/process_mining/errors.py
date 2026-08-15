"""Typed failures for observer-only process-intelligence primitives."""


class ProcessMiningError(RuntimeError):
    """Base error for the process-mining package."""


class SourceIntegrityError(ProcessMiningError):
    """A source record or its declared predecessor failed verification."""


class EventStoreIntegrityError(ProcessMiningError):
    """The normalized append-only store is missing, malformed, or tampered."""


class MigrationIntegrityError(EventStoreIntegrityError):
    """A PostgreSQL schema migration is missing, reordered, or tampered."""


class ConflictingDuplicateError(ProcessMiningError):
    """An event id was reused for different normalized content."""


class TenantIsolationError(ProcessMiningError):
    """A source or graph operation attempted to cross tenant boundaries."""


class GraphConflictError(ProcessMiningError):
    """A graph id was reused with conflicting content."""


class GraphReferenceError(ProcessMiningError):
    """A graph edge or query referenced a missing entity."""
