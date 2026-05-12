"""Time utilities.

`datetime.utcnow()` was deprecated in Python 3.12 and is scheduled for
removal. The replacement is `datetime.now(timezone.utc)`, but that returns
a *timezone-aware* datetime, while the rest of this codebase (and the
DateTime(timezone=True) column defaults that feed PostgreSQL) was written
against the *naive* UTC datetime that utcnow() produced.

Swapping naive for aware in one shot would change every JSON-serialized
timestamp (`isoformat()` would emit `+00:00`), comparisons between stored
naive datetimes and freshly aware ones would raise TypeError, and the
SQLAlchemy `default=` / `onupdate=` callables that pass the function
reference around would silently change schema-on-insert behavior.

This helper returns a naive UTC datetime — semantically identical to the
old `datetime.utcnow()` — and is the only place that depends on
`datetime.now(timezone.utc)`. Replacing call sites with `utcnow()` (and
`default=utcnow` for SQLAlchemy column defaults) makes the deprecation
warning go away without changing any output formats or comparison
semantics. Migrating the whole codebase to timezone-aware datetimes is a
separate, larger contract change.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime.

    Equivalent to the now-deprecated `datetime.utcnow()` — kept naive so
    callers that compare, subtract, or `.isoformat()` against existing
    stored values don't observe a sudden tzinfo change.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
