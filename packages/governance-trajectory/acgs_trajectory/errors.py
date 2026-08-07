"""Typed errors for the ingestion foundation."""

from __future__ import annotations


class IngestError(Exception):
    """Base class for ingestion failures."""


class ParseError(IngestError):
    """A raw JSONL line could not be parsed (malformed transcript)."""

    def __init__(self, line_no: int, message: str) -> None:
        super().__init__(f"line {line_no}: {message}")
        self.line_no = line_no


class QuarantineError(IngestError):
    """Raised when a record must be quarantined and callers requested strict mode.

    Quarantine is normally a *status*, not an exception — the record is retained
    and flagged (fail-closed, never silently dropped). This exception exists only
    for call sites that opt into strict-abort behavior.
    """

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons
