"""Packaged generated contracts for offline Process Intelligence consumers."""

from __future__ import annotations

from importlib.resources import files


def process_event_schema_bytes() -> bytes:
    """Return the generated ProcessEvent schema from this installed wheel."""
    return files(__package__).joinpath("process-event.schema.json").read_bytes()
