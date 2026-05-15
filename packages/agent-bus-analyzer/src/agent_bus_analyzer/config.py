"""Configuration loader for the analyzer.

Resolves runtime config from env + caller-provided defaults. The
constitutional hash is the load-bearing piece: it is the anchor every
captured event references. If it cannot be resolved we fail closed
(``IntegrityStoreUnavailable``).

Foundational scope: env is the only constitutional-hash source. The plan
permits a fallback to ``ACGS.src.core.shared.constants`` — that fallback
is deferred to US1 to keep Foundational primitives decoupled from ACGS
imports.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from agent_bus_analyzer.errors import IntegrityStoreUnavailable

DEFAULT_QUEUE_CAPACITY = 10_000
DEFAULT_DISPATCH_TIMEOUT_SECONDS = 30
DEFAULT_REGISTRY_POLL_SECONDS = 30
DEFAULT_RETENTION_DAYS = 90

_HASH_PATTERN = re.compile(r"^[a-f0-9]{16}$")


@dataclass(frozen=True)
class AnalyzerConfig:
    bus_endpoint: str
    audit_file: Path
    store_dir: Path
    constitutional_hash: str
    queue_capacity: int = DEFAULT_QUEUE_CAPACITY
    dispatch_timeout_seconds: int = DEFAULT_DISPATCH_TIMEOUT_SECONDS
    registry_poll_seconds: int = DEFAULT_REGISTRY_POLL_SECONDS
    retention_days: int = DEFAULT_RETENTION_DAYS


def resolve_constitutional_hash() -> str:
    """Read CONSTITUTIONAL_HASH from env. Fail closed if unset or malformed."""
    value = os.getenv("CONSTITUTIONAL_HASH")
    if not value:
        raise IntegrityStoreUnavailable(
            "CONSTITUTIONAL_HASH env var is unset; observer cannot anchor traces"
        )
    if not _HASH_PATTERN.match(value):
        raise IntegrityStoreUnavailable(
            f"CONSTITUTIONAL_HASH must be 16 lowercase hex chars, got: {value!r}"
        )
    return value


def load_config(
    *,
    bus_endpoint: str,
    audit_file: str | Path,
    store_dir: str | Path,
    queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
    dispatch_timeout_seconds: int = DEFAULT_DISPATCH_TIMEOUT_SECONDS,
    registry_poll_seconds: int = DEFAULT_REGISTRY_POLL_SECONDS,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> AnalyzerConfig:
    return AnalyzerConfig(
        bus_endpoint=bus_endpoint,
        audit_file=Path(audit_file),
        store_dir=Path(store_dir),
        constitutional_hash=resolve_constitutional_hash(),
        queue_capacity=queue_capacity,
        dispatch_timeout_seconds=dispatch_timeout_seconds,
        registry_poll_seconds=registry_poll_seconds,
        retention_days=retention_days,
    )
