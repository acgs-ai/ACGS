"""Stable pseudonymization for machine-local operator identity evidence."""

from __future__ import annotations

import os
import pwd
from typing import Any

PSEUDONYM = "agent-user"


def current_operator() -> str:
    """Return the local account name used only while collecting evidence."""
    return pwd.getpwuid(os.getuid()).pw_name


def pseudonymize(value: Any, *, source_identity: str | None = None) -> Any:
    """Replace the operator name without altering numeric credential evidence."""
    source = source_identity or current_operator()
    if isinstance(value, str):
        legacy_placeholder = "<" + PSEUDONYM + ">"
        return value.replace(source, PSEUDONYM).replace(legacy_placeholder, PSEUDONYM)
    if isinstance(value, list):
        return [pseudonymize(item, source_identity=source) for item in value]
    if isinstance(value, tuple):
        return tuple(pseudonymize(item, source_identity=source) for item in value)
    if isinstance(value, dict):
        return {
            pseudonymize(key, source_identity=source): pseudonymize(item, source_identity=source)
            for key, item in value.items()
        }
    return value
