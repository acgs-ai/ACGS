"""Backward-compat contract for the extracted file-lock primitive.

``_exclusive_file_lock`` moved from ``gove_zone.audit`` to the shared
``gove_zone._locking`` module. The historical import path
``from gove_zone.audit import _exclusive_file_lock`` must keep resolving, and
it must resolve to the very same object as the new home — not a copy.
"""

from gove_zone import _locking, audit
from gove_zone.audit import _exclusive_file_lock as audit_lock


def test_audit_import_path_still_resolves() -> None:
    assert callable(audit_lock)


def test_audit_reexport_is_locking_implementation() -> None:
    assert audit._exclusive_file_lock is _locking._exclusive_file_lock
