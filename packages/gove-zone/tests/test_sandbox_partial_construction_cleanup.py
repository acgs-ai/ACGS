"""``LocalProcessSandbox`` destruction must be safe after a failed constructor.

``__init__`` does failure-prone work *before* it assigns ``self._temp_dir``:
it can raise :class:`SandboxError` when ``require_bwrap=True`` and bubblewrap is
absent, and it emits a ``UserWarning`` that a warnings filter can promote to an
exception. Either way the object exists but has no ``_temp_dir`` attribute, and
``__del__`` read it unguarded — so garbage-collecting a half-built sandbox
emitted an unraisable ``AttributeError`` from the interpreter.

That is not a leak of anything sensitive, but it is an object whose finalizer
raises: noisy, non-deterministic, and it hides real cleanup failures behind
interpreter chatter. Cleanup must be safe for a partially built instance,
idempotent, and must never touch a directory the sandbox does not own.
"""

from __future__ import annotations

import gc
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any

import pytest

from gove_zone import sandbox as sandbox_module
from gove_zone.sandbox import LocalProcessSandbox, SandboxError


class _UnraisableRecorder:
    """Capture anything the interpreter reports from a finalizer."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def __call__(self, unraisable: Any) -> None:
        self.events.append(unraisable)

    @property
    def exception_types(self) -> list[type[BaseException]]:
        return [type(event.exc_value) for event in self.events if event.exc_value is not None]


@pytest.fixture
def unraisable() -> Any:
    """Install a recording ``sys.unraisablehook`` for the duration of a test."""

    recorder = _UnraisableRecorder()
    previous = sys.unraisablehook
    sys.unraisablehook = recorder
    try:
        yield recorder
    finally:
        sys.unraisablehook = previous


def _partially_constructed(
    monkeypatch: pytest.MonkeyPatch,
) -> LocalProcessSandbox:
    """Build a sandbox whose ``__init__`` fails before the temp dir exists.

    Deterministic on any host: ``shutil.which`` is forced to report bubblewrap
    as absent inside the sandbox module, so ``require_bwrap=True`` raises at the
    first guard — well before ``self._temp_dir`` is assigned.
    """

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda _name: None)
    holder: list[LocalProcessSandbox] = []

    class _Probe(LocalProcessSandbox):
        def __init__(self, **kwargs: Any) -> None:
            holder.append(self)  # capture the half-built object before it raises
            super().__init__(**kwargs)

    with pytest.raises(SandboxError, match="require_bwrap=True"):
        _Probe(use_bwrap=True, require_bwrap=True)

    assert holder, "the probe never reached __init__"
    return holder[0]


# --- partial construction ------------------------------------------------------


def test_a_constructor_that_failed_before_the_temp_dir_has_no_temp_dir_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins the precondition the rest of this module depends on."""

    partial = _partially_constructed(monkeypatch)

    assert not hasattr(partial, "sandbox_dir")


def test_destroying_a_partially_constructed_sandbox_raises_nothing(
    monkeypatch: pytest.MonkeyPatch, unraisable: _UnraisableRecorder
) -> None:
    partial = _partially_constructed(monkeypatch)

    del partial
    gc.collect()

    assert unraisable.exception_types == []


def test_the_destructor_can_be_run_directly_on_a_partial_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Called directly, ``__del__`` must return rather than raise.

    ``sys.unraisablehook`` only sees exceptions the interpreter swallows; this
    asserts the method itself is safe, which is the invariant a finalizer needs.
    """

    partial = _partially_constructed(monkeypatch)

    partial.__del__()  # must not raise
    partial.__del__()  # and must stay harmless when repeated


def test_a_warning_promoted_to_an_error_also_leaves_a_safe_object(
    monkeypatch: pytest.MonkeyPatch, unraisable: _UnraisableRecorder
) -> None:
    """The second real pre-``_temp_dir`` failure point: the bwrap fallback warning.

    Under ``-W error`` (or ``filterwarnings = error``) the ``UserWarning`` at the
    fallback branch raises out of ``__init__`` before the temp dir is created.
    """

    monkeypatch.setattr(sandbox_module.shutil, "which", lambda _name: None)
    holder: list[LocalProcessSandbox] = []

    class _Probe(LocalProcessSandbox):
        def __init__(self, **kwargs: Any) -> None:
            holder.append(self)
            super().__init__(**kwargs)

    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        with pytest.raises(UserWarning, match="bubblewrap"):
            _Probe(use_bwrap=True, require_bwrap=False)

    assert holder
    partial = holder[0]
    assert not hasattr(partial, "sandbox_dir")

    del partial
    holder.clear()
    gc.collect()

    assert unraisable.exception_types == []


def test_a_constructor_that_failed_after_the_temp_dir_still_cleans_it_up(
    unraisable: _UnraisableRecorder,
) -> None:
    """The other side of the boundary: the temp dir exists, so it must be removed.

    Base ``__init__`` has no failure point after the directory is created, so a
    subclass raising in its own ``__init__`` is the faithful way to reach this
    state — and it is the realistic one, since that is where a caller's extra
    setup would live.
    """

    created: list[Path] = []

    class _FailsAfterSetup(LocalProcessSandbox):
        def __init__(self) -> None:
            super().__init__(use_bwrap=False)
            created.append(Path(self.sandbox_dir))
            raise RuntimeError("subclass setup failed")

    with pytest.raises(RuntimeError, match="subclass setup failed"):
        _FailsAfterSetup()

    assert created and created[0].name.startswith("gove-sandbox-")
    gc.collect()

    assert not created[0].exists()
    assert unraisable.exception_types == []


# --- ownership -----------------------------------------------------------------


def test_a_caller_supplied_directory_is_never_removed(
    tmp_path: Path, unraisable: _UnraisableRecorder
) -> None:
    """``sandbox_dir=`` means the caller owns it; the sandbox must not delete it."""

    owned_by_caller = tmp_path / "caller-owned"
    owned_by_caller.mkdir()
    sentinel = owned_by_caller / "keep.txt"
    sentinel.write_text("do not delete", encoding="utf-8")

    sandbox = LocalProcessSandbox(use_bwrap=False, sandbox_dir=str(owned_by_caller))
    assert sandbox.sandbox_dir == str(owned_by_caller)

    del sandbox
    gc.collect()

    assert sentinel.read_text(encoding="utf-8") == "do not delete"
    assert unraisable.exception_types == []


def test_a_replacement_path_is_never_removed_by_cleanup(
    tmp_path: Path, unraisable: _UnraisableRecorder
) -> None:
    """Cleanup targets the temp dir the sandbox created, not whatever is there now.

    An unrelated directory swapped onto the same attribute (or left behind after
    the owned one is gone) must survive destruction.
    """

    sandbox = LocalProcessSandbox(use_bwrap=False)
    owned = Path(sandbox.sandbox_dir)
    assert owned.is_dir()

    unrelated = tmp_path / "not-the-sandbox"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_text("unrelated", encoding="utf-8")
    sandbox.sandbox_dir = str(unrelated)

    del sandbox
    gc.collect()

    assert not owned.exists()  # the sandbox-owned directory is gone
    assert (unrelated / "keep.txt").read_text(encoding="utf-8") == "unrelated"
    assert unraisable.exception_types == []


# --- idempotency ---------------------------------------------------------------


def test_cleanup_is_idempotent_and_destruction_after_it_is_harmless(
    unraisable: _UnraisableRecorder,
) -> None:
    sandbox = LocalProcessSandbox(use_bwrap=False)
    owned = Path(sandbox.sandbox_dir)
    assert owned.is_dir()

    sandbox._release_temp_dir()
    assert not owned.exists()
    sandbox._release_temp_dir()  # second explicit release: no-op, no raise

    sandbox.__del__()
    del sandbox
    gc.collect()

    assert unraisable.exception_types == []


def test_a_fully_initialized_sandbox_removes_its_own_temp_dir(
    unraisable: _UnraisableRecorder,
) -> None:
    """Existing behavior anchor: normal shutdown still cleans up."""

    sandbox = LocalProcessSandbox(use_bwrap=False)
    owned = Path(sandbox.sandbox_dir)
    assert owned.is_dir()
    assert owned.name.startswith("gove-sandbox-")

    del sandbox
    gc.collect()

    assert not owned.exists()
    assert unraisable.exception_types == []


def test_a_failing_removal_does_not_escape_the_destructor(
    unraisable: _UnraisableRecorder,
) -> None:
    """A cleanup that itself fails is contained; the finalizer stays silent.

    ``tempfile.TemporaryDirectory.cleanup`` is the explicit path and keeps its
    own error contract — the fault is injected there and observed to propagate
    on a direct call, then observed *not* to escape destruction.
    """

    sandbox = LocalProcessSandbox(use_bwrap=False)
    temp_dir = sandbox._temp_dir
    assert isinstance(temp_dir, tempfile.TemporaryDirectory)

    def _boom() -> None:
        raise OSError("removal failed")

    temp_dir.cleanup = _boom  # type: ignore[method-assign]

    with pytest.raises(OSError, match="removal failed"):
        temp_dir.cleanup()

    sandbox.__del__()  # must not raise
    del sandbox
    del temp_dir
    gc.collect()

    assert unraisable.exception_types == []


def test_the_destructor_of_a_never_initialized_instance_is_safe(
    unraisable: _UnraisableRecorder,
) -> None:
    """The bluntest partial object: ``__init__`` never ran at all."""

    bare = object.__new__(LocalProcessSandbox)
    assert not hasattr(bare, "_temp_dir")

    bare.__del__()  # must not raise

    del bare
    gc.collect()

    assert unraisable.exception_types == []
