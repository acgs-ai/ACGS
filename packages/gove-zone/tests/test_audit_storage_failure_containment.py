"""Storage failures inside the audit sink must not escape the gateway contract.

The gateway's public promise is that *every* refusal is a
:class:`~gove_zone.gateway.GatewayResult` — transport surfaces project it
without exception plumbing (``UniversalGateway.invoke`` docstring). Its
audit-unavailable branches are written as ``except AuditError``.

Two things broke that promise:

1. ``ChainHashAuditStore.append`` performs real filesystem work (lock
   acquisition, append, fsync) and let a raw :class:`OSError` out. The
   gateway paths that call ``self._audit.append`` *around* the kernel —
   :meth:`UniversalGateway._append_synthesized_deny` — therefore saw an
   exception type their ``except AuditError`` clauses do not name.
   (The kernel path is already safe: ``Kernel._append_validated`` normalizes
   every append exception into ``AuditError``.)
2. Gateway audit-failure paths must return the canonical leak-safe error result.
   In particular, synthesized actor-allowlist, human-loop, and pending-capacity
   denials cannot claim a recorded denial when their audit append failed.
3. The ``UniversalGateway.invoke`` ``last_hash()`` chain-linkage pre-read must
   also stay inside the audit-error containment boundary.

The authorization outcome was never fail-open, but the response contract and
the leak-safety boundary were. These tests pin both.
"""

from __future__ import annotations

import builtins
import errno
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any

import pytest

from gove_zone import AllowAllPolicy, ChainHashAuditStore
from gove_zone._locking import FileLockUnavailableError
from gove_zone.audit import AuditChainError
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.errors import AuditError
from gove_zone.gateway import MCP_APPROVE_TOOL, UniversalGateway
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator

# Storage failures a real append can hit: I/O error, disk full, permission
# denied, read-only filesystem. Every one is an OSError subclass or an OSError
# carrying that errno.
STORAGE_ERRNOS = [errno.EIO, errno.ENOSPC, errno.EACCES, errno.EROFS]


def _record(event_id: str = "event-1", tool: str = "echo") -> DecisionRecord:
    return DecisionRecord(
        decision=Decision.DENY,
        tool=tool,
        argument_hash=sha256_json({}),
        policy_version="test/v1",
        event_id=event_id,
        reason="test record",
        actor="agent-a",
    )


def _break_lock_acquisition(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    """Fail the store's real lock-acquisition boundary with *exc*.

    ``_exclusive_file_lock`` is the platform ``flock``/``msvcrt`` wrapper that
    ``append`` enters before writing anything, so the injected failure lands on
    a genuine OS boundary *and* guarantees nothing was persisted — which is what
    lets the "no success record was produced" assertions mean what they say.
    """

    @contextmanager
    def _raise(_fh: IO[Any]) -> Iterator[None]:
        raise exc
        yield  # unreachable; present so the function is a generator

    monkeypatch.setattr("gove_zone.audit._exclusive_file_lock", _raise)


def _make_gateway(
    tmp_path: Path,
    *,
    allowed_actors: frozenset[str] | None = None,
    policy: Policy | None = None,
    max_pending: int = 256,
    max_pending_per_principal: int = 64,
) -> UniversalGateway:
    return UniversalGateway(
        tenant_id="tenant-1",
        execution_boundary="boundary-1",
        policy=policy or AllowAllPolicy(),
        profile=GovernanceProfile.dev(),
        validator=Validator(validator_id="validator-1"),
        authority="authority-1",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
        allowed_actors=allowed_actors,
        max_pending=max_pending,
        max_pending_per_principal=max_pending_per_principal,
    )


def _audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _envelope_text(outcome: Any) -> str:
    """Everything a caller can read off the result, flattened for leak checks."""

    return json.dumps(outcome.to_dict(), default=repr)


# --- store-level normalization -------------------------------------------------


def test_a_real_storage_failure_in_append_surfaces_as_an_audit_error(
    tmp_path: Path,
) -> None:
    """No monkeypatching: the store's own lock file is a directory.

    ``append`` opens ``<audit>.lock`` before it writes, so a directory there is
    a real ``IsADirectoryError`` (an ``OSError``) raised by production code on
    a genuine filesystem boundary. Root-safe — it does not depend on permission
    bits.
    """

    path = tmp_path / "audit.jsonl"
    store = ChainHashAuditStore(path)
    (tmp_path / "audit.jsonl.lock").mkdir()

    with pytest.raises(AuditError) as exc_info:
        store.append(_record())

    assert isinstance(exc_info.value.__cause__, OSError)
    # Nothing was persisted: the chain is still empty and still verifies.
    assert not path.exists() or path.read_text() == ""
    assert store.verify_chain()["valid"] is True


@pytest.mark.parametrize("code", STORAGE_ERRNOS)
def test_every_storage_errno_is_normalized_by_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    _break_lock_acquisition(monkeypatch, OSError(code, "injected storage failure"))

    with pytest.raises(AuditError) as exc_info:
        store.append(_record())

    cause = exc_info.value.__cause__
    assert isinstance(cause, OSError) and cause.errno == code


@pytest.mark.parametrize("code", STORAGE_ERRNOS)
def test_every_storage_errno_is_normalized_by_append_many(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The batch path is the same storage transaction and gets the same contract."""

    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    _break_lock_acquisition(monkeypatch, OSError(code, "injected storage failure"))

    with pytest.raises(AuditError) as exc_info:
        store.append_many([_record("event-1"), _record("event-2")])

    cause = exc_info.value.__cause__
    assert isinstance(cause, OSError) and cause.errno == code


def test_a_host_without_a_file_lock_primitive_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "No lock primitive" is a storage refusal, and it is not an ``OSError``.

    Exercises the real ``_exclusive_file_lock`` body by making both ``fcntl``
    and ``msvcrt`` unimportable, which is the only way that branch is reachable
    on a host that has one of them.
    """

    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    real_import = builtins.__import__

    def _no_lock_modules(name: str, *args: Any, **kwargs: Any) -> Any:
        if name in {"fcntl", "msvcrt"}:
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_lock_modules)

    with pytest.raises(AuditError) as exc_info:
        store.append(_record())

    assert isinstance(exc_info.value.__cause__, FileLockUnavailableError)
    # A RuntimeError subclass — so a caller must not have to widen its guard to
    # every RuntimeError, which would swallow genuine defects.
    assert isinstance(exc_info.value.__cause__, RuntimeError)


def test_normalization_does_not_swallow_an_unrelated_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock-unavailable type is named specifically, not ``RuntimeError``."""

    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    _break_lock_acquisition(monkeypatch, RuntimeError("an ordinary defect"))

    with pytest.raises(RuntimeError, match="an ordinary defect") as exc_info:
        store.append(_record())

    assert not isinstance(exc_info.value, AuditError)


def test_normalization_does_not_swallow_a_programming_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A defect in the store is a defect, not an ordinary storage refusal.

    Asserted against the store directly: the kernel converts *every* append
    exception into ``AuditError`` by design, so the same assertion made through
    ``Kernel.dispatch`` would pass vacuously.
    """

    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    _break_lock_acquisition(monkeypatch, TypeError("not a storage failure"))

    with pytest.raises(TypeError, match="not a storage failure"):
        store.append(_record())


def test_a_successful_append_is_unchanged_and_still_verifies(tmp_path: Path) -> None:
    """Baseline: normalization must not touch the healthy path."""

    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    first = store.append(_record("event-1"))
    second = store.append(_record("event-2"))

    assert second["previous_hash"] == first["event_hash"]
    result = store.verify_chain(expected_count=2, expected_last_hash=second["event_hash"])
    assert result["valid"] is True and result["checked"] == 2


# --- gateway containment -------------------------------------------------------


def test_a_storage_failure_on_the_allowlist_refusal_returns_canonical_audit_error(
    tmp_path: Path,
) -> None:
    """An actor-allowlist refusal is audited through ``_append_synthesized_deny``.

    A dead audit sink must return the canonical ``AuditError`` result rather
    than claiming a recorded denial with a synthetic rejection envelope.
    """

    gateway = _make_gateway(tmp_path, allowed_actors=frozenset({"agent-a"}))
    ran: list[str] = []

    def echo(message: str) -> str:
        ran.append(message)
        return message

    gateway.register_tool("echo", echo)
    (tmp_path / "audit.jsonl.lock").mkdir()

    outcome = gateway.invoke("stranger", "echo", {"message": "hi"})

    assert outcome.to_dict() == {
        "status": "error",
        "tool": "echo",
        "actor": "stranger",
        "audit_hash": "",
        "error_class": "AuditError",
    }
    assert ran == []  # no downstream invocation
    assert _audit_events(tmp_path) == []  # and no success record


def test_a_storage_failure_on_the_chain_pre_read_returns_an_envelope(
    tmp_path: Path,
) -> None:
    """``invoke`` pre-reads the chain tail for the receipt's linkage anchor.

    That read sits outside the ``except AuditError`` guard, so an unreadable
    chain escaped as an exception rather than the canonical error result.
    """

    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text('{"event_id":"broken"\n', encoding="utf-8")
    gateway = _make_gateway(tmp_path)
    ran: list[str] = []

    def echo(message: str) -> str:
        ran.append(message)
        return message

    gateway.register_tool("echo", echo)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.status == "error"
    assert outcome.error_class == "AuditError"
    assert ran == []
    # The corrupt chain was not rewritten or extended.
    assert audit_path.read_text(encoding="utf-8") == '{"event_id":"broken"\n'


@pytest.mark.parametrize("code", STORAGE_ERRNOS)
def test_a_storage_failure_never_leaks_its_detail_to_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The refusal envelope carries no path, errno text, or exception repr."""

    gateway = _make_gateway(tmp_path, allowed_actors=frozenset({"agent-a"}))
    ran: list[str] = []

    def echo(message: str) -> str:
        ran.append(message)
        return message

    gateway.register_tool("echo", echo)
    _break_lock_acquisition(
        monkeypatch, OSError(code, "injected storage failure", str(tmp_path / "audit.jsonl"))
    )

    outcome = gateway.invoke("stranger", "echo", {"message": "hunter2"})

    assert outcome.status == "error"
    assert outcome.error_class == "AuditError"
    text = _envelope_text(outcome)
    assert "injected storage failure" not in text
    assert str(tmp_path) not in text
    assert "audit.jsonl" not in text
    assert "OSError" not in text
    assert "Traceback" not in text
    assert ran == []


def test_human_loop_audit_failure_projects_as_canonical_mcp_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = _make_gateway(tmp_path)

    def _boom(*_args: Any, **_kwargs: Any) -> tuple[DecisionRecord, str]:
        raise AuditError(f"sensitive audit path: {tmp_path / 'audit.jsonl'}")

    monkeypatch.setattr(gateway, "_append_synthesized_deny", _boom)

    outcome = gateway.handle_mcp_call(
        {"name": MCP_APPROVE_TOOL, "arguments": {}},
        actor="agent-a",
    )

    assert outcome == {
        "isError": True,
        "content": [{"type": "text", "text": f"gove-zone error: {MCP_APPROVE_TOOL}"}],
        "_meta": {"gove_zone": {"decision": "error", "error_class": "AuditError"}},
    }
    assert str(tmp_path) not in json.dumps(outcome)
    assert _audit_events(tmp_path) == []


def test_pending_capacity_audit_failure_projects_as_canonical_mcp_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = RuleSetPolicy(
        policy_id="capacity-test",
        rules=(
            PolicyRule(
                rule_id="escalate-deploy",
                effect=Decision.ESCALATE,
                tools=frozenset({"deploy"}),
                reason="approval required",
            ),
        ),
    )
    gateway = _make_gateway(
        tmp_path,
        policy=policy,
        max_pending=1,
        max_pending_per_principal=1,
    )
    ran: list[str] = []
    gateway.register_tool("deploy", lambda env: ran.append(env))

    first = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "first"}},
        actor="agent-a",
    )
    assert first["_meta"]["gove_zone"]["decision"] == "escalated"

    def _boom(*_args: Any, **_kwargs: Any) -> tuple[DecisionRecord, str]:
        raise AuditError(f"sensitive audit path: {tmp_path / 'audit.jsonl'}")

    monkeypatch.setattr(gateway, "_append_synthesized_deny", _boom)
    outcome = gateway.handle_mcp_call(
        {"name": "deploy", "arguments": {"env": "overflow"}},
        actor="agent-a",
    )

    assert outcome == {
        "isError": True,
        "content": [{"type": "text", "text": "gove-zone error: deploy"}],
        "_meta": {"gove_zone": {"decision": "error", "error_class": "AuditError"}},
    }
    assert str(tmp_path) not in json.dumps(outcome)
    assert ran == []
    assert len(gateway._pending) == 1


def test_a_typed_audit_error_still_produces_the_canonical_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The already-supported path must keep behaving identically."""

    gateway = _make_gateway(tmp_path)
    ran: list[str] = []

    def echo(message: str) -> str:
        ran.append(message)
        return message

    gateway.register_tool("echo", echo)

    def _boom(_record: DecisionRecord) -> dict[str, Any]:
        raise AuditChainError("audit chain unavailable")

    monkeypatch.setattr(gateway._audit, "append", _boom)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.status == "error"
    assert outcome.error_class == "AuditError"
    assert ran == []
    assert _audit_events(tmp_path) == []


def test_a_healthy_gateway_call_is_unaffected(tmp_path: Path) -> None:
    """Regression anchor: containment must not change the normal outcome."""

    gateway = _make_gateway(tmp_path, allowed_actors=frozenset({"agent-a"}))
    ran: list[str] = []

    def echo(message: str) -> str:
        ran.append(message)
        return message

    gateway.register_tool("echo", echo)

    outcome = gateway.invoke("agent-a", "echo", {"message": "hi"})

    assert outcome.executed
    assert ran == ["hi"]
    events = _audit_events(tmp_path)
    assert [event["decision"] for event in events] == ["allow"]
    assert ChainHashAuditStore(tmp_path / "audit.jsonl").verify_chain()["valid"] is True
