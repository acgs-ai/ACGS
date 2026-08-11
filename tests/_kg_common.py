"""Import helpers for the standalone ``tools/kg/`` extraction scripts.

``tools/kg/`` ships four scripts whose module names — ``extract``, ``load``,
``verify``, ``reports`` — are generic enough to shadow unrelated modules if the
directory were put on ``sys.path`` the way ``tests/conftest.py`` does for
``scripts/``. Load them by file path under a namespaced module name instead.

The three Neo4j-backed scripts import the ``neo4j`` driver *inside* ``main()``,
so importing the module never requires the driver; :func:`fake_neo4j` installs a
recording stub for the tests that do exercise ``main()``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

KG_DIR = Path(__file__).resolve().parent.parent / "tools" / "kg"


def load_kg_module(stem: str) -> ModuleType:
    """Import ``tools/kg/<stem>.py`` under a namespaced module name."""
    name = f"_acgs_kg_{stem}"
    path = KG_DIR / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeRecord:
    """A neo4j Record supports both ``rec["col"]`` and ``rec.data()``; the kg
    scripts use each style in different places, so the stub must offer both."""

    def __init__(self, row: dict[str, Any]) -> None:
        self._row = row

    def __getitem__(self, key: str) -> Any:
        return self._row[key]

    def data(self) -> dict[str, Any]:
        return dict(self._row)


class FakeResult:
    """Stands in for a neo4j Result: iterable of records, plus ``single()``."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):
        return iter(FakeRecord(row) for row in self._rows)

    def single(self) -> FakeRecord | None:
        return FakeRecord(self._rows[0]) if self._rows else None


class FakeTransaction:
    """Recording explicit transaction with commit/rollback state."""

    def __init__(self, responder, all_calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.responder = responder
        self.all_calls = all_calls
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.committed = False
        self.rolled_back = False

    def run(self, query: str, **params: Any) -> FakeResult:
        call = (query, params)
        self.calls.append(call)
        self.all_calls.append(call)
        return FakeResult(self.responder(query))

    def __enter__(self) -> FakeTransaction:
        return self

    def __exit__(self, exc_type: object, *_exc: object) -> None:
        if exc_type is None:
            self.committed = True
        else:
            self.rolled_back = True


class FakeSession:
    """Records every statement run against it and replays canned rows."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.autocommit_calls: list[tuple[str, dict[str, Any]]] = []
        self.transactions: list[FakeTransaction] = []

    def run(self, query: str, **params: Any) -> FakeResult:
        call = (query, params)
        self.calls.append(call)
        self.autocommit_calls.append(call)
        return FakeResult(self.responder(query))

    def begin_transaction(self) -> FakeTransaction:
        transaction = FakeTransaction(self.responder, self.calls)
        self.transactions.append(transaction)
        return transaction

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeDriver:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.sessions: list[FakeSession] = []
        self.closed = False
        self.connectivity_checked = False

    def verify_connectivity(self) -> None:
        self.connectivity_checked = True

    def session(self, database: str | None = None) -> FakeSession:
        session = FakeSession(self.responder)
        session.database = database  # type: ignore[attr-defined]
        self.sessions.append(session)
        return session

    def close(self) -> None:
        self.closed = True


def fake_neo4j(monkeypatch, responder) -> dict[str, Any]:
    """Install a stub ``neo4j`` module; return a dict holding the built driver.

    ``responder(query) -> list[dict]`` supplies the rows each statement returns.
    """
    captured: dict[str, Any] = {}

    class GraphDatabase:
        @staticmethod
        def driver(uri: str, auth: tuple[str, str]) -> FakeDriver:
            driver = FakeDriver(responder)
            captured["driver"] = driver
            captured["uri"] = uri
            captured["auth"] = auth
            return driver

    module = ModuleType("neo4j")
    module.GraphDatabase = GraphDatabase  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "neo4j", module)
    return captured
