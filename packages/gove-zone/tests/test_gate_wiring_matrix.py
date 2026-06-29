"""Track F / ADV9 — the static "is the gate wired" check.

``docs/INTEGRATION_MATRIX.md`` is the canonical claim surface for the
neutrality story: each row labelled **Shipped + tested** promises a *runnable
example* in which a side effect is mediated by the gove-zone gate. The core
invariant printed at the top of that file is **"No valid Decision Receipt, no
side effect."**

ADV9 is the *out-of-gate executor bypass*: a caller invokes the raw tool and
never reaches the governed executor. ``test_integration_gaps.py`` already locks
the ``.claude`` runtime-hook surface against the "handler exists but not wired"
failure class. This module extends that discipline to every example the
integration matrix *claims* is shipped, statically (AST only — the example
modules are never imported or executed here, so the check has no side effects of
its own). For each claimed example it proves three things:

1. **Claim integrity** — the cited example path actually exists. Catches matrix
   drift where a row keeps citing an example that was renamed or deleted.
2. **The gate is wired** — the example imports *and calls* a gove-zone gate
   entrypoint (``execute_with_receipt`` / ``GovernedExecutor`` for the execute
   surface, or ``emit_receipt_for_hook`` for the runtime-hook/audit surface). An
   example that drifts into calling its raw tool directly — the ADV9 bypass —
   stops matching and fails here.
3. **The gate has teeth** — the example exercises a fail-closed branch: an
   ``except`` for a gove-zone fail-closed error (``ReceiptValidationError``,
   ``GateModeError``, ...). An example that only demonstrates the happy ALLOW
   path, never a denial, is not a faithful gate demonstration.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = REPO_ROOT / "docs" / "INTEGRATION_MATRIX.md"

# Gove-zone *gate entrypoints*: importing+calling one of these is what makes a
# side effect "mediated". The execute surface gates the call itself; the
# runtime-hook surface (``emit_receipt_for_hook``) is the passive auditor that
# fails closed under enforce mode.
_GATE_ENTRYPOINTS = frozenset({"execute_with_receipt", "GovernedExecutor", "emit_receipt_for_hook"})

# Gove-zone fail-closed error types. An ``except`` for one of these is the
# example demonstrating denial/refusal, not just the happy path.
_FAILCLOSED_ERRORS = frozenset(
    {
        "ReceiptValidationError",
        "GateModeError",
        "ProductionProfileError",
        "AuthzDeniedError",
        "ReceiptAlreadyUsedError",
        "UnsafeAuditStorageError",
    }
)

# Example path tokens may appear as a directory (``examples/foo/`` → ``foo/demo.py``)
# or a concrete file (``packages/gove-zone/examples/runtime_hook_demo.py``).
_EXAMPLE_TOKEN = re.compile(r"(?:packages/gove-zone/)?examples/[\w./-]+")

_SHIPPED_TESTED = "Shipped + tested"


def _parse_shipped_tested_examples() -> list[str]:
    """Return every ``examples/...`` path cited by a Shipped + tested matrix row.

    Parses the markdown table directly: a data row is a ``|``-delimited line with
    at least ``runtime | tier | backing-artifact`` cells. Only rows whose tier
    cell is exactly ``Shipped + tested`` contribute, so honest lower-tier rows
    (``Pattern`` / ``Roadmap`` / "Shipped (shape parse)") are not over-claimed.
    """
    text = MATRIX_PATH.read_text(encoding="utf-8")
    found: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) < 3:
            continue
        tier, backing = cells[1], cells[2]
        if tier != _SHIPPED_TESTED:
            continue
        for match in _EXAMPLE_TOKEN.finditer(backing):
            token = match.group(0).rstrip("/")
            if token not in found:
                found.append(token)
    return found


def _resolve_demo(token: str) -> Path:
    """Resolve a matrix example token to the concrete demo ``.py`` file."""
    path = REPO_ROOT / token
    if path.suffix == ".py":
        return path
    return path / "demo.py"


_CLAIMED_EXAMPLES = _parse_shipped_tested_examples()


def test_matrix_parser_is_not_vacuous() -> None:
    # Guard against a parser regression silently matching zero rows and making
    # every parametrized check below pass vacuously.
    assert len(_CLAIMED_EXAMPLES) >= 4, (
        "expected >=4 'Shipped + tested' example citations in INTEGRATION_MATRIX.md; "
        f"parsed {_CLAIMED_EXAMPLES!r}"
    )
    # The known kernel example surfaces must all be claimed.
    joined = " ".join(_CLAIMED_EXAMPLES)
    for expected in ("python_tool_gate", "mcp_tool_gate", "ci_deploy_gate", "runtime_hook_demo"):
        assert expected in joined, f"matrix no longer cites {expected}: {_CLAIMED_EXAMPLES!r}"


def _gate_imports_and_calls(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return (gate entrypoints imported from gove_zone, call-target names)."""
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("gove_zone"):
            for alias in node.names:
                if alias.name in _GATE_ENTRYPOINTS:
                    imported.add(alias.name)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
    return imported, called


def _failclosed_handlers(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            continue
        for sub in ast.walk(node.type):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                names.add(sub.attr)
    return names & _FAILCLOSED_ERRORS


@pytest.mark.parametrize("token", _CLAIMED_EXAMPLES)
def test_shipped_example_exists(token: str) -> None:
    demo = _resolve_demo(token)
    assert demo.is_file(), (
        f"INTEGRATION_MATRIX.md cites '{token}' as Shipped + tested, but "
        f"{demo.relative_to(REPO_ROOT)} does not exist (claim/artifact drift)"
    )


@pytest.mark.parametrize("token", _CLAIMED_EXAMPLES)
def test_shipped_example_routes_through_gate(token: str) -> None:
    demo = _resolve_demo(token)
    tree = ast.parse(demo.read_text(encoding="utf-8"), filename=str(demo))
    imported, called = _gate_imports_and_calls(tree)

    assert imported, (
        f"{token}: imports no gove-zone gate entrypoint "
        f"({sorted(_GATE_ENTRYPOINTS)}); side effect would be ungoverned (ADV9)"
    )
    # A gate that is imported but never invoked is the "handler exists but not
    # wired" failure class — the import alone is not enough.
    assert imported & called, (
        f"{token}: gate entrypoint {sorted(imported)} is imported but never "
        f"called; the example does not route its side effect through the gate (ADV9)"
    )


@pytest.mark.parametrize("token", _CLAIMED_EXAMPLES)
def test_shipped_example_exercises_failclosed_branch(token: str) -> None:
    demo = _resolve_demo(token)
    tree = ast.parse(demo.read_text(encoding="utf-8"), filename=str(demo))
    handlers = _failclosed_handlers(tree)
    assert handlers, (
        f"{token}: no fail-closed except handler "
        f"({sorted(_FAILCLOSED_ERRORS)}); a shipped example must demonstrate the "
        f"gate denying a side effect, not only the happy ALLOW path"
    )
