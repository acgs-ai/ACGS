#!/usr/bin/env python3
"""Empirical proof of the enforcement CEILING (Step 2D), with REAL processes.

This is a self-refutation, not an enforcement demo. It shows that the two
enforcement mechanisms available WITHOUT an OS privilege boundary —
(1) an in-process application choke point, and (2) a same-UID filesystem
permission boundary (chmod read-only) — are both bypassed by ordinary
mutation carriers. Each case asserts the bypass SUCCEEDS and the governed
byte actually changed.

Conclusion it establishes: to make "no valid authorization → no governed state
change" true across all carriers, enforcement must live at a layer an ordinary
same-UID process cannot escape (separate UID / immutable bit / mount / broker
holding a privilege the mutator lacks). That layer does not exist in the
current execution model, which is why the round's verdict is BLOCKED.

Uses only the process's own temp dir. Real `subprocess`, real `bash`, real
`open('w')`. No gove-zone import, no repo mutation.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Result:
    name: str
    ceiling_confirmed: bool  # True = bypass succeeded = enforcement does NOT dominate
    detail: str


def _governed_file(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    f = base / "governed.txt"
    f.write_text("CANONICAL\n")
    return f


def demo_in_process_choke_bypassed(base: Path) -> Result:
    """An in-process 'gate' object is irrelevant to code that just writes."""
    f = _governed_file(base)

    class InProcessGate:
        def __init__(self) -> None:
            self.authorized = False  # nothing was authorized

        def write(self, path: Path, data: str) -> None:
            if not self.authorized:
                raise PermissionError("gate: denied")
            path.write_text(data)

    gate = InProcessGate()
    # Attacker does not use the gate. Same process, same interpreter.
    f.write_text("MUTATED_BYPASSING_GATE\n")
    changed = f.read_text() == "MUTATED_BYPASSING_GATE\n"
    return Result(
        "in-process choke point",
        ceiling_confirmed=changed,
        detail="raw write ignores the gate object entirely (any code with the path can mutate)",
    )


def demo_chmod_readonly_bypassed_by_owner(base: Path) -> Result:
    """Same-UID chmod 0444 is reversible by the owner — subprocess chmods back."""
    f = _governed_file(base)
    os.chmod(f, 0o444)  # "seal" the governed file read-only
    before = f.read_text()
    # Ordinary subprocess, same UID: restore write, mutate, done.
    script = f"import os,pathlib; p=pathlib.Path({str(f)!r}); os.chmod(p,0o644); p.write_text('MUTATED_AFTER_CHMOD\\n')"
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    after = f.read_text()
    changed = after == "MUTATED_AFTER_CHMOD\n" and before != after
    return Result(
        "same-UID chmod 0444 boundary",
        ceiling_confirmed=changed and proc.returncode == 0,
        detail="owner subprocess chmod u+w then wrote — a same-UID permission bit is not a boundary",
    )


def demo_shell_operator_bypass(base: Path) -> Result:
    """A shell redirect mutates the file with no governed binary named."""
    f = _governed_file(base)
    before = f.read_text()
    # execution.py marks this decidable=False and does not route it anywhere.
    proc = subprocess.run(
        ["bash", "-c", f"echo SHELL_MUTATED > {f}"], capture_output=True, text=True
    )
    after = f.read_text()
    changed = after.strip() == "SHELL_MUTATED" and before != after
    return Result(
        "shell operator redirect (decidable=False carrier)",
        ceiling_confirmed=changed and proc.returncode == 0,
        detail="`echo > file` mutated governed state with no governed binary to classify",
    )


def demo_subprocess_direct_write(base: Path) -> Result:
    """A child process writes the governed file directly."""
    f = _governed_file(base)
    before = f.read_text()
    proc = subprocess.run(
        [sys.executable, "-c", f"open({str(f)!r},'w').write('SUBPROC_MUTATED\\n')"],
        capture_output=True,
        text=True,
    )
    after = f.read_text()
    changed = after == "SUBPROC_MUTATED\n" and before != after
    return Result(
        "subprocess direct filesystem write",
        ceiling_confirmed=changed and proc.returncode == 0,
        detail="a child process the in-process gate never sees mutated the file",
    )


DEMOS = [
    demo_in_process_choke_bypassed,
    demo_chmod_readonly_bypassed_by_owner,
    demo_shell_operator_bypass,
    demo_subprocess_direct_write,
]


def run(work_dir: Path) -> list[Result]:
    out: list[Result] = []
    for i, fn in enumerate(DEMOS):
        try:
            out.append(fn(work_dir / f"d{i:02d}"))
        except Exception as exc:
            out.append(Result(fn.__name__, False, f"demo error: {type(exc).__name__}: {exc}"))
    return out


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ceiling-demo-") as tmp:
        results = run(Path(tmp))
    width = max(len(r.name) for r in results)
    # The ceiling is PROVEN only if EVERY bypass actually succeeded. A demo that
    # failed to bypass would mean the environment has stronger enforcement than
    # assumed — report it rather than silently claiming the ceiling.
    all_confirmed = all(r.ceiling_confirmed for r in results)
    for r in results:
        tag = "BYPASSED" if r.ceiling_confirmed else "BLOCKED?"
        print(f"[{tag}] {r.name.ljust(width)}  {r.detail}")
    print()
    if all_confirmed:
        print(
            "CEILING CONFIRMED: same-UID in-process and permission-bit enforcement do NOT "
            "dominate subprocess/shell/direct-write carriers. OS-level privilege separation "
            "is required; it is absent here. (Step 2D)"
        )
        return 0
    print(
        "UNEXPECTED: at least one bypass did not succeed — the environment may enforce more "
        "than assumed. Investigate before relying on this ceiling proof."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
