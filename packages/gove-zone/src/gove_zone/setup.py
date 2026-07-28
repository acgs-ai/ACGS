"""Auto-setup for gove-zone in a host project.

The intent: an operator (or agent) runs ``gove-zone setup`` from anywhere
inside a project and gets back enough information to wire gove-zone into
the runtime hook of their choice — no hand-rolled JSON, no guessing about
audit paths, no silent missing deps.

Public surface:

* :func:`detect_environment` — read-only probe of host (interpreter,
  package install state, runtime config files present).
* :func:`validate_dependencies` — confirm gove-zone import works AND that
  the audit path target is writable.
* :func:`generate_config` — render Claude Code ``PreToolUse`` JSON snippet
  + the env vars needed for enforce mode.
* :func:`instructions` — produce a single agent-facing markdown block with
  copy-paste-ready setup steps tailored to the detected environment.

All four functions are pure-ish: ``detect_environment`` and
``validate_dependencies`` touch the filesystem read-only; the others
return data only.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from gove_zone.integration import current_gate_mode, resolve_audit_path

__all__ = [
    "EnvironmentReport",
    "ValidationReport",
    "detect_environment",
    "validate_dependencies",
    "generate_config",
    "instructions",
]


@dataclass(frozen=True)
class EnvironmentReport:
    project_dir: str | None
    cwd: str
    python: str
    python_version: str
    uv_installed: bool
    gove_zone_installed: bool
    gove_zone_version: str | None
    audit_path: str
    runtime_hosts: list[str] = field(default_factory=list)
    gate_mode: str = "observe"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ValidationReport:
    ok: bool
    checks: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _project_dir() -> Path:
    raw = os.environ.get("CLAUDE_PROJECT_DIR")
    if raw:
        return Path(raw)
    return Path.cwd()


def _detect_runtime_hosts(project_dir: Path) -> list[str]:
    hosts: list[str] = []
    if (project_dir / ".claude").is_dir():
        hosts.append("claude-code")
    if (project_dir / ".codex").is_dir() or (project_dir / "AGENTS.md").exists():
        hosts.append("codex")
    if (project_dir / ".cursor").is_dir():
        hosts.append("cursor")
    return hosts


def _gove_zone_version() -> str | None:
    try:
        from gove_zone import __version__

        return str(__version__)
    except Exception:  # noqa: BLE001
        return None


def detect_environment() -> EnvironmentReport:
    proj = _project_dir()
    return EnvironmentReport(
        project_dir=str(proj) if proj.exists() else None,
        cwd=os.getcwd(),
        python=sys.executable,
        python_version=sys.version.split()[0],
        uv_installed=shutil.which("uv") is not None,
        gove_zone_installed=_gove_zone_version() is not None,
        gove_zone_version=_gove_zone_version(),
        audit_path=str(resolve_audit_path()),
        runtime_hosts=_detect_runtime_hosts(proj),
        gate_mode=current_gate_mode().value,
    )


def _check_writable(path: Path) -> dict[str, Any]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        probe = path.parent / ".gove-zone-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return {"name": "audit_path_writable", "ok": True, "path": str(path)}
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "audit_path_writable",
            "ok": False,
            "path": str(path),
            "error": repr(exc),
        }


def validate_dependencies() -> ValidationReport:
    checks: list[dict[str, Any]] = []

    try:
        import gove_zone  # noqa: F401

        checks.append({"name": "gove_zone_importable", "ok": True})
    except ImportError as exc:
        checks.append(
            {
                "name": "gove_zone_importable",
                "ok": False,
                "error": repr(exc),
                "fix": "uv sync   # or: pip install -e packages/gove-zone",
            }
        )

    try:
        from gove_zone.integration import emit_receipt_for_hook  # noqa: F401

        checks.append({"name": "integration_adapter_present", "ok": True})
    except ImportError as exc:
        checks.append(
            {
                "name": "integration_adapter_present",
                "ok": False,
                "error": repr(exc),
            }
        )

    checks.append(_check_writable(resolve_audit_path()))

    return ValidationReport(ok=all(c["ok"] for c in checks), checks=checks)


def generate_config(*, enforce: bool = False) -> dict[str, Any]:
    """Render the host-runtime config payload."""
    # ``--project`` pins uv's workspace resolution to the project root. Without it the
    # hook inherits the tool call's cwd; outside the workspace uv exits with
    # "No `pyproject.toml` found" before importing gove_zone, so no receipt is emitted.
    hook_cmd = (
        'uv run --project "$CLAUDE_PROJECT_DIR" --package gove-zone '
        'python "$CLAUDE_PROJECT_DIR/.claude/hooks/acgs-emit-receipt.py"'
    )
    env: dict[str, str] = {}
    if enforce:
        env["GOVE_ZONE_GATE_MODE"] = "enforce"

    return {
        "claude_code": {
            "settings_fragment": {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Edit|Write|MultiEdit",
                            "hooks": [{"type": "command", "command": hook_cmd}],
                        },
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": hook_cmd}],
                        },
                    ]
                }
            },
            "env": env,
        }
    }


def instructions(*, enforce: bool = False) -> str:
    env_report = detect_environment()
    cfg = generate_config(enforce=enforce)
    fragment = json.dumps(cfg["claude_code"]["settings_fragment"], indent=2)
    mode_line = (
        "Run with `GOVE_ZONE_GATE_MODE=enforce` to make the gate fail-closed."
        if not enforce
        else "`GOVE_ZONE_GATE_MODE=enforce` is set: any emission failure exits non-zero."
    )

    return (
        "# gove-zone setup\n\n"
        f"- Project: `{env_report.project_dir or env_report.cwd}`\n"
        f"- Python: `{env_report.python_version}` at `{env_report.python}`\n"
        f"- uv detected: `{env_report.uv_installed}`\n"
        f"- gove-zone installed: `{env_report.gove_zone_installed}` "
        f"(version {env_report.gove_zone_version or 'n/a'})\n"
        f"- Detected runtime hosts: `{', '.join(env_report.runtime_hosts) or 'none'}`\n"
        f"- Audit chain path: `{env_report.audit_path}`\n"
        f"- Current gate mode: `{env_report.gate_mode}`\n\n"
        "## 1. Install\n"
        "```bash\n"
        "uv sync   # or: pip install -e packages/gove-zone\n"
        "```\n\n"
        "## 2. Merge this into `.claude/settings.json` under `hooks`\n"
        "```json\n"
        f"{fragment}\n"
        "```\n\n"
        "## 3. Gate mode\n"
        f"{mode_line}\n\n"
        "## 4. Replay re-derivation (opt-in)\n"
        "Replay verifies the audit chain by default. To additionally **re-derive**\n"
        "decisions — re-run the original policy against the original arguments —\n"
        "enable the raw-args side-store. It is off by default and stores raw\n"
        "arguments, so treat it as an explicit privacy cost; use a redaction\n"
        "predicate for sensitive calls.\n\n"
        "```python\n"
        "from gove_zone import Kernel, ReplaySideStore\n"
        'store = ReplaySideStore(".gove-zone/replay.jsonl")\n'
        "kernel = Kernel(policy=..., audit=..., side_store=store)\n"
        "```\n\n"
        "```bash\n"
        "gove-zone replay --audit .gove-zone/audit.jsonl \\\n"
        "  --side-store .gove-zone/replay.jsonl --policy-bundle policy.bundle.json --event EV\n"
        "```\n\n"
        "`GOVE_ZONE_REPLAY_STORE` is reserved for the deferred runtime-hook wiring;\n"
        "today the side-store is enabled via the `Kernel(side_store=...)` constructor\n"
        "and the `gove-zone replay --side-store` flag.\n"
    )
