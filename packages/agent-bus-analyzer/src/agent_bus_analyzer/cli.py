"""CLI entry point: ``python -m agent_bus_analyzer <subcommand>``.

Foundational scope (T069): only ``serve`` is functional. Other subcommands
(``observer`` per T072, ``verify`` per T055, ``dev-traffic`` per T061) land
in their respective user-story phases. The subparsers exist now so
``--help`` lists the surface and unimplemented subcommands fail loudly with
a non-zero exit code instead of behaving silently.
"""

from __future__ import annotations

import argparse
import sys


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "agent_bus_analyzer.api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )
    return 0


def _cmd_not_implemented(args: argparse.Namespace) -> int:
    print(
        f"agent_bus_analyzer: subcommand '{args.cmd}' is not implemented in this build",
        file=sys.stderr,
    )
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent_bus_analyzer")
    subs = parser.add_subparsers(dest="cmd", required=True)

    p_serve = subs.add_parser("serve", help="Run the FastAPI HTTP server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8042)
    p_serve.add_argument("--log-level", default="info")
    p_serve.set_defaults(func=_cmd_serve)

    for name in ("observer", "verify", "dev-traffic"):
        sub = subs.add_parser(name, help=f"(planned) {name} — not yet implemented")
        sub.set_defaults(func=_cmd_not_implemented)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
