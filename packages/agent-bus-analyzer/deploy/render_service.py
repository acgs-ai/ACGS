#!/usr/bin/env python3
"""Render the analyzer Cloud Run service manifest from environment values.

Used by .github/workflows/deploy-agent-bus-analyzer.yml. Stdlib-only and
fail-closed by design:

- every placeholder must have a non-empty environment value;
- values are restricted to a conservative character set so a misconfigured
  secret can never inject YAML structure into the manifest;
- no ``REPLACE_`` placeholder may survive rendering;
- the rendered manifest must preserve the deployment invariants: a single
  serving instance (``maxScale: "1"`` — the file-backed TraceStore is
  single-writer) and Secret-Manager-managed evidence-signing material
  (pinned ``secretKeyRef``, never an inline secret value).

Any violation aborts with a non-zero exit before a manifest is written.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path

#: Template placeholder -> environment variable that must supply its value.
PLACEHOLDERS: dict[str, str] = {
    "REPLACE_AT_DEPLOY_TIME": "RENDER_IMAGE",
    "REPLACE_GCP_PROJECT_NUMBER": "RENDER_PROJECT_NUMBER",
    "REPLACE_ANALYZER_RUNTIME_SERVICE_ACCOUNT": "RENDER_RUNTIME_SA",
    "REPLACE_ANALYZER_TRACE_BUCKET": "RENDER_TRACE_BUCKET",
}

#: Literal fragments that must survive rendering (deployment invariants).
REQUIRED_INVARIANTS: tuple[str, ...] = (
    'autoscaling.knative.dev/maxScale: "1"',
    "secretKeyRef:",
    "run.googleapis.com/secrets: evidence-signing-secret:projects/",
)

#: Image URIs, project numbers, SA emails, and bucket names all fit this.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._@:/-]+$")


class RenderError(ValueError):
    """Raised when rendering must fail closed."""


def render(template: str, values: Mapping[str, str]) -> str:
    """Substitute placeholders and enforce the deployment invariants."""
    rendered = template
    for placeholder, env_name in PLACEHOLDERS.items():
        value = values.get(env_name, "").strip()
        if not value:
            raise RenderError(f"fail-closed: missing value {env_name} for {placeholder}")
        if not _SAFE_VALUE.match(value):
            raise RenderError(
                f"fail-closed: {env_name} contains characters unsafe for the manifest"
            )
        if placeholder not in rendered:
            raise RenderError(f"fail-closed: template lost placeholder {placeholder}")
        rendered = rendered.replace(placeholder, value)

    # Comment lines may legitimately *mention* REPLACE_ (the template's header
    # documents the render contract); only live YAML lines are load-bearing.
    leftovers = [
        line.strip()
        for line in rendered.splitlines()
        if "REPLACE_" in line and not line.lstrip().startswith("#")
    ]
    if leftovers:
        raise RenderError("fail-closed: unrendered placeholder(s): " + "; ".join(leftovers))

    for invariant in REQUIRED_INVARIANTS:
        if invariant not in rendered:
            raise RenderError(
                f"fail-closed: deployment invariant missing after render: {invariant!r}"
            )

    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        rendered = render(args.template.read_text(encoding="utf-8"), os.environ)
    except (OSError, RenderError) as exc:
        print(f"render_service: {exc}", file=sys.stderr)
        return 1

    args.out.write_text(rendered, encoding="utf-8")
    print(f"render_service: wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
