"""
Direct Anthropic Claude-on-Vertex caller for Hermes ACGS.

This module intentionally avoids the Anthropic SDK so it can be dropped into a
Hermes runtime that already has `gcloud` auth available:

    python hermes_vertex_claude.py "Say hello"
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

try:
    from .hermes_acgs_middleware import HermesACGSMiddleware
except ImportError:  # pragma: no cover - supports direct file drop-in
    from hermes_acgs_middleware import HermesACGSMiddleware


DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_LOCATION = "global"
ANTHROPIC_VERTEX_VERSION = "vertex-2023-10-16"
MULTI_REGION_LOCATIONS = {"us", "eu"}


def vertex_endpoint(location: str) -> str:
    if location == "global":
        return "https://aiplatform.googleapis.com"
    if location in MULTI_REGION_LOCATIONS:
        return f"https://aiplatform.{location}.rep.googleapis.com"
    return f"https://{location}-aiplatform.googleapis.com"


def build_payload(prompt: str, *, max_tokens: int = 512, stream: bool = False) -> dict[str, Any]:
    return {
        "anthropic_version": ANTHROPIC_VERTEX_VERSION,
        "stream": stream,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }


def gcloud_access_token() -> str:
    result = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def raw_predict_url(*, project_id: str, location: str, model: str, stream: bool = False) -> str:
    method = "streamRawPredict" if stream else "rawPredict"
    return (
        f"{vertex_endpoint(location)}/v1/projects/{project_id}/locations/{location}"
        f"/publishers/anthropic/models/{model}:{method}"
    )


def post_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    access_token: str,
    timeout: float = 120,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Vertex AI request failed with HTTP {exc.code}: {body}") from exc


def extract_text(response: Mapping[str, Any]) -> str:
    parts = response.get("content", [])
    if isinstance(parts, list):
        text_parts = [
            part.get("text", "")
            for part in parts
            if isinstance(part, Mapping) and part.get("type") == "text"
        ]
        if text_parts:
            return "".join(text_parts)
    return json.dumps(response, ensure_ascii=False)


def generate_response(
    prompt: str,
    *,
    project_id: str,
    location: str = DEFAULT_LOCATION,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 512,
    access_token: str | None = None,
    request_func: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> str:
    payload = build_payload(prompt, max_tokens=max_tokens, stream=False)
    url = raw_predict_url(project_id=project_id, location=location, model=model)

    if request_func is None:
        token = access_token or gcloud_access_token()
        response = post_json(url, payload, access_token=token)
    else:
        response = dict(request_func(url, payload))

    return extract_text(response)


def generate_governed_response(
    prompt: str,
    *,
    project_id: str,
    acgs: HermesACGSMiddleware | None = None,
    context: Mapping[str, Any] | None = None,
    location: str = DEFAULT_LOCATION,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 512,
    access_token: str | None = None,
    request_func: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> str:
    middleware = acgs or HermesACGSMiddleware()
    draft = generate_response(
        prompt,
        project_id=project_id,
        location=location,
        model=model,
        max_tokens=max_tokens,
        access_token=access_token,
        request_func=request_func,
    )
    decision = middleware.check_final(draft, context=context)
    return middleware.apply_final_action(draft, decision)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Call Claude on Vertex AI with Hermes ACGS final governance.")
    parser.add_argument("prompt")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--location", default=DEFAULT_LOCATION)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--domain", default="")
    args = parser.parse_args(argv)

    context = {"domain": args.domain} if args.domain else None
    print(
        generate_governed_response(
            args.prompt,
            project_id=args.project_id,
            location=args.location,
            model=args.model,
            max_tokens=args.max_tokens,
            context=context,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
