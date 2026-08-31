import base64
import json
import math
import os
import resource
import signal
import subprocess
import sys
from contextlib import suppress
from typing import Any

from second_brain.parsers import ParsedDocument, ParseFailure, Passage, parse_document


class ParserIsolationFailure(ParseFailure):
    pass


def _limits(timeout: float, max_output_bytes: int) -> None:
    memory_bytes = 512 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    cpu_seconds = max(1, math.ceil(timeout))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_bytes, max_output_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def parse_document_isolated(
    data: bytes,
    source_type: str,
    max_chars: int,
    timeout: float,
) -> ParsedDocument:
    max_output = max(64_000, min(max_chars * 4 + 64_000, 32_000_000))
    request = json.dumps(
        {
            "data": base64.b64encode(data).decode("ascii"),
            "source_type": source_type,
            "max_chars": max_chars,
        },
        separators=(",", ":"),
    ).encode()
    process = subprocess.Popen(
        [sys.executable, "-m", "second_brain.parser_subprocess", "--child"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1"},
        close_fds=True,
        start_new_session=True,
        shell=False,
        preexec_fn=lambda: _limits(timeout, max_output),
    )
    try:
        output, _ = process.communicate(request, timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        _terminate_group(process)
        raise ParserIsolationFailure("parser subprocess exceeded its deadline") from None
    if process.returncode != 0 or len(output) > max_output:
        raise ParserIsolationFailure("parser subprocess failed safely")
    try:
        result: dict[str, Any] = json.loads(output)
        if not result.get("ok"):
            raise ParserIsolationFailure(str(result.get("error", "parser rejected the source")))
        passages = tuple(Passage(item["text"], item["location"]) for item in result["passages"])
        return ParsedDocument(result["text"], passages)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, ParserIsolationFailure):
            raise
        raise ParserIsolationFailure("parser subprocess returned a malformed result") from exc


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=0.5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def _child() -> int:
    try:
        request = json.loads(sys.stdin.buffer.read())
        data = base64.b64decode(request["data"], validate=True)
        parsed = parse_document(data, request["source_type"], int(request["max_chars"]))
        result = {
            "ok": True,
            "text": parsed.text,
            "passages": [
                {"text": passage.text, "location": passage.location} for passage in parsed.passages
            ],
        }
    except Exception as exc:
        result = {"ok": False, "error": type(exc).__name__}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__" and sys.argv[1:] == ["--child"]:
    raise SystemExit(_child())
