import io
import json
import os
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pypdf import PdfWriter

from second_brain.parser_subprocess import (
    ParserIsolationFailure,
    _limits,
    _terminate_group,
    parse_document_isolated,
)


def test_parser_subprocess_round_trip_is_bounded_and_deterministic() -> None:
    parsed = parse_document_isolated(b"line one\r\nline two", "txt", 1_000, 5)
    assert parsed.text == "line one\nline two"
    assert parsed.passages[0].location == {"char_start": 0, "char_end": 17}


def test_parser_subprocess_uses_minimal_environment_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeProcess:
        returncode = 0
        pid = 123

        def communicate(self, request: bytes, timeout: float) -> tuple[bytes, bytes]:
            del request, timeout
            return (
                json.dumps(
                    {
                        "ok": True,
                        "text": "safe",
                        "passages": [{"text": "safe", "location": {}}],
                    }
                ).encode(),
                b"",
            )

    def fake_popen(command: list[str], **kwargs: Any) -> FakeProcess:
        captured.update({"command": command, **kwargs})
        return FakeProcess()

    monkeypatch.setenv("DATABASE_URL", "private-database-secret")
    monkeypatch.setenv("HTTPS_PROXY", "private-proxy-secret")
    monkeypatch.setenv("MODEL_API_KEY", "private-model-secret")
    monkeypatch.setattr("second_brain.parser_subprocess.subprocess.Popen", fake_popen)
    assert parse_document_isolated(b"safe", "txt", 100, 1).text == "safe"
    assert captured["shell"] is False
    assert captured["close_fds"] is True
    assert captured["start_new_session"] is True
    assert set(captured["env"]) == {"LANG", "LC_ALL", "PYTHONNOUSERSITE"}
    assert captured["stderr"] == subprocess.DEVNULL


def test_parser_subprocess_timeout_and_malformed_output_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[int] = []

    class SlowProcess:
        returncode = None
        pid = 456

        def communicate(self, request: bytes, timeout: float) -> tuple[bytes, bytes]:
            del request
            raise subprocess.TimeoutExpired("parser", timeout)

    monkeypatch.setattr(
        "second_brain.parser_subprocess.subprocess.Popen", lambda *args, **kwargs: SlowProcess()
    )
    monkeypatch.setattr(
        "second_brain.parser_subprocess._terminate_group",
        lambda process: terminated.append(process.pid),
    )
    with pytest.raises(ParserIsolationFailure, match="deadline"):
        parse_document_isolated(b"safe", "txt", 100, 0.01)
    assert terminated == [456]

    class MalformedProcess:
        returncode = 0
        pid = 789

        def communicate(self, request: bytes, timeout: float) -> tuple[bytes, bytes]:
            del request, timeout
            return b"not-json", b""

    monkeypatch.setattr(
        "second_brain.parser_subprocess.subprocess.Popen",
        lambda *args, **kwargs: MalformedProcess(),
    )
    with pytest.raises(ParserIsolationFailure, match="malformed"):
        parse_document_isolated(b"safe", "txt", 100, 1)


def test_parser_process_group_termination_reaches_descendants() -> None:
    program = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "print(child.pid,flush=True); time.sleep(60)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", program],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert process.stdout is not None
    descendant_pid = int(process.stdout.readline().decode().strip())
    try:
        _terminate_group(process)
        deadline = time.monotonic() + 2
        stat_path = Path(f"/proc/{descendant_pid}/stat")
        state: str | None = None
        while time.monotonic() < deadline and stat_path.exists():
            state = stat_path.read_text(encoding="utf-8").split()[2]
            if state == "Z":
                break
            time.sleep(0.01)
        assert process.poll() is not None
        assert not stat_path.exists() or state == "Z"
    finally:
        if process.poll() is None:
            process.kill()
        with suppress(ProcessLookupError):
            os.kill(descendant_pid, 9)


def test_parser_address_space_limit_is_enforced() -> None:
    process = subprocess.run(
        [sys.executable, "-c", "bytearray(600 * 1024 * 1024)"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        preexec_fn=lambda: _limits(2, 64_000),
    )
    assert process.returncode != 0


def test_parser_child_rejects_encrypted_empty_and_archive_bomb_documents() -> None:
    encrypted = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt("secret")
    writer.write(encrypted)
    with pytest.raises(ParserIsolationFailure):
        parse_document_isolated(encrypted.getvalue(), "pdf", 1_000, 5)

    empty = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(empty)
    with pytest.raises(ParserIsolationFailure):
        parse_document_isolated(empty.getvalue(), "pdf", 1_000, 5)

    archive_bytes = io.BytesIO()
    with ZipFile(archive_bytes, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        archive.writestr("word/document.xml", b"A" * 2_000_000)
    with pytest.raises(ParserIsolationFailure):
        parse_document_isolated(archive_bytes.getvalue(), "docx", 1_000, 5)
