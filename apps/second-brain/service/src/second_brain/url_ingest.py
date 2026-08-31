import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx


class SafeUrlError(ValueError):
    pass


Address = IPv4Address | IPv6Address


class Resolver(Protocol):
    def resolve(self, hostname: str, port: int, deadline: float) -> tuple[Address, ...]: ...


class BoundTransport(Protocol):
    def get(
        self, url: str, host: str, address: Address, timeout: float, max_bytes: int
    ) -> "BoundResponse": ...


@dataclass(frozen=True)
class BoundResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes
    peer_address: Address | None


@dataclass(frozen=True)
class RedirectHop:
    uri: str
    chosen_address: str
    peer_address: str
    status_code: int


@dataclass(frozen=True)
class FetchResult:
    content: bytes
    mime_type: str
    final_uri: str
    chosen_address: str
    peer_address: str
    redirects: tuple[RedirectHop, ...]

    def __iter__(self) -> Iterator[object]:
        # Backward-compatible tuple unpacking for the original worker/tests.
        yield self.content
        yield self.mime_type
        yield self.final_uri


class SystemResolver:
    _CHILD = """
import json, socket, sys
answers = []
for item in socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM):
    value = item[4][0]
    if value not in answers:
        answers.append(value)
    if len(answers) >= 64:
        break
sys.stdout.write(json.dumps(answers, separators=(\",\", \":\")))
"""

    def __init__(self, child_code: str | None = None) -> None:
        self.child_code = child_code or self._CHILD

    def resolve(self, hostname: str, port: int, deadline: float) -> tuple[Address, ...]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeUrlError("URL fetch deadline exceeded")
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", self.child_code, hostname, str(port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env={"LANG": "C", "LC_ALL": "C"},
        )
        try:
            stdout, _ = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            self._terminate(process)
            raise SafeUrlError("URL fetch deadline exceeded") from None
        if process.returncode != 0 or len(stdout) > 16_384:
            raise SafeUrlError("URL resolution failed")
        try:
            values = json.loads(stdout)
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise ValueError
            return tuple(dict.fromkeys(ip_address(value) for value in values))
        except (ValueError, json.JSONDecodeError):
            raise SafeUrlError("URL resolution failed") from None

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=0.2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if process.poll() is None:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=1)


class HttpxBoundTransport:
    def get(
        self, url: str, host: str, address: Address, timeout: float, max_bytes: int
    ) -> BoundResponse:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        address_text = f"[{address}]" if address.version == 6 else str(address)
        target = parsed._replace(netloc=f"{address_text}:{port}").geturl()
        host_header = host if port in {80, 443} else f"{host}:{port}"
        request = httpx.Request(
            "GET",
            target,
            headers={"host": host_header, "accept-encoding": "identity"},
            extensions={"sni_hostname": host.encode()},
        )
        deadline = time.monotonic() + timeout
        with httpx.Client(follow_redirects=False, timeout=timeout, trust_env=False) as client:
            response = client.send(request, stream=True)
            try:
                encoding = response.headers.get("content-encoding", "identity").lower()
                if encoding not in {"", "identity"}:
                    raise SafeUrlError("URL content encoding is unsupported")
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        if int(declared) > max_bytes:
                            raise SafeUrlError("URL response exceeds configured byte limit")
                    except ValueError as exc:
                        raise SafeUrlError("URL response length is invalid") from exc
                content = bytearray()
                for block in response.iter_raw():
                    if time.monotonic() >= deadline:
                        raise SafeUrlError("URL fetch deadline exceeded")
                    content.extend(block)
                    if len(content) > max_bytes:
                        raise SafeUrlError("URL response exceeds configured byte limit")
                stream = response.extensions.get("network_stream")
                peer = stream.get_extra_info("server_addr") if stream is not None else None
                if not peer:
                    raise SafeUrlError("URL peer address was unavailable")
                actual = ip_address(peer[0])
            finally:
                response.close()
        return BoundResponse(response.status_code, dict(response.headers), bytes(content), actual)


def _public(address: Address) -> bool:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def validate_url_syntax(url: str) -> tuple[str, str, int]:
    if any(ord(character) < 32 or character == "\\" for character in url):
        raise SafeUrlError("URL contains forbidden syntax")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SafeUrlError("URL authority is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or "@" in parsed.netloc
        or "%" in parsed.hostname
    ):
        raise SafeUrlError("URL must be public HTTP or HTTPS without user information")
    expected_port = 443 if parsed.scheme == "https" else 80
    if port not in {None, expected_port}:
        raise SafeUrlError("URL port is not allowed")
    normalized = urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized, parsed.hostname, expected_port


def validate_url(
    url: str, resolver: Resolver, deadline: float | None = None
) -> tuple[str, str, Address]:
    normalized, hostname, expected_port = validate_url_syntax(url)
    resolution_deadline = deadline if deadline is not None else time.monotonic() + 10
    addresses = resolver.resolve(hostname, expected_port, resolution_deadline)
    if not addresses or any(not _public(address) for address in addresses):
        raise SafeUrlError("URL resolved to a prohibited address")
    return normalized, hostname, addresses[0]


def fetch_safe_url(
    url: str,
    *,
    resolver: Resolver | None = None,
    transport: BoundTransport | None = None,
    max_redirects: int = 3,
    max_bytes: int = 5_000_000,
    timeout: float = 10,
    deadline: float | None = None,
) -> FetchResult:
    resolver = resolver or SystemResolver()
    transport = transport or HttpxBoundTransport()
    deadline = min(deadline or float("inf"), time.monotonic() + timeout)
    current = url
    lineage: list[RedirectHop] = []
    for redirect in range(max_redirects + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeUrlError("URL fetch deadline exceeded")
        current, host, address = validate_url(current, resolver, deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeUrlError("URL fetch deadline exceeded")
        response = transport.get(current, host, address, remaining, max_bytes)
        if time.monotonic() >= deadline:
            raise SafeUrlError("URL fetch deadline exceeded")
        if response.peer_address is None:
            raise SafeUrlError("URL peer address was unavailable")
        if response.peer_address != address:
            raise SafeUrlError("URL peer address did not match validation")
        lineage.append(
            RedirectHop(
                current,
                str(address),
                str(response.peer_address),
                response.status_code,
            )
        )
        if 300 <= response.status_code < 400:
            if redirect == max_redirects or "location" not in response.headers:
                raise SafeUrlError("URL redirect limit exceeded")
            current = urljoin(current, response.headers["location"])
            continue
        if response.status_code < 200 or response.status_code >= 300:
            raise SafeUrlError("URL returned an unsuccessful status")
        if len(response.content) > max_bytes:
            raise SafeUrlError("URL response exceeds configured byte limit")
        encoding = response.headers.get("content-encoding", "identity").lower()
        if encoding not in {"", "identity"}:
            raise SafeUrlError("URL content encoding is unsupported")
        mime = response.headers.get("content-type", "").split(";", 1)[0].lower()
        if mime not in {
            "text/plain",
            "text/markdown",
            "text/html",
            "application/pdf",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }:
            raise SafeUrlError("URL content type is unsupported")
        return FetchResult(
            response.content,
            mime,
            current,
            str(address),
            str(response.peer_address),
            tuple(lineage),
        )
    raise SafeUrlError("URL redirect limit exceeded")
