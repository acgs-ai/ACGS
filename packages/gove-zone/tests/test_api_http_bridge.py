"""Dispatcher-level guards for the local console HTTP bridge in ``gove_zone.api``.

``handle_api_request`` is unit-testable and already exercised. What was not
covered is the layer that actually receives traffic: ``GoveZoneHandler``. A
route table that is correct in isolation proves nothing if the handler never
reaches it, mis-frames the response, or lets a malformed body raise inside the
server thread — so every assertion here goes through a real
``ThreadingHTTPServer`` over a socket rather than calling the handler directly.

The server binds 127.0.0.1 on an ephemeral port; nothing outside the loopback
interface is touched and no dependency beyond the standard library is needed.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer

import pytest

from gove_zone.api import GoveZoneHandler, handle_api_request


class _QuietHandler(GoveZoneHandler):
    """Same handler; request logging suppressed so the test output stays clean."""

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002 - stdlib hook
        return


@pytest.fixture
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(url: str, *, method: str = "GET", body: object = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - loopback only
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - loopback only
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


# --------------------------------------------------------------------------- #
# Routing through the real server
# --------------------------------------------------------------------------- #
def test_settings_route_is_reachable_over_http(base_url: str):
    status, headers, raw = _request(f"{base_url}/api/v1/settings")

    assert status == 200
    assert headers["content-type"] == "application/json"
    assert json.loads(raw) == []


def test_account_route_returns_the_console_contract_shape(base_url: str):
    status, _, raw = _request(f"{base_url}/api/v1/account")

    assert status == 200
    assert set(json.loads(raw)) == {"identity", "sessions", "actions"}


def test_actions_route_is_reachable_over_http(base_url: str):
    status, _, raw = _request(f"{base_url}/api/v1/actions")

    assert status == 200
    assert isinstance(json.loads(raw), list)


def test_post_action_test_route_is_reachable_over_http(base_url: str):
    status, _, raw = _request(
        f"{base_url}/api/v1/actions/test",
        method="POST",
        body={"tool": "file.write", "args": {}},
    )

    assert status == 200
    assert isinstance(json.loads(raw), dict)


def test_an_unknown_path_is_a_404_naming_the_path(base_url: str):
    status, _, raw = _request(f"{base_url}/api/v1/nope")

    assert status == 404
    assert json.loads(raw) == {"error": "not_found", "path": "/api/v1/nope"}


def test_a_post_to_a_get_only_route_is_not_served(base_url: str):
    """Method is part of the route key: POSTing to a GET route must 404 rather
    than fall through to the GET handler."""
    status, _, raw = _request(f"{base_url}/api/v1/settings", method="POST", body={})

    assert status == 404
    assert json.loads(raw)["error"] == "not_found"


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #
def test_content_length_matches_the_body_exactly(base_url: str):
    _, headers, raw = _request(f"{base_url}/api/v1/account")

    assert int(headers["content-length"]) == len(raw)


def test_head_returns_the_status_and_a_zero_length_body(base_url: str):
    status, headers, raw = _request(f"{base_url}/api/v1/settings", method="HEAD")

    assert status == 200
    assert headers["content-length"] == "0"
    assert raw == b""


def test_head_on_an_unknown_path_reports_the_same_status_as_get(base_url: str):
    head_status, _, _ = _request(f"{base_url}/api/v1/nope", method="HEAD")
    get_status, _, _ = _request(f"{base_url}/api/v1/nope")

    assert head_status == get_status == 404


def test_responses_are_key_sorted_so_they_are_byte_stable(base_url: str):
    first = _request(f"{base_url}/api/v1/account")[2]
    second = _request(f"{base_url}/api/v1/account")[2]

    assert first == second
    assert first == json.dumps(json.loads(first), sort_keys=True).encode()


# --------------------------------------------------------------------------- #
# Malformed input
# --------------------------------------------------------------------------- #
def test_a_malformed_json_body_is_treated_as_empty_not_a_server_error(base_url: str):
    """A body the client mangled must not raise inside the server thread."""
    req = urllib.request.Request(  # noqa: S310 - loopback only
        f"{base_url}/api/v1/actions/test",
        data=b"{not json",
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - loopback only
        assert resp.status == 200
        assert isinstance(json.loads(resp.read()), dict)


def test_a_body_less_post_is_handled(base_url: str):
    status, _, raw = _request(f"{base_url}/api/v1/actions/test", method="POST", body={})

    assert status == 200
    assert isinstance(json.loads(raw), dict)


def test_the_server_keeps_serving_after_a_malformed_request(base_url: str):
    _request(f"{base_url}/api/v1/actions/test", method="POST", body=None)

    status, _, _ = _request(f"{base_url}/api/v1/settings")

    assert status == 200


# --------------------------------------------------------------------------- #
# The handler and the route table agree
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/settings"),
        ("GET", "/api/v1/account"),
        ("GET", "/api/v1/actions"),
        ("POST", "/api/v1/actions/test"),
        ("GET", "/api/v1/unknown"),
    ],
)
def test_served_status_matches_the_route_table(base_url: str, method: str, path: str):
    """Guards the wiring specifically: if the handler stopped delegating to
    ``handle_api_request``, these would diverge."""
    expected_status, _ = handle_api_request(method, path, {})

    served_status, _, _ = _request(
        f"{base_url}{path}", method=method, body={} if method == "POST" else None
    )

    assert served_status == expected_status
