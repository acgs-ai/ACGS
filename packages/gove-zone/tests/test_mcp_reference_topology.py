from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from inspect import signature
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

from gove_zone.mcp_reference import (
    MCPReferenceHTTPGateway,
    create_reference_http_gateway,
)
from gove_zone.mcp_security import (
    MCPOriginError,
    MCPOriginReasonCode,
    MCPOriginValidator,
    MCPPrivateServicePin,
    _mint_reference_fixture_http_origin,
)

ROOT = Path(__file__).resolve().parents[3]
TOPOLOGY = ROOT / "packages/gove-zone/examples/mcp-tool-gateway/reference-topology"


def test_exact_https_private_service_pin_and_dns_reconciliation() -> None:
    answers = ["172.30.0.10"]
    validator = MCPOriginValidator(resolver=lambda _host, _port: tuple(answers))
    pin = MCPPrivateServicePin(
        hostname="downstream",
        port=8000,
        expected_addresses=("172.30.0.10",),
    )
    origin = validator.validate_private_service(
        server_id="fixture-server",
        url="https://downstream:8000/mcp",
        pin=pin,
    )
    assert origin.test_local is False
    answers[:] = ["172.30.0.11"]
    with pytest.raises(MCPOriginError) as raised:
        validator.reconcile(origin)
    assert raised.value.reason_code is MCPOriginReasonCode.DNS_REBINDING


def test_private_service_https_is_not_fixture_local() -> None:
    validator = MCPOriginValidator(resolver=lambda _host, _port: ("10.10.0.8",))
    origin = validator.validate_private_service(
        server_id="internal-production-service",
        url="https://payments.internal:8443/mcp",
        pin=MCPPrivateServicePin(
            hostname="payments.internal",
            port=8443,
            expected_addresses=("10.10.0.8",),
        ),
    )
    assert origin.test_local is False


@pytest.mark.parametrize(
    "addresses",
    [
        ("172.30.0.10", "8.8.8.8"),
        ("169.254.169.254",),
        ("fe80::a9fe:a9fe",),
        ("127.0.0.1",),
        ("192.0.2.10",),
        ("2001:db8::10",),
    ],
)
def test_private_service_pin_rejects_non_private_unicast(addresses: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        MCPPrivateServicePin(
            hostname="downstream",
            port=8000,
            expected_addresses=addresses,
        )


def test_public_private_service_pin_has_no_fixture_http_escape_hatch() -> None:
    with pytest.raises(TypeError):
        MCPPrivateServicePin(  # type: ignore[call-arg]
            hostname="downstream",
            port=8000,
            expected_addresses=("172.30.0.10",),
            allow_fixture_http=True,
        )


@pytest.mark.parametrize(
    "hostname",
    [
        "2130706433",
        "0177.0.0.1",
        "0x7f000001",
        "127.1",
        "fd00::1%eth0",
        "fd00::1%25eth0",
    ],
)
def test_private_service_pin_rejects_noncanonical_or_zoned_hosts(hostname: str) -> None:
    with pytest.raises(ValueError):
        MCPPrivateServicePin(
            hostname=hostname,
            port=8000,
            expected_addresses=("172.30.0.10",),
        )


@pytest.mark.parametrize(
    "address",
    [
        "2130706433",
        "0177.0.0.1",
        "0x7f000001",
        "127.1",
        "fd00::1%eth0",
        "fd00::1%25eth0",
        "fd00:0:0:0:0:0:0:1",
    ],
)
def test_private_service_pin_rejects_noncanonical_or_zoned_addresses(address: str) -> None:
    with pytest.raises(ValueError):
        MCPPrivateServicePin(
            hostname="downstream",
            port=8000,
            expected_addresses=(address,),
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://2130706433:8000/mcp",
        "https://0177.0.0.1:8000/mcp",
        "https://0x7f000001:8000/mcp",
        "https://127.1:8000/mcp",
        "https://[fd00::1%25eth0]:8000/mcp",
        "https://[fd00::1%eth0]:8000/mcp",
    ],
)
def test_validator_rejects_noncanonical_or_zoned_url_hosts(url: str) -> None:
    validator = MCPOriginValidator(resolver=lambda _host, _port: ("172.30.0.10",))
    pin = MCPPrivateServicePin(
        hostname="downstream",
        port=8000,
        expected_addresses=("172.30.0.10",),
    )
    with pytest.raises(MCPOriginError) as raised:
        validator.validate_private_service(server_id="fixture-server", url=url, pin=pin)
    assert raised.value.reason_code is MCPOriginReasonCode.INVALID_ORIGIN


def test_private_service_pin_rejects_wrong_host_port_ip_and_http_default() -> None:
    validator = MCPOriginValidator(resolver=lambda _host, _port: ("172.30.0.10",))
    pin = MCPPrivateServicePin(
        hostname="downstream",
        port=8000,
        expected_addresses=("172.30.0.10",),
    )
    with pytest.raises(MCPOriginError) as http_denied:
        validator.validate_private_service(
            server_id="fixture-server",
            url="http://downstream:8000/mcp",
            pin=pin,
        )
    assert http_denied.value.reason_code is MCPOriginReasonCode.TLS_REQUIRED
    for url in (
        "https://other:8000/mcp",
        "https://downstream:8443/mcp",
    ):
        with pytest.raises(MCPOriginError) as mismatch:
            validator.validate_private_service(
                server_id="fixture-server",
                url=url,
                pin=pin,
            )
        assert mismatch.value.reason_code is MCPOriginReasonCode.ORIGIN_MISMATCH
    changed = MCPOriginValidator(resolver=lambda _host, _port: ("172.30.0.11",))
    with pytest.raises(MCPOriginError) as wrong_ip:
        changed.validate_private_service(
            server_id="fixture-server",
            url="https://downstream:8000/mcp",
            pin=pin,
        )
    assert wrong_ip.value.reason_code is MCPOriginReasonCode.DNS_REBINDING


def test_compose_enforces_two_internal_networks_and_secret_isolation() -> None:
    document = yaml.safe_load((TOPOLOGY / "compose.yaml").read_text(encoding="utf-8"))
    services = document["services"]
    assert set(document["networks"]) == {"ingress", "backend"}
    assert all(value["internal"] is True for value in document["networks"].values())
    assert set(services["probe"]["networks"]) == {"ingress"}
    assert set(services["downstream"]["networks"]) == {"backend"}
    assert services["downstream"]["networks"]["backend"] == {"ipv4_address": "172.30.0.10"}
    assert set(services["gateway"]["networks"]) == {"ingress", "backend"}
    assert document["networks"]["backend"]["ipam"]["config"] == [{"subnet": "172.30.0.0/24"}]
    assert all("ports" not in service for service in services.values())
    assert "secrets" not in document
    assert all("volumes" not in service for service in services.values())
    credential_reference = "${ACGS_DOWNSTREAM_CREDENTIAL:?set ACGS_DOWNSTREAM_CREDENTIAL}"
    assert "ACGS_DOWNSTREAM_CREDENTIAL" not in services["probe"]["environment"]
    assert services["gateway"]["environment"]["ACGS_DOWNSTREAM_CREDENTIAL"] == (
        credential_reference
    )
    assert services["downstream"]["environment"]["ACGS_DOWNSTREAM_CREDENTIAL"] == (
        credential_reference
    )
    assert not {
        "ACGS_DOWNSTREAM_URL",
        "ACGS_DOWNSTREAM_HOST",
        "ACGS_DOWNSTREAM_PORT",
        "ACGS_DOWNSTREAM_EXPECTED_IP",
    }.intersection(services["gateway"]["environment"])
    assert "docker.sock" not in json.dumps(services["probe"], sort_keys=True)
    script = (TOPOLOGY / "run-demo.sh").read_text(encoding="utf-8")
    assert "secrets.token_urlsafe(48)" in script
    assert "unset ACGS_DOWNSTREAM_CREDENTIAL" in script
    assert "fixture material leaked into evidence" in script
    probe_config = json.dumps(services["probe"], sort_keys=True)
    assert "downstream" not in probe_config
    assert "172.30.0.10" not in probe_config
    for service in services.values():
        assert service["user"] == ("${ACGS_RUNTIME_UID:-10001}:${ACGS_RUNTIME_GID:-10001}")
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["tmpfs"]


def test_reference_sources_use_public_gateway_factory_without_parallel_auth() -> None:
    gateway = (TOPOLOGY / "gateway.py").read_text(encoding="utf-8")
    probe = (TOPOLOGY / "probe.py").read_text(encoding="utf-8")
    compose = (TOPOLOGY / "compose.yaml").read_text(encoding="utf-8")
    assert "create_reference_http_gateway" in gateway
    assert "build_mcp_server(runtime.gateway)" in gateway
    assert "MCPPrivateServicePin" not in gateway
    assert "class Authorization" not in gateway
    assert "class Policy" not in gateway
    assert "class Receipt" not in gateway
    assert '"downstream"' not in probe
    assert "http://downstream" not in probe
    assert "ACGS_DOWNSTREAM" not in probe
    assert "fallback" not in compose.lower()


def test_reference_bundle_does_not_expose_raw_transport_or_secrets() -> None:
    runtime = object.__new__(MCPReferenceHTTPGateway)
    object.__setattr__(runtime, "gateway", object())
    object.__setattr__(runtime, "_transport", {"secret": "must-not-appear"})
    public = {name for name in dir(runtime) if not name.startswith("_")}
    assert public == {"aclose", "gateway"}
    assert all(
        marker not in public for marker in ("transport", "call_tool", "credential", "origin")
    )
    assert "must-not-appear" not in repr(runtime)
    assert "secret" not in repr(runtime).lower()
    with pytest.raises(TypeError):
        # Not a dataclass by design, which is exactly what this asserts: the
        # runtime must not be trivially serializable out of the process.
        asdict(runtime)  # type: ignore[call-overload]
    with pytest.raises(TypeError):
        json.dumps(runtime)


def test_reference_factory_has_no_target_selector_and_rejects_extra_targets() -> None:
    factory_signature = signature(create_reference_http_gateway)
    # The point of this pin is that the caller cannot choose a *target*: the
    # origin and downstream are fixed by the factory.  health_token and
    # token_verifier are identity seams, not targets -- neither can redirect the
    # gateway at a different server.
    assert set(factory_signature.parameters) == {
        "state_dir",
        "inbound_token",
        "session_id",
        "validator",
        "downstream_credential",
        "adapter_timeout",
        "health_token",
        "token_verifier",
    }
    base_arguments = {
        "state_dir": Path("/fixture-state"),
        "inbound_token": "fixture-inbound-token",
        "session_id": "fixture-session",
        "validator": MCPOriginValidator(),
        "downstream_credential": object(),
    }
    for selector in (
        {"fixture_url": "http://other:8000/mcp"},
        {"fixture_hostname": "other"},
        {"fixture_port": 9000},
        {"fixture_expected_addresses": ("10.0.0.8",)},
        {"fixture_expected_addresses": ("fd00::8",)},
    ):
        with pytest.raises(TypeError):
            factory_signature.bind(**base_arguments, **selector)


def test_fixture_mint_is_fixed_and_dns_mismatch_fails_closed() -> None:
    observed: list[tuple[str, int]] = []

    def wrong_resolver(hostname: str, port: int) -> tuple[str, ...]:
        observed.append((hostname, port))
        return ("172.30.0.11",)

    mint_signature = signature(_mint_reference_fixture_http_origin)
    assert set(mint_signature.parameters) == {"validator"}
    with pytest.raises(TypeError):
        mint_signature.bind(
            validator=MCPOriginValidator(),
            hostname="other",
            expected_addresses=("10.0.0.8",),
        )
    with pytest.raises(MCPOriginError) as raised:
        _mint_reference_fixture_http_origin(validator=MCPOriginValidator(resolver=wrong_resolver))
    assert raised.value.reason_code is MCPOriginReasonCode.DNS_REBINDING
    assert observed == [("downstream", 8000)]


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
def test_live_container_reference_topology() -> None:
    completed = subprocess.run(
        [str(TOPOLOGY / "run-demo.sh")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=360,
    )
    evidence = json.loads(completed.stdout)
    governed = evidence["governed"]
    gateway_down = evidence["gateway_down"]
    assert governed["allowed"]["executed"] is True
    assert governed["downstream_effect_count"] == 1
    assert governed["denied_additional_effects"] == 0
    assert governed["direct_bypass"] is False
    assert governed["actor_token_present_downstream"] is False
    assert all(governed["denied_reason_codes"].values())
    assert gateway_down == {
        "mode": "gateway-down",
        "gateway_available": False,
        "direct_bypass": False,
        "fallback_executed": False,
    }
    assert "credential" not in completed.stdout.lower()
    assert "ACGS_DOWNSTREAM_CREDENTIAL" not in completed.stdout
    assert "fixture-downstream-credential" not in completed.stdout


# --------------------------------------------------------------------------
# Remote override: exactly one published TLS gateway port, none downstream.
# --------------------------------------------------------------------------

_REMOTE_TOPOLOGY = (
    Path(__file__).resolve().parents[1] / "examples" / "mcp-tool-gateway" / "reference-topology"
)


def _remote_compose() -> dict[str, Any]:
    document = yaml.safe_load(
        (_REMOTE_TOPOLOGY / "compose.remote.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(document, dict)
    return cast("dict[str, Any]", document)


def test_remote_override_publishes_only_the_gateway_tls_port_on_loopback() -> None:
    services = _remote_compose()["services"]
    assert services["gateway"]["ports"] == ["127.0.0.1:8443:8443"]


def test_remote_override_publishes_no_downstream_host_port() -> None:
    services = _remote_compose()["services"]
    assert services["downstream"]["ports"] == []


def test_remote_override_mounts_secrets_read_only() -> None:
    volumes = _remote_compose()["services"]["gateway"]["volumes"]
    # ":ro,z" keeps the mount read-only while relabelling for SELinux hosts.
    assert all("ro" in str(item).rsplit(":", 1)[-1].split(",") for item in volumes)


def test_remote_override_passes_secrets_as_paths_not_values() -> None:
    """Runtime gets mounted secret file paths; env values are inert placeholders."""

    environment = _remote_compose()["services"]["gateway"]["environment"]
    for name in ("ACGS_DOWNSTREAM_CREDENTIAL_FILE", "ACGS_INBOUND_IDENTITY_FILE"):
        assert environment[name].startswith("/run/acgs/")
    for name in ("ACGS_DOWNSTREAM_CREDENTIAL", "ACGS_INBOUND_IDENTITY"):
        assert environment[name].startswith("unused-in-remote-mode")


def test_remote_override_grants_no_docker_socket_or_privilege() -> None:
    compose = _remote_compose()
    rendered = json.dumps(compose)
    assert "docker.sock" not in rendered
    assert "privileged" not in rendered


def test_remote_gateway_entrypoint_reads_no_secret_from_the_environment() -> None:
    source = (_REMOTE_TOPOLOGY / "gateway_remote.py").read_text(encoding="utf-8")
    # Secrets are read through read_secret_file from a mounted path, never os.environ.
    assert 'read_secret_file(Path(os.environ["ACGS_DOWNSTREAM_CREDENTIAL_FILE"]))' in source
    assert 'read_secret_file(Path(os.environ["ACGS_INBOUND_IDENTITY_FILE"]))' in source


def test_remote_demo_never_mounts_the_fixture_ca_private_key() -> None:
    script = (_REMOTE_TOPOLOGY / "run-remote-demo.sh").read_text(encoding="utf-8")
    compose = json.dumps(_remote_compose())
    # The CA private key lives in its own generator directory, which is not the
    # directory mounted into the gateway.
    assert 'CA_DIR="$WORK/ca-private"' in script
    assert 'SECRET_DIR="$WORK/secrets"' in script
    assert "ca-private" not in compose


def _docker_daemon_is_reachable() -> bool:
    """Docker is unavailable only if the CLI is absent or the daemon refuses us."""

    if shutil.which("docker") is None:
        return False
    try:
        probe = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


@pytest.mark.skipif(
    not _docker_daemon_is_reachable(),
    reason="Docker CLI or daemon is unavailable",
)
def test_live_container_remote_topology() -> None:
    """Run the live remote TLS demo and assert its governance results hold.

    Invoked through ``uv run ... sh`` so the demo's host-side minting uses the
    workspace interpreter.  The script self-execs under uv when run directly, so
    this and a bare ``sh run-remote-demo.sh`` take the same path.
    """

    completed = subprocess.run(
        [
            "uv",
            "run",
            "--package",
            "gove-zone",
            "sh",
            str(_REMOTE_TOPOLOGY / "run-remote-demo.sh"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=1500,
    )
    results = [line for line in completed.stderr.splitlines() if line.startswith("ok: ")]
    failures = [line for line in completed.stderr.splitlines() if line.startswith("FAIL")]

    assert failures == []
    assert completed.returncode == 0
    # The demo asserts the whole remote posture: published-port shape, network
    # isolation, the governed call, the health-authority attack, and the
    # gateway-down case.  Guard the count so a silently shortened demo fails.
    assert len(results) >= 22, f"only {len(results)} security results: {completed.stderr}"

    # The health credential lists, and cannot call, over the public listener.
    attack = json.loads(
        next(line for line in completed.stdout.splitlines() if '"health-attack-remote"' in line)
    )
    assert attack["health_listed_tools"] == ["fixture.read"]
    assert attack["health_calls_executed"] == 0
    assert len(attack["health_call_attempts"]) == 2
    assert all(item["executed"] is False for item in attack["health_call_attempts"])
    assert attack["downstream_effect_unchanged"] is True

    # No secret material on stdout.
    assert "credential" not in completed.stdout.lower()
    assert "ACGS_DOWNSTREAM_CREDENTIAL" not in completed.stdout

    # Teardown: the demo removes its own project's containers and networks.
    # `docker ps` formats the name as .Names; `docker network ls` as .Name.
    for args, template in ((["ps", "-a"], "{{.Names}}"), (["network", "ls"], "{{.Name}}")):
        listed = subprocess.run(
            ["docker", *args, "--filter", "name=acgs-p1-remote", "--format", template],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        assert listed.stdout.strip() == ""
