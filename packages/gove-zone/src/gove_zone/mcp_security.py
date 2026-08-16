"""Transport identity controls for the protocol-agnostic MCP gateway."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast
from urllib.parse import SplitResult, urlsplit


def _require_text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    return value


class MCPOriginReasonCode(StrEnum):
    """Stable fail-closed origin and transport reasons."""

    INVALID_ORIGIN = "mcp.origin.invalid"
    TLS_REQUIRED = "mcp.origin.tls_required"
    FORBIDDEN_ADDRESS = "mcp.origin.forbidden_address"
    DNS_UNAVAILABLE = "mcp.origin.dns_unavailable"
    DNS_REBINDING = "mcp.origin.dns_rebinding"
    REDIRECT_FORBIDDEN = "mcp.origin.redirect_forbidden"
    ORIGIN_MISMATCH = "mcp.origin.mismatch"
    PEER_MISMATCH = "mcp.origin.peer_mismatch"


class MCPStdioReasonCode(StrEnum):
    """Stable fail-closed fixed-process transport reasons."""

    INVALID_TARGET = "mcp.stdio.invalid_target"
    FORBIDDEN_ENVIRONMENT = "mcp.stdio.forbidden_environment"
    ARTIFACT_DRIFT = "mcp.stdio.artifact_drift"
    SESSION_MISMATCH = "mcp.stdio.session_mismatch"


class MCPOriginError(RuntimeError):
    """Structured, non-retryable origin rejection."""

    non_retryable = True

    def __init__(self, reason_code: MCPOriginReasonCode) -> None:
        if not isinstance(reason_code, MCPOriginReasonCode):
            raise TypeError("reason_code must be an MCPOriginReasonCode")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


class MCPStdioError(RuntimeError):
    """Structured, non-retryable fixed-stdio target rejection."""

    non_retryable = True

    def __init__(self, reason_code: MCPStdioReasonCode) -> None:
        if not isinstance(reason_code, MCPStdioReasonCode):
            raise TypeError("reason_code must be an MCPStdioReasonCode")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


AddressResolver = Callable[[str, int], Sequence[str]]


def _system_resolver(hostname: str, port: int) -> Sequence[str]:
    return tuple(
        sorted(
            {
                cast(str, cast(tuple[Any, ...], entry[4])[0])
                for entry in socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
            }
        )
    )


_METADATA_NAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.aws.internal",
        "instance-data",
    }
)
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_LEGACY_NUMERIC_HOST_RE = re.compile(
    r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*",
    re.IGNORECASE,
)


def _canonical_hostname(value: str) -> str:
    raw = _require_text(value, "hostname")
    if "%" in raw:
        raise ValueError("hostname must not contain an IPv6 zone identifier")
    normalized = raw.rstrip(".").casefold()
    if not normalized or len(normalized.encode("ascii", errors="ignore")) != len(normalized):
        raise ValueError("hostname must be an ASCII DNS name or canonical IP literal")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        if (
            ":" in normalized
            or _LEGACY_NUMERIC_HOST_RE.fullmatch(normalized) is not None
            or len(normalized) > 253
            or any(_DNS_LABEL_RE.fullmatch(label) is None for label in normalized.split("."))
        ):
            raise ValueError("hostname must be an ASCII DNS name or canonical IP literal") from None
        return normalized
    if address.compressed != normalized:
        raise ValueError("IP literal must use its canonical compressed form")
    return normalized


def _normalized_host(parts: SplitResult) -> str:
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN) from None
    if hostname is None or port is not None and not 1 <= port <= 65535:
        raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN)
    try:
        return _canonical_hostname(hostname)
    except ValueError:
        raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN) from None


def _port(parts: SplitResult) -> int:
    try:
        explicit = parts.port
    except ValueError:
        raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN) from None
    if explicit is not None:
        return explicit
    return 443 if parts.scheme == "https" else 80


def _parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    candidate = _require_text(value, "address")
    if "%" in candidate:
        raise MCPOriginError(MCPOriginReasonCode.DNS_UNAVAILABLE)
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        raise MCPOriginError(MCPOriginReasonCode.DNS_UNAVAILABLE) from None


def _address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_global and not any(
        (
            address.is_loopback,
            address.is_private,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA_NETWORK = ipaddress.ip_network("fc00::/7")


def _private_service_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Accept only explicit RFC1918 or ULA unicast service addresses."""

    if any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_unspecified,
            address.is_reserved,
        )
    ):
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in _RFC1918_NETWORKS)
    return address in _ULA_NETWORK


_ORIGIN_FACTORY_TOKEN = object()
_STDIO_FACTORY_TOKEN = object()
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_FORBIDDEN_ENV_MARKERS = (
    "AUTH",
    "BEARER",
    "CREDENTIAL",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
)


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class _AncestorChainSnapshot:
    path: Path
    digest: str


def _ancestor_component_record(path: Path, info: os.stat_result) -> dict[str, int | str]:
    """Return stable identity for one already-accepted directory component.

    Directory link count reflects ambient immediate child-directory activity,
    not stable identity, so it is deliberately omitted for every component.
    Canonical path, type, device, inode, owner, group, and mode remain bound and
    are revalidated fail closed.
    """

    mode = stat.S_IMODE(info.st_mode)
    record: dict[str, int | str] = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "owner": info.st_uid,
        "group": info.st_gid,
        "mode": mode,
    }
    return record


def _ancestor_chain_snapshot(
    directory: Path,
    *,
    require_private_leaf: bool = False,
) -> _AncestorChainSnapshot:
    """Bind every canonical directory component from ``directory`` to root.

    Group/other-writable components are rejected unless they are root-owned
    sticky directories such as ``/tmp``. This closes less-privileged ancestor
    replacement without claiming protection against the trusted gateway uid.
    """

    try:
        if not directory.is_absolute() or directory.resolve(strict=True) != directory:
            raise OSError
        records: list[dict[str, int | str]] = []
        current = directory
        while True:
            info = os.lstat(current)
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
                raise OSError
            if mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
                raise OSError
            if (
                current == directory
                and require_private_leaf
                and (info.st_uid != os.geteuid() or mode != 0o700)
            ):
                raise OSError
            records.append(_ancestor_component_record(current, info))
            if current.parent == current:
                break
            current = current.parent
        if directory.resolve(strict=True) != directory:
            raise OSError
        for record in records:
            path = Path(cast(str, record["path"]))
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or _ancestor_component_record(path, info) != record:
                raise OSError
    except (OSError, TypeError, ValueError):
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    return _AncestorChainSnapshot(
        path=directory,
        digest=_canonical_digest(
            {
                "schema": "gove-zone.canonical-ancestor-chain.v3",
                "components": records,
            }
        ),
    )


def validate_private_state_root(value: str | os.PathLike[str]) -> Path:
    """Return one canonical owner-private state root with a trusted chain."""

    try:
        raw = Path(value).expanduser()
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        path = raw.resolve(strict=True)
        if raw != path:
            raise OSError
    except (OSError, TypeError, ValueError):
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    return _ancestor_chain_snapshot(path, require_private_leaf=True).path


@dataclass(frozen=True, slots=True)
class _ArtifactSnapshot:
    path: Path
    sha256: str
    device: int
    inode: int
    size: int
    owner: int
    mode: int
    ancestor_digest: str


def _artifact_snapshot(value: object) -> _ArtifactSnapshot:
    """Bind one gateway-owner, private, immutable script from the opened fd.

    This is a same-host gateway-owner trust boundary, not protection against a
    process already running as the gateway user. The private directory and
    non-writable single-link artifact remove less-privileged replacement paths;
    device/inode/size/digest/owner/mode are rechecked after child initialize.
    """

    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None:
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
    try:
        raw = Path(_require_text(value, "artifact_path")).expanduser()
        if not raw.is_absolute():
            raise OSError
        path = raw.resolve(strict=True)
        if raw != path:
            raise OSError
        parent = path.parent
        ancestor = _ancestor_chain_snapshot(parent)
        parent_info = os.lstat(parent)
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or parent_mode & 0o077
        ):
            raise OSError
        flags = os.O_RDONLY | cloexec | nofollow
        descriptor = os.open(path, flags)
    except (OSError, TypeError, ValueError):
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    try:
        before = os.fstat(descriptor)
        linked = os.stat(path, follow_symlinks=False)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or not mode & stat.S_IRUSR
            or mode & 0o7277
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise OSError
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise OSError
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_uid, mode) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
        ) or total != before.st_size:
            raise OSError
    except OSError:
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    finally:
        os.close(descriptor)
    return _ArtifactSnapshot(
        path=path,
        sha256=digest.hexdigest(),
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        owner=before.st_uid,
        mode=mode,
        ancestor_digest=ancestor.digest,
    )


@dataclass(frozen=True, slots=True)
class _ExecutableSnapshot:
    path: Path
    sha256: str
    device: int
    inode: int
    size: int
    owner: int
    mode: int
    nlink: int
    ancestor_digest: str


def _effective_execute_bit(info: os.stat_result, mode: int) -> bool:
    effective_uid = os.geteuid()
    if effective_uid == info.st_uid:
        return bool(mode & stat.S_IXUSR)
    effective_groups = {os.getegid(), *os.getgroups()}
    if info.st_gid in effective_groups:
        return bool(mode & stat.S_IXGRP)
    return bool(mode & stat.S_IXOTH)


def _executable_snapshot(value: object) -> _ExecutableSnapshot:
    """Securely bind the exact canonical interpreter opened by the gateway.

    Root and the gateway euid are the only trusted owners. Owner-writable
    interpreters remain a same-uid trust boundary: another process already
    running as that uid can still race the final path-based ``exec``. Callers
    requiring a stronger boundary must use a distinct OS identity/container or
    a read-only trusted mount.
    """

    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None:
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
    try:
        raw = Path(_require_text(value, "executable")).expanduser()
        if not raw.is_absolute():
            raise OSError
        path = raw.resolve(strict=True)
        if raw != path:
            raise OSError
        parent = path.parent
        ancestor = _ancestor_chain_snapshot(parent)
        parent_info = os.lstat(parent)
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid not in {0, os.geteuid()}
            or parent_mode & 0o022
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | cloexec | nofollow)
    except (OSError, TypeError, ValueError):
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    try:
        before = os.fstat(descriptor)
        linked = os.stat(path, follow_symlinks=False)
        mode = stat.S_IMODE(before.st_mode)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_uid,
            mode,
            before.st_nlink,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or before.st_nlink != 1
            or mode & 0o7022
            or not _effective_execute_bit(before, mode)
            or identity
            != (
                linked.st_dev,
                linked.st_ino,
                linked.st_size,
                linked.st_uid,
                stat.S_IMODE(linked.st_mode),
                linked.st_nlink,
            )
        ):
            raise OSError
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > 256 * 1024 * 1024:
                raise OSError
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            identity
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
            )
            or total != before.st_size
        ):
            raise OSError
    except OSError:
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    finally:
        os.close(descriptor)
    return _ExecutableSnapshot(
        path=path,
        sha256=digest.hexdigest(),
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        owner=before.st_uid,
        mode=mode,
        nlink=before.st_nlink,
        ancestor_digest=ancestor.digest,
    )


def _resolved_directory(value: object, name: str) -> _AncestorChainSnapshot:
    try:
        raw = Path(_require_text(value, name)).expanduser()
        path = raw.resolve(strict=True)
        if not raw.is_absolute() or raw != path:
            raise OSError
    except OSError:
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
    if not path.is_dir():
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
    return _ancestor_chain_snapshot(path)


def _fixed_environment(value: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if type(value) is not dict:
        raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
    pairs: list[tuple[str, str]] = []
    for key, item in value.items():
        if type(key) is not str or _ENV_NAME_RE.fullmatch(key) is None or type(item) is not str:
            raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
        upper = key.upper()
        if any(marker in upper for marker in _FORBIDDEN_ENV_MARKERS):
            raise MCPStdioError(MCPStdioReasonCode.FORBIDDEN_ENVIRONMENT)
        try:
            item.encode("utf-8")
        except UnicodeEncodeError:
            raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET) from None
        pairs.append((key, item))
    return tuple(sorted(pairs))


@dataclass(frozen=True, slots=True, init=False)
class ValidatedMCPStdioTarget:
    """Validator-minted binding for one fixed local MCP child session.

    This proves a trusted local launch specification and active SDK session. It
    is deliberately not described as OS, hardware, or in-memory attestation.
    """

    server_id: str
    executable: str
    executable_sha256: str
    executable_device: int
    executable_inode: int
    executable_size: int
    executable_owner: int
    executable_mode: int
    executable_nlink: int
    executable_ancestor_digest: str
    argv: tuple[str, ...]
    cwd: str
    artifact_path: str
    artifact_sha256: str
    artifact_device: int
    artifact_inode: int
    artifact_size: int
    artifact_owner: int
    artifact_mode: int
    artifact_ancestor_digest: str
    cwd_ancestor_digest: str
    environment: tuple[tuple[str, str], ...]
    instance_id: str
    launch_digest: str
    transport_binding: str

    def __init__(
        self,
        *,
        server_id: str,
        executable: str,
        executable_sha256: str,
        executable_device: int,
        executable_inode: int,
        executable_size: int,
        executable_owner: int,
        executable_mode: int,
        executable_nlink: int,
        executable_ancestor_digest: str,
        argv: tuple[str, ...],
        cwd: str,
        artifact_path: str,
        artifact_sha256: str,
        artifact_device: int,
        artifact_inode: int,
        artifact_size: int,
        artifact_owner: int,
        artifact_mode: int,
        artifact_ancestor_digest: str,
        cwd_ancestor_digest: str,
        environment: tuple[tuple[str, str], ...],
        instance_id: str,
        launch_digest: str,
        transport_binding: str,
        _factory_token: object | None = None,
    ) -> None:
        if _factory_token is not _STDIO_FACTORY_TOKEN:
            raise TypeError("ValidatedMCPStdioTarget must be created by MCPStdioTargetValidator")
        for name in (
            "server_id",
            "executable",
            "executable_sha256",
            "executable_ancestor_digest",
            "cwd",
            "artifact_path",
            "artifact_sha256",
            "artifact_ancestor_digest",
            "cwd_ancestor_digest",
            "instance_id",
            "launch_digest",
            "transport_binding",
        ):
            object.__setattr__(self, name, _require_text(locals()[name], name))
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "environment", environment)
        for name in (
            "executable_device",
            "executable_inode",
            "executable_size",
            "executable_owner",
            "executable_mode",
            "executable_nlink",
            "artifact_device",
            "artifact_inode",
            "artifact_size",
            "artifact_owner",
            "artifact_mode",
        ):
            value = locals()[name]
            if type(value) is not int or value < 0:
                raise TypeError(f"{name} must be a non-negative integer")
            object.__setattr__(self, name, value)

    @property
    def environment_mapping(self) -> dict[str, str]:
        return dict(self.environment)


class MCPStdioTargetValidator:
    """Mint and revalidate immutable fixed-child transport capabilities."""

    def __init__(self) -> None:
        self._minted_bindings: set[str] = set()

    def validate(
        self,
        *,
        server_id: str,
        executable: str,
        argv: Sequence[str],
        cwd: str,
        artifact_path: str,
        environment: Mapping[str, str] | None,
        instance_id: str,
    ) -> ValidatedMCPStdioTarget:
        identity = _require_text(server_id, "server_id")
        instance = _require_text(instance_id, "instance_id")
        if type(argv) not in (tuple, list):
            raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
        arguments = tuple(_require_text(item, "argv item") for item in argv)
        executable_snapshot = _executable_snapshot(executable)
        directory = _resolved_directory(cwd, "cwd")
        artifact = _artifact_snapshot(artifact_path)
        if arguments != (str(artifact.path),):
            raise MCPStdioError(MCPStdioReasonCode.INVALID_TARGET)
        fixed_environment = _fixed_environment(
            dict(environment) if isinstance(environment, Mapping) else environment
        )
        launch = _canonical_digest(
            {
                "schema": "gove-zone.mcp-stdio-launch.v3",
                "server_id": identity,
                "executable": str(executable_snapshot.path),
                "executable_sha256": executable_snapshot.sha256,
                "executable_device": executable_snapshot.device,
                "executable_inode": executable_snapshot.inode,
                "executable_size": executable_snapshot.size,
                "executable_owner": executable_snapshot.owner,
                "executable_mode": executable_snapshot.mode,
                "executable_nlink": executable_snapshot.nlink,
                "executable_ancestor_digest": executable_snapshot.ancestor_digest,
                "argv": list(arguments),
                "cwd": str(directory.path),
                "cwd_ancestor_digest": directory.digest,
                "artifact_path": str(artifact.path),
                "artifact_sha256": artifact.sha256,
                "artifact_device": artifact.device,
                "artifact_inode": artifact.inode,
                "artifact_size": artifact.size,
                "artifact_owner": artifact.owner,
                "artifact_mode": artifact.mode,
                "artifact_ancestor_digest": artifact.ancestor_digest,
                "environment": [[key, item] for key, item in fixed_environment],
            }
        )
        binding = _canonical_digest(
            {
                "schema": "gove-zone.mcp-stdio-session.v1",
                "launch_digest": launch,
                "instance_id": instance,
            }
        )
        target = ValidatedMCPStdioTarget(
            server_id=identity,
            executable=str(executable_snapshot.path),
            executable_sha256=executable_snapshot.sha256,
            executable_device=executable_snapshot.device,
            executable_inode=executable_snapshot.inode,
            executable_size=executable_snapshot.size,
            executable_owner=executable_snapshot.owner,
            executable_mode=executable_snapshot.mode,
            executable_nlink=executable_snapshot.nlink,
            executable_ancestor_digest=executable_snapshot.ancestor_digest,
            argv=arguments,
            cwd=str(directory.path),
            artifact_path=str(artifact.path),
            artifact_sha256=artifact.sha256,
            artifact_device=artifact.device,
            artifact_inode=artifact.inode,
            artifact_size=artifact.size,
            artifact_owner=artifact.owner,
            artifact_mode=artifact.mode,
            artifact_ancestor_digest=artifact.ancestor_digest,
            cwd_ancestor_digest=directory.digest,
            environment=fixed_environment,
            instance_id=instance,
            launch_digest=launch,
            transport_binding=binding,
            _factory_token=_STDIO_FACTORY_TOKEN,
        )
        self._minted_bindings.add(target.transport_binding)
        return target

    def revalidate(self, target: ValidatedMCPStdioTarget) -> ValidatedMCPStdioTarget:
        if not isinstance(target, ValidatedMCPStdioTarget):
            raise TypeError("target must be a ValidatedMCPStdioTarget")
        if target.transport_binding not in self._minted_bindings:
            raise MCPStdioError(MCPStdioReasonCode.SESSION_MISMATCH)
        try:
            current = self.validate(
                server_id=target.server_id,
                executable=target.executable,
                argv=target.argv,
                cwd=target.cwd,
                artifact_path=target.artifact_path,
                environment=target.environment_mapping,
                instance_id=target.instance_id,
            )
        except MCPStdioError as exc:
            if exc.reason_code is MCPStdioReasonCode.FORBIDDEN_ENVIRONMENT:
                raise
            raise MCPStdioError(MCPStdioReasonCode.ARTIFACT_DRIFT) from None
        if current.instance_id != target.instance_id:
            raise MCPStdioError(MCPStdioReasonCode.SESSION_MISMATCH)
        if current != target:
            raise MCPStdioError(MCPStdioReasonCode.ARTIFACT_DRIFT)
        return current

    def validate_response(
        self,
        target: ValidatedMCPStdioTarget,
        *,
        transport_binding: str,
    ) -> None:
        current = self.revalidate(target)
        if _require_text(transport_binding, "transport_binding") != current.transport_binding:
            raise MCPStdioError(MCPStdioReasonCode.SESSION_MISMATCH)


@dataclass(frozen=True, slots=True, init=False)
class ValidatedMCPOrigin:
    """An immutable origin minted only after URL and DNS validation.

    Callers cannot construct this capability directly.  The validator also
    re-derives every field from ``url`` and the configured resolver before each
    network boundary, so copying or field-forging an instance is not trusted.
    """

    server_id: str
    url: str
    hostname: str
    port: int
    pinned_addresses: tuple[str, ...]
    test_local: bool = False

    def __init__(
        self,
        *,
        server_id: str,
        url: str,
        hostname: str,
        port: int,
        pinned_addresses: tuple[str, ...],
        test_local: bool,
        _factory_token: object | None = None,
    ) -> None:
        if _factory_token is not _ORIGIN_FACTORY_TOKEN:
            raise TypeError("ValidatedMCPOrigin must be created by MCPOriginValidator")
        for name in ("server_id", "url", "hostname"):
            value = locals()[name]
            object.__setattr__(self, name, _require_text(value, name))
        if type(port) is not int or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        object.__setattr__(self, "port", port)
        if type(pinned_addresses) is not tuple or not pinned_addresses:
            raise ValueError("pinned_addresses must be a non-empty tuple")
        if tuple(sorted(set(pinned_addresses))) != pinned_addresses:
            raise ValueError("pinned_addresses must be sorted and unique")
        object.__setattr__(self, "pinned_addresses", pinned_addresses)
        if type(test_local) is not bool:
            raise TypeError("test_local must be a boolean")
        object.__setattr__(self, "test_local", test_local)


@dataclass(frozen=True, slots=True)
class MCPPrivateServicePin:
    """Exact HTTPS private-service DNS pin."""

    hostname: str
    port: int
    expected_addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            normalized = _canonical_hostname(self.hostname)
        except ValueError:
            raise ValueError("hostname must be one exact normalized private-service name") from None
        if (
            self.hostname != normalized
            or "*" in normalized
            or "/" in normalized
            or normalized in _METADATA_NAMES
            or normalized.endswith(".metadata.google.internal")
        ):
            raise ValueError("hostname must be one exact normalized private-service name")
        if type(self.port) is not int or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if type(self.expected_addresses) is not tuple or not self.expected_addresses:
            raise ValueError("expected_addresses must be a non-empty tuple")
        try:
            parsed = tuple(_parse_address(value) for value in self.expected_addresses)
        except MCPOriginError:
            raise ValueError("expected_addresses contains an invalid address") from None
        canonical = tuple(sorted({item.compressed for item in parsed}))
        if canonical != self.expected_addresses or not all(
            _private_service_address(item) for item in parsed
        ):
            raise ValueError("expected_addresses must be canonical private unicast pins")


_FIXTURE_HTTP_CAPABILITY_TOKEN = object()
_REFERENCE_FIXTURE_IDENTITY_VERSION = "mcp-reference-compose-fixture/v1"
_REFERENCE_FIXTURE_SERVER_ID = "fixture-server"
_REFERENCE_FIXTURE_ORIGIN = "http://downstream:8000/mcp"
_REFERENCE_FIXTURE_PATH = "/mcp"
_REFERENCE_FIXTURE_HOSTNAME = "downstream"
_REFERENCE_FIXTURE_PORT = 8000
_REFERENCE_FIXTURE_BACKEND_IP = "172.30.0.10"


@dataclass(frozen=True, slots=True, init=False)
class _MCPFixtureHTTPServicePin:
    """Identity-token-minted capability for the isolated Compose fixture only."""

    hostname: str
    port: int
    expected_addresses: tuple[str, ...]
    target_kind: str

    def __init__(
        self,
        *,
        hostname: str,
        port: int,
        expected_addresses: tuple[str, ...],
        _identity_token: object,
    ) -> None:
        if _identity_token is not _FIXTURE_HTTP_CAPABILITY_TOKEN:
            raise TypeError("fixture HTTP capability must be minted internally")
        public_pin = MCPPrivateServicePin(
            hostname=hostname,
            port=port,
            expected_addresses=expected_addresses,
        )
        object.__setattr__(self, "hostname", public_pin.hostname)
        object.__setattr__(self, "port", public_pin.port)
        object.__setattr__(self, "expected_addresses", public_pin.expected_addresses)
        object.__setattr__(self, "target_kind", _REFERENCE_FIXTURE_IDENTITY_VERSION)


class MCPOriginValidator:
    """Validate a fixed downstream origin and fail on DNS rebinding."""

    def __init__(self, *, resolver: AddressResolver | None = None) -> None:
        if resolver is not None and not callable(resolver):
            raise TypeError("resolver must be callable")
        self._resolver = resolver or _system_resolver

    def validate(
        self,
        *,
        server_id: str,
        url: str,
        allow_test_local: bool = False,
    ) -> ValidatedMCPOrigin:
        identity = _require_text(server_id, "server_id")
        candidate = _require_text(url, "url")
        if type(allow_test_local) is not bool:
            raise TypeError("allow_test_local must be a boolean")
        try:
            parts = urlsplit(candidate)
        except ValueError:
            raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN) from None
        if (
            not parts.netloc
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.scheme not in {"https", "http"}
        ):
            raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN)
        hostname = _normalized_host(parts)
        port = _port(parts)
        if hostname in _METADATA_NAMES or hostname.endswith(".metadata.google.internal"):
            raise MCPOriginError(MCPOriginReasonCode.FORBIDDEN_ADDRESS)
        if parts.scheme != "https" and not allow_test_local:
            raise MCPOriginError(MCPOriginReasonCode.TLS_REQUIRED)

        addresses = self._resolve(hostname, port)
        parsed = tuple(_parse_address(value) for value in addresses)
        if allow_test_local:
            local_name = hostname == "localhost"
            if parts.scheme == "http" and not (
                local_name and all(item.is_loopback for item in parsed)
            ):
                raise MCPOriginError(MCPOriginReasonCode.FORBIDDEN_ADDRESS)
            if not all(item.is_loopback or _address_allowed(item) for item in parsed):
                raise MCPOriginError(MCPOriginReasonCode.FORBIDDEN_ADDRESS)
        elif not all(_address_allowed(item) for item in parsed):
            raise MCPOriginError(MCPOriginReasonCode.FORBIDDEN_ADDRESS)

        return ValidatedMCPOrigin(
            server_id=identity,
            url=candidate,
            hostname=hostname,
            port=port,
            pinned_addresses=addresses,
            test_local=allow_test_local,
            _factory_token=_ORIGIN_FACTORY_TOKEN,
        )

    def validate_private_service(
        self,
        *,
        server_id: str,
        url: str,
        pin: MCPPrivateServicePin,
    ) -> ValidatedMCPOrigin:
        """Mint one exact HTTPS private-service origin without widening defaults."""

        if not isinstance(pin, MCPPrivateServicePin):
            raise TypeError("pin must be an MCPPrivateServicePin")
        return self._validate_private_service(
            server_id=server_id,
            url=url,
            pin=pin,
            fixture_http=False,
        )

    def _validate_fixture_private_service(
        self,
        *,
        server_id: str,
        url: str,
        pin: _MCPFixtureHTTPServicePin,
    ) -> ValidatedMCPOrigin:
        if not isinstance(pin, _MCPFixtureHTTPServicePin):
            raise TypeError("pin must be an internally minted fixture HTTP capability")
        return self._validate_private_service(
            server_id=server_id,
            url=url,
            pin=pin,
            fixture_http=True,
        )

    def _validate_private_service(
        self,
        *,
        server_id: str,
        url: str,
        pin: MCPPrivateServicePin | _MCPFixtureHTTPServicePin,
        fixture_http: bool,
    ) -> ValidatedMCPOrigin:
        identity = _require_text(server_id, "server_id")
        candidate = _require_text(url, "url")
        try:
            parts = urlsplit(candidate)
        except ValueError:
            raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN) from None
        if (
            not parts.netloc
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.scheme not in {"https", "http"}
        ):
            raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN)
        hostname = _normalized_host(parts)
        port = _port(parts)
        if hostname != pin.hostname or port != pin.port:
            raise MCPOriginError(MCPOriginReasonCode.ORIGIN_MISMATCH)
        if hostname in _METADATA_NAMES or hostname.endswith(".metadata.google.internal"):
            raise MCPOriginError(MCPOriginReasonCode.FORBIDDEN_ADDRESS)
        if not fixture_http and parts.scheme != "https":
            raise MCPOriginError(MCPOriginReasonCode.TLS_REQUIRED)
        if fixture_http:
            if not isinstance(pin, _MCPFixtureHTTPServicePin):
                raise TypeError("fixture HTTP validation requires its internal capability")
            if (
                parts.scheme != "http"
                or parts.path != _REFERENCE_FIXTURE_PATH
                or pin.target_kind != _REFERENCE_FIXTURE_IDENTITY_VERSION
            ):
                raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN)
        addresses = self._resolve(hostname, port)
        if addresses != pin.expected_addresses:
            raise MCPOriginError(MCPOriginReasonCode.DNS_REBINDING)
        if not all(_private_service_address(_parse_address(item)) for item in addresses):
            raise MCPOriginError(MCPOriginReasonCode.FORBIDDEN_ADDRESS)
        return ValidatedMCPOrigin(
            server_id=identity,
            url=candidate,
            hostname=hostname,
            port=port,
            pinned_addresses=addresses,
            test_local=fixture_http,
            _factory_token=_ORIGIN_FACTORY_TOKEN,
        )

    def reconcile(self, origin: ValidatedMCPOrigin) -> ValidatedMCPOrigin:
        """Re-derive the complete origin capability from URL and live DNS."""

        if not isinstance(origin, ValidatedMCPOrigin):
            raise TypeError("origin must be a ValidatedMCPOrigin")
        try:
            parts = urlsplit(origin.url)
        except ValueError:
            raise MCPOriginError(MCPOriginReasonCode.INVALID_ORIGIN) from None
        if _normalized_host(parts) != origin.hostname or _port(parts) != origin.port:
            raise MCPOriginError(MCPOriginReasonCode.ORIGIN_MISMATCH)
        if self._resolve(origin.hostname, origin.port) != origin.pinned_addresses:
            raise MCPOriginError(MCPOriginReasonCode.DNS_REBINDING)
        parsed = tuple(_parse_address(item) for item in origin.pinned_addresses)
        if origin.test_local and parsed and all(_private_service_address(item) for item in parsed):
            current = _mint_reference_fixture_http_origin(
                validator=self,
            )
        elif parsed and all(_private_service_address(item) for item in parsed):
            current = self.validate_private_service(
                server_id=origin.server_id,
                url=origin.url,
                pin=MCPPrivateServicePin(
                    hostname=origin.hostname,
                    port=origin.port,
                    expected_addresses=origin.pinned_addresses,
                ),
            )
        else:
            current = self.validate(
                server_id=origin.server_id,
                url=origin.url,
                allow_test_local=origin.test_local,
            )
        if current != origin:
            raise MCPOriginError(MCPOriginReasonCode.DNS_REBINDING)
        return current

    def revalidate(self, origin: ValidatedMCPOrigin) -> None:
        self.reconcile(origin)

    def validate_response(
        self,
        origin: ValidatedMCPOrigin,
        *,
        response_origin: str,
        redirect_url: str | None,
        peer_address: str,
    ) -> None:
        current = self.reconcile(origin)
        if redirect_url is not None:
            raise MCPOriginError(MCPOriginReasonCode.REDIRECT_FORBIDDEN)
        if _require_text(response_origin, "response_origin") != current.url:
            raise MCPOriginError(MCPOriginReasonCode.ORIGIN_MISMATCH)
        peer = _parse_address(_require_text(peer_address, "peer_address")).compressed
        if peer not in current.pinned_addresses:
            raise MCPOriginError(MCPOriginReasonCode.PEER_MISMATCH)

    def _resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        try:
            raw = self._resolver(hostname, port)
            addresses = tuple(sorted({_parse_address(item).compressed for item in raw}))
        except MCPOriginError:
            raise
        except Exception:
            raise MCPOriginError(MCPOriginReasonCode.DNS_UNAVAILABLE) from None
        if not addresses:
            raise MCPOriginError(MCPOriginReasonCode.DNS_UNAVAILABLE)
        return addresses


def _mint_reference_fixture_http_origin(
    *,
    validator: MCPOriginValidator,
) -> ValidatedMCPOrigin:
    """Mint only the immutable, versioned Compose fixture HTTP identity."""

    if not isinstance(validator, MCPOriginValidator):
        raise TypeError("validator must be an MCPOriginValidator")
    if (
        f"http://{_REFERENCE_FIXTURE_HOSTNAME}:{_REFERENCE_FIXTURE_PORT}"
        f"{_REFERENCE_FIXTURE_PATH}" != _REFERENCE_FIXTURE_ORIGIN
    ):
        raise RuntimeError("reference fixture identity constants are inconsistent")
    pin = _MCPFixtureHTTPServicePin(
        hostname=_REFERENCE_FIXTURE_HOSTNAME,
        port=_REFERENCE_FIXTURE_PORT,
        expected_addresses=(_REFERENCE_FIXTURE_BACKEND_IP,),
        _identity_token=_FIXTURE_HTTP_CAPABILITY_TOKEN,
    )
    return validator._validate_fixture_private_service(
        server_id=_REFERENCE_FIXTURE_SERVER_ID,
        url=_REFERENCE_FIXTURE_ORIGIN,
        pin=pin,
    )


__all__ = [
    "AddressResolver",
    "MCPOriginError",
    "MCPPrivateServicePin",
    "MCPOriginReasonCode",
    "MCPOriginValidator",
    "MCPStdioError",
    "MCPStdioReasonCode",
    "MCPStdioTargetValidator",
    "ValidatedMCPOrigin",
    "ValidatedMCPStdioTarget",
    "validate_private_state_root",
]
