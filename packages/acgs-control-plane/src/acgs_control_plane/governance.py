"""The governance membrane: control-plane mutations dispatch through gove-zone.

Core invariant, made literal for the platform itself:

    **No valid Decision Receipt, no side effect.**

Every mutating control-plane operation (register agent, publish policy,
activate policy, create user, generate export, ...) is registered as a kernel
tool and executed via :meth:`gove_zone.Kernel.dispatch` under the
organization's *active* policy bundle. The receipt — ALLOW, DENY, or
ESCALATE — is persisted in the same transaction as the side effect. A DENY
or ESCALATE rolls the transaction back, persists only the receipt, and maps
to HTTP 403 / 202.

The org's audit chain is a per-org ``ChainHashAuditStore`` file; its tip
(count + last hash) is anchored in the ``organizations`` row on every
dispatch so file-level truncation is detectable from the database.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast

from gove_zone import (
    ChainHashAuditStore,
    DeniedError,
    EscalateError,
    Kernel,
    Receipt,
)
from gove_zone.decision import Decision, DecisionRecord, sha256_json
from gove_zone.policy import Policy, PolicyRule, RuleSetPolicy
from gove_zone.tool import ToolCall, normalize_path_context
from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.auth import Principal
from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    TENANT_BOOTSTRAP_ACTION,
)
from acgs_control_plane.models import Organization, PolicyBundle, ReceiptRow

BASELINE_POLICY_ID = "acp-baseline/v1"


class ExecutionClass(StrEnum):
    LEGACY_UNSIGNED_WRITE = "legacy_unsigned_write"
    READ_ONLY_OPERATION = "read_only_operation"
    PROTOCOL_OPERATION = "protocol_operation"
    CANONICAL_MANAGED_WRITE = "canonical_managed_write"


@dataclass(frozen=True)
class RouteContract:
    method: str
    path: str
    execution_class: ExecutionClass
    action: str | None = None
    permits_persistent_effect: bool = False
    permits_filesystem_effect: bool = False
    permits_external_effect: bool = False


_READ_PATHS = (
    ("GET", "/orgs/{org_id}"),
    ("GET", "/orgs/{org_id}/users"),
    ("GET", "/orgs/{org_id}/agents"),
    ("GET", "/orgs/{org_id}/agents/{agent_id}"),
    ("GET", "/orgs/{org_id}/policies"),
    ("POST", "/orgs/{org_id}/policies/simulate"),
    ("GET", "/orgs/{org_id}/receipts"),
    ("GET", "/orgs/{org_id}/receipts/{receipt_id}"),
    ("POST", "/orgs/{org_id}/receipts/{receipt_id}/verify"),
    ("GET", "/orgs/{org_id}/dashboard"),
    ("GET", "/orgs/{org_id}/exports"),
    ("GET", "/orgs/{org_id}/exports/{export_id}"),
)
_LEGACY_WRITES = (
    ("POST", "/orgs", "org.create"),
    ("POST", "/orgs/{org_id}/users", "user.create"),
    ("PATCH", "/orgs/{org_id}/agents/{agent_id}/status", "agent.set_status"),
    ("POST", "/orgs/{org_id}/policies", "policy.publish"),
    ("POST", "/orgs/{org_id}/policies/{bundle_id}/activate", "policy.activate"),
    ("POST", "/orgs/{org_id}/exports", "export.generate"),
)
ROUTE_CONTRACTS: tuple[RouteContract, ...] = (
    RouteContract("GET", "/healthz", ExecutionClass.PROTOCOL_OPERATION),
    RouteContract("GET", "/readyz", ExecutionClass.PROTOCOL_OPERATION),
    RouteContract("GET", "/v1", ExecutionClass.PROTOCOL_OPERATION),
    RouteContract(
        "POST",
        "/v1/tenant-bootstrap",
        ExecutionClass.CANONICAL_MANAGED_WRITE,
        TENANT_BOOTSTRAP_ACTION,
        True,
        False,
        False,
    ),
    RouteContract(
        "POST",
        "/orgs/{org_id}/agents",
        ExecutionClass.CANONICAL_MANAGED_WRITE,
        CONTROL_PLANE_AGENT_CREATE_ACTION,
        True,
        False,
        False,
    ),
    # The /v1 alias is served for every org route, so agent creation needs the
    # same governed contract under both prefixes. Classifying only the unversioned
    # path would leave the alias unclassified, which the registry refuses.
    RouteContract(
        "POST",
        "/v1/orgs/{org_id}/agents",
        ExecutionClass.CANONICAL_MANAGED_WRITE,
        CONTROL_PLANE_AGENT_CREATE_ACTION,
        True,
        False,
        False,
    ),
    *(RouteContract(m, p, ExecutionClass.READ_ONLY_OPERATION) for m, p in _READ_PATHS),
    *(RouteContract(m, f"/v1{p}", ExecutionClass.READ_ONLY_OPERATION) for m, p in _READ_PATHS),
    *(
        RouteContract(m, p, ExecutionClass.LEGACY_UNSIGNED_WRITE, a, True, True)
        for m, p, a in _LEGACY_WRITES
    ),
    *(
        RouteContract(m, f"/v1{p}", ExecutionClass.LEGACY_UNSIGNED_WRITE, a, True, True)
        for m, p, a in _LEGACY_WRITES
    ),
)
FRAMEWORK_PROTOCOL_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/docs"),
    ("HEAD", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("HEAD", "/docs/oauth2-redirect"),
    ("GET", "/openapi.json"),
    ("HEAD", "/openapi.json"),
    ("GET", "/redoc"),
    ("HEAD", "/redoc"),
)


@dataclass(frozen=True, order=True)
class PostureBlocker:
    code: str
    component: str
    route: str | None = None
    execution_class: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "component": self.component,
            "route": self.route,
            "execution_class": self.execution_class,
        }


class ProductionPostureBlocked(RuntimeError):
    code = "PRODUCTION_POSTURE_BLOCKED"
    stage = "pre-persistence"

    def __init__(self, blockers: Sequence[PostureBlocker]) -> None:
        self.blockers = tuple(sorted(blockers))
        super().__init__(
            json.dumps(
                {
                    "code": self.code,
                    "stage": self.stage,
                    "blockers": [b.to_dict() for b in self.blockers],
                },
                sort_keys=True,
            )
        )


def reconcile_route_contracts(actual: Sequence[tuple[str, str]]) -> tuple[PostureBlocker, ...]:
    expected = [(r.method, r.path) for r in ROUTE_CONTRACTS]
    blockers: list[PostureBlocker] = []
    for key in sorted(set(expected)):
        if expected.count(key) != 1 or actual.count(key) != 1:
            blockers.append(
                PostureBlocker("ROUTE_CONTRACT_DRIFT", "route-registry", f"{key[0]} {key[1]}")
            )
    for key in sorted(set(actual) - set(expected)):
        blockers.append(
            PostureBlocker("UNCLASSIFIED_ROUTE", "route-registry", f"{key[0]} {key[1]}")
        )
    return tuple(blockers)


def reconcile_http_routes(
    actual_application: Sequence[tuple[str, str]],
    actual_protocol: Sequence[tuple[str, str]],
) -> tuple[PostureBlocker, ...]:
    blockers = list(reconcile_route_contracts(actual_application))
    for key in sorted(set(actual_protocol) | set(FRAMEWORK_PROTOCOL_ROUTES)):
        if actual_protocol.count(key) != 1 or FRAMEWORK_PROTOCOL_ROUTES.count(key) != 1:
            blockers.append(
                PostureBlocker("UNCLASSIFIED_HTTP_ROUTE", "route-registry", f"{key[0]} {key[1]}")
            )
    return tuple(sorted(blockers))


class ProviderPreflight(Protocol):
    def preflight(self) -> object: ...


def production_blockers(
    route_drift: Sequence[PostureBlocker], providers: Sequence[ProviderPreflight] = ()
) -> tuple[PostureBlocker, ...]:
    """Return blockers without invoking providers while legacy writes exist."""
    del providers
    blockers = list(route_drift)
    legacy = [
        PostureBlocker(
            "LEGACY_UNSIGNED_WRITE",
            "governance-membrane",
            f"{r.method} {r.path}",
            r.execution_class.value,
        )
        for r in ROUTE_CONTRACTS
        if r.execution_class is ExecutionClass.LEGACY_UNSIGNED_WRITE
    ]
    blockers.extend(legacy)
    required = (
        "cursor-aead-keyring",
        "durable-consumption-uow",
        "migration-head",
        "signer-issuer",
        "trust-verifier",
    )
    blockers.extend(PostureBlocker("PROVIDER_PREFLIGHT_SKIPPED", c) for c in required)
    return tuple(sorted(blockers))


_CONTEXT_CAPABILITY = object()
_BUNDLE_CAPABILITY = object()
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


@dataclass(frozen=True, init=False)
class AuthenticatedRuntimeContext:
    actor: str
    tenant: str
    project: str
    environment: str
    authentication_method: str
    authority_domain: str
    validated_at: str

    def __init__(self, capability: object, **bindings: str) -> None:
        if capability is not _CONTEXT_CAPABILITY:
            raise TypeError("server authentication capability required")
        names = {
            "actor",
            "tenant",
            "project",
            "environment",
            "authentication_method",
            "authority_domain",
            "validated_at",
        }
        if set(bindings) != names or any(
            not isinstance(bindings[n], str) or not bindings[n].strip() for n in names
        ):
            raise ValueError("complete nonempty authenticated context required")
        for name in names:
            object.__setattr__(self, name, bindings[name])
        _parse_utc(bindings["validated_at"])
        for name in names - {"validated_at"}:
            if not _IDENTIFIER.fullmatch(bindings[name]):
                raise ValueError(f"invalid context identifier: {name}")


def _issue_authenticated_runtime_context(**bindings: str) -> AuthenticatedRuntimeContext:
    """In-process P0 convention boundary; not an unforgeable authentication primitive."""
    return AuthenticatedRuntimeContext(_CONTEXT_CAPABILITY, **bindings)


@dataclass(frozen=True, init=False)
class ServerManagedBundle:
    context: AuthenticatedRuntimeContext
    authority: str
    validator: str
    policy_id: str
    policy_version: str
    policy_hash: str
    issued_at: str
    expires_at: str
    key_id: str
    audit_anchor: str
    idempotency_key: str

    def __init__(self, capability: object, **values: Any) -> None:
        if capability is not _BUNDLE_CAPABILITY:
            raise TypeError("server bundle capability required")
        context = values.pop("context", None)
        if not isinstance(context, AuthenticatedRuntimeContext):
            raise TypeError("authenticated runtime context required")
        names = {
            "authority",
            "validator",
            "policy_id",
            "policy_version",
            "policy_hash",
            "issued_at",
            "expires_at",
            "key_id",
            "audit_anchor",
            "idempotency_key",
        }
        if set(values) != names or any(
            not isinstance(values[n], str) or not values[n].strip() for n in names
        ):
            raise ValueError("complete nonempty server bundle required")
        if values["authority"] == values["validator"]:
            raise ValueError("authority and validator must be distinct")
        for name in names - {"policy_hash", "audit_anchor", "issued_at", "expires_at"}:
            if not _IDENTIFIER.fullmatch(values[name]):
                raise ValueError(f"invalid server identifier: {name}")
        for name in ("policy_hash", "audit_anchor"):
            if len(values[name]) != 64 or any(c not in "0123456789abcdef" for c in values[name]):
                raise ValueError(f"{name} must be lowercase SHA-256")
        issued = _parse_utc(values["issued_at"])
        expires = _parse_utc(values["expires_at"])
        lifetime = (expires - issued).total_seconds()
        if lifetime <= 0 or lifetime > 300:
            raise ValueError("expiry must be after issuance and bounded to 300 seconds")
        object.__setattr__(self, "context", context)
        for name in names:
            object.__setattr__(self, name, values[name])


def _parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must be UTC Z form")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid UTC timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return parsed


def _issue_server_managed_bundle(
    *, context: AuthenticatedRuntimeContext, **bindings: str
) -> ServerManagedBundle:
    """P0 private factory convention; no unforgeable capability or callback is claimed."""
    return ServerManagedBundle(_BUNDLE_CAPABILITY, context=context, **bindings)


def _canonical_json_subset(value: Any) -> bytes:
    """RFC 8785-compatible constrained subset (integers only, exact builtins)."""

    def string(value: str) -> str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("canonical JSON rejects lone surrogates") from exc
        return json.dumps(value, ensure_ascii=False, allow_nan=False)

    def render(item: Any) -> str:
        if item is None:
            return "null"
        if type(item) is bool:
            return "true" if item else "false"
        if type(item) is int:
            if abs(item) > 9_007_199_254_740_991:
                raise ValueError("canonical JSON integer exceeds I-JSON safe domain")
            return str(item)
        if type(item) is str:
            return string(item)
        if type(item) is list:
            return "[" + ",".join(render(child) for child in item) + "]"
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("canonical JSON object keys must be strings")
            for key in item:
                string(key)
            keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
            return "{" + ",".join(f"{string(key)}:{render(item[key])}" for key in keys) + "}"
        raise ValueError("canonical JSON subset rejects floats, subclasses, and non-JSON values")

    return render(value).encode("utf-8")


def _immutable_snapshot(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _immutable_snapshot(child) for key, child in value.items()})
    if type(value) is list:
        return tuple(_immutable_snapshot(child) for child in value)
    return value


@dataclass(frozen=True)
class ManagedMutationContract:
    contract: str
    action: str
    execution_boundary: str
    argument_hash: str
    canonical_arguments: Mapping[str, Any]
    canonical_path_enabled: bool = False


_CLIENT_BODY_FIELDS = {
    "tenant.bootstrap/v1": frozenset({"display_name", "admin_name", "admin_email"}),
    "agent.register/v1": frozenset({"name", "description", "configuration"}),
}
_CONTRACT_ACTIONS = {
    "tenant.bootstrap/v1": ("tenant.bootstrap", "control-plane:tenant.bootstrap/v1"),
    "agent.register/v1": ("agent.register", "control-plane:agent.register/v1"),
}


def managed_contract_stub(
    contract: str, body: Mapping[str, Any], bundle: ServerManagedBundle, *, decision: str
) -> None:
    """Validate the inert contract and always stop without callbacks or retained arguments."""
    if contract not in _CONTRACT_ACTIONS:
        raise ValueError("unknown managed contract")
    if not isinstance(bundle, ServerManagedBundle):
        raise TypeError("closed server bundle required")
    if type(body) is not dict:
        raise TypeError("plain JSON object body required")
    extra = sorted(set(body) - _CLIENT_BODY_FIELDS[contract])
    if extra:
        raise ValueError(f"caller-controlled or unknown fields: {','.join(extra)}")
    canonical = _canonical_json_subset(body)
    # Hash and snapshot come from the exact same bytes; nothing is retained on refusal.
    snapshot = json.loads(canonical)
    action, boundary = _CONTRACT_ACTIONS[contract]
    _ = ManagedMutationContract(
        contract,
        action,
        boundary,
        hashlib.sha256(canonical).hexdigest(),
        _immutable_snapshot(snapshot),
    )
    codes = {
        "DENY": "MANAGED_DECISION_DENIED",
        "ESCALATE": "MANAGED_DECISION_ESCALATED",
        "ALLOW": "CANONICAL_PATH_NOT_ENABLED",
    }
    if decision not in codes:
        raise ValueError("unknown decision")
    raise ProductionPostureBlocked(
        (
            PostureBlocker(
                codes[decision],
                contract,
                execution_class=ExecutionClass.CANONICAL_MANAGED_WRITE.value,
            ),
        )
    )


def baseline_policy() -> RuleSetPolicy:
    """Default governance when an org has no active bundle yet.

    ``RuleSetPolicy`` is allow-by-default (rules can only deny/escalate), so
    the baseline ships one protective rule instead of a no-op: destructive
    org-level operations escalate until an explicit policy says otherwise.
    """
    return RuleSetPolicy(
        policy_id=BASELINE_POLICY_ID,
        rules=(
            PolicyRule(
                rule_id="baseline-escalate-org-destructive",
                effect=Decision.ESCALATE,
                tools=frozenset({"org.delete", "org.purge"}),
                reason="destructive org operations require explicit policy + approval",
            ),
        ),
    )


def load_active_policy(session: Session, org_id: str) -> Policy:
    row = session.execute(
        select(PolicyBundle).where(PolicyBundle.org_id == org_id, PolicyBundle.status == "active")
    ).scalar_one_or_none()
    if row is None:
        return baseline_policy()
    return RuleSetPolicy.from_dict(row.bundle)


def org_audit_store(audit_dir: Path, org_id: str) -> ChainHashAuditStore:
    """Legacy local-dev writer; production is blocked before this path is reachable.

    This containment check is not claimed as a race-free production writer.
    P1 replaces the legacy file writer with the durable evidence transaction.
    """
    if not re.fullmatch(r"[A-Za-z0-9._-]+", org_id):
        raise ValueError("invalid audit organization identifier")
    if audit_dir.is_symlink():
        raise ValueError("audit root symlinks are forbidden")
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / f"{org_id}.audit.jsonl"
    if path.is_symlink() or path.parent.resolve() != audit_dir.resolve():
        raise ValueError("audit path must be a contained regular path")
    if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("audit path must be a regular file")
    return ChainHashAuditStore(path)


@dataclass(frozen=True)
class ReadOnlyAuditSnapshot:
    """Bounded, recursively immutable events captured from one no-follow descriptor."""

    events: tuple[Mapping[str, Any], ...]

    def iter_events(self) -> Sequence[Mapping[str, Any]]:
        return self.events

    def verify_chain(
        self, *, expected_count: int | None = None, expected_last_hash: str | None = None
    ) -> dict[str, Any]:
        previous = "0" * 64
        failures: list[dict[str, Any]] = []
        events = self.events
        for event in events:
            if event.get("previous_hash") != previous:
                failures.append(
                    {"event_id": event.get("event_id"), "type": "previous_hash_mismatch"}
                )
            claimed = event.get("event_hash")
            payload = dict(event)
            payload.pop("event_hash", None)
            if claimed != sha256_json(_thaw_frozen_json(payload)):
                failures.append({"event_id": event.get("event_id"), "type": "event_hash_mismatch"})
            previous = str(claimed)
        if expected_count is not None and len(events) != expected_count:
            failures.append(
                {
                    "event_id": None,
                    "type": "length_mismatch",
                    "expected": expected_count,
                    "actual": len(events),
                }
            )
        if expected_last_hash is not None and previous != expected_last_hash:
            failures.append(
                {
                    "event_id": None,
                    "type": "last_hash_mismatch",
                    "expected": expected_last_hash,
                    "actual": previous,
                }
            )
        return {
            "valid": not failures,
            "checked": len(events),
            "failures": failures,
            "last_hash": previous,
        }


_MAPPING_PROXY_TYPE: type[Any] = type(MappingProxyType({}))


def _thaw_frozen_json(value: Any) -> Any:
    """Copy only exact frozen/JSON-native types for internal hash verification."""
    if type(value) is _MAPPING_PROXY_TYPE or type(value) is dict:
        if any(type(key) is not str for key in value):
            raise AuditReadError("unsupported-frozen-event-type")
        return {key: _thaw_frozen_json(child) for key, child in value.items()}
    if type(value) is tuple or type(value) is list:
        return [_thaw_frozen_json(child) for child in value]
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise AuditReadError("unsupported-frozen-event-type")


AUDIT_READ_MAX_BYTES = 8 * 1024 * 1024
AUDIT_READ_MAX_EVENTS = 10_000


class AuditReadError(RuntimeError):
    """Stable fail-closed refusal for unsupported or over-envelope audit reads."""

    code = "AUDIT_READ_REFUSED"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(self.code)


def _parse_audit_snapshot_line(line: bytes, number: int) -> dict[str, Any] | None:
    if number > AUDIT_READ_MAX_EVENTS:
        raise AuditReadError("event-limit-exceeded")
    if not line.strip():
        return None
    try:
        event = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditReadError("invalid-json") from exc
    if type(event) is not dict:
        raise AuditReadError("non-object-event")
    return event


def existing_org_audit_store(audit_dir: Path, org_id: str) -> ReadOnlyAuditSnapshot | None:
    """Capture a read-only chain through no-follow descriptors; never reopen a path."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", org_id):
        raise ValueError("invalid audit organization identifier")
    if audit_dir.is_symlink():
        raise AuditReadError("unsafe-audit-root")
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
    ):
        raise AuditReadError("platform-no-follow-unsupported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        root_fd = os.open(audit_dir, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuditReadError("unsafe-audit-root") from exc
    try:
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(f"{org_id}.audit.jsonl", file_flags, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AuditReadError("unsafe-audit-file") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise AuditReadError("non-regular-audit-file")
            if metadata.st_size > AUDIT_READ_MAX_BYTES:
                raise AuditReadError("byte-limit-exceeded")
            pending = bytearray()
            events: list[Mapping[str, Any]] = []
            total = 0
            while chunk := os.read(fd, 65536):
                total += len(chunk)
                if total > AUDIT_READ_MAX_BYTES:
                    raise AuditReadError("byte-limit-exceeded")
                pending.extend(chunk)
                while (newline := pending.find(b"\n")) >= 0:
                    line = bytes(pending[:newline])
                    del pending[: newline + 1]
                    event = _parse_audit_snapshot_line(line, len(events) + 1)
                    if event is not None:
                        events.append(cast(Mapping[str, Any], _immutable_snapshot(event)))
            if pending:
                event = _parse_audit_snapshot_line(bytes(pending), len(events) + 1)
                if event is not None:
                    events.append(cast(Mapping[str, Any], _immutable_snapshot(event)))
            return ReadOnlyAuditSnapshot(tuple(events))
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def chain_tip(store: ChainHashAuditStore) -> tuple[int, str]:
    """Single pass over the chain file: (event_count, last_event_hash)."""
    count = 0
    last = ""
    for event in store.iter_events():
        count += 1
        last = str(event.get("event_hash", ""))
    return count, last


@dataclass(frozen=True)
class GovernedOutcome:
    """What a governed mutation produced: a result (ALLOW only) + receipt row."""

    result: Any
    receipt: ReceiptRow
    decision: str


class PolicyDeniedError(Exception):
    """Mutation denied by the org's policy bundle. Receipt row is committed."""

    def __init__(self, receipt: ReceiptRow, reason: str) -> None:
        self.receipt = receipt
        self.reason = reason
        super().__init__(reason)


class PolicyEscalatedError(Exception):
    """Mutation requires approval. Receipt row is committed; nothing executed."""

    def __init__(self, receipt: ReceiptRow, reason: str) -> None:
        self.receipt = receipt
        self.reason = reason
        super().__init__(reason)


def _receipt_row_from_payload(org_id: str, payload: dict[str, Any]) -> ReceiptRow:
    return ReceiptRow(
        id=str(payload["event_id"]),
        org_id=org_id,
        tool=str(payload["tool"]),
        decision=str(payload["decision"]),
        actor=str(payload.get("actor", "")),
        goal=str(payload.get("goal", "")),
        argument_hash=str(payload.get("argument_hash", "")),
        audit_hash=str(payload.get("audit_hash", "")),
        policy_version=str(payload.get("policy_version", "")),
        result_hash=payload.get("result_hash"),
        error_class=payload.get("error_class"),
        payload=payload,
    )


def _blocked_payload(record: DecisionRecord, audit_hash: str) -> dict[str, Any]:
    return {
        **record.to_dict(),
        "audit_hash": audit_hash,
        "actor": record.actor,
        "result_hash": None,
        "error_class": None,
    }


def _anchor(session: Session, org_id: str, store: ChainHashAuditStore) -> None:
    """Advance the org's chain-tip anchor — never regress it.

    The file append is serialized by the audit store's flock, but two
    concurrent requests can commit their DB anchors out of order. The row
    lock (``with_for_update``; no-op on SQLite, row-level on PostgreSQL)
    serializes writers, and the monotonic guard makes a stale reader skip
    rather than regress the anchor below the true chain length — a regressed
    anchor would make ``verify_chain`` falsely report a healthy chain as
    truncated.
    """
    count, last = chain_tip(store)
    org = session.get(Organization, org_id, with_for_update=True)
    if org is not None and count >= org.audit_anchor_count:
        org.audit_anchor_count = count
        org.audit_anchor_hash = last


class GovernanceMembrane:
    """Per-request bridge between one org's HTTP mutations and its kernel."""

    def __init__(
        self,
        session: Session,
        audit_dir: Path,
        org_id: str,
        principal: Principal,
    ) -> None:
        self.session = session
        self.org_id = org_id
        self.principal = principal
        self.store = org_audit_store(audit_dir, org_id)
        self.kernel = Kernel(
            policy=load_active_policy(session, org_id),
            audit=self.store,
            actor=principal.actor_id,
        )

    def run(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        fn: Callable[..., Any],
        *,
        goal: str = "",
        path: Sequence[str] = (),
        state: Mapping[str, Any] | None = None,
        persist_blocked_row: bool = True,
    ) -> GovernedOutcome:
        """Dispatch ``fn`` as governed tool ``tool_name``; commit receipt + effect atomically.

        On ALLOW: side effect + receipt row + audit anchor commit together.
        On DENY/ESCALATE: session is rolled back first, then ONLY the receipt
        row + anchor are committed, and a typed error is raised for the HTTP
        layer to map (403 / 202).

        ``persist_blocked_row=False`` is for the genesis dispatch only: when
        the governed mutation *creates the org itself*, a rolled-back DENY /
        ESCALATE leaves no ``organizations`` row for the receipt to reference,
        so persisting one would dangle its foreign key (an IntegrityError on
        PostgreSQL). The decision is still on the org's audit chain file; only
        the queryable DB row is skipped.
        """
        self.kernel.registry.register(tool_name, fn)
        call_state = {"principal_role": self.principal.role.value, **dict(state or {})}
        try:
            result, receipt = self.kernel.dispatch(
                tool_name,
                dict(args),
                goal=goal,
                path=list(path),
                state=call_state,
            )
        except DeniedError as exc:
            row = self._commit_blocked(
                _blocked_payload(exc.record, exc.audit_hash), persist_blocked_row
            )
            raise PolicyDeniedError(row, exc.record.reason) from exc
        except EscalateError as exc:
            row = self._commit_blocked(
                _blocked_payload(exc.record, exc.audit_hash), persist_blocked_row
            )
            raise PolicyEscalatedError(row, exc.record.reason) from exc
        except Exception as exc:
            # Tool execution failed after ALLOW: the kernel appended a
            # synthesized ":failure" DENY event to the audit chain
            # (best-effort). No partial side effect may survive, and the
            # failure must stay visible in the queryable receipts store —
            # these are exactly the receipts a compliance review needs.
            self.session.rollback()
            self._persist_failure_row(tool_name, exc)
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
            raise

        row = self._persist_allowed(receipt)
        return GovernedOutcome(result=result, receipt=row, decision=row.decision)

    def _commit_blocked(self, payload: dict[str, Any], persist_row: bool) -> ReceiptRow:
        """Rollback the blocked mutation, commit only the receipt + anchor."""
        self.session.rollback()
        row = _receipt_row_from_payload(self.org_id, payload)
        if persist_row:
            self.session.add(row)
            _anchor(self.session, self.org_id, self.store)
            self.session.commit()
        return row

    def _persist_failure_row(self, tool_name: str, exc: Exception) -> None:
        """Mirror the kernel's synthesized execution-failure event into the DB.

        The kernel's append is best-effort (suppressed on error), so only
        persist a row when the failure event actually reached the chain.
        """
        last_event: dict[str, Any] | None = None
        for event in self.store.iter_events():
            last_event = event
        if (
            last_event is None
            or last_event.get("tool") != tool_name
            or not str(last_event.get("event_id", "")).endswith(":failure")
        ):
            return
        payload = {
            **last_event,
            "audit_hash": str(last_event.get("event_hash", "")),
            "result_hash": None,
            "error_class": type(exc).__name__,
        }
        self.session.add(_receipt_row_from_payload(self.org_id, payload))

    def _persist_allowed(self, receipt: Receipt) -> ReceiptRow:
        row = _receipt_row_from_payload(self.org_id, receipt.to_dict())
        self.session.add(row)
        _anchor(self.session, self.org_id, self.store)
        self.session.commit()
        return row

    def simulate_decision(
        self,
        tool_name: str,
        args: Mapping[str, Any],
        *,
        actor: str,
        goal: str = "",
        path: Sequence[str] = (),
        state: Mapping[str, Any] | None = None,
    ) -> DecisionRecord:
        """Pure policy preview: evaluate without executing or auditing."""
        call = ToolCall(
            name=tool_name,
            args=dict(args),
            goal=goal,
            actor=actor,
            path=normalize_path_context(list(path)),
            state=dict(state or {}),
        )
        return self.kernel.policy.evaluate(call)
