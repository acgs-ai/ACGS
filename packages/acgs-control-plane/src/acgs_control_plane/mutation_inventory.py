"""Runtime inventory for canonical managed control-plane mutations.

This module is an accidental-drift guard, not an in-process sandbox. It seals
the concrete FastAPI route/dependency objects created at startup and refuses
requests if a later route, endpoint, or RBAC dependency mutation changes that
surface before the handler runs.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
import json
import textwrap
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse
from starlette.routing import Route

from acgs_control_plane.managed_mutations import (
    CONTROL_PLANE_AGENT_CREATE_ACTION,
    CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
    CONTROL_PLANE_POLICY_PUBLISH_ACTION,
    TENANT_BOOTSTRAP_ACTION,
)
from acgs_control_plane.rbac import Permission


class MutationEffectClass(StrEnum):
    SQL_ATOMIC = "sql_atomic"
    DURABLE_JOB_ENQUEUE = "durable_job_enqueue"
    EXTERNAL_ATTEMPT = "external_attempt"


@dataclass(frozen=True)
class MutationDefinition:
    operation_id: str
    method: str
    path: str
    action: str
    effect_class: MutationEffectClass
    dispatcher: str
    service: str
    state_key: str
    service_method: str
    permission: str | None
    scope: str
    static_symbols: tuple[str, ...]
    allowed_static_findings: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class MutationInventoryBlocker:
    code: str
    component: str
    operation_id: str | None = None
    route: str | None = None
    detail: str | None = None

    def to_redacted_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "component": self.component,
            "operation_id": self.operation_id,
            "route": self.route,
            "detail": self.detail,
        }


class MutationInventoryDriftError(RuntimeError):
    code = "MUTATION_INVENTORY_DRIFT"

    def __init__(self, blockers: Sequence[MutationInventoryBlocker]) -> None:
        self.blockers = tuple(blockers)
        super().__init__(self.code)


class MutationGuardedFastAPI(FastAPI):
    """FastAPI app with an outer HTTP drift guard before middleware dispatch."""

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            try:
                enforce_mutation_inventory(self)
            except MutationInventoryDriftError as exc:
                response = mutation_inventory_drift_response(exc)
                await response(scope, receive, send)
                return
        await super().__call__(scope, receive, send)


_UNVERSIONED_CANONICAL_MUTATION_DEFINITIONS: tuple[MutationDefinition, ...] = (
    MutationDefinition(
        operation_id="tenant-bootstrap.create",
        method="POST",
        path="/v1/tenant-bootstrap",
        action=TENANT_BOOTSTRAP_ACTION,
        effect_class=MutationEffectClass.SQL_ATOMIC,
        dispatcher="managed-mutation-uow.execute_with_receipt",
        service="acgs_control_plane.tenant_bootstrap.TenantBootstrapService",
        state_key="tenant_bootstrap_service",
        service_method="bootstrap",
        permission=None,
        scope="platform-to-tenant-default-project-environment",
        static_symbols=(
            "acgs_control_plane.tenant_bootstrap.TenantBootstrapService.bootstrap",
            "acgs_control_plane.tenant_bootstrap.TenantBootstrapService._execute_allow",
            "acgs_control_plane.tenant_bootstrap.TenantBootstrapService._record_non_executable",
            "acgs_control_plane.tenant_bootstrap._execute_bootstrap_effect",
            "acgs_control_plane.managed_mutations._execute_verified_operation",
        ),
        allowed_static_findings={
            "acgs_control_plane.tenant_bootstrap.TenantBootstrapService._record_non_executable": (
                "SQL_ATOMIC_FORBIDDEN_METHOD:direct-transaction-control",
            )
        },
    ),
    MutationDefinition(
        operation_id="agent.register",
        method="POST",
        path="/orgs/{org_id}/agents",
        action=CONTROL_PLANE_AGENT_CREATE_ACTION,
        effect_class=MutationEffectClass.SQL_ATOMIC,
        dispatcher="managed-mutation-uow.execute_with_receipt",
        service="acgs_control_plane.agent_registration.AgentRegistrationService",
        state_key="agent_registration_service",
        service_method="register",
        permission=Permission.AGENT_REGISTER.value,
        scope="org-default-project-environment",
        static_symbols=(
            "acgs_control_plane.agent_registration.AgentRegistrationService.register",
            "acgs_control_plane.managed_mutations._execute_verified_operation",
        ),
    ),
    MutationDefinition(
        operation_id="environment-policy.publish",
        method="POST",
        path="/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies",
        action=CONTROL_PLANE_POLICY_PUBLISH_ACTION,
        effect_class=MutationEffectClass.SQL_ATOMIC,
        dispatcher="managed-mutation-uow.execute_with_receipt",
        service="acgs_control_plane.policy_registry.PolicyRegistryService",
        state_key="policy_registry_service",
        service_method="publish",
        permission=Permission.POLICY_PUBLISH.value,
        scope="org-project-environment",
        static_symbols=(
            "acgs_control_plane.policy_registry.PolicyRegistryService.publish",
            "acgs_control_plane.policy_registry.PolicyRegistryService._record_non_executable",
            "acgs_control_plane.managed_mutations._execute_verified_operation",
        ),
    ),
    MutationDefinition(
        operation_id="environment-policy.activate",
        method="POST",
        path="/orgs/{org_id}/projects/{project_id}/environments/{environment_id}/policies/{policy_version_id}/activate",
        action=CONTROL_PLANE_POLICY_ACTIVATE_ACTION,
        effect_class=MutationEffectClass.SQL_ATOMIC,
        dispatcher="managed-mutation-uow.execute_with_receipt",
        service="acgs_control_plane.policy_registry.PolicyRegistryService",
        state_key="policy_registry_service",
        service_method="activate",
        permission=Permission.POLICY_ACTIVATE.value,
        scope="org-project-environment",
        static_symbols=(
            "acgs_control_plane.policy_registry.PolicyRegistryService.activate",
            "acgs_control_plane.policy_registry.PolicyRegistryService._record_non_executable",
            "acgs_control_plane.managed_mutations._execute_verified_operation",
        ),
    ),
)

# Every canonical managed write is also served under the /v1 alias prefix, so
# each aliased route carries the same sealed mutation contract as its
# unversioned source. Leaving the alias out of the inventory would exempt an
# active managed write route from per-route binding checks.
CANONICAL_MUTATION_DEFINITIONS: tuple[MutationDefinition, ...] = (
    *_UNVERSIONED_CANONICAL_MUTATION_DEFINITIONS,
    *(
        replace(
            definition,
            operation_id=f"{definition.operation_id}.v1",
            path=f"/v1{definition.path}",
        )
        for definition in _UNVERSIONED_CANONICAL_MUTATION_DEFINITIONS
        if not definition.path.startswith("/v1")
    ),
)


@dataclass(frozen=True)
class MutationInventorySeal:
    definitions: Mapping[str, Mapping[str, Any]]
    surface_hash: str
    route_hashes: Mapping[str, str]


def build_mutation_inventory_seal(app: FastAPI) -> MutationInventorySeal:
    """Seal the current app route/dependency surface and canonical mutations."""
    blockers = verify_static_sql_atomic_safety(CANONICAL_MUTATION_DEFINITIONS)
    definitions = _definition_index(CANONICAL_MUTATION_DEFINITIONS)
    surface, route_hashes, surface_blockers = _surface_snapshot(app, definitions)
    blockers = (*blockers, *surface_blockers)
    if blockers:
        raise MutationInventoryDriftError(blockers)
    frozen_definitions = {
        operation_id: MappingProxyType(payload) for operation_id, payload in definitions.items()
    }
    return MutationInventorySeal(
        definitions=MappingProxyType(frozen_definitions),
        surface_hash=_hash_json(surface),
        route_hashes=MappingProxyType(route_hashes),
    )


def enforce_mutation_inventory(app: FastAPI) -> None:
    seal = getattr(app.state, "mutation_inventory_seal", None)
    if not isinstance(seal, MutationInventorySeal):
        raise MutationInventoryDriftError(
            (
                MutationInventoryBlocker(
                    "MUTATION_INVENTORY_UNSEALED",
                    "mutation-inventory",
                    detail="request refused before handler",
                ),
            )
        )
    definitions = {
        operation_id: dict(payload) for operation_id, payload in seal.definitions.items()
    }
    surface, route_hashes, blockers = _surface_snapshot(app, definitions)
    if _hash_json(surface) != seal.surface_hash:
        blockers = (
            *blockers,
            MutationInventoryBlocker(
                "ROUTE_SURFACE_DRIFT",
                "mutation-inventory",
                detail="request refused before handler",
            ),
        )
    for operation_id, sealed_hash in seal.route_hashes.items():
        if route_hashes.get(operation_id) != sealed_hash:
            definition = definitions.get(operation_id, {})
            blockers = (
                *blockers,
                MutationInventoryBlocker(
                    "MANAGED_ROUTE_BINDING_DRIFT",
                    "mutation-inventory",
                    operation_id=operation_id,
                    route=f"{definition.get('method')} {definition.get('path')}",
                    detail="request refused before handler",
                ),
            )
    if blockers:
        raise MutationInventoryDriftError(_dedupe_blockers(blockers))


def mutation_inventory_drift_response(exc: MutationInventoryDriftError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "code": exc.code,
            "status": "mutation-inventory-drift",
            "details": [blocker.to_redacted_dict() for blocker in exc.blockers],
        },
    )


def verify_static_sql_atomic_safety(
    definitions: Sequence[MutationDefinition],
) -> tuple[MutationInventoryBlocker, ...]:
    blockers: list[MutationInventoryBlocker] = []
    for definition in definitions:
        if definition.effect_class is not MutationEffectClass.SQL_ATOMIC:
            continue
        for symbol in definition.static_symbols:
            allowed = frozenset(definition.allowed_static_findings.get(symbol, ()))
            blockers.extend(
                blocker
                for blocker in _scan_symbol(symbol, operation_id=definition.operation_id)
                if f"{blocker.code}:{blocker.detail}" not in allowed
            )
    return tuple(_dedupe_blockers(blockers))


def _definition_index(definitions: Sequence[MutationDefinition]) -> dict[str, dict[str, Any]]:
    active_non_sql = [
        d.operation_id
        for d in definitions
        if d.effect_class
        in {MutationEffectClass.DURABLE_JOB_ENQUEUE, MutationEffectClass.EXTERNAL_ATTEMPT}
    ]
    if active_non_sql:
        raise MutationInventoryDriftError(
            tuple(
                MutationInventoryBlocker(
                    "UNIMPLEMENTED_EFFECT_CLASS_ACTIVE",
                    "mutation-inventory",
                    operation_id=operation_id,
                    detail="job/external contracts are representational only in this slice",
                )
                for operation_id in active_non_sql
            )
        )
    return {
        definition.operation_id: {
            "operation_id": definition.operation_id,
            "method": definition.method,
            "path": definition.path,
            "action": definition.action,
            "effect_class": definition.effect_class.value,
            "dispatcher": definition.dispatcher,
            "service": definition.service,
            "state_key": definition.state_key,
            "service_method": definition.service_method,
            "permission": definition.permission,
            "scope": definition.scope,
            "static_symbols": list(definition.static_symbols),
            "allowed_static_findings": {
                symbol: list(findings)
                for symbol, findings in sorted(definition.allowed_static_findings.items())
            },
        }
        for definition in definitions
    }


def _surface_snapshot(
    app: FastAPI, definitions: Mapping[str, Mapping[str, Any]]
) -> tuple[dict[str, Any], dict[str, str], tuple[MutationInventoryBlocker, ...]]:
    blockers: list[MutationInventoryBlocker] = []
    routes: list[dict[str, Any]] = []
    route_hashes: dict[str, str] = {}
    expected = {(str(d["method"]), str(d["path"])): op for op, d in definitions.items()}
    seen_expected: dict[str, int] = {operation_id: 0 for operation_id in definitions}
    dependency_overrides = _dependency_override_snapshot(app)
    for index, route in enumerate(app.routes):
        if not isinstance(route, Route):
            blockers.append(
                MutationInventoryBlocker(
                    "UNCLASSIFIED_ACTIVE_SURFACE",
                    "route-registry",
                    route=f"{type(route).__name__} {getattr(route, 'path', '<unknown>')}",
                )
            )
            continue
        if not isinstance(route, APIRoute):
            routes.append(
                {
                    "index": index,
                    "kind": type(route).__name__,
                    "path": route.path,
                    "methods": sorted(route.methods or ()),
                    "endpoint": _callable_fingerprint(getattr(route, "endpoint", None)),
                    "route_app": _callable_fingerprint(getattr(route, "app", None)),
                    "path_regex": _path_regex_snapshot(route),
                    "param_convertors": _param_convertor_snapshot(route),
                    "dependencies": [],
                    "operation_id": None,
                }
            )
            continue
        dependencies = sorted(
            (
                fingerprint
                for fingerprint in (
                    _callable_fingerprint(call) for call in _dependency_calls(route)
                )
                if fingerprint is not None
            ),
            key=_hash_json,
        )
        for method in sorted(route.methods or ()):
            operation_id = expected.get((method, route.path))
            permissions = sorted(_dependency_permissions(route))
            route_record = {
                "index": index,
                "kind": "APIRoute",
                "path": route.path,
                "method": method,
                "endpoint": _callable_fingerprint(route.endpoint),
                "route_app": _callable_fingerprint(getattr(route, "app", None)),
                "dependant_call": _callable_fingerprint(getattr(route.dependant, "call", None)),
                "dependencies": dependencies,
                "dependency_overrides": dependency_overrides,
                "path_regex": _path_regex_snapshot(route),
                "param_convertors": _param_convertor_snapshot(route),
                "permissions": permissions,
                "operation_id": operation_id,
            }
            routes.append(route_record)
            if operation_id is not None:
                seen_expected[operation_id] += 1
                definition = definitions[operation_id]
                expected_permission = definition.get("permission")
                if expected_permission is not None and expected_permission not in permissions:
                    blockers.append(
                        MutationInventoryBlocker(
                            "RBAC_CONTRACT_DRIFT",
                            "mutation-inventory",
                            operation_id=operation_id,
                            route=f"{method} {route.path}",
                            detail="request refused before handler",
                        )
                    )
                service_record, service_blockers = _service_binding_snapshot(
                    app, operation_id=operation_id, definition=definition
                )
                blockers.extend(service_blockers)
                route_record["service_binding"] = service_record
                route_hashes[operation_id] = _hash_json(route_record)
    for operation_id, count in seen_expected.items():
        if count != 1:
            definition = definitions[operation_id]
            blockers.append(
                MutationInventoryBlocker(
                    "MANAGED_ROUTE_CONTRACT_DRIFT",
                    "mutation-inventory",
                    operation_id=operation_id,
                    route=f"{definition.get('method')} {definition.get('path')}",
                    detail="request refused before handler",
                )
            )
    surface = {
        "schema": "acgs-mutation-inventory-surface/v1",
        "middleware": [
            _middleware_fingerprint(middleware)
            for middleware in getattr(app, "user_middleware", ())
        ],
        "routes": routes,
    }
    return surface, route_hashes, tuple(_dedupe_blockers(blockers))


def _service_binding_snapshot(
    app: FastAPI, *, operation_id: str, definition: Mapping[str, Any]
) -> tuple[dict[str, Any], tuple[MutationInventoryBlocker, ...]]:
    state_key = str(definition.get("state_key"))
    method_name = str(definition.get("service_method"))
    expected_service = str(definition.get("service"))
    service = getattr(app.state, state_key, None)
    if service is None:
        return {}, (
            MutationInventoryBlocker(
                "SERVICE_BINDING_MISSING",
                "mutation-inventory",
                operation_id=operation_id,
                detail="request refused before handler",
            ),
        )
    service_type = type(service)
    service_type_name = f"{service_type.__module__}.{service_type.__qualname__}"
    blockers: list[MutationInventoryBlocker] = []
    if service_type_name != expected_service:
        blockers.append(
            MutationInventoryBlocker(
                "SERVICE_BINDING_DRIFT",
                "mutation-inventory",
                operation_id=operation_id,
                detail="request refused before handler",
            )
        )
    return (
        {
            "state_key": state_key,
            "service_type": service_type_name,
            "service_instance": _object_fingerprint(service),
            "bound_method": _callable_fingerprint(getattr(service, method_name, None)),
            "class_method": _callable_fingerprint(getattr(service_type, method_name, None)),
            "dispatcher": definition.get("dispatcher"),
        },
        tuple(blockers),
    )


def _dependency_calls(route: APIRoute) -> Iterable[Any]:
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return
    stack = list(dependant.dependencies)
    while stack:
        dependant = stack.pop()
        yield getattr(dependant, "call", None)
        stack.extend(getattr(dependant, "dependencies", ()))


def _dependency_permissions(route: APIRoute) -> set[str]:
    permissions: set[str] = set()
    for call in _dependency_calls(route):
        permissions.update(_permissions_from_callable(call))
    return permissions


def _dependency_override_snapshot(app: FastAPI) -> list[dict[str, Any]]:
    return [
        {
            "key": _callable_fingerprint(key),
            "value": _callable_fingerprint(value),
        }
        for key, value in app.dependency_overrides.items()
    ]


def _middleware_fingerprint(middleware: Any) -> dict[str, Any]:
    return {
        "cls": _callable_fingerprint(getattr(middleware, "cls", None)),
        "args_hash": _hash_json(
            [_config_fingerprint(arg) for arg in getattr(middleware, "args", ())]
        ),
        "kwargs_hash": _hash_json(
            {
                str(key): _config_fingerprint(value)
                for key, value in getattr(middleware, "kwargs", {}).items()
            }
        ),
    }


def _safe_symbol(value: Any) -> str:
    return f"{type(value).__module__}.{type(value).__qualname__}"


def _config_fingerprint(value: Any) -> dict[str, Any]:
    if callable(value):
        return {"kind": "callable", "value": _callable_fingerprint(value)}
    if value is None or isinstance(value, str | int | bool):
        return {"kind": "literal", "type": _safe_symbol(value), "value": value}
    if isinstance(value, tuple):
        return {"kind": "tuple", "items": [_config_fingerprint(item) for item in value]}
    if isinstance(value, frozenset):
        items = [_config_fingerprint(item) for item in value]
        return {"kind": "frozenset", "items": sorted(items, key=_hash_json)}
    if isinstance(value, Mapping):
        return {
            "kind": "mapping",
            "items": [
                {
                    "key": _config_fingerprint(key),
                    "value": _config_fingerprint(item_value),
                }
                for key, item_value in sorted(
                    value.items(), key=lambda item: _hash_json(_config_fingerprint(item[0]))
                )
            ],
        }
    return {
        "kind": "opaque",
        "type": _safe_symbol(value),
        "object_hash": _object_fingerprint(value),
    }


def _permissions_from_callable(call: Any) -> set[str]:
    permissions: set[str] = set()
    closure = getattr(call, "__closure__", None) or ()
    for cell in closure:
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        if isinstance(value, Permission):
            permissions.add(value.value)
    return permissions


def _callable_fingerprint(call: Any) -> dict[str, Any] | None:
    if call is None:
        return None
    function = getattr(call, "__func__", call)
    code = getattr(function, "__code__", None)
    code_payload: dict[str, Any] | None = None
    if code is not None:
        code_payload = {
            "argcount": code.co_argcount,
            "kwonlyargcount": code.co_kwonlyargcount,
            "names": list(code.co_names),
            "varnames": list(code.co_varnames),
            "bytecode": code.co_code.hex(),
        }
    return {
        "module": getattr(function, "__module__", type(function).__module__),
        "qualname": getattr(function, "__qualname__", type(function).__qualname__),
        "object_hash": _object_fingerprint(function),
        "self_hash": _object_fingerprint(getattr(call, "__self__", None)),
        "code_hash": _hash_json(code_payload) if code_payload is not None else None,
        "closure_permissions": sorted(_permissions_from_callable(call)),
    }


_FORBIDDEN_CALLS = {
    "open": "filesystem",
    "io.open": "filesystem",
    "os.open": "filesystem",
    "Path.open": "filesystem",
    "subprocess.run": "subprocess",
    "subprocess.Popen": "subprocess",
    "subprocess.call": "subprocess",
    "subprocess.check_call": "subprocess",
    "subprocess.check_output": "subprocess",
    "requests.get": "network",
    "requests.post": "network",
    "requests.request": "network",
    "httpx.get": "network",
    "httpx.post": "network",
    "httpx.request": "network",
    "socket.socket": "network",
    "socket.create_connection": "network",
    "BackgroundTasks": "background-task",
    "threading.Thread": "thread",
    "multiprocessing.Process": "process",
}
_FORBIDDEN_METHODS = {
    "commit": "direct-transaction-control",
    "rollback": "direct-transaction-control",
    "add_task": "background-task",
    "start": "thread-or-process-start",
}


def _scan_symbol(symbol: str, *, operation_id: str) -> tuple[MutationInventoryBlocker, ...]:
    obj = _resolve_symbol(symbol)
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(obj)))
    except (OSError, SyntaxError, TypeError) as exc:
        return (
            MutationInventoryBlocker(
                "STATIC_GUARD_SOURCE_UNAVAILABLE",
                "mutation-static-guard",
                operation_id=operation_id,
                detail=type(exc).__name__,
            ),
        )
    blockers: list[MutationInventoryBlocker] = []
    aliases = _import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _resolve_alias(_call_name(node.func), aliases)
        if call_name in _FORBIDDEN_CALLS:
            blockers.append(
                MutationInventoryBlocker(
                    "SQL_ATOMIC_FORBIDDEN_CALL",
                    "mutation-static-guard",
                    operation_id=operation_id,
                    detail=_FORBIDDEN_CALLS[call_name],
                )
            )
        if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_METHODS:
            blockers.append(
                MutationInventoryBlocker(
                    "SQL_ATOMIC_FORBIDDEN_METHOD",
                    "mutation-static-guard",
                    operation_id=operation_id,
                    detail=_FORBIDDEN_METHODS[node.func.attr],
                )
            )
    return tuple(blockers)


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Assign):
            value = _resolve_alias(_call_name(node.value), aliases)
            if value in _FORBIDDEN_CALLS:
                for target in node.targets:
                    target_name = _call_name(target)
                    if target_name:
                        aliases[target_name] = value
    return aliases


def _resolve_alias(name: str, aliases: Mapping[str, str]) -> str:
    if not name:
        return name
    parts = name.split(".")
    head = aliases.get(parts[0])
    if head is None:
        return name
    return ".".join((head, *parts[1:]))


def _resolve_symbol(symbol: str) -> Any:
    module_name, _, attr_path = symbol.partition(":")
    if not attr_path:
        parts = symbol.split(".")
        module = None
        attr_parts: list[str] = []
        for index in range(len(parts), 0, -1):
            candidate = ".".join(parts[:index])
            try:
                module = importlib.import_module(candidate)
            except ModuleNotFoundError:
                continue
            attr_parts = parts[index:]
            break
        if module is None or not attr_parts:
            raise ModuleNotFoundError(symbol)
        obj: Any = module
        for attr in attr_parts:
            obj = getattr(obj, attr)
        return obj
    module = importlib.import_module(module_name)
    colon_obj: Any = module
    for attr in attr_path.split("."):
        colon_obj = getattr(colon_obj, attr)
    return colon_obj


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _path_regex_snapshot(route: Route) -> dict[str, Any] | None:
    path_regex = getattr(route, "path_regex", None)
    if path_regex is None:
        return None
    return {
        "pattern": getattr(path_regex, "pattern", None),
        "flags": getattr(path_regex, "flags", None),
    }


def _param_convertor_snapshot(route: Route) -> dict[str, dict[str, str]]:
    convertors = getattr(route, "param_convertors", {})
    return {
        str(name): {
            "type": type(convertor).__qualname__,
            "regex": str(getattr(convertor, "regex", "")),
        }
        for name, convertor in sorted(convertors.items())
    }


def _object_fingerprint(value: Any) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(
        f"{type(value).__module__}.{type(value).__qualname__}:{id(value)}".encode("ascii")
    ).hexdigest()


def _hash_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _dedupe_blockers(
    blockers: Sequence[MutationInventoryBlocker],
) -> tuple[MutationInventoryBlocker, ...]:
    return tuple(
        sorted(
            {
                (
                    blocker.code,
                    blocker.component,
                    blocker.operation_id,
                    blocker.route,
                    blocker.detail,
                ): blocker
                for blocker in blockers
            }.values(),
            key=lambda item: (
                item.code,
                item.component,
                item.operation_id or "",
                item.route or "",
                item.detail or "",
            ),
        )
    )
