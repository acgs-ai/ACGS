"""OpenAPI drift sentinel for the current v0 control-plane contract."""

from __future__ import annotations

import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from acgs_control_plane.app import create_app
from acgs_control_plane.config import RuntimePosture, Settings

PARAMETER_SCHEMAS: dict[str, dict[str, Any]] = {
    "path:agent_id": {
        "in": "path",
        "name": "agent_id",
        "required": True,
        "schema": {"type": "string"},
    },
    "path:bundle_id": {
        "in": "path",
        "name": "bundle_id",
        "required": True,
        "schema": {"type": "string"},
    },
    "path:export_id": {
        "in": "path",
        "name": "export_id",
        "required": True,
        "schema": {"type": "string"},
    },
    "path:org_id": {
        "in": "path",
        "name": "org_id",
        "required": True,
        "schema": {"type": "string"},
    },
    "path:receipt_id": {
        "in": "path",
        "name": "receipt_id",
        "required": True,
        "schema": {"type": "string"},
    },
    "query:actor": {
        "in": "query",
        "name": "actor",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "query:cursor": {
        "in": "query",
        "name": "cursor",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "query:decision": {
        "in": "query",
        "name": "decision",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "query:limit": {
        "in": "query",
        "name": "limit",
        "required": False,
        "schema": {"default": 50, "maximum": 500, "minimum": 1, "type": "integer"},
    },
    "query:offset": {
        "in": "query",
        "name": "offset",
        "required": False,
        "schema": {"default": 0, "minimum": 0, "type": "integer"},
    },
    "query:since": {
        "in": "query",
        "name": "since",
        "required": False,
        "schema": {"anyOf": [{"format": "date-time", "type": "string"}, {"type": "null"}]},
    },
    "query:tool": {
        "in": "query",
        "name": "tool",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "query:until": {
        "in": "query",
        "name": "until",
        "required": False,
        "schema": {"anyOf": [{"format": "date-time", "type": "string"}, {"type": "null"}]},
    },
    "header:X-API-Key": {
        "in": "header",
        "name": "X-API-Key",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "header:X-Bootstrap-Token": {
        "in": "header",
        "name": "X-Bootstrap-Token",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "header:Authorization": {
        "in": "header",
        "name": "Authorization",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "header:X-Bootstrap-Invitation": {
        "in": "header",
        "name": "X-Bootstrap-Invitation",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "header:Idempotency-Key": {
        "in": "header",
        "name": "Idempotency-Key",
        "required": False,
        "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
}


def _expected_params(*names: str) -> list[dict[str, Any]]:
    return [copy.deepcopy(PARAMETER_SCHEMAS[name]) for name in names]


PLATFORM_BOOTSTRAP_PATH = "/v1/tenant-bootstrap"
PLATFORM_BOOTSTRAP_RESPONSE_COMPONENT = "TenantBootstrapResponse"

EXPECTED_PATHS: dict[str, dict[str, dict[str, Any]]] = {
    "/healthz": {
        "get": {
            "operation_id": "healthz_healthz_get",
            "parameters": [],
            "responses": ["200"],
            "tag": "meta",
        }
    },
    "/readyz": {
        "get": {
            "operation_id": "readyz_readyz_get",
            "parameters": [],
            "responses": ["200"],
            "tag": "meta",
        }
    },
    "/orgs": {
        "post": {
            "operation_id": "create_org_orgs_post",
            "parameters": _expected_params("header:X-Bootstrap-Token"),
            "responses": ["201", "422"],
            "tag": "orgs",
        }
    },
    "/orgs/{org_id}": {
        "get": {
            "operation_id": "get_org_orgs__org_id__get",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "orgs",
        }
    },
    "/orgs/{org_id}/agents": {
        "get": {
            "operation_id": "list_agents_orgs__org_id__agents_get",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "agents",
        },
        "post": {
            "operation_id": "register_agent_orgs__org_id__agents_post",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["201", "422"],
            "tag": "agents",
        },
    },
    "/orgs/{org_id}/agents/{agent_id}": {
        "get": {
            "operation_id": "get_agent_orgs__org_id__agents__agent_id__get",
            "parameters": _expected_params("path:agent_id", "path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "agents",
        }
    },
    "/orgs/{org_id}/agents/{agent_id}/status": {
        "patch": {
            "operation_id": "set_agent_status_orgs__org_id__agents__agent_id__status_patch",
            "parameters": _expected_params("path:agent_id", "path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "agents",
        }
    },
    "/orgs/{org_id}/dashboard": {
        "get": {
            "operation_id": "dashboard_orgs__org_id__dashboard_get",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "dashboard",
        }
    },
    "/orgs/{org_id}/exports": {
        "get": {
            "operation_id": "list_exports_orgs__org_id__exports_get",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "exports",
        },
        "post": {
            "operation_id": "create_export_orgs__org_id__exports_post",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["201", "422"],
            "tag": "exports",
        },
    },
    "/orgs/{org_id}/exports/{export_id}": {
        "get": {
            "operation_id": "get_export_orgs__org_id__exports__export_id__get",
            "parameters": _expected_params("path:export_id", "path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "exports",
        }
    },
    "/orgs/{org_id}/policies": {
        "get": {
            "operation_id": "list_policies_orgs__org_id__policies_get",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "policies",
        },
        "post": {
            "operation_id": "publish_policy_orgs__org_id__policies_post",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["201", "422"],
            "tag": "policies",
        },
    },
    "/orgs/{org_id}/policies/simulate": {
        "post": {
            "operation_id": "simulate_orgs__org_id__policies_simulate_post",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "policies",
        }
    },
    "/orgs/{org_id}/policies/{bundle_id}/activate": {
        "post": {
            "operation_id": "activate_policy_orgs__org_id__policies__bundle_id__activate_post",
            "parameters": _expected_params("path:bundle_id", "path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "policies",
        }
    },
    "/orgs/{org_id}/receipts": {
        "get": {
            "operation_id": "list_receipts_orgs__org_id__receipts_get",
            "parameters": _expected_params(
                "path:org_id",
                "query:decision",
                "query:tool",
                "query:actor",
                "query:since",
                "query:until",
                "query:limit",
                "query:offset",
                "query:cursor",
                "header:X-API-Key",
            ),
            "responses": ["200", "422"],
            "tag": "receipts",
        }
    },
    "/orgs/{org_id}/receipts/{receipt_id}": {
        "get": {
            "operation_id": "get_receipt_orgs__org_id__receipts__receipt_id__get",
            "parameters": _expected_params("path:receipt_id", "path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "receipts",
        }
    },
    "/orgs/{org_id}/receipts/{receipt_id}/verify": {
        "post": {
            "operation_id": "verify_receipt_orgs__org_id__receipts__receipt_id__verify_post",
            "parameters": _expected_params("path:receipt_id", "path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "receipts",
        }
    },
    "/orgs/{org_id}/users": {
        "get": {
            "operation_id": "list_users_orgs__org_id__users_get",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["200", "422"],
            "tag": "users",
        },
        "post": {
            "operation_id": "create_user_orgs__org_id__users_post",
            "parameters": _expected_params("path:org_id", "header:X-API-Key"),
            "responses": ["201", "422"],
            "tag": "users",
        },
    },
    # Platform tenant bootstrap. This is the one route served under /v1, and it is a
    # control-plane provisioning entry point rather than part of the tenant-facing /v1
    # API surface -- see the boundary test below for why its presence is pinned here
    # but must not be read as /v1 delivery.
    PLATFORM_BOOTSTRAP_PATH: {
        "post": {
            "operation_id": "tenant_bootstrap_v1_tenant_bootstrap_post",
            "parameters": _expected_params(
                "header:Authorization",
                "header:X-Bootstrap-Invitation",
                "header:Idempotency-Key",
            ),
            "responses": ["201", "422"],
            "tag": "tenant-bootstrap",
        }
    },
}

EXPECTED_COMPONENTS = {
    "AgentRegisterRequest",
    "AgentResponse",
    "AgentStatusRequest",
    "DashboardResponse",
    "ExportCreateRequest",
    "ExportDetail",
    "ExportSummary",
    "HTTPValidationError",
    "OrgCreateRequest",
    "OrgCreateResponse",
    "OrgResponse",
    "PolicyPublishRequest",
    "PolicyResponse",
    "ReceiptDetail",
    "ReceiptListResponse",
    "ReceiptSummary",
    "ReceiptVerifyResponse",
    "Role",
    "SimulateRequest",
    "SimulateResponse",
    PLATFORM_BOOTSTRAP_RESPONSE_COMPONENT,
    "UserCreateRequest",
    "UserCreateResponse",
    "UserResponse",
    "ValidationError",
}

EXPECTED_SELECTED_COMPONENTS: dict[str, dict[str, Any]] = {
    "ExportSummary": {
        "properties": {
            "bundle_hash": {"type": "string"},
            "created_at": {"format": "date-time", "type": "string"},
            "created_by": {"type": "string"},
            "export_id": {"type": "string"},
            "receipt_count": {"type": "integer"},
            "receipt_id": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
        "required": [
            "export_id",
            "created_by",
            "receipt_count",
            "bundle_hash",
            "created_at",
        ],
        "type": "object",
    },
    "ReceiptListResponse": {
        "properties": {
            "items": {"items": {"$ref": "#/components/schemas/ReceiptSummary"}, "type": "array"},
            "limit": {"type": "integer"},
            "next_cursor": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "offset": {"type": "integer"},
            "total": {"type": "integer"},
        },
        "required": ["items", "total", "limit", "offset"],
        "type": "object",
    },
    "ReceiptSummary": {
        "properties": {
            "actor": {"type": "string"},
            "audit_hash": {"type": "string"},
            "created_at": {"format": "date-time", "type": "string"},
            "decision": {"type": "string"},
            "goal": {"type": "string"},
            "policy_version": {"type": "string"},
            "receipt_id": {"type": "string"},
            "tool": {"type": "string"},
        },
        "required": [
            "receipt_id",
            "tool",
            "decision",
            "actor",
            "goal",
            "policy_version",
            "audit_hash",
            "created_at",
        ],
        "type": "object",
    },
    "Role": {
        "enum": ["org_admin", "policy_author", "agent_operator", "auditor", "viewer"],
        "type": "string",
    },
}


def _app_for_openapi(tmp_path: Path) -> Any:
    return create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'openapi.sqlite3'}",
            audit_dir=tmp_path / "audit",
            bootstrap_token="test-bootstrap-token",
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )


def _tree_bytes(path: Path) -> bytes:
    if not path.exists():
        return b""
    payload = bytearray()
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        payload.extend(child.relative_to(path).as_posix().encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(child.read_bytes())
    return bytes(payload)


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compact_schema(schema: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for key in (
        "$ref",
        "type",
        "format",
        "default",
        "minimum",
        "maximum",
        "enum",
    ):
        if key in schema:
            compact[key] = schema[key]
    if "anyOf" in schema:
        compact["anyOf"] = [_compact_schema(branch) for branch in schema["anyOf"]]
    if "items" in schema:
        compact["items"] = _compact_schema(schema["items"])
    if "required" in schema:
        compact["required"] = list(schema["required"])
    if "properties" in schema:
        compact["properties"] = {
            name: _compact_schema(property_schema)
            for name, property_schema in sorted(schema["properties"].items())
        }
    return compact


def _parameter_contract(parameter: dict[str, Any]) -> dict[str, Any]:
    return {
        "in": parameter["in"],
        "name": parameter["name"],
        "required": parameter["required"],
        "schema": _compact_schema(parameter["schema"]),
    }


def _operation_contract(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "operation_id": operation["operationId"],
        "parameters": [
            _parameter_contract(parameter) for parameter in operation.get("parameters", [])
        ],
        "responses": sorted(operation["responses"]),
        "tag": operation["tags"][0],
    }


def _normalized_contract(schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "openapi": schema["openapi"],
        "paths": {
            path: {
                method: _operation_contract(operation)
                for method, operation in sorted(methods.items())
            }
            for path, methods in sorted(schema["paths"].items())
        },
        "components": sorted(schema["components"]["schemas"]),
        "selected_components": {
            name: _compact_schema(schema["components"]["schemas"][name])
            for name in sorted(EXPECTED_SELECTED_COMPONENTS)
        },
        "receipt_list_response": schema["components"]["schemas"]["ReceiptListResponse"],
    }


def _contract_digest(schema: dict[str, Any]) -> str:
    return hashlib.sha256(_json_bytes(_normalized_contract(schema))).hexdigest()


def _assert_current_v0_contract(schema: dict[str, Any]) -> None:
    normalized = _normalized_contract(schema)
    assert normalized["paths"] == EXPECTED_PATHS
    assert set(normalized["components"]) == EXPECTED_COMPONENTS
    assert normalized["selected_components"] == EXPECTED_SELECTED_COMPONENTS

    receipt_response = normalized["receipt_list_response"]
    assert receipt_response["required"] == ["items", "total", "limit", "offset"]
    assert "next_cursor" in receipt_response["properties"]
    assert receipt_response["properties"]["next_cursor"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "title": "Next Cursor",
    }
    assert (
        schema["paths"]["/orgs/{org_id}/receipts"]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/ReceiptListResponse"
    )


def test_current_openapi_contract_is_stable_and_side_effect_free(tmp_path: Path) -> None:
    app = _app_for_openapi(tmp_path)
    database_path = tmp_path / "openapi.sqlite3"
    audit_dir = tmp_path / "audit"
    before = {"database": _file_hash(database_path), "audit": _tree_bytes(audit_dir)}

    schema = app.openapi()
    _assert_current_v0_contract(schema)

    assert {"database": _file_hash(database_path), "audit": _tree_bytes(audit_dir)} == before
    assert _contract_digest(schema) == _contract_digest(app.openapi())

    with ThreadPoolExecutor(max_workers=4) as executor:
        digests = set(executor.map(lambda _: _contract_digest(app.openapi()), range(12)))
    assert digests == {_contract_digest(schema)}


def test_current_openapi_contract_records_missing_beta_contract_boundaries(
    tmp_path: Path,
) -> None:
    schema = _app_for_openapi(tmp_path).openapi()
    serialized = json.dumps(schema, sort_keys=True)

    # The platform tenant-bootstrap route is the only path served under /v1. It
    # provisions tenants; it is not the tenant-facing /v1 API contract, and the
    # per-request Idempotency-Key header it accepts is not the durable idempotency
    # persistence the aggregate G102 contract still owes. Both carve-outs name that
    # one route explicitly, so a second /v1 path -- or an idempotency surface
    # anywhere else in the schema -- still trips this sentinel.
    # Note: docs/saas/DELIVERY_DAG.yaml does not mention this route and still records
    # "/v1 root ... remain missing" for G102. Reconciling that wording is follow-up
    # work; this carve-out records the served surface, not a delivery claim.
    assert [path for path in schema["paths"] if path == "/v1" or path.startswith("/v1/")] == [
        PLATFORM_BOOTSTRAP_PATH
    ]
    outside_bootstrap = copy.deepcopy(schema)
    del outside_bootstrap["paths"][PLATFORM_BOOTSTRAP_PATH]
    del outside_bootstrap["components"]["schemas"][PLATFORM_BOOTSTRAP_RESPONSE_COMPONENT]
    serialized_outside_bootstrap = json.dumps(outside_bootstrap, sort_keys=True)
    assert "Idempotency-Key" not in serialized_outside_bootstrap
    assert "idempotency_key" not in serialized_outside_bootstrap
    assert "/jobs" not in serialized
    assert "AsyncExport" not in serialized
    assert "202" not in schema["paths"]["/orgs/{org_id}/exports"]["post"]["responses"]

    cursor_parameters = [
        (path, method)
        for path, methods in schema["paths"].items()
        for method, operation in methods.items()
        if any(parameter["name"] == "cursor" for parameter in operation.get("parameters", []))
    ]
    assert cursor_parameters == [("/orgs/{org_id}/receipts", "get")]
    assert all(
        "next_cursor" not in json.dumps(component, sort_keys=True)
        for name, component in schema["components"]["schemas"].items()
        if name != "ReceiptListResponse"
    )


def test_current_openapi_contract_does_not_leak_local_runtime_values(tmp_path: Path) -> None:
    database_path = tmp_path / "secret-control-plane.sqlite3"
    audit_dir = tmp_path / "secret-audit-dir"
    bootstrap_token = "sk_live_OPENAPI_SENTINEL_BOOTSTRAP"
    app = create_app(
        Settings(
            database_url=f"sqlite:///{database_path}",
            audit_dir=audit_dir,
            bootstrap_token=bootstrap_token,
            create_tables=True,
            runtime_posture=RuntimePosture.LOCAL_DEV_LEGACY_UNSIGNED,
        )
    )

    serialized = json.dumps(app.openapi(), sort_keys=True)

    assert bootstrap_token not in serialized
    assert str(database_path) not in serialized
    assert str(audit_dir) not in serialized
    assert "secret-control-plane.sqlite3" not in serialized
    assert "secret-audit-dir" not in serialized


def test_contract_sentinel_detects_receipt_parameter_schema_drift(tmp_path: Path) -> None:
    schema = copy.deepcopy(_app_for_openapi(tmp_path).openapi())
    receipt_parameters = schema["paths"]["/orgs/{org_id}/receipts"]["get"]["parameters"]
    limit_parameter = next(
        parameter for parameter in receipt_parameters if parameter["name"] == "limit"
    )
    cursor_parameter = next(
        parameter for parameter in receipt_parameters if parameter["name"] == "cursor"
    )
    limit_parameter["schema"]["default"] = 25
    limit_parameter["schema"]["maximum"] = 1000

    with pytest.raises(AssertionError):
        _assert_current_v0_contract(schema)

    schema = copy.deepcopy(_app_for_openapi(tmp_path).openapi())
    receipt_parameters = schema["paths"]["/orgs/{org_id}/receipts"]["get"]["parameters"]
    cursor_parameter = next(
        parameter for parameter in receipt_parameters if parameter["name"] == "cursor"
    )
    cursor_parameter["required"] = True

    with pytest.raises(AssertionError):
        _assert_current_v0_contract(schema)


def test_contract_sentinel_detects_response_component_schema_drift(tmp_path: Path) -> None:
    schema = copy.deepcopy(_app_for_openapi(tmp_path).openapi())
    schema["components"]["schemas"]["ExportSummary"]["properties"]["receipt_count"]["type"] = (
        "string"
    )

    with pytest.raises(AssertionError):
        _assert_current_v0_contract(schema)

    schema = copy.deepcopy(_app_for_openapi(tmp_path).openapi())
    schema["components"]["schemas"]["ReceiptListResponse"]["properties"]["total"]["type"] = "string"
    schema["components"]["schemas"]["ReceiptListResponse"]["required"].remove("total")

    with pytest.raises(AssertionError):
        _assert_current_v0_contract(schema)
