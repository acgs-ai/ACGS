"""Request admission and redacted API error contracts."""

from __future__ import annotations

import json
import math
import re
import secrets
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from acgs_control_plane.config import validate_max_request_body_bytes

REQUEST_ID_HEADER = "x-request-id"
REQUEST_ID_BYTES = 16
REQUEST_ID_RE = re.compile(r"^req_[0-9a-f]{32}$")
IJSON_MAX_SAFE_INTEGER = (1 << 53) - 1
IJSON_MAX_DEPTH = 64
IJSON_MAX_NODES = 10_000

_JSON_HEADERS = [
    (b"content-type", b"application/json"),
    (b"cache-control", b"no-store"),
]


def new_request_id() -> str:
    """Return a bounded server-generated request ID."""

    return f"req_{secrets.token_hex(REQUEST_ID_BYTES)}"


def request_id_from_scope(scope: Scope) -> str:
    state = scope.setdefault("state", {})
    request_id = state.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        request_id = new_request_id()
        state["request_id"] = request_id
    return request_id


def redacted_error(code: str, request_id: str, *, status: str = "error") -> dict[str, str]:
    return {"code": code, "status": status, "request_id": request_id}


def _content_length_values(scope: Scope) -> list[bytes]:
    return [
        value.strip()
        for name, value in scope.get("headers", [])
        if name.lower() == b"content-length"
    ]


def parse_content_length(
    scope: Scope, *, max_request_body_bytes: int
) -> tuple[int | None, str | None]:
    values = _content_length_values(scope)
    if not values:
        return None, None
    if len(values) != 1:
        return None, "invalid_content_length"
    raw = values[0]
    if not raw.isascii() or not raw.isdigit():
        return None, "invalid_content_length"
    if len(raw) > len(str(max_request_body_bytes)):
        return None, "request_body_too_large"
    return int(raw), None


class RequestAdmissionMiddleware:
    """Raw ASGI admission gate before FastAPI body parsing or route invocation."""

    def __init__(self, app: ASGIApp, *, max_request_body_bytes: int) -> None:
        self.app = app
        self.max_request_body_bytes = validate_max_request_body_bytes(max_request_body_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = request_id_from_scope(scope)
        declared_length, length_error = parse_content_length(
            scope, max_request_body_bytes=self.max_request_body_bytes
        )
        if length_error is not None:
            status = (
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                if length_error == "request_body_too_large"
                else HTTPStatus.BAD_REQUEST
            )
            await _send_json(send, status, redacted_error(length_error, request_id))
            return
        if declared_length is not None and declared_length > self.max_request_body_bytes:
            await _send_json(
                send,
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                redacted_error("request_body_too_large", request_id),
            )
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await _send_json(
                    send,
                    HTTPStatus.BAD_REQUEST,
                    redacted_error("invalid_request_stream", request_id),
                )
                return

            chunk = message.get("body", b"")
            append_result = append_bounded_body_chunk(
                body, chunk, max_request_body_bytes=self.max_request_body_bytes
            )
            if append_result == "too_large":
                await _send_json(
                    send,
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    redacted_error("request_body_too_large", request_id),
                )
                return
            if append_result == "invalid":
                await _send_json(
                    send,
                    HTTPStatus.BAD_REQUEST,
                    redacted_error("invalid_request_stream", request_id),
                )
                return

            if not message.get("more_body", False):
                break

        if declared_length is not None and declared_length != len(body):
            await _send_json(
                send,
                HTTPStatus.BAD_REQUEST,
                redacted_error("invalid_content_length", request_id),
            )
            return

        replayed = False
        admitted = bytes(body)
        if _is_runtime_report_request(scope):
            try:
                decoded = admitted.decode("utf-8", errors="strict")
                if decoded.startswith("\ufeff"):
                    raise ValueError("JSON byte order marks are not admitted")
                parsed = json.loads(
                    decoded,
                    object_pairs_hook=_reject_duplicate_json_object,
                    parse_constant=_reject_non_finite_json_number,
                )
                _validate_ijson_value(parsed)
                _validate_runtime_report_wire_types(parsed)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                ValueError,
                TypeError,
                RecursionError,
            ):
                await _send_json(
                    send,
                    HTTPStatus.BAD_REQUEST,
                    redacted_error("request_body_invalid_ijson", request_id),
                )
                return

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": admitted, "more_body": False}
            return {"type": "http.disconnect"}

        async def add_request_id_header(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers = [(k, v) for k, v in headers if k.lower() != b"x-request-id"]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, replay_receive, add_request_id_header)


def _is_runtime_report_request(scope: Scope) -> bool:
    path = scope.get("path")
    return (
        scope.get("method") == "POST"
        and isinstance(path, str)
        and path.startswith("/v1/runtime-identities/")
        and path.endswith("/reports")
    )


def _reject_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate JSON key")
        payload[key] = value
    return payload


def _reject_non_finite_json_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_ijson_value(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    node_count = 0
    while stack:
        current, depth = stack.pop()
        node_count += 1
        if node_count > IJSON_MAX_NODES:
            raise ValueError("JSON value exceeds the node limit")
        if depth > IJSON_MAX_DEPTH:
            raise ValueError("JSON value exceeds the nesting limit")
        if isinstance(current, bool) or current is None:
            continue
        if isinstance(current, int):
            if abs(current) > IJSON_MAX_SAFE_INTEGER:
                raise ValueError("JSON integer exceeds I-JSON safe range")
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("JSON number is not finite")
            continue
        if isinstance(current, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in current):
                raise ValueError("JSON string contains an invalid Unicode surrogate")
            continue
        child_depth = depth + 1
        if isinstance(current, list):
            stack.extend((item, child_depth) for item in reversed(current))
            continue
        if isinstance(current, dict):
            for key, item in reversed(tuple(current.items())):
                stack.append((item, child_depth))
                stack.append((key, child_depth))
            continue
        raise TypeError("JSON value has an unsupported type")


def _validate_runtime_report_wire_types(value: Any) -> None:
    if type(value) is not dict:
        raise TypeError("runtime report must be a JSON object")
    required_types = {
        "kind": str,
        "sequence": int,
        "expires_at": str,
        "policy_version_id": str,
        "policy_head_generation": int,
        "policy_content_hash": str,
        "runtime_build_digest": str,
        "configuration_digest": str,
        "policy_snapshot": dict,
    }
    for field_name, expected_type in required_types.items():
        if type(value.get(field_name)) is not expected_type:
            raise TypeError(f"runtime report {field_name} has the wrong JSON type")
    kind = value["kind"]
    if kind not in {"status", "wiring"}:
        raise ValueError("runtime report kind is invalid")
    challenge = value.get("challenge_token")
    artifact = value.get("artifact")
    if challenge is not None and type(challenge) is not str:
        raise TypeError("runtime report challenge_token has the wrong JSON type")
    if artifact is not None and type(artifact) is not dict:
        raise TypeError("runtime report artifact has the wrong JSON type")
    _validate_policy_snapshot_wire_schema(value["policy_snapshot"])
    if kind == "status":
        if challenge is not None or artifact is not None:
            raise ValueError("status report cannot carry wiring evidence")
    else:
        if type(challenge) is not str or type(artifact) is not dict:
            raise TypeError("wiring report requires exact challenge and artifact types")
        _validate_wiring_artifact_wire_schema(artifact)


_POLICY_SNAPSHOT_FIELDS = {
    "schema": str,
    "purpose": str,
    "scope": dict,
    "runtime_identity_id": str,
    "credential_id": str,
    "credential_generation": int,
    "cursor": str,
    "head_generation": int,
    "head_updated_at": str,
    "policy_version_id": str,
    "policy_id": str,
    "version": str,
    "content_hash": str,
    "activation_receipt_id": str,
    "activation_receipt_hash": str,
    "activation_event_hash": str,
    "policy_envelope": dict,
    "attestation_purpose": str,
    "attestation_trust_epoch": int,
    "attestation_key_id": str,
    "attestation_signature_algorithm": str,
    "issued_at": str,
    "revocation_checked_at": str,
    "fresh_until": str,
    "expires_at": str,
    "attestation_signature": str,
}
_POLICY_ENVELOPE_FIELDS = {
    "schema": str,
    "scope": dict,
    "policy_id": str,
    "version": str,
    "content_hash": str,
    "document": dict,
    "rules": list,
    "key_id": str,
    "signature_algorithm": str,
    "trust_epoch": int,
    "purpose": str,
    "signature": str,
}
_PROVENANCE_FIELDS = {
    "scope": dict,
    "runtime_identity_id": str,
    "credential_id": str,
    "credential_generation": int,
    "cursor": str,
    "head_generation": int,
    "head_updated_at": str,
    "policy_version_id": str,
    "policy_id": str,
    "version": str,
    "content_hash": str,
    "activation_receipt_id": str,
    "activation_receipt_hash": str,
    "activation_event_hash": str,
    "policy_sync_schema": str,
    "policy_sync_purpose": str,
    "policy_trust_purpose": str,
    "policy_trust_epoch": int,
    "policy_key_id": str,
    "policy_signature_algorithm": str,
    "policy_key_fingerprint": str,
    "attestation_purpose": str,
    "attestation_trust_epoch": int,
    "attestation_key_id": str,
    "attestation_signature_algorithm": str,
    "attestation_key_fingerprint": str,
    "signed_snapshot_hash": str,
}
_WIRING_FIELDS = {
    "schema": str,
    "purpose": str,
    "assurance_class": str,
    "evidence_kind": str,
    "scope": dict,
    "runtime": dict,
    "execution_boundary": str,
    "package": dict,
    "policy_head": dict,
    "policy_provenance_hash": str,
    "policy_issued_at": str,
    "policy_fresh_until": str,
    "policy_expires_at": str,
    "policy_mode": str,
    "suite_id": str,
    "suite_hash": str,
    "results": list,
    "sequence": int,
    "nonce": str,
    "issued_at": str,
    "expires_at": str,
    "signature_algorithm": str,
    "signing_key_id": str,
    "attestation_hash": str,
    "signature": str,
}
_WIRING_RESULT_FIELDS = {
    **{
        name: str
        for name in (
            "case_id",
            "dispatcher",
            "classification",
            "outcome",
            "receipt_id",
            "receipt_hash",
            "receipt_signature_algorithm",
            "receipt_signing_key_id",
            "audit_hash",
            "previous_audit_hash",
            "action_hash",
            "argument_hash",
            "actor",
            "receipt_expires_at",
            "receipt_rejection_code",
            "policy_hash",
            "policy_version_id",
            "policy_provenance_hash",
            "consumption_commitment",
        )
    },
    "side_effect_count": int,
    "executor_verified": bool,
    "receipt": dict,
    "audit_event": dict,
    "consumption_entry": dict,
}
_RECEIPT_FIELDS = {
    **{
        name: str
        for name in (
            "receipt_id",
            "request_id",
            "tenant_id",
            "actor",
            "subject",
            "proposed_action",
            "declared_goal",
            "execution_boundary",
            "policy_bundle_id",
            "policy_version",
            "policy_hash",
            "decision",
            "timestamp",
            "expires_at",
            "authority",
            "validator_id",
            "validator_role",
            "argument_hash",
            "previous_audit_hash",
            "audit_event_hash",
            "signature_algorithm",
            "signing_key_id",
            "receipt_hash",
            "signature",
            "receipt_schema_version",
            "project_id",
            "environment_id",
        )
    },
    "matched_rules": list,
    "constraints": dict,
    "transformations": list,
    "approval_chain_summary": dict,
    "trust_epoch": int,
}
_AUDIT_EVENT_FIELDS = {
    **{
        name: str
        for name in (
            "actor",
            "argument_hash",
            "decision",
            "decision_request_hash",
            "event_hash",
            "event_id",
            "goal",
            "policy_provenance_hash",
            "policy_version",
            "previous_hash",
            "reason",
            "timestamp_iso",
            "tool",
        )
    },
    "matched_rules": list,
    "path": list,
    "state_hash": (str, type(None)),
    "transformed_args": (dict, type(None)),
}
_CONSUMPTION_FIELDS = {
    name: str
    for name in (
        "actor",
        "consumed_at",
        "consumed_key",
        "entry_hash",
        "expires_at",
        "previous_hash",
        "proposed_action",
        "receipt_hash",
        "request_id",
        "tenant_id",
    )
}


def _exact_wire_object(value: Any, fields: Mapping[str, Any], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields):
        raise TypeError(f"runtime report {label} has the wrong object shape")
    for name, expected_type in fields.items():
        if expected_type is object:
            continue
        if type(value[name]) not in (
            expected_type if isinstance(expected_type, tuple) else (expected_type,)
        ):
            raise TypeError(f"runtime report {label}.{name} has the wrong JSON type")
    return value


def _string_list(value: list[Any], label: str) -> None:
    if any(type(item) is not str for item in value):
        raise TypeError(f"runtime report {label} entries must be strings")


def _object_list(value: list[Any], label: str) -> None:
    if any(type(item) is not dict for item in value):
        raise TypeError(f"runtime report {label} entries must be objects")


_POLICY_RULE_ALLOWED_FIELDS = {
    "id",
    "effect",
    "tools",
    "path_prefix",
    "state_equals",
    "state_contains",
    "allow",
    "trust_tier_key",
    "reason",
}


def _validate_policy_rule(value: Any, label: str) -> None:
    if type(value) is not dict or not {"id", "effect"}.issubset(value):
        raise TypeError(f"runtime report {label} has the wrong object shape")
    if not set(value).issubset(_POLICY_RULE_ALLOWED_FIELDS):
        raise TypeError(f"runtime report {label} has unknown fields")
    if type(value["id"]) is not str or type(value["effect"]) is not str:
        raise TypeError(f"runtime report {label} id/effect has the wrong JSON type")
    for name in ("tools", "path_prefix"):
        if name in value:
            if type(value[name]) is not list:
                raise TypeError(f"runtime report {label}.{name} has the wrong JSON type")
            _string_list(value[name], f"{label}.{name}")
    for name in ("state_equals", "state_contains"):
        if name in value and type(value[name]) is not dict:
            raise TypeError(f"runtime report {label}.{name} has the wrong JSON type")
    if "allow" in value:
        allow = value["allow"]
        if type(allow) is not dict or not set(allow).issubset({"actors", "trust_tiers"}):
            raise TypeError(f"runtime report {label}.allow has the wrong object shape")
        for name, entries in allow.items():
            if type(entries) is not list:
                raise TypeError(f"runtime report {label}.allow.{name} has the wrong JSON type")
            _string_list(entries, f"{label}.allow.{name}")
    for name in ("trust_tier_key", "reason"):
        if name in value and type(value[name]) is not str:
            raise TypeError(f"runtime report {label}.{name} has the wrong JSON type")


def _validate_policy_rules(value: list[Any], label: str) -> None:
    for index, rule in enumerate(value):
        _validate_policy_rule(rule, f"{label}[{index}]")


def _validate_receipt_constraints(value: Any, label: str) -> None:
    constraints = _exact_wire_object(
        value,
        {"schema": str, "policy_provenance": dict, "policy_provenance_hash": str},
        label,
    )
    provenance = _exact_wire_object(
        constraints["policy_provenance"], _PROVENANCE_FIELDS, f"{label}.policy_provenance"
    )
    _exact_wire_object(
        provenance["scope"],
        {"org_id": str, "project_id": str, "environment_id": str, "gate_id": str},
        f"{label}.policy_provenance.scope",
    )


def _validate_transformations(value: list[Any], label: str) -> None:
    for index, transformation in enumerate(value):
        _exact_wire_object(
            transformation,
            {"field": str, "value": object},
            f"{label}[{index}]",
        )


def _validate_approval_summary(value: Any, label: str) -> None:
    _exact_wire_object(
        value,
        {"proposer": str, "validator_id": str, "validator_role": str, "authority": str},
        label,
    )


def _validate_policy_snapshot_wire_schema(value: dict[str, Any]) -> None:
    snapshot = _exact_wire_object(value, _POLICY_SNAPSHOT_FIELDS, "policy_snapshot")
    _exact_wire_object(
        snapshot["scope"],
        {"org_id": str, "project_id": str, "environment_id": str, "gate_id": str},
        "policy_snapshot.scope",
    )
    envelope = _exact_wire_object(
        snapshot["policy_envelope"], _POLICY_ENVELOPE_FIELDS, "policy_snapshot.policy_envelope"
    )
    _exact_wire_object(
        envelope["scope"],
        {"org_id": str, "project_id": str, "environment_id": str},
        "policy_snapshot.policy_envelope.scope",
    )
    document = _exact_wire_object(
        envelope["document"],
        {"id": str, "version": str, "rules": list},
        "policy_snapshot.policy_envelope.document",
    )
    _validate_policy_rules(envelope["rules"], "policy_snapshot.policy_envelope.rules")
    _validate_policy_rules(document["rules"], "policy_snapshot.policy_envelope.document.rules")


def _validate_wiring_artifact_wire_schema(value: dict[str, Any]) -> None:
    artifact = _exact_wire_object(value, _WIRING_FIELDS, "artifact")
    _exact_wire_object(
        artifact["scope"],
        {"org_id": str, "project_id": str, "environment": str, "gate_id": str},
        "artifact.scope",
    )
    _exact_wire_object(
        artifact["runtime"],
        {
            "runtime_identity_id": str,
            "credential_id": str,
            "credential_generation": int,
            "workload_key_id": str,
            "public_key_thumbprint": str,
        },
        "artifact.runtime",
    )
    _exact_wire_object(
        artifact["package"],
        {
            "name": str,
            "version": str,
            "runtime_build_digest": str,
            "configuration_digest": str,
        },
        "artifact.package",
    )
    provenance = _exact_wire_object(
        artifact["policy_head"], _PROVENANCE_FIELDS, "artifact.policy_head"
    )
    _exact_wire_object(
        provenance["scope"],
        {"org_id": str, "project_id": str, "environment_id": str, "gate_id": str},
        "artifact.policy_head.scope",
    )
    for index, raw_result in enumerate(artifact["results"]):
        result = _exact_wire_object(raw_result, _WIRING_RESULT_FIELDS, f"artifact.results[{index}]")
        _string_list(result["receipt"].get("matched_rules", []), "receipt.matched_rules")
        if result["receipt"]:
            receipt = _exact_wire_object(
                result["receipt"], _RECEIPT_FIELDS, f"artifact.results[{index}].receipt"
            )
            _string_list(receipt["matched_rules"], "receipt.matched_rules")
            _validate_receipt_constraints(
                receipt["constraints"], f"artifact.results[{index}].receipt.constraints"
            )
            _validate_transformations(
                receipt["transformations"],
                f"artifact.results[{index}].receipt.transformations",
            )
            _validate_approval_summary(
                receipt["approval_chain_summary"],
                f"artifact.results[{index}].receipt.approval_chain_summary",
            )
        if result["audit_event"]:
            audit_fields = dict(_AUDIT_EVENT_FIELDS)
            if result["case_id"] == "sealed_handle.raw_bypass_zero":
                audit_fields.pop("policy_provenance_hash")
            audit = _exact_wire_object(
                result["audit_event"],
                audit_fields,
                f"artifact.results[{index}].audit_event",
            )
            _string_list(audit["matched_rules"], "audit_event.matched_rules")
            _string_list(audit["path"], "audit_event.path")
        if result["consumption_entry"]:
            _exact_wire_object(
                result["consumption_entry"],
                _CONSUMPTION_FIELDS,
                f"artifact.results[{index}].consumption_entry",
            )


async def _send_json(send: Send, status: HTTPStatus, content: dict[str, Any]) -> None:
    payload = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = [
        *_JSON_HEADERS,
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"x-request-id", str(content["request_id"]).encode("ascii")),
    ]
    await send({"type": "http.response.start", "status": int(status), "headers": headers})
    await send({"type": "http.response.body", "body": payload, "more_body": False})


def append_bounded_body_chunk(
    body: bytearray, chunk: object, *, max_request_body_bytes: int
) -> str:
    if not isinstance(chunk, bytes | bytearray | memoryview):
        return "invalid"
    chunk_length = len(chunk)
    if chunk_length > max_request_body_bytes - len(body):
        return "too_large"
    body.extend(chunk)
    return "ok"


def has_json_decode_error(errors: Sequence[Any]) -> bool:
    return any(str(error.get("type", "")).lower() == "json_invalid" for error in errors)
