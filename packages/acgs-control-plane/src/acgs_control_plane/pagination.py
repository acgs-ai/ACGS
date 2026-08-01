"""Opaque cursor tokens for additive receipt pagination."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CURSOR_RESOURCE_RECEIPTS = "receipts"
CURSOR_ORDER_RECEIPTS_DESC = "created_at_desc_id_desc"
COLLECTION_CURSOR_RESOURCES = frozenset({"users", "agents", "policies", "exports"})
COLLECTION_CURSOR_ORDER = "created_at_desc_id_desc"
COLLECTION_CURSOR_FILTER_DIGEST = hashlib.sha256(b"{}").hexdigest()
CURSOR_VERSION = 1
CURSOR_KEY_ID_MAX_LENGTH = 64
CURSOR_TOKEN_MAX_LENGTH = 4096
CURSOR_MIN_TTL_SECONDS = 1
CURSOR_MAX_TTL_SECONDS = 86_400
CURSOR_DEFAULT_TTL_SECONDS = 300
CURSOR_MIN_CLOCK_SKEW_SECONDS = 0
CURSOR_MAX_CLOCK_SKEW_SECONDS = 300
CURSOR_DEFAULT_CLOCK_SKEW_SECONDS = 30
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_NONCE_BYTES = 12


class InvalidCursorError(ValueError):
    """Generic cursor refusal; never expose parsing, crypto, scope, or expiry details."""


class CursorConfigurationError(RuntimeError):
    """Stable pre-persistence refusal for unsafe cursor key settings."""

    code = "CURSOR_CONFIGURATION_INVALID"
    stage = "pre-persistence"

    def __init__(self) -> None:
        super().__init__(
            json.dumps(
                {
                    "code": self.code,
                    "stage": self.stage,
                    "setting": "ACP_CURSOR_KEY_ID/ACP_CURSOR_KEY",
                },
                sort_keys=True,
            )
        )


@dataclass(frozen=True)
class CursorKeyring:
    active_key_id: str
    active_key: bytes = field(repr=False)
    ttl_seconds: int = CURSOR_DEFAULT_TTL_SECONDS
    clock_skew_seconds: int = CURSOR_DEFAULT_CLOCK_SKEW_SECONDS
    ephemeral: bool = False

    def __post_init__(self) -> None:
        if not _valid_key_id(self.active_key_id) or len(self.active_key) != 32:
            raise CursorConfigurationError()
        object.__setattr__(self, "active_key", bytes(self.active_key))
        object.__setattr__(self, "ttl_seconds", validate_cursor_ttl_seconds(self.ttl_seconds))
        object.__setattr__(
            self,
            "clock_skew_seconds",
            validate_cursor_clock_skew_seconds(self.clock_skew_seconds),
        )


@dataclass(frozen=True)
class ReceiptCursor:
    created_at: datetime
    receipt_id: str


@dataclass(frozen=True)
class CollectionCursor:
    created_at: datetime
    item_id: str


def local_ephemeral_cursor_keyring(
    ttl_seconds: int = CURSOR_DEFAULT_TTL_SECONDS,
    clock_skew_seconds: int = CURSOR_DEFAULT_CLOCK_SKEW_SECONDS,
) -> CursorKeyring:
    return CursorKeyring(
        active_key_id="local-ephemeral",
        active_key=secrets.token_bytes(32),
        ttl_seconds=ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
        ephemeral=True,
    )


def configured_cursor_keyring(
    *, key_id: str | None, key_b64: str | None, ttl_seconds: int, clock_skew_seconds: int
) -> CursorKeyring | None:
    if not key_id and not key_b64:
        return None
    if not key_id or not key_b64 or not _valid_key_id(key_id):
        raise CursorConfigurationError()
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CursorConfigurationError() from exc
    if len(key) != 32:
        raise CursorConfigurationError()
    return CursorKeyring(
        active_key_id=key_id,
        active_key=key,
        ttl_seconds=ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )


def parse_cursor_ttl_seconds(raw: str | None) -> int:
    if raw is None or raw == "":
        return CURSOR_DEFAULT_TTL_SECONDS
    if not raw.isdecimal() or len(raw) > len(str(CURSOR_MAX_TTL_SECONDS)):
        raise CursorConfigurationError()
    return validate_cursor_ttl_seconds(int(raw))


def validate_cursor_ttl_seconds(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CursorConfigurationError()
    if not (CURSOR_MIN_TTL_SECONDS <= value <= CURSOR_MAX_TTL_SECONDS):
        raise CursorConfigurationError()
    return value


def parse_cursor_clock_skew_seconds(raw: str | None) -> int:
    if raw is None or raw == "":
        return CURSOR_DEFAULT_CLOCK_SKEW_SECONDS
    if not raw.isdecimal() or len(raw) > len(str(CURSOR_MAX_CLOCK_SKEW_SECONDS)):
        raise CursorConfigurationError()
    return validate_cursor_clock_skew_seconds(int(raw))


def validate_cursor_clock_skew_seconds(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CursorConfigurationError()
    if not (CURSOR_MIN_CLOCK_SKEW_SECONDS <= value <= CURSOR_MAX_CLOCK_SKEW_SECONDS):
        raise CursorConfigurationError()
    return value


def receipt_filter_digest(
    *,
    decision: str | None,
    tool: str | None,
    actor: str | None,
    since: datetime | None,
    until: datetime | None,
) -> str:
    normalized = {
        "actor": _normalize_string_filter(actor),
        "decision": _normalize_string_filter(decision),
        "since_us": _datetime_to_epoch_us(since) if since else None,
        "tool": _normalize_string_filter(tool),
        "until_us": _datetime_to_epoch_us(until) if until else None,
    }
    return hashlib.sha256(_canonical_json(normalized)).hexdigest()


def issue_receipt_cursor(
    *,
    keyring: CursorKeyring,
    org_id: str,
    filter_digest: str,
    boundary_created_at: datetime,
    boundary_receipt_id: str,
    now: datetime | None = None,
) -> str:
    now = _normalize_datetime(now or datetime.now(UTC))
    payload = {
        "boundary_created_at_us": _datetime_to_epoch_us(boundary_created_at),
        "boundary_receipt_id": boundary_receipt_id,
        "exp_us": _datetime_to_epoch_us(now + timedelta(seconds=keyring.ttl_seconds)),
        "filter_digest": filter_digest,
        "iat_us": _datetime_to_epoch_us(now),
        "kid": keyring.active_key_id,
        "order": CURSOR_ORDER_RECEIPTS_DESC,
        "resource": CURSOR_RESOURCE_RECEIPTS,
        "scope_org_id": org_id,
        "v": CURSOR_VERSION,
    }
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = AESGCM(keyring.active_key).encrypt(
        nonce,
        _canonical_json(payload),
        _aad(keyring.active_key_id, org_id),
    )
    token = _b64url(nonce + ciphertext)
    if len(token) > CURSOR_TOKEN_MAX_LENGTH:
        raise InvalidCursorError("invalid cursor")
    return token


def decode_receipt_cursor(
    *,
    token: str,
    keyring: CursorKeyring,
    org_id: str,
    filter_digest: str,
    now: datetime | None = None,
) -> ReceiptCursor:
    try:
        payload = _decrypt_payload(token, keyring=keyring, org_id=org_id)
        now_us = _datetime_to_epoch_us(now or datetime.now(UTC))
        expected_keys = {
            "boundary_created_at_us",
            "boundary_receipt_id",
            "exp_us",
            "filter_digest",
            "iat_us",
            "kid",
            "order",
            "resource",
            "scope_org_id",
            "v",
        }
        if set(payload) != expected_keys:
            raise InvalidCursorError("invalid cursor")
        if type(payload["v"]) is not int or payload["v"] != CURSOR_VERSION:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["kid"], max_length=CURSOR_KEY_ID_MAX_LENGTH):
            raise InvalidCursorError("invalid cursor")
        if payload["kid"] != keyring.active_key_id:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["resource"], max_length=32):
            raise InvalidCursorError("invalid cursor")
        if payload["resource"] != CURSOR_RESOURCE_RECEIPTS:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["order"], max_length=64):
            raise InvalidCursorError("invalid cursor")
        if payload["order"] != CURSOR_ORDER_RECEIPTS_DESC:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["scope_org_id"], max_length=128):
            raise InvalidCursorError("invalid cursor")
        if payload["scope_org_id"] != org_id:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["filter_digest"], max_length=64):
            raise InvalidCursorError("invalid cursor")
        if payload["filter_digest"] != filter_digest:
            raise InvalidCursorError("invalid cursor")
        for name in ("boundary_created_at_us", "exp_us", "iat_us"):
            if type(payload[name]) is not int or payload[name] < 0:
                raise InvalidCursorError("invalid cursor")
        if payload["exp_us"] <= payload["iat_us"]:
            raise InvalidCursorError("invalid cursor")
        skew_us = keyring.clock_skew_seconds * 1_000_000
        if payload["iat_us"] > now_us + skew_us or payload["exp_us"] <= now_us:
            raise InvalidCursorError("invalid cursor")
        if payload["exp_us"] - payload["iat_us"] > CURSOR_MAX_TTL_SECONDS * 1_000_000:
            raise InvalidCursorError("invalid cursor")
        receipt_id = payload["boundary_receipt_id"]
        if not _exact_string(receipt_id, max_length=128):
            raise InvalidCursorError("invalid cursor")
        return ReceiptCursor(
            created_at=_epoch_us_to_datetime(payload["boundary_created_at_us"]),
            receipt_id=receipt_id,
        )
    except InvalidCursorError:
        raise
    except Exception as exc:
        raise InvalidCursorError("invalid cursor") from exc


def issue_collection_cursor(
    *,
    keyring: CursorKeyring,
    org_id: str,
    resource: str,
    boundary_created_at: datetime,
    boundary_id: str,
    now: datetime | None = None,
) -> str:
    """Issue an opaque cursor for one of the public v1 collection routes."""

    if resource not in COLLECTION_CURSOR_RESOURCES:
        raise InvalidCursorError("invalid cursor")
    if not _exact_string(org_id, max_length=128):
        raise InvalidCursorError("invalid cursor")
    if not _exact_string(boundary_id, max_length=128):
        raise InvalidCursorError("invalid cursor")
    try:
        now = _normalize_datetime(now or datetime.now(UTC))
        boundary_created_at_us = _datetime_to_epoch_us(boundary_created_at)
        iat_us = _datetime_to_epoch_us(now)
        exp_us = _datetime_to_epoch_us(now + timedelta(seconds=keyring.ttl_seconds))
    except (AttributeError, OverflowError, TypeError, ValueError) as exc:
        raise InvalidCursorError("invalid cursor") from exc
    payload = {
        "boundary_created_at_us": boundary_created_at_us,
        "boundary_id": boundary_id,
        "exp_us": exp_us,
        "filter_digest": COLLECTION_CURSOR_FILTER_DIGEST,
        "iat_us": iat_us,
        "kid": keyring.active_key_id,
        "order": COLLECTION_CURSOR_ORDER,
        "resource": resource,
        "scope_org_id": org_id,
        "v": CURSOR_VERSION,
    }
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = AESGCM(keyring.active_key).encrypt(
        nonce,
        _canonical_json(payload),
        _collection_aad(keyring.active_key_id, org_id, resource),
    )
    token = _b64url(nonce + ciphertext)
    if len(token) > CURSOR_TOKEN_MAX_LENGTH:
        raise InvalidCursorError("invalid cursor")
    return token


def decode_collection_cursor(
    *,
    token: str,
    keyring: CursorKeyring,
    org_id: str,
    expected_resource: str,
    now: datetime | None = None,
) -> CollectionCursor:
    """Decode a public collection cursor, refusing every failure generically."""

    try:
        if expected_resource not in COLLECTION_CURSOR_RESOURCES:
            raise InvalidCursorError("invalid cursor")
        payload = _decrypt_collection_payload(
            token,
            keyring=keyring,
            org_id=org_id,
            resource=expected_resource,
        )
        expected_keys = {
            "boundary_created_at_us",
            "boundary_id",
            "exp_us",
            "filter_digest",
            "iat_us",
            "kid",
            "order",
            "resource",
            "scope_org_id",
            "v",
        }
        if set(payload) != expected_keys:
            raise InvalidCursorError("invalid cursor")
        if type(payload["v"]) is not int or payload["v"] != CURSOR_VERSION:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["kid"], max_length=CURSOR_KEY_ID_MAX_LENGTH):
            raise InvalidCursorError("invalid cursor")
        if payload["kid"] != keyring.active_key_id:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["resource"], max_length=32):
            raise InvalidCursorError("invalid cursor")
        if payload["resource"] != expected_resource:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["order"], max_length=64):
            raise InvalidCursorError("invalid cursor")
        if payload["order"] != COLLECTION_CURSOR_ORDER:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["scope_org_id"], max_length=128):
            raise InvalidCursorError("invalid cursor")
        if payload["scope_org_id"] != org_id:
            raise InvalidCursorError("invalid cursor")
        if not _exact_string(payload["filter_digest"], max_length=64):
            raise InvalidCursorError("invalid cursor")
        if payload["filter_digest"] != COLLECTION_CURSOR_FILTER_DIGEST:
            raise InvalidCursorError("invalid cursor")
        for name in ("boundary_created_at_us", "exp_us", "iat_us"):
            if type(payload[name]) is not int or payload[name] < 0:
                raise InvalidCursorError("invalid cursor")
        if payload["exp_us"] <= payload["iat_us"]:
            raise InvalidCursorError("invalid cursor")
        now_us = _datetime_to_epoch_us(now or datetime.now(UTC))
        skew_us = keyring.clock_skew_seconds * 1_000_000
        if payload["iat_us"] > now_us + skew_us or payload["exp_us"] <= now_us:
            raise InvalidCursorError("invalid cursor")
        if payload["exp_us"] - payload["iat_us"] > CURSOR_MAX_TTL_SECONDS * 1_000_000:
            raise InvalidCursorError("invalid cursor")
        boundary_id = payload["boundary_id"]
        if not _exact_string(boundary_id, max_length=128):
            raise InvalidCursorError("invalid cursor")
        return CollectionCursor(
            created_at=_epoch_us_to_datetime(payload["boundary_created_at_us"]),
            item_id=boundary_id,
        )
    except InvalidCursorError:
        raise
    except Exception as exc:
        raise InvalidCursorError("invalid cursor") from exc


def _decrypt_payload(token: str, *, keyring: CursorKeyring, org_id: str) -> dict[str, Any]:
    if not isinstance(token, str) or not token:
        raise InvalidCursorError("invalid cursor")
    if len(token) > CURSOR_TOKEN_MAX_LENGTH or not _TOKEN_RE.fullmatch(token):
        raise InvalidCursorError("invalid cursor")
    try:
        raw = _b64url_decode(token)
    except (binascii.Error, ValueError) as exc:
        raise InvalidCursorError("invalid cursor") from exc
    if len(raw) <= _NONCE_BYTES + 16:
        raise InvalidCursorError("invalid cursor")
    nonce = raw[:_NONCE_BYTES]
    ciphertext = raw[_NONCE_BYTES:]
    try:
        plaintext = AESGCM(keyring.active_key).decrypt(
            nonce, ciphertext, _aad(keyring.active_key_id, org_id)
        )
    except InvalidTag as exc:
        raise InvalidCursorError("invalid cursor") from exc
    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise InvalidCursorError("invalid cursor") from exc
    if type(payload) is not dict:
        raise InvalidCursorError("invalid cursor")
    return payload


def _decrypt_collection_payload(
    token: str,
    *,
    keyring: CursorKeyring,
    org_id: str,
    resource: str,
) -> dict[str, Any]:
    if not isinstance(token, str) or not token:
        raise InvalidCursorError("invalid cursor")
    if len(token) > CURSOR_TOKEN_MAX_LENGTH or not _TOKEN_RE.fullmatch(token):
        raise InvalidCursorError("invalid cursor")
    try:
        raw = _b64url_decode(token)
    except (binascii.Error, ValueError) as exc:
        raise InvalidCursorError("invalid cursor") from exc
    if len(raw) <= _NONCE_BYTES + 16:
        raise InvalidCursorError("invalid cursor")
    try:
        plaintext = AESGCM(keyring.active_key).decrypt(
            raw[:_NONCE_BYTES],
            raw[_NONCE_BYTES:],
            _collection_aad(keyring.active_key_id, org_id, resource),
        )
    except InvalidTag as exc:
        raise InvalidCursorError("invalid cursor") from exc
    try:
        payload = json.loads(plaintext, object_pairs_hook=_reject_duplicate_cursor_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise InvalidCursorError("invalid cursor") from exc
    if type(payload) is not dict:
        raise InvalidCursorError("invalid cursor")
    return payload


def _reject_duplicate_cursor_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate cursor key")
        payload[key] = value
    return payload


def _valid_key_id(value: str) -> bool:
    return isinstance(value, str) and bool(_KEY_ID_RE.fullmatch(value))


def _exact_string(value: object, *, max_length: int) -> bool:
    return type(value) is str and 0 < len(value) <= max_length


def _normalize_string_filter(value: str | None) -> str | None:
    if value is None:
        return None
    return value


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _datetime_to_epoch_us(value: datetime) -> int:
    normalized = _normalize_datetime(value)
    return int(normalized.timestamp() * 1_000_000)


def _epoch_us_to_datetime(value: int) -> datetime:
    seconds, micros = divmod(value, 1_000_000)
    return datetime.fromtimestamp(seconds, tz=UTC).replace(microsecond=micros)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _aad(key_id: str, org_id: str) -> bytes:
    return _canonical_json(
        {
            "kid": key_id,
            "order": CURSOR_ORDER_RECEIPTS_DESC,
            "resource": CURSOR_RESOURCE_RECEIPTS,
            "scope_org_id": org_id,
            "v": CURSOR_VERSION,
        }
    )


def _collection_aad(key_id: str, org_id: str, resource: str) -> bytes:
    return _canonical_json(
        {
            "kid": key_id,
            "resource": resource,
            "scope_org_id": org_id,
        }
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
