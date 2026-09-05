"""CI enforcement for claim-sensitive ACGS design invariants.

The RFC (``docs/design/acgs-physical-execution-profile.md``) declares five
decisions frozen before P0 implementation. Until this file existed, that freeze
was enforced by human review only — a reviewer had to notice that an edit
quietly relaxed one. These tests make the freeze mechanical.

Design note on brittleness: these assertions deliberately match **structure and
distinctive tokens**, never long prose sentences. A gate that asserts a full
paragraph turns every editorial commit red and trains people to edit the gate
instead of restoring the invariant — which is exactly backwards. Prose may be
rewritten freely here; the invariants may not.

Scope is limited to the physical execution profile and the two reviewed
questionnaire/site-copy contracts named below. Other design files belong to
different work streams and are not governed by this file.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from gove_zone.errors import ReceiptValidationError
from gove_zone.receipt import DecisionReceipt
from gove_zone.tier import ToolTierRegistry
from gove_zone.tool import ToolCall

ROOT = Path(__file__).resolve().parents[2]
RFC = "docs/design/acgs-physical-execution-profile.md"
QUESTIONNAIRE_SPEC = "docs/superpowers/specs/2026-07-25-agent-run-ai-questionnaire-pack-design.md"
SITE_DECK = "docs/SITE-COPY-DECK-0.md"

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
PINNED_ASSEMBLY_ROOT_P256_SPKI_DER = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ED25519_Q = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_D = -121665 * pow(121666, ED25519_Q - 2, ED25519_Q) % ED25519_Q
ED25519_I = pow(2, (ED25519_Q - 1) // 4, ED25519_Q)


def _ed25519_xrecover(y: int) -> int:
    x = pow((y * y - 1) * pow(ED25519_D * y * y + 1, ED25519_Q - 2, ED25519_Q),
            (ED25519_Q + 3) // 8, ED25519_Q)
    if (x * x - (y * y - 1) * pow(ED25519_D * y * y + 1, ED25519_Q - 2, ED25519_Q)) % ED25519_Q:
        x = x * ED25519_I % ED25519_Q
    return x if x % 2 == 0 else ED25519_Q - x


ED25519_B_Y = 4 * pow(5, ED25519_Q - 2, ED25519_Q) % ED25519_Q
ED25519_B = (_ed25519_xrecover(ED25519_B_Y), ED25519_B_Y)


def _ed25519_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    common = ED25519_D * x1 * x2 * y1 * y2 % ED25519_Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + common, ED25519_Q - 2, ED25519_Q)
        % ED25519_Q,
        (y1 * y2 + x1 * x2) * pow(1 - common, ED25519_Q - 2, ED25519_Q)
        % ED25519_Q,
    )


def _ed25519_mul(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_add(addend, addend)
        scalar >>= 1
    return result


def _ed25519_encode(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _ed25519_decode(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point length")
    raw = int.from_bytes(encoded, "little")
    y = raw & ((1 << 255) - 1)
    if y >= ED25519_Q:
        raise ValueError("non-canonical Ed25519 point")
    x = _ed25519_xrecover(y)
    if (x & 1) != (raw >> 255):
        x = ED25519_Q - x
    point = (x, y)
    if _ed25519_add(point, (0, 1)) != point:
        raise ValueError("invalid Ed25519 point")
    return point


def _ed25519_secret(seed: bytes) -> tuple[int, bytes, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = _ed25519_encode(_ed25519_mul(ED25519_B, scalar))
    return scalar, digest[32:], public_key


def _ed25519_sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    scalar, prefix, public_key = _ed25519_secret(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % ED25519_L
    encoded_r = _ed25519_encode(_ed25519_mul(ED25519_B, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % ED25519_L
    signature = encoded_r + ((nonce + challenge * scalar) % ED25519_L).to_bytes(
        32, "little"
    )
    return public_key, signature


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        encoded_r, encoded_s = signature[:32], signature[32:]
        scalar_s = int.from_bytes(encoded_s, "little")
        if scalar_s >= ED25519_L:
            return False
        point_a = _ed25519_decode(public_key)
        point_r = _ed25519_decode(encoded_r)
        challenge = int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(), "little"
        ) % ED25519_L
        return _ed25519_mul(ED25519_B, scalar_s) == _ed25519_add(
            point_r,
            _ed25519_mul(point_a, challenge),
        )
    except (Exception, MemoryError):
        return False


def _p256_add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P256_P)
    slope %= P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    return x3, (slope * (x1 - x3) - y1) % P256_P


def _p256_mul(scalar: int, point: tuple[int, int] = P256_G) -> tuple[int, int]:
    result = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        scalar >>= 1
    assert result is not None
    return result


def _p256_spki(private_scalar: int) -> bytes:
    x, y = _p256_mul(private_scalar)
    return bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + (
        x.to_bytes(32, "big") + y.to_bytes(32, "big")
    )


def _safe_pinned_assembly_root_spki() -> bytes | None:
    try:
        spki = _p256_spki(1)
        if (
            type(spki) is not bytes
            or spki != PINNED_ASSEMBLY_ROOT_P256_SPKI_DER
        ):
            return None
        return PINNED_ASSEMBLY_ROOT_P256_SPKI_DER
    except (Exception, MemoryError):
        return None


def _p256_sign(message: bytes, private_scalar: int, nonce: int) -> bytes:
    r = _p256_mul(nonce)[0] % P256_N
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    s = (pow(nonce, -1, P256_N) * (z + r * private_scalar)) % P256_N
    s = min(s, P256_N - s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _p256_verify(message: bytes, signature: bytes, public_scalar: int) -> bool:
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < P256_N and 1 <= s <= P256_N // 2):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, P256_N)
    point = _p256_add(
        _p256_mul((z * w) % P256_N),
        _p256_mul((r * w) % P256_N, _p256_mul(public_scalar)),
    )
    return point is not None and point[0] % P256_N == r


def _p256_verify_spki(message: bytes, signature: bytes, spki: bytes) -> bool:
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    if len(spki) != 91 or not spki.startswith(prefix):
        return False
    public_point = (
        int.from_bytes(spki[27:59], "big"),
        int.from_bytes(spki[59:91], "big"),
    )
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < P256_N and 1 <= s <= P256_N // 2):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, P256_N)
    point = _p256_add(
        _p256_mul((z * w) % P256_N),
        _p256_mul((r * w) % P256_N, public_point),
    )
    return point is not None and point[0] % P256_N == r


MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4096
MAX_JSON_CONTAINERS = 1024
JSON_SAFE_INTEGER_MAX = (1 << 53) - 1


def _is_closed_json_value(value: object) -> bool:
    try:
        root_type = type(value)
        if root_type not in {dict, list, str, bool, int, type(None)}:
            return False
        stack: list[tuple[object, int]] = [(value, 0)]
        seen_containers: set[int] = set()
        scheduled_nodes = 1
        scheduled_containers = int(root_type in {dict, list})
        while stack:
            member, depth = stack.pop()
            if depth > MAX_JSON_DEPTH:
                return False
            member_type = type(member)
            if member is None or member_type is bool:
                continue
            if member_type is int:
                if not -JSON_SAFE_INTEGER_MAX <= member <= JSON_SAFE_INTEGER_MAX:
                    return False
                continue
            if member_type is str:
                member.encode("utf-8")
                continue
            if member_type not in {dict, list}:
                return False
            identity = id(member)
            if identity in seen_containers:
                return False
            seen_containers.add(identity)
            member_size = len(member)
            added_nodes = member_size * (2 if member_type is dict else 1)
            if scheduled_nodes + added_nodes > MAX_JSON_NODES:
                return False
            added_containers = 0
            if member_type is dict:
                for key, nested in member.items():
                    if type(key) is not str:
                        return False
                    key.encode("utf-8")
                    added_containers += int(type(nested) in {dict, list})
            else:
                for nested in member:
                    added_containers += int(type(nested) in {dict, list})
            if scheduled_containers + added_containers > MAX_JSON_CONTAINERS:
                return False
            scheduled_nodes += added_nodes
            scheduled_containers += added_containers
            if member_type is dict:
                for nested in member.values():
                    stack.append((nested, depth + 1))
            else:
                for nested in member:
                    stack.append((nested, depth + 1))
        return True
    except (Exception, MemoryError):
        return False


def _canonical_jcs(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _domain_hash(domain: str, value: object) -> str:
    return "sha256:" + hashlib.sha256(
        domain.encode("ascii") + b"\0" + _canonical_jcs(value)
    ).hexdigest()


def _safe_canonical_jcs(value: object) -> bytes | None:
    try:
        if not _is_closed_json_value(value):
            return None
        return _canonical_jcs(value)
    except (Exception, MemoryError):
        return None


def _safe_domain_hash(domain: str, value: object) -> str | None:
    try:
        if type(domain) is not str:
            return None
        payload = _safe_canonical_jcs(value)
        if payload is None:
            return None
        return "sha256:" + hashlib.sha256(
            domain.encode("ascii") + b"\0" + payload
        ).hexdigest()
    except (Exception, MemoryError):
        return None


def _safe_domain_bytes_hash(
    domain: object,
    payload: object,
    prefix: object = "sha256:",
) -> str | None:
    try:
        if (
            type(domain) is not str
            or type(payload) is not bytes
            or type(prefix) is not str
        ):
            return None
        return prefix + hashlib.sha256(
            domain.encode("ascii") + b"\0" + payload
        ).hexdigest()
    except (Exception, MemoryError):
        return None


def _safe_p256_verify_spki(
    message: object,
    signature: object,
    spki: object,
) -> bool:
    try:
        if not all(type(value) is bytes for value in (message, signature, spki)):
            return False
        return _p256_verify_spki(message, signature, spki)
    except (Exception, MemoryError):
        return False


def test_safe_domain_hash_contains_all_failure_boundaries(monkeypatch) -> None:
    class HostileDomain(str):
        accesses = 0

        def encode(self, *args: object, **kwargs: object) -> bytes:
            type(self).accesses += 1
            raise AssertionError("hostile domain encode must not run")

    assert _safe_domain_hash(HostileDomain("hostile"), {}) is None
    assert HostileDomain.accesses == 0

    def exploding_validator(value: object) -> bool:
        raise RuntimeError(f"validator failed for {type(value).__name__}")

    with monkeypatch.context() as patcher:
        patcher.setitem(globals(), "_is_closed_json_value", exploding_validator)
        assert _safe_domain_hash("acgs.questionnaire.injected/v1", {}) is None

    def exploding_hash(value: bytes) -> object:
        raise AssertionError(f"hash backend failed for {len(value)} bytes")

    with monkeypatch.context() as patcher:
        patcher.setattr(hashlib, "sha256", exploding_hash)
        assert _safe_domain_hash("acgs.questionnaire.injected/v1", {}) is None


def _parse_rfc3339(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("not a timezone-aware RFC 3339 instant")
    try:
        if re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
            r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
            value,
        ) is None:
            raise ValueError("not a timezone-aware RFC 3339 instant")
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except Exception as error:
        raise ValueError("not a timezone-aware RFC 3339 instant") from error
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed.astimezone(UTC)


def _canonical_b64u(value: object) -> bytes:
    if (
        type(value) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
        or "=" in value
    ):
        raise ValueError("non-canonical base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ValueError("non-canonical base64url")
    return decoded


def validate_verified_assembly_trust_chain(
    verified_policy_chain: object,
    accepted_at_value: object,
) -> dict[str, object] | None:
    """Return the verified trust preimage, or fail closed with None."""
    if type(verified_policy_chain) is not dict:
        return None
    trust_manifest_fields = {
        "schema_version",
        "preimage",
        "assembly_verification_trust_manifest_hash",
    }
    trust_preimage_fields = {
        "schema_version",
        "trust_root_id",
        "trust_root_version",
        "root_signing_key_id",
        "authorized_manifest_purposes",
        "signature_algorithm",
        "signature_encoding",
        "root_public_key_spki_der_b64u",
        "root_public_key_spki_sha256",
        "min_manifest_sequence",
        "valid_from",
        "valid_until",
        "head_acceptance_key_purpose",
        "predecessor_signing_key_purpose",
        "predecessor_signing_domain",
        "revocation_snapshot",
        "revocation_snapshot_hash",
    }
    snapshot_fields = {
        "snapshot_sequence",
        "issued_at",
        "revoked_signing_key_ids",
        "revoked_verification_manifest_hashes",
    }
    policy_preimage_fields = {
        "schema_version",
        "policy_bundle_id",
        "decision_policy_artifact_hash",
        "registry_verification_key_manifest_hash",
        "receipt_verification_key_manifest_hash",
        "assembly_verification_trust_manifest_hash",
        "burn_verification_manifest_hash",
        "burn_manifest_head_acceptance_hash",
    }
    policy_bundle_fields = policy_preimage_fields | {"policy_version"}
    try:
        policy_preimage = verified_policy_chain["policy_bundle_preimage"]
        policy_bundle = verified_policy_chain["policy_bundle"]
        receipt = verified_policy_chain["decision_receipt"]
        trust_manifest = verified_policy_chain["assembly_trust_manifest"]
        if not all(
            type(item) is dict
            for item in (policy_preimage, policy_bundle, receipt, trust_manifest)
        ):
            return None
        if not all(
            _is_closed_json_value(item)
            for item in (policy_preimage, policy_bundle, receipt, trust_manifest)
        ):
            return None
        trust_preimage = trust_manifest["preimage"]
        if (
            type(trust_preimage) is not dict
            or set(trust_manifest) != trust_manifest_fields
            or set(trust_preimage) != trust_preimage_fields
            or set(policy_preimage) != policy_preimage_fields
            or set(policy_bundle) != policy_bundle_fields
        ):
            return None
        snapshot = trust_preimage["revocation_snapshot"]
        if type(snapshot) is not dict or set(snapshot) != snapshot_fields:
            return None
        required_ids = (
            "trust_root_id",
            "root_signing_key_id",
            "head_acceptance_key_purpose",
            "predecessor_signing_key_purpose",
            "predecessor_signing_domain",
        )
        if any(
            type(trust_preimage[field]) is not str
            or not trust_preimage[field]
            for field in required_ids
        ):
            return None
        if (
            type(trust_preimage["trust_root_version"]) is not int
            or trust_preimage["trust_root_version"] < 0
            or type(trust_preimage["min_manifest_sequence"]) is not int
            or trust_preimage["min_manifest_sequence"] < 0
            or type(snapshot["snapshot_sequence"]) is not int
            or snapshot["snapshot_sequence"] < 0
        ):
            return None
        purposes = trust_preimage["authorized_manifest_purposes"]
        expected_purposes = [
            "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING",
            "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
            "RECEIPT_BURN_VERIFICATION_MANIFEST_SIGNING",
        ]
        if (
            purposes != expected_purposes
            or len(set(purposes)) != len(purposes)
            or trust_preimage["predecessor_signing_key_purpose"]
            != "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING"
            or trust_preimage["predecessor_signing_key_purpose"] not in purposes
            or trust_preimage["predecessor_signing_domain"]
            != "acgs.questionnaire.assembly-manifest-predecessor-signature/v1"
        ):
            return None
        revoked_key_ids = snapshot["revoked_signing_key_ids"]
        revoked_manifest_hashes = snapshot[
            "revoked_verification_manifest_hashes"
        ]
        if (
            type(revoked_key_ids) is not list
            or not all(
                type(value) is str and value for value in revoked_key_ids
            )
            or revoked_key_ids != sorted(set(revoked_key_ids))
            or type(revoked_manifest_hashes) is not list
            or not all(
                type(value) is str
                and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                for value in revoked_manifest_hashes
            )
            or revoked_manifest_hashes != sorted(set(revoked_manifest_hashes))
        ):
            return None
        canonical_seconds = re.compile(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
        )
        root_times = (
            trust_preimage["valid_from"],
            trust_preimage["valid_until"],
            snapshot["issued_at"],
        )
        if any(
            type(value) is not str
            or canonical_seconds.fullmatch(value) is None
            for value in root_times
        ):
            return None
        accepted_at = _parse_rfc3339(accepted_at_value)
        valid_from = datetime.strptime(
            trust_preimage["valid_from"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        valid_until = datetime.strptime(
            trust_preimage["valid_until"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        datetime.strptime(snapshot["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
        root_spki = _canonical_b64u(
            trust_preimage["root_public_key_spki_der_b64u"]
        )
    except (KeyError, TypeError, ValueError):
        return None
    snapshot_hash = _safe_domain_hash(
        "acgs.questionnaire.assembly-revocation-snapshot/v1",
        snapshot,
    )
    root_spki_hash = _safe_domain_bytes_hash(
        "acgs.questionnaire.p256-spki/v1",
        root_spki,
    )
    pinned_root_spki = _safe_pinned_assembly_root_spki()
    if (
        snapshot_hash is None
        or root_spki_hash is None
        or pinned_root_spki is None
    ):
        return None
    if (
        root_spki != pinned_root_spki
        or trust_preimage["schema_version"]
        != "AssemblyVerificationTrustManifestPreimage/v1"
        or trust_manifest["schema_version"]
        != "AssemblyVerificationTrustManifest/v1"
        or policy_preimage["schema_version"]
        != "QuestionnairePolicyBundlePreimage/v1"
        or policy_bundle["schema_version"] != "QuestionnairePolicyBundle/v1"
        or trust_preimage["signature_algorithm"] != "ECDSA_P256_SHA256"
        or trust_preimage["signature_encoding"] != "P1363_BASE64URL_NOPAD"
        or trust_preimage["root_public_key_spki_sha256"] != root_spki_hash
        or trust_preimage["revocation_snapshot_hash"]
        != snapshot_hash
        or trust_preimage["root_signing_key_id"] in revoked_key_ids
        or not valid_from <= accepted_at < valid_until
    ):
        return None
    trust_hash = _safe_domain_hash(
        "acgs.questionnaire.assembly-verification-trust/v1",
        trust_preimage,
    )
    policy_payload = _safe_canonical_jcs(policy_preimage)
    policy_version = _safe_domain_bytes_hash(
        "acgs.questionnaire.policy-bundle/v1",
        policy_payload,
        "questionnaire-policy/",
    )
    if trust_hash is None or policy_payload is None or policy_version is None:
        return None
    expected_bundle = {
        "schema_version": "QuestionnairePolicyBundle/v1",
        "policy_bundle_id": policy_preimage["policy_bundle_id"],
        "policy_version": policy_version,
        **{
            field: policy_preimage[field]
            for field in policy_preimage
            if field not in {"schema_version", "policy_bundle_id"}
        },
    }
    if (
        policy_bundle != expected_bundle
        or not isinstance(policy_preimage["policy_bundle_id"], str)
        or not policy_preimage["policy_bundle_id"]
        or receipt.get("policy_bundle_id") != policy_preimage["policy_bundle_id"]
        or receipt.get("policy_version")
        != receipt.get("policy_hash")
        != policy_version
        or policy_preimage["assembly_verification_trust_manifest_hash"]
        != trust_manifest["assembly_verification_trust_manifest_hash"]
        != trust_hash
    ):
        return None
    return trust_preimage

# Responses that must never be reachable from a fault or a geometric violation.
PATH_FOLLOWING_RESPONSE = "ramp_stop"

# A violation of any of these means the commanded path itself is untrustworthy,
# so continuing along it is never an acceptable response.
NO_PATH_FOLLOWING_TRIGGERS = (
    "TorqueSensorMismatch",
    "ActuatorIntegrityFailure",
    "SDF / forbidden zone",
    "Non-finite setpoint",
    "Calibration epoch change",
    "Lease revoked",
)

# Every field the execution binding must commit to. Dropping any one of these
# re-opens a replay path: the same trajectory bytes becoming valid in a
# different physical context.
EXECUTION_ROOT_BINDINGS = (
    "merkle_root",
    "receipt_id",
    "robot_id",
    "calibration_digest",
    "contract_digest",
    "lease_id",
    "calibration_epoch",
    "boot_id",
)

# The loader verifies and refuses. It never decides.
LOADER_PROHIBITIONS = (
    "modify or re-derive constraints",
    "resolve conflicts",
    "upgrade, widen",
    "substitute a default",
    "recompute a digest",
)

# Claim boundaries. These must stay absent regardless of how the RFC evolves.
#
# Each entry must be a phrase that can ONLY appear as a claim. Loose terms are
# actively harmful here: "certified safe" also matches the disclaimer "requires
# a certified safety function", so banning it would flag the RFC for correctly
# disclaiming certification. A gate that fires on its own disclaimers teaches
# people to delete disclaimers.
FORBIDDEN_CLAIMS = (
    "production-certified",
    "compliance-certified",
    "safety-certified",
    "regulator-approved",
    "formal verification complete",
    "guaranteed safe",
    "production-ready",
)


def _rfc() -> str:
    path = ROOT / RFC
    assert path.is_file(), f"missing design RFC: {RFC}"
    return path.read_text(encoding="utf-8")


def _read(relative: str) -> str:
    path = ROOT / relative
    assert path.is_file(), f"missing required design document: {relative}"
    return path.read_text(encoding="utf-8")


def _python_symbols(relative: str) -> set[str]:
    tree = ast.parse(_read(relative))
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.add(node.name)
    return symbols


def _table_rows(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.lstrip().startswith("|")]


def _prose(text: str) -> str:
    """Lowercase text with markdown emphasis and line breaks flattened.

    Claim-boundary sentences carry bold/italic markers that move around during
    ordinary editing (``is **not** a functional-safety system``). Matching the
    normalized form keeps the gate anchored to the claim rather than to its
    current formatting.
    """
    return re.sub(r"\s+", " ", text.replace("*", "").replace("`", "")).lower()


def test_rfc_declares_its_frozen_decisions() -> None:
    """The freeze section must exist and still carry five numbered decisions."""
    text = _rfc()
    assert "Frozen before P0" in text, "RFC lost its frozen-decision section"

    _, _, tail = text.partition("### Frozen before P0")
    section, _, _ = tail.partition("### Open questions")
    numbered = re.findall(r"^\d+\.\s+\*\*", section, flags=re.MULTILINE)
    assert len(numbered) == 5, (
        f"expected 5 frozen decisions, found {len(numbered)}. "
        "Adding or removing one is an RFC amendment, not an edit."
    )


def test_fault_and_geometric_violations_never_follow_the_path() -> None:
    """A fault or geometric violation must not resolve to ``ramp_stop``.

    ``ramp_stop`` decelerates *along the authorized path*. Applying it to an SDF
    or forbidden-zone violation drives the robot into the obstacle that
    triggered the stop; applying it to a fault keeps following a trajectory
    planned against dynamics that no longer describe the machine.
    """
    rows = _table_rows(_rfc())
    for trigger in NO_PATH_FOLLOWING_TRIGGERS:
        matching = [r for r in rows if trigger in r]
        assert matching, f"violation class disappeared from the RFC: {trigger}"
        for row in matching:
            assert PATH_FOLLOWING_RESPONSE not in row, (
                f"{trigger!r} maps to {PATH_FOLLOWING_RESPONSE!r}; a fault or "
                "geometric violation must never continue along the path"
            )


def test_torque_taxonomy_separates_envelope_breach_from_fault() -> None:
    """A limit breach and a fault must remain distinct classes."""
    text = _rfc()
    for token in (
        "TorqueEnvelopeViolation",
        "TorqueSensorMismatch",
        "ActuatorIntegrityFailure",
    ):
        assert token in text, f"torque taxonomy lost its {token} class"

    envelope_rows = [r for r in _table_rows(text) if "TorqueEnvelopeViolation" in r]
    assert envelope_rows, "TorqueEnvelopeViolation left the response table"
    assert any(PATH_FOLLOWING_RESPONSE in r for r in envelope_rows), (
        "TorqueEnvelopeViolation no longer maps to ramp_stop — an envelope "
        "breach leaves the model intact and the path valid"
    )


def test_execution_root_binds_the_full_physical_context() -> None:
    """The enforced root must commit to context, not just trajectory bytes."""
    text = _rfc()
    assert "execution_root" in text, "execution_root binding removed"
    _, _, tail = text.partition("execution_root = H(")
    formula, _, _ = tail.partition(")")
    assert formula, "execution_root derivation formula removed"
    for field in EXECUTION_ROOT_BINDINGS:
        assert field in formula, (
            f"execution_root no longer binds {field!r}; dropping it re-opens "
            "replay of the same trajectory in a different physical context"
        )


def test_loader_cannot_become_a_second_authority() -> None:
    """The compiler decides; the loader only verifies and refuses."""
    text = _rfc()
    assert "Compiler / Loader authority boundary" in text
    for prohibition in LOADER_PROHIBITIONS:
        assert prohibition in text, (
            f"loader prohibition removed: {prohibition!r}. A loader that can "
            "decide is a second authority with no receipt recording which won."
        )


def test_constraint_compilation_is_monotonic() -> None:
    """Narrowing is allowed; relaxation must fail compilation."""
    text = _rfc()
    assert "operator_override  ⊆  cell_policy  ⊆  robot_capability" in text, (
        "constraint monotonicity lattice removed or reordered"
    )
    assert "CompilationRejected" in text or "FAILS COMPILATION" in text, (
        "relaxation no longer produces a compile-time failure"
    )


def test_calibration_drift_is_checked_live() -> None:
    """T-13 must stay a per-tick check, not an activation-time snapshot."""
    text = _rfc()
    assert "T-13" in text, "calibration drift threat removed"
    assert "calibration_epoch" in text, "calibration epoch guard removed"


def test_threat_ids_are_contiguous() -> None:
    """No threat may be silently dropped from the middle of the table."""
    found = sorted({int(m) for m in re.findall(r"\|\s*T-(\d{2})\s*\|", _rfc())})
    assert found, "threat table has no entries"
    assert found == list(range(1, len(found) + 1)), f"threat ids are not contiguous: {found}"


def test_rfc_makes_no_certification_or_safety_claim() -> None:
    """Authority is not safety, and this RFC must never imply otherwise."""
    prose = _prose(_rfc())
    for phrase in FORBIDDEN_CLAIMS:
        assert phrase not in prose, f"RFC makes a forbidden claim: {phrase!r}"

    for required in (
        "not a functional-safety system",
        "signature is not a safety case",
        "design budgets, not measurements",
    ):
        assert required in prose, f"RFC lost its claim boundary: {required!r}"


def test_mar_issuance_uses_full_append_metadata_and_profile_expiry() -> None:
    text = _rfc()
    issuance = text.partition("### Issuance flow")[2].partition("---")[0]
    assert "Kernel.evaluate_and_append(call)" in issuance
    assert 'audited.append_result["previous_hash"]' in issuance
    assert "`Kernel.evaluate_and_record` (or" not in issuance
    for token in (
        "nonempty, timezone-aware `expires_at`",
        "maximum MAR TTL",
        "trusted clock",
        "require_expiry=True",
        "GovernanceProfile.production_strict",
        "require_expiry=False",
        "missing/malformed `previous_hash`",
    ):
        assert token in issuance
    assert "Receipt persisted to the audit chain" not in issuance
    assert "persists the `DecisionRecord`" in issuance
    assert "constructs the receipt in memory" in issuance


def test_physical_transform_requires_fresh_allow_and_never_runs_original_args() -> None:
    issuance = _rfc().partition("### Issuance flow")[2].partition("---")[0]
    issuance = re.sub(r"\s+", " ", issuance)
    for token in (
        "recompiled",
        "rebound",
        "rehashed",
        "fresh evaluation",
        "original arguments are discarded",
        "final `ALLOW`",
    ):
        assert token in issuance


def test_physical_replay_authority_is_not_attributed_to_execution_root() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    assert "derived lease-context identity" in normalized
    assert "not from `execution_root`" in normalized
    for authority in (
        "signed receipt bindings",
        "bounded expiry",
        "applicable composite authority",
        "pinned boot state",
        "shared nonce/receipt-burn authority",
    ):
        assert authority in normalized


def test_physical_drive_and_replay_authorities_are_in_the_tcb() -> None:
    text = _rfc()
    diagram = text.partition("```mermaid")[2].partition("```")[0]
    trust = text.partition("### TCB enumeration")[2].partition("## 4.")[0]
    enumeration = trust.partition("The published receipt-only")[0]
    normalized = re.sub(r"\s+", " ", trust)
    for token in (
        "drive command boundary",
        "pinned bus/interface configuration",
        "command-channel credentials or physical isolation",
        "Drives accept commands only from the RT kernel",
        "ROS, DDS, and other processes receive neither the bus mapping nor command credential",
        "hardware command subset",
        "Compromise can command arbitrary motion",
        "profile-local composite receipt-plus-",
        "one durable transaction/lock",
        "protected checkpoint",
        "REQUIRED but UNIMPLEMENTED",
        "shared nonce/receipt-burn authority",
        "durable transactional or consensus store",
        "redundant controllers remain unsupported and must fail closed",
        "direct ROS publisher or untrusted process attempting drive actuation",
        "rejected at the bus/arbiter boundary without actuator motion",
        "non-authoritative reference code",
        "outside the Security TCB",
        "excluded from the claim that compromise can mint accepted motion",
    ):
        assert token in normalized
    assert "ReceiptConsumptionLedger" not in enumeration
    diagram = re.sub(r"\s+", " ", diagram)
    for token in (
        'subgraph REF["Reference only — outside Security TCB"]',
        'RCL["ReceiptConsumptionLedger(path, checkpoint=True)<br/>receipt-anchor-only '
        'reference; insufficient"]',
        'SCB["Profile single-controller composite burn authority<br/>UNIMPLEMENTED — '
        'required before activation"]',
        'BURN["Shared transactional burn/nonce authority<br/>UNIMPLEMENTED — required '
        'for redundant controllers"]',
        'LA -. "reference receipt-only consume" .-> RCL',
        'LA -. "single-controller composite burn required;<br/>fail closed if absent" '
        '.-> SCB',
        'LA -. "redundant consume required;<br/>fail closed if absent" .-> BURN',
        "class MC,AUD,REV,RCL semi",
        "class ACGS,LOAD,RTSK,SHM,LA,SCB,BURN tcb",
    ):
        assert token in diagram
    tcb_diagram = diagram.partition(
        'subgraph TCB["Security TCB (RT subset marked)"]'
    )[2].partition('subgraph REF["Reference only — outside Security TCB"]')[0]
    assert "RCL[" not in tcb_diagram
    compromise = normalized.partition("Compromise of")[2].partition(
        "failures are not containable"
    )[0]
    assert "ReceiptConsumptionLedger" not in compromise
    assert "replay ledger/store" not in compromise


def test_physical_tcb_and_atomic_state_publication_are_explicit() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "Lease Authority binary",
        "pinned configuration",
        "bootstrap write path for the authority page",
        "typed `EMPTY -> ARMED` request to the STM",
        "OS identity, permissions, and process isolation",
        "policy bundle and policy-decision path",
        "receipt issuer, signer, verification-key custody",
        "non-RT loader executable",
        "exclusive ownership of the verified setpoint buffer",
        "exclusive capability to release-store `blocks_verified`",
        "RT subset",
        "can cause unauthorized motion",
        "class ACGS,LOAD,RTSK,SHM,LA,SCB,BURN tcb",
        "atomic release-store",
        "acquire-load",
        "_Atomic uint32_t blocks_verified",
        "fresh-block `EMPTY -> ARMED`",
        "ARMED -> ACTIVE",
        "ACTIVE -> CONSUMED",
        "ARMED|ACTIVE -> REVOKED",
        "ARMED|ACTIVE -> EXPIRED",
        "cannot be overwritten",
        "revocation is dominant",
        "never clear/rebind an old request page or reuse a terminal block",
        "STM.transition_inline(ARMED->ACTIVE) must succeed",
        "final_state = acquire-load immediately before emit",
        "bounded next-tick revocation contract",
        "at most the current command",
        "No subsequent tick may emit",
        "inline validated STM state path",
        "category_1_stop` (never path-following ramp stop)",
        "loader_watermark_page",
        "rt_sequence_page",
        "lease_state_page",
        "verified setpoint buffer is a fifth region",
        "page alignment ensures no writable mapping exposes",
        "Negative capability tests attempt every external cross-field write",
        "no writable lease-state, identity, or acknowledgement mapping",
        "sole RW capability is the safe-direction `revoke_publish_page`",
        "REVOKED -> ACTIVE|ARMED",
        "CONSUMED|EXPIRED -> ACTIVE|ARMED",
    ):
        assert token in normalized

    state_section = text.partition("/* Page D: trusted RT component RW only")[2]
    state_section = state_section.partition("### Per-tick RT check")[0]
    assert "Trusted RT component (Safety Kernel + inline STM)" in state_section
    assert "revoke request adapter | `revoke_publish_page` only" in state_section
    assert "revoker writable state" not in state_section


def test_physical_final_tick_completes_without_out_of_range_tick() -> None:
    hot_path = _rfc().partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    for token in (
        "if seq == seq_hi",
        "STM.transition_inline(ACTIVE->CONSUMED)",
        "if observed state is REVOKED/EXPIRED: preserve it",
        "success returns without scheduling a next out-of-range tick",
        "after the final command is committed",
        "no extra command is emitted",
        "steady ACTIVE branch performs one sequence CAS",
        "first tick may also make one inline STM `ARMED -> ACTIVE` transition",
        "final tick may also make one inline STM `ACTIVE -> CONSUMED` transition",
        "WCET characterization must measure each branch separately",
    ):
        assert token in normalized
    assert "integer compares, one CAS" not in normalized


def test_physical_revoke_is_a_mediated_request_without_write_mapping() -> None:
    text = _rfc()
    trust = text.partition("## 3. Trust boundaries")[2].partition("## 4.")[0]
    control = text.partition("### Control block")[2].partition("### Per-tick RT check")[0]
    interfaces = text.partition("### Interfaces")[2].partition("### Why ROS 2")[0]
    trust = re.sub(r"\s+", " ", trust)
    control = re.sub(r"\s+", " ", control)
    interfaces = re.sub(r"\s+", " ", interfaces)
    for token in (
        'REV["revoke request adapter"]',
        'REV -- "lease-bound monotonic revoke generation" --> RTSK',
        'RTSK -- "inline validated STM state path" --> SHM',
        "state page's only RW mapping",
    ):
        assert token in trust
    for token in (
        "no writable lease-state, identity, or acknowledgement mapping",
        "revoke request adapter | `revoke_publish_page` only",
        "invalid predecessors are refused",
        "trusted RT source mutates state only through STM",
    ):
        assert token in control
    assert "atomically increment `published_generation`" in interfaces
    assert "sole RW capability is the safe-direction publish page" in interfaces


def test_physical_stm_is_rt_inline_bounded_and_nonblocking() -> None:
    text = _rfc()
    trust = text.partition("### TCB enumeration")[2].partition("## 4.")[0]
    control = text.partition("### Control block")[2].partition("### Per-tick RT check")[0]
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    trust = re.sub(r"\s+", " ", trust + control)
    hot_path = re.sub(r"\s+", " ", hot_path)
    for token in (
        "same trusted RT component that owns the state RW mapping",
        "Items 1--4, including item 1's inline STM path, are the **RT software subset**",
        "fixed-size requests through per-principal SPSC mailboxes",
            "allocation-bound monotonic revoke generation",
        "No synchronous IPC or blocking operation exists on the servo path",
        "not a service process or a protection boundary",
        "executes at most one CAS",
    ):
        assert token in trust
    assert "No IPC, wait, timeout, hash, lock, or allocation occurs in the hot path" in hot_path


def test_physical_hot_path_failures_latch_terminal_before_stop() -> None:
    text = _rfc()
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    for failure in (
        "BOOT_MISMATCH",
        "SEQUENCE",
        "WATERMARK",
        "NONFINITE",
        "INADMISSIBLE",
        "STALE_PERCEPTION",
        "CALIBRATION",
    ):
        assert f"fail_terminal({failure})" in normalized
    for token in (
        "inline safe-terminal transition",
        "preserve any first terminal winner",
        "execute `category_1_stop`",
        "return without emitting",
        "no subsequent tick can emit",
    ):
        assert token in normalized


def test_physical_completion_and_cleanup_never_reuse_terminal_lease() -> None:
    text = _rfc()
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    lifecycle = text.partition("### State transitions")[2].partition("### Interfaces")[0]
    hot_path = re.sub(r"\s+", " ", hot_path)
    lifecycle = re.sub(r"\s+", " ", lifecycle)
    for token in (
        "outcome == SUCCESS: report normal CONSUMED completion",
        "observed state is REVOKED/EXPIRED",
        "at most one additional conditional CAS to `REVOKED`",
        "never report normal completion while ACTIVE",
    ):
        assert token in hot_path
    for token in (
        "retire/destroy without zero/reset/reuse",
        "state remains terminal for the allocation's entire observable lifetime",
        "never writes `EMPTY`, zeroes state, or reuses identity",
    ):
        assert token in lifecycle


def test_physical_never_published_empty_allocation_retires_without_revoke_ack() -> None:
    lifecycle = _rfc().partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", lifecycle)
    for token in (
        "fails before the `EMPTY -> ARMED` CAS",
        "never published as a lease",
        "proves no RT tick ever started",
        "RT quiescence holds",
        "never-published `EMPTY` allocation directly",
        "without waiting for revoke acknowledgement",
        "never exposed, reset, or reused",
        "distinct from cleanup of an observable lease",
    ):
        assert token in normalized


def test_physical_rt_and_stm_share_one_trust_domain() -> None:
    text = _rfc()
    control = text.partition("### Control block")[2].partition("### Per-tick RT check")[0]
    threat = text.partition("| T-09 |")[2].partition("| T-10 |")[0]
    control = re.sub(r"\s+", " ", control)
    for token in (
        "logical STM API by code invariant",
        "not a service process or a protection boundary",
        "compromised RT component can bypass it",
        "Structural review and unit tests—not OS mapping claims",
        "external attempt must fault or be refused",
    ):
        assert token in control
    assert "STM is the reviewed state-mutation path, not isolation from RT compromise" in threat


def test_physical_revoke_generation_is_lease_bound_monotonic_and_stale_safe() -> None:
    text = _rfc()
    control = text.partition("struct revoke_identity_page")[2]
    control = control.partition("### Per-tick RT check")[0]
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    lifecycle = text.partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", control + hot_path + lifecycle)
    for token in (
        "lease_identity[32]",
        "revoke_publish_page",
        "revoke_ack_page",
        "published_generation",
        "acknowledged_generation",
        "no writable lease-state, identity, or acknowledgement mapping",
        "monotonically advances `acknowledged_generation`",
        "publish after either per-tick snapshot is observed no later than the next tick",
        "stale handle therefore targets only the retired allocation",
        "fresh generation namespace",
        "never clear/rebind an old request page",
    ):
        assert token in normalized


def test_physical_revoke_pages_are_disjoint_page_level_capabilities() -> None:
    text = _rfc()
    control = text.partition("### Control block")[2]
    control = control.partition("### Per-tick RT check")[0]
    normalized = re.sub(r"\s+", " ", control)
    for token in (
        "Three separate page-aligned request mappings",
        "adapter RW; contains ONLY this field",
        "trusted RT component RW only",
        "Identity, publish, and acknowledgement never share a writable page",
        "protection is page-level",
        "revoke request adapter | `revoke_publish_page` only",
        "identity RO; ack and every lease region unmapped or RO",
    ):
        assert token in normalized


def test_physical_revoke_processing_orders_latch_ack_stop_and_end_tick() -> None:
    text = _rfc()
    hot_path = text.partition("process_revoke_snapshot(revoke):")[2]
    hot_path = hot_path.partition("1. revoke =")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    ordered = (
        "STM.transition_inline(ARMED|ACTIVE -> REVOKED)",
        "if observed in {REVOKED, EXPIRED, CONSUMED}",
        "release-store acknowledged_generation = revoke.published",
        "emit revoke evidence",
        "category_1_stop",
        "return END_TICK",
    )
    positions = [normalized.index(token) for token in ordered]
    assert positions == sorted(positions)
    assert "pending request remains unacknowledged" in normalized
    assert "Next tick retries the same generation before any command can emit" in normalized


def test_physical_revoke_cas_loss_retries_once_and_never_acks_nonterminal() -> None:
    text = _rfc()
    hot_path = text.partition("process_revoke_snapshot(revoke):")[2]
    hot_path = hot_path.partition("1. revoke =")[0]
    contract = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    lifecycle = text.partition("### State transitions")[2].partition("### Why ROS 2")[0]
    normalized = re.sub(r"\s+", " ", hot_path + contract + lifecycle)
    for token in (
        "result == CAS_LOST and observed == ACTIVE",
        "ARMED -> ACTIVE won",
        "STM.transition_inline(ACTIVE -> REVOKED)",
        "one bounded retry",
        "leaves the generation pending and unacknowledged",
        "retries before emission on the next tick",
        "only the servo thread calls STM for a revoke",
        "every non-servo, adapter, and lifecycle caller can only publish a request",
        "only after tick scheduling has stopped and RT quiescence is proven",
    ):
        assert token in normalized
    assert normalized.index("if observed in {REVOKED, EXPIRED, CONSUMED}") < normalized.index(
        "release-store acknowledged_generation"
    )


def test_physical_cleanup_waits_before_unmapping() -> None:
    text = _rfc()
    lifecycle = text.partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", lifecycle)
    for token in (
        "stop scheduling new RT ticks",
        "wait for RT quiescence",
        "only after acknowledgement/terminal observation revoke mappings, unmap",
        "No mapping is revoked or unmapped before both RT quiescence",
    ):
        assert token in normalized
    assert "remains terminal `CONSUMED`" in re.sub(r"\s+", " ", text)
    assert "acknowledges the revoke generation as terminal/non-executable" in re.sub(
        r"\s+", " ", text
    )


def test_physical_final_failure_branch_has_finite_cas_bound() -> None:
    hot_path = _rfc().partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    for token in (
        "exactly one CAS",
        "at most one additional conditional",
        "category_1_stop and emit failure evidence regardless of its result",
        "never loop",
        "at most two state CAS operations, with no loop",
    ):
        assert token in normalized


def test_physical_receipt_hash_uses_internal_canonical_payload() -> None:
    text = _rfc()
    assert "`_hash_payload()`" in text
    assert "inside `to_dict()`, which is what `compute_hash` canonicalizes" not in text


def test_physical_live_bindings_and_negative_requirements_are_frozen() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "two disjoint",
        "live compiled contract",
        "source_hash",
        "immutable source repository revision",
        "missing/mismatched predecessor metadata",
        "empty/naive/expired/overlong expiry",
        "unavailable shared nonce authority",
    ):
        assert token in normalized


def test_physical_contract_projection_is_canonical_and_checked_before_arming() -> None:
    text = _rfc()
    section = text.partition(
        "### Canonical physical-contract projection and activation comparison"
    )[2].partition("### Why each binding exists")[0]
    normalized = re.sub(r"\s+", " ", section)
    for token in (
        "PhysicalContractProjection/v0",
        "LiveDeviceProjection/v0",
        "physical_contract_projection_hash",
        "live_device_projection_hash",
        "acgs.physical.contract-projection/v0\\0",
        "acgs.physical.live-device-projection/v0\\0",
        "RFC 8785 canonical JSON",
        '"sha256:" + lowerhex',
        "exactly 64 lowercase hexadecimal characters",
        "Authoritative source",
        "MAR PhysicalContractProjection equals compiled-artifact projection",
        "MAR LiveDeviceProjection equals live projection",
        "field-for-field canonical equality",
        "loaded compiled contract is valid only when recomputing each projection",
        "three-way equality among the recomputed MAR live hash",
        "one indivisible activation predicate",
        (
            "validly signed MAR that mixes contract A's contract_digest with "
            "contract B's live_device_projection_hash is rejected"
        ),
        "robot/tool/action-space field substituted into the static projection",
        "compiler/contract field substituted into the live projection",
        "static/live substitution",
        "no coercion, tolerance, fallback, or default",
        "fails before arming",
        "Per-motion fields are deliberately outside the contract projection",
        "compiler.input_plan_digest",
        "canonical MotionRequest/argument_hash",
        "only within the bound initial_state.tolerance_rad",
        "may not be moved between these sets",
    ):
        assert token in normalized.replace("`", "")


def test_questionnaire_refuted_and_insufficient_states_never_support_delivery() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    assert "QA output is citation-level data" in text
    assert "stable `question_id`" in text
    for state, verdict in (("QA_REFUTED", "REFUTED"), ("QA_INSUFFICIENT", "INSUFFICIENT")):
        assert state in text
        assert f"QA-`{verdict}`" in text
    section = text.partition("### 8.3.2b Refuted and insufficient QA never support delivery")[2]
    section = section.partition("### ")[0]
    assert "fail the assembly support predicate" in section
    assert "cannot reach delivery" in section


def test_questionnaire_verification_reducer_is_total_and_first_match() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    response = text.partition("### 2.4 Response")[2].partition("### 2.5 Gap")[0]
    regression = text.partition(
        "### 8.3.2b Refuted and insufficient QA never support delivery"
    )[2].partition("### 8.3.3")[0]
    response_normalized = re.sub(r"\s+", " ", response).replace("`", "")
    regression_normalized = re.sub(r"\s+", " ", regression).replace("`", "")
    for token in (
        "first-match precedence",
        "mutually exclusive and deterministic",
        "CONTRADICTED_BY_OTHER_ARTIFACT",
        "otherwise, any check-0-valid citation is REFUTED",
        "otherwise, any check-0-valid citation is INSUFFICIENT",
        "otherwise, any check-0-valid citation lacks a valid PASS QA record",
        "REFUTED + INSUFFICIENT + CANDIDATE_EVIDENCE reduces to QA_REFUTED",
        "INSUFFICIENT + CANDIDATE_EVIDENCE reduces to QA_INSUFFICIENT",
        "CONFIRMED + CANDIDATE_EVIDENCE remains CANDIDATE_EVIDENCE",
        "Contradiction dominates every mix",
        "CONTRADICTED > REFUTED > INSUFFICIENT > CANDIDATE_EVIDENCE",
    ):
        assert token in response_normalized
    for token in (
        "REFUTED + INSUFFICIENT + CANDIDATE_EVIDENCE -> QA_REFUTED",
        "INSUFFICIENT + CANDIDATE_EVIDENCE -> QA_INSUFFICIENT",
        "CONFIRMED + CANDIDATE_EVIDENCE -> CANDIDATE_EVIDENCE",
        "CONTRADICTED_BY_OTHER_ARTIFACT",
        "No mixed input may depend on record iteration order",
        "contrary to the first-match precedence",
    ):
        assert token in regression_normalized


def test_questionnaire_citation_qa_is_per_citation_and_reduced() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "### 2.3.1 CitationQARecord",
        "citation_qa_record_id",
        "deterministic_check_passed",
        "qa_outcome_hash",
        "response_version",
        "answer_hash",
        "assertion_id",
        "assertion_hash",
        "evidence_binding_hash",
        "source_evidence_hash",
        "receipt `argument_hash`",
        "QA `OutcomeEvent.result_hash`",
        "Evidence.verified_by_receipt_id == CitationQARecord.qa_receipt_id",
        "Evidence.verified_by_outcome_hash == CitationQARecord.qa_outcome_hash",
        "Evidence.citation_qa_record_id == CitationQARecord.citation_qa_record_id",
        "substituted otherwise-valid pointer",
        "stale response version or swapped assertion/evidence record fails",
        "response reducer",
        "complete record set",
        "cannot contribute to `SUPPORTED`",
        "distinct QA executions",
        "distinct receipt ids and outcome hashes",
    ):
        assert token in normalized
    response_section = text.partition("### 2.4 Response")[2].partition("### 2.5 Gap")[0]
    response_table = response_section.partition("**`verification_state`")[0]
    assert "| `qa_verdict` |" not in response_table
    assert "| `qa_rationale` |" not in response_table
    assert "| `verified_by_receipt_id` |" not in response_table
    assert "| `verified_by_outcome_hash` |" not in response_table


def test_questionnaire_source_fidelity_is_not_semantic_support() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "Check 0 proves source fidelity only",
        "cannot decide whether those bytes support an assertion",
        "An LLM `PASS` alone is insufficient",
        "Independent semantic-relevance gate",
        "CANDIDATE_EVIDENCE",
        "check-0-valid but irrelevant citation",
        "stubbed QA model returns `PASS`",
        "non-deliverable as `SUPPORTED`",
    ):
        assert token in normalized
    assert "Every path that adds support terminates in a deterministic check" not in text


def test_questionnaire_trust_summary_requires_all_three_support_gates() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("### 6.2 Prompt injection")[0]
    trust = re.sub(r"\s+", " ", trust)
    for token in (
        "deterministic check 0",
        "valid assertion/evidence-bound `CitationQARecord`",
        "valid independently signed and bound `SemanticAdjudicationRecord`",
        "QA alone is never sufficient",
        "non-deliverable `CANDIDATE_EVIDENCE`",
    ):
        assert token in trust


def test_questionnaire_semantic_adjudication_is_signed_and_cross_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.2 SemanticAdjudicationRecord")[2]
    schema = schema.partition("### 2.3.3 MiningOutcomeEnvelope")[0]
    schema = re.sub(r"\s+", " ", schema)
    for token in (
        "immutable signed event",
        "response_version` / `answer_hash",
        "assertion_id` / `assertion_hash",
        "evidence_id` / `producer_lineage_hash",
        "semantic_evidence_binding_hash",
        "adjudicator_id` / `adjudicator_kind",
        "rule_id` / `rule_version",
        "semantic_adjudication_event_hash",
        "signature",
        "allowlisted key",
        "recomputes the rule inputs and verdict",
        "unknown/revoked adjudicator or key",
        "both a valid QA record and a valid confirming semantic record",
    ):
        assert token in schema

    lineage_test = text.partition("### 8.3.10 Immutable assertion-level QA lineage")[2]
    lineage_test = lineage_test.partition("### 8.3.11")[0]
    lineage_test = re.sub(r"\s+", " ", lineage_test)
    for token in (
        "signed `SemanticAdjudicationRecord`",
        "tampered record/hash/signature",
        "unknown or revoked adjudicator/key",
        "differs from recomputation",
        "QA alone, including `PASS`, cannot produce `SUPPORTED`",
    ):
        assert token in lineage_test


def test_questionnaire_mining_envelope_binds_producer_lineage_without_cycle() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    schema = re.sub(r"\s+", " ", schema)
    for token in (
        "RawMiningResult",
        "MUST NOT construct an `AssertionManifest`",
        "Construct `MiningOutcomePreimage`",
        "Only then hash the preimage",
        "outcome_event_id, produced_by_receipt_id",
        "evidence_records[] sorted by evidence_id",
        "classifier_registry_proofs[] sorted by",
        "complete ClassifierRegistryProofArchive/v1",
        "RegistryKeyAuthorityProof/v1",
        "producer_receipt_reference.policy_hash",
        "no unreferenced archive",
        "assertion_manifest_hash",
        "complete ordered AssertionManifest",
        "MUST NOT contain `produced_by_outcome_hash`",
        "OutcomeEvent.result_hash",
        "OutcomeEvent.outcome_hash",
        "mining_result_hash",
        "mining_envelope_hash",
        "producer_lineage_hash",
        "Response.response_lineage_hash",
        "receipt's `argument_hash`",
        "substituted producer pointer",
        "wrong envelope",
        "without asking either hash to contain itself",
    ):
        assert token in schema

    regression = text.partition("### 8.3.12 Mining envelope and producer lineage")[2]
    regression = regression.partition("### 8.4")[0]
    regression = re.sub(r"\s+", " ", regression)
    for token in (
        "agent returns that raw result only",
        "cannot construct the manifest, canonical preimage, or outcome",
        "wrapper canonicalizes the answer",
        "constructs `MiningOutcomePreimage`",
        "only then computes the inner payload hash and outer",
        "reserves a unique append slot",
        "atomically finalizes the pending record",
        "verifies the bound `ATTESTED` `AppendAcceptance`",
        "only afterward constructs `MiningOutcomeEnvelope`",
        "producer receipt",
        "outcome-event id",
        "outcome hash",
        "remove or swap an evidence record",
        "wrong envelope",
        "not self-referential",
    ):
        assert token in regression


def test_questionnaire_assertion_manifest_is_complete_and_lineage_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    response = text.partition("### 2.4 Response")[2].partition("### 2.5 Gap")[0]
    regression = text.partition("### 8.3.11a Assertion manifest completeness")[2]
    regression = regression.partition("### 8.3.12")[0]
    normalized = re.sub(r"\s+", " ", schema + response + regression)
    for token in (
        "AssertionManifestMemberPreimage",
        "It excludes assertion_hash",
        "acgs.questionnaire.assertion-member/v1\\0",
        '"sha256:" + lowerhex',
        "exactly 64 lowercase hexadecimal characters",
        "ownership, immutable response/answer version",
        "segmentation-rule version",
        "text-only hash is invalid",
        "complete member preimage plus its derived assertion_hash",
        "assertion_hash inconsistent with its acyclic member preimage",
        "segmentation_rule_id",
        "segmentation_rule_version",
        "contiguous assertion_index order",
        "answer_utf8_start",
        "answer_utf8_end",
        "acgs.questionnaire.assertion-manifest/v1\\0",
        "RFC 8785 canonical JSON",
        "assertion_manifest_hash",
        "response_lineage_hash binds",
        "every evidence assertion id/hash must name an exact manifest member",
        "every manifest assertion to have at least one bound Evidence",
        "complete valid CitationQARecord",
        "valid bound SemanticAdjudicationRecord",
        "rejects any assertion missing any one of those records",
        "Reorder assertions, duplicate or skip an index/id",
        "prevent the response from reaching SUPPORTED",
        "known-vector AssertionManifestMemberPreimage",
        "include assertion_hash in that preimage",
        "substitute a text-only hash",
        "mutate the domain literal",
    ):
        assert token.lower() in normalized.replace("`", "").lower()


def test_questionnaire_raw_mining_flow_precedes_canonical_outcome() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    normalized = re.sub(r"\s+", " ", schema).replace("`", "")
    ordered = (
        "RawMiningResult",
        "Validate answer_text",
        "Construct and durably store the canonical ordered AssertionManifest",
        "Validate every raw candidate against the canonical answer and manifest",
        "derive and attach the matched member's assertion_id and assertion_hash",
        "Construct MiningOutcomePreimage",
        "Only then hash the preimage",
    )
    positions = [normalized.index(token) for token in ordered]
    assert positions == sorted(positions)
    assert "Before mining, the product freezes" not in schema
    assert "mining agent returns only a MiningOutcomePreimage" not in normalized


def test_questionnaire_raw_candidates_cannot_choose_assertion_identity() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    regression = text.partition("### 8.3.12 Mining envelope and producer lineage")[2]
    regression = regression.partition("### 8.4")[0]
    normalized = re.sub(r"\s+", " ", schema + regression)
    normalized = normalized.replace("`", "")

    for token in (
        "RawMiningResult has exactly answer_text and evidence_candidates",
        "RawEvidenceCandidate",
        "candidate_id",
        "assertion_answer_utf8_start",
        "assertion_answer_utf8_end",
        "immutable source-evidence fields",
        "MUST NOT contain assertion_id, assertion_hash, source_metadata, or any unknown field",
        "trusted-wrapper outputs, never model-selected inputs",
        "0 <= start < end <= len(answer_utf8)",
        "UTF-8 code point boundaries",
        "equal exactly one manifest member",
        "Overlap, containment, fuzzy matching, and text search are not binding rules",
        "rejects zero or multiple exact matches",
        "duplicate candidate_id",
        "stale, out-of-range, or non-boundary offsets",
        "model-supplied assertion_id or assertion_hash",
        "wrapper—not the model— derives and attaches",
        "produces no accepted outcome",
        "source_metadata is never accepted from RawMiningResult",
        "SourceMetadata/v1",
        "SOURCE | TEST | CONFIG | DOC | PROCESS | OTHER",
        "Filesystem mtime is neither accepted nor derived",
        "classifier_artifact_hash",
        "classifier_registry_entry_hash",
        "classifier_registry_checkpoint_hash",
        "ClassifierRegistryEntryPreimage/v1",
        "ClassifierRegistryCheckpointPreimage/v1",
        "linearizable authenticated-head authority",
        "durable high-water tuple keyed by registry_id/classifier_id/classifier_version",
        "replaying sequence 7 ACTIVE after observing sequence 8 REVOKED is denied",
        "SourceEvidencePreimage/v1",
        "acgs.questionnaire.artifact/v1\\0",
        "acgs.questionnaire.excerpt/v1\\0",
        "acgs.questionnaire.source-classifier-artifact/v1\\0",
        "acgs.questionnaire.classifier-registry-entry/v1\\0",
        "acgs.questionnaire.classifier-registry-checkpoint/v1\\0",
        "acgs.questionnaire.source-evidence/v1\\0",
        "model-selected metadata",
        "classifier substitution",
    ):
        assert token in normalized

    raw_schema = schema.partition("The raw schemas are closed:")[2]
    raw_schema = raw_schema.partition("The trusted product wrapper")[0]
    for source_field in (
        "file_path",
        "line_start",
        "line_end",
        "excerpt",
        "artifact_hash",
        "commit_sha",
    ):
        assert source_field in raw_schema
    raw_candidate = raw_schema.partition("RawEvidenceCandidate = {")[2].partition("}")[0]
    assert "source_metadata" not in raw_candidate


def test_questionnaire_answer_bytes_and_hash_are_canonical_and_frozen() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    regression = text.partition("### 8.3.12 Mining envelope and producer lineage")[2]
    regression = regression.partition("### 8.4")[0]
    normalized = re.sub(r"\s+", " ", schema + regression).replace("`", "")
    for token in (
        "canonical answer is an identity encoding, not a text normalization",
        "decode one RFC 8259 JSON string",
        "invalid UTF-8",
        "unpaired Unicode surrogates",
        "canonical_answer_bytes = UTF8(answer_text)",
        "no Unicode normalization, CRLF/LF conversion, whitespace trimming",
        "acgs.questionnaire.answer/v1\\0",
        "410d0ac3a9f09f9982",
        "sha256:f07c9b089a9c3b49dc69d4268dc1d091590d7d98f62f5519874241e69c20d0ec",
        "c3a9",
        "sha256:4feb9b937ca108cd20a4e967393299b910514315042ca0edb83627ca08ca794c",
        "65cc81",
        "sha256:5dde93076bcf9a7ac0b22fbb390bf88f96fbcc79a3c848f11b7345c55cebb766",
        "U+0065 U+0301",
        '"e\\u0301"',
        "Composed and decomposed Unicode remain distinct",
        "Freeze the three answer-byte/hash vectors",
        "Preserve CRLF",
        "vector mismatch must fail before manifest construction",
    ):
        assert token in normalized


def test_questionnaire_source_evidence_hash_components_are_frozen(
    monkeypatch,
) -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    regression = text.partition("### 8.3.12 Mining envelope and producer lineage")[2]
    regression = regression.partition("### 8.4")[0]
    normalized = re.sub(r"\s+", " ", schema + regression).replace("`", "")

    def domain_hash(domain: str, payload: bytes) -> str:
        digest = hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()
        return "sha256:" + digest

    def vector_jcs(value: object) -> bytes:
        # This vector uses only JCS-stable strings and integers.
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    artifact_hash = domain_hash("acgs.questionnaire.artifact/v1", b"alpha\n")
    excerpt_hash = domain_hash("acgs.questionnaire.excerpt/v1", b"alpha")
    classifier_artifact_hash = domain_hash(
        "acgs.questionnaire.source-classifier-artifact/v1",
        b"classifier-v1\n",
    )
    registry_preimage = {
        "schema_version": "ClassifierRegistryEntry/v1",
        "classifier_id": "source-role",
        "classifier_version": "1.0.0",
        "classifier_artifact_hash": classifier_artifact_hash,
        "registry_sequence": 7,
        "status": "ACTIVE",
    }
    classifier_registry_entry_hash = domain_hash(
        "acgs.questionnaire.classifier-registry-entry/v1",
        vector_jcs(registry_preimage),
    )
    checkpoint_preimage = {
        "schema_version": "ClassifierRegistryCheckpoint/v1",
        "registry_id": "source-classifier-registry",
        "classifier_id": "source-role",
        "classifier_version": "1.0.0",
        "current_registry_sequence": 7,
        "current_registry_entry_hash": classifier_registry_entry_hash,
        "current_status": "ACTIVE",
        "request_nonce": "000102030405060708090a0b0c0d0e0f",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:01:00Z",
    }
    classifier_registry_checkpoint_hash = domain_hash(
        "acgs.questionnaire.classifier-registry-checkpoint/v1",
        vector_jcs(checkpoint_preimage),
    )
    source_metadata = {
        "schema_version": "SourceMetadata/v1",
        "language": "Python",
        "detected_role": "SOURCE",
        "classifier_id": "source-role",
        "classifier_version": "1.0.0",
        "classifier_artifact_hash": classifier_artifact_hash,
        "classifier_registry_entry_hash": classifier_registry_entry_hash,
        "classifier_registry_checkpoint_hash": classifier_registry_checkpoint_hash,
    }
    source_evidence_preimage = {
        "schema_version": "SourceEvidencePreimage/v1",
        "evidence_id": "ev-1",
        "assertion_id": "as-1",
        "assertion_hash": "sha256:" + "a" * 64,
        "commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "file_path": "src/a.py",
        "line_start": 1,
        "line_end": 1,
        "artifact_hash": artifact_hash,
        "excerpt_hash": excerpt_hash,
        "source_metadata": source_metadata,
    }
    source_evidence_hash = domain_hash(
        "acgs.questionnaire.source-evidence/v1",
        vector_jcs(source_evidence_preimage),
    )

    expected = (
        "sha256:1e6f051f9e613e96aa7cae9326e57c1e48eca357fc5c81728786ce493f1d4f43",
        "sha256:bb38581a1481f962bdb5e211141f1e62d8a76e6ba1552c9586fec56b8b563648",
        "sha256:312edfabd0313bacd27057bd1165f6ce2259faa69870e478a8cf5b9188bcb97b",
        "sha256:09eac77595895cbbb35761d703259a93c960d4721869fd5a8447fa02a9524405",
        "sha256:36cfa8824963f2f91527e5a75d75f391c3a4fea797ce50aeefff12c43b464ab2",
        "sha256:c8db69efe2684d07acd3d111eba7bbd12b5b2288757a97061d3527c4d6a3ffed",
    )
    assert (
        artifact_hash,
        excerpt_hash,
        classifier_artifact_hash,
        classifier_registry_entry_hash,
        classifier_registry_checkpoint_hash,
        source_evidence_hash,
    ) == expected

    key_manifest = {
        "schema_version": "RegistryVerificationKeyManifest/v1",
        "manifest_id": "source-classifier-registry-keys/v1",
        "keys": [
            {
                "purpose": "CHECKPOINT",
                "key_id": "checkpoint-key-1",
                "signature_alg": "Ed25519",
                "public_key_b64u": (
                    "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
                ),
                "status": "ACTIVE",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            },
            {
                "purpose": "ENTRY",
                "key_id": "entry-key-1",
                "signature_alg": "Ed25519",
                "public_key_b64u": (
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
                ),
                "status": "ACTIVE",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            },
        ],
    }
    def registry_key_manifest_is_accepted(
        manifest: object,
        accepted_at_value: object,
    ) -> bool:
        if (
            type(manifest) is not dict
            or type(accepted_at_value) is not str
            or not _is_closed_json_value(manifest)
        ):
            return False
        manifest_fields = {"schema_version", "manifest_id", "keys"}
        key_fields = {
            "purpose",
            "key_id",
            "signature_alg",
            "public_key_b64u",
            "status",
            "not_before",
            "not_after",
        }
        if (
            set(manifest) != manifest_fields
            or manifest.get("schema_version")
            != "RegistryVerificationKeyManifest/v1"
            or type(manifest.get("manifest_id")) is not str
            or not manifest["manifest_id"]
            or type(manifest.get("keys")) is not list
            or not manifest["keys"]
        ):
            return False
        try:
            accepted_at = _parse_rfc3339(accepted_at_value)
        except (TypeError, ValueError):
            return False
        key_order: list[tuple[str, str, str]] = []
        key_ids: list[str] = []
        for key_record in manifest["keys"]:
            if type(key_record) is not dict or set(key_record) != key_fields:
                return False
            if (
                key_record["purpose"] not in {"ENTRY", "CHECKPOINT"}
                or key_record["status"] not in {"ACTIVE", "REVOKED"}
                or key_record["signature_alg"] != "Ed25519"
                or type(key_record["key_id"]) is not str
                or not key_record["key_id"]
            ):
                return False
            try:
                public_key = _canonical_b64u(key_record["public_key_b64u"])
                if any(
                    type(key_record[field]) is not str
                    or re.fullmatch(
                        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                        key_record[field],
                    )
                    is None
                    for field in ("not_before", "not_after")
                ):
                    return False
                not_before = _parse_rfc3339(key_record["not_before"])
                not_after = _parse_rfc3339(key_record["not_after"])
            except (TypeError, ValueError):
                return False
            if (
                len(public_key) != 32
                or not not_before < not_after
                or (
                    key_record["status"] == "ACTIVE"
                    and not not_before <= accepted_at < not_after
                )
            ):
                return False
            key_order.append(
                (
                    str(key_record["purpose"]),
                    str(key_record["key_id"]),
                    str(key_record["signature_alg"]),
                )
            )
            key_ids.append(str(key_record["key_id"]))
        return (
            key_order == sorted(key_order)
            and len(key_ids) == len(set(key_ids))
        )

    key_manifest_hash = domain_hash(
        "acgs.questionnaire.registry-verification-keys/v1",
        vector_jcs(key_manifest),
    )
    receipt_signing_seed = b"\x01" * 32
    receipt_signing_key_id = "mining-receipt-key-1"
    receipt_public_key, _ = _ed25519_sign(receipt_signing_seed, b"")
    receipt_key_manifest = {
        "schema_version": "ReceiptVerificationKeyManifest/v1",
        "manifest_id": "questionnaire-receipt-keys/v1",
        "key_purpose": "DECISION_RECEIPT_SIGNING",
        "key_id": receipt_signing_key_id,
        "status": "ACTIVE",
        "signature_algorithm": "ed25519",
        "public_key_b64u": base64.urlsafe_b64encode(receipt_public_key)
        .rstrip(b"=")
        .decode(),
        "valid_from": "2026-07-01T00:00:00Z",
        "valid_until": "2026-08-01T00:00:00Z",
        "revoked_key_ids": [],
    }
    receipt_key_manifest_hash = domain_hash(
        "acgs.questionnaire.receipt-verification-keys/v1",
        vector_jcs(receipt_key_manifest),
    )
    assert set(receipt_key_manifest) == {
        "schema_version",
        "manifest_id",
        "key_purpose",
        "key_id",
        "status",
        "signature_algorithm",
        "public_key_b64u",
        "valid_from",
        "valid_until",
        "revoked_key_ids",
    }
    assert receipt_key_manifest_hash == (
        "sha256:47afc439f1b0f8ed6fa3f10f7c149c1"
        "d2787b02fb57634379a1a45f01df45bf7"
    )
    root_spki = _p256_spki(1)
    root_spki_b64u = base64.urlsafe_b64encode(root_spki).rstrip(b"=").decode()
    root_spki_hash = domain_hash(
        "acgs.questionnaire.p256-spki/v1",
        root_spki,
    )
    revocation_snapshot = {
        "snapshot_sequence": 4,
        "issued_at": "2026-07-01T00:00:00Z",
        "revoked_signing_key_ids": [],
        "revoked_verification_manifest_hashes": [],
    }
    revocation_snapshot_hash = domain_hash(
        "acgs.questionnaire.assembly-revocation-snapshot/v1",
        vector_jcs(revocation_snapshot),
    )
    assembly_trust_preimage = {
        "schema_version": "AssemblyVerificationTrustManifestPreimage/v1",
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "root_signing_key_id": "assembly-root-key-1",
        "authorized_manifest_purposes": [
            "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING",
            "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
            "RECEIPT_BURN_VERIFICATION_MANIFEST_SIGNING",
        ],
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "root_public_key_spki_der_b64u": root_spki_b64u,
        "root_public_key_spki_sha256": root_spki_hash,
        "min_manifest_sequence": 7,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "head_acceptance_key_purpose": (
            "BURN_MANIFEST_HEAD_ACCEPTANCE_SIGNING"
        ),
        "predecessor_signing_key_purpose": (
            "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING"
        ),
        "predecessor_signing_domain": (
            "acgs.questionnaire.assembly-manifest-predecessor-signature/v1"
        ),
        "revocation_snapshot": revocation_snapshot,
        "revocation_snapshot_hash": revocation_snapshot_hash,
    }
    assembly_trust_hash = domain_hash(
        "acgs.questionnaire.assembly-verification-trust/v1",
        vector_jcs(assembly_trust_preimage),
    )
    assembly_trust_manifest = {
        "schema_version": "AssemblyVerificationTrustManifest/v1",
        "preimage": assembly_trust_preimage,
        "assembly_verification_trust_manifest_hash": assembly_trust_hash,
    }
    assert set(revocation_snapshot) == {
        "snapshot_sequence",
        "issued_at",
        "revoked_signing_key_ids",
        "revoked_verification_manifest_hashes",
    }
    assert set(assembly_trust_preimage) == {
        "schema_version",
        "trust_root_id",
        "trust_root_version",
        "root_signing_key_id",
        "authorized_manifest_purposes",
        "signature_algorithm",
        "signature_encoding",
        "root_public_key_spki_der_b64u",
        "root_public_key_spki_sha256",
        "min_manifest_sequence",
        "valid_from",
        "valid_until",
        "head_acceptance_key_purpose",
        "predecessor_signing_key_purpose",
        "predecessor_signing_domain",
        "revocation_snapshot",
        "revocation_snapshot_hash",
    }
    burn_spki = _p256_spki(3)
    burn_spki_b64u = base64.urlsafe_b64encode(burn_spki).rstrip(b"=").decode()
    burn_spki_hash = domain_hash(
        "acgs.questionnaire.p256-spki/v1",
        burn_spki,
    )
    burn_revocation_snapshot = {
        "snapshot_sequence": 5,
        "issued_at": "2026-07-01T00:00:00Z",
        "revoked_burn_signing_key_ids": [],
        "revoked_burn_verification_manifest_hashes": [],
    }
    burn_revocation_snapshot_hash = domain_hash(
        "acgs.questionnaire.receipt-burn-revocation-snapshot/v1",
        vector_jcs(burn_revocation_snapshot),
    )
    burn_manifest_preimage = {
        "schema_version": "ReceiptBurnVerificationManifestPreimage/v1",
        "manifest_id": "receipt-burn-manifest-1",
        "manifest_sequence": 7,
        "previous_burn_verification_manifest_hash": "GENESIS",
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "authority_id": "receipt-burn-authority-1",
        "key_purpose": "RECEIPT_BURN_ACCEPTANCE_SIGNING",
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "signing_key_id": "receipt-burn-key-1",
        "public_key_spki_der_b64u": burn_spki_b64u,
        "public_key_spki_sha256": burn_spki_hash,
        "valid_from": "2026-07-01T00:00:00Z",
        "valid_until": "2026-08-01T00:00:00Z",
        "revocation_snapshot": burn_revocation_snapshot,
        "revocation_snapshot_hash": burn_revocation_snapshot_hash,
    }
    burn_manifest_hash = domain_hash(
        "acgs.questionnaire.receipt-burn-verification-manifest/v1",
        vector_jcs(burn_manifest_preimage),
    )
    burn_manifest_message = (
        b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
        + burn_manifest_hash.encode("ascii")
    )
    burn_manifest_root_signature_raw = _p256_sign(burn_manifest_message, 1, 11)
    burn_manifest_root_signature = base64.urlsafe_b64encode(
        burn_manifest_root_signature_raw
    ).rstrip(b"=").decode()
    burn_manifest = {
        "schema_version": "ReceiptBurnVerificationManifest/v1",
        "preimage": burn_manifest_preimage,
        "burn_verification_manifest_hash": burn_manifest_hash,
        "root_signature_algorithm": "ECDSA_P256_SHA256",
        "root_signature_encoding": "P1363_BASE64URL_NOPAD",
        "root_signing_key_id": "assembly-root-key-1",
        "root_signature": burn_manifest_root_signature,
    }
    assert set(burn_revocation_snapshot) == {
        "snapshot_sequence",
        "issued_at",
        "revoked_burn_signing_key_ids",
        "revoked_burn_verification_manifest_hashes",
    }
    assert set(burn_manifest_preimage) == {
        "schema_version",
        "manifest_id",
        "manifest_sequence",
        "previous_burn_verification_manifest_hash",
        "trust_root_id",
        "trust_root_version",
        "authority_id",
        "key_purpose",
        "signature_algorithm",
        "signature_encoding",
        "signing_key_id",
        "public_key_spki_der_b64u",
        "public_key_spki_sha256",
        "valid_from",
        "valid_until",
        "revocation_snapshot",
        "revocation_snapshot_hash",
    }
    assert set(burn_manifest) == {
        "schema_version",
        "preimage",
        "burn_verification_manifest_hash",
        "root_signature_algorithm",
        "root_signature_encoding",
        "root_signing_key_id",
        "root_signature",
    }
    assert _p256_verify(burn_manifest_message, burn_manifest_root_signature_raw, 1)
    assert not _p256_verify(
        burn_manifest_message, burn_manifest_root_signature_raw, 2
    )
    assert burn_manifest_hash == (
        "sha256:26de74aa8b88621232d7ce3c238552f37"
        "c459f912fa8d210cad199e4b8bb01da"
    )
    assert burn_manifest_root_signature == (
        "PtETt4g7TFkGODedsMIc2hZ0LtAlUEi_QzOR03S8IdE0jRS5Eq7c4IQKeM1Y0IUc"
        "LuABw9qoR3MpmopXsduWyA"
    )

    manifest_validation_store_record = {
        "schema_version": "ReceiptBurnStoreRecordPreimage/v1",
        "commit_timestamp": "2026-07-26T22:44:59.000000Z",
    }

    def parse_utc_seconds(value: object) -> datetime:
        if type(value) is not str or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
        ):
            raise ValueError("non-canonical UTC seconds")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )
        except Exception as error:
            raise ValueError("non-canonical UTC seconds") from error

    def parse_utc_microseconds(value: object) -> datetime:
        if type(value) is not str or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value
        ):
            raise ValueError("non-canonical UTC microseconds")
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=UTC
            )
        except Exception as error:
            raise ValueError("non-canonical UTC microseconds") from error

    def make_burn_policy_chain(
        trust_manifest: dict[str, object],
    ) -> dict[str, object]:
        trust_hash = trust_manifest[
            "assembly_verification_trust_manifest_hash"
        ]
        policy_preimage = {
            "schema_version": "QuestionnairePolicyBundlePreimage/v1",
            "policy_bundle_id": "questionnaire-default",
            "decision_policy_artifact_hash": "sha256:" + "1" * 64,
            "registry_verification_key_manifest_hash": key_manifest_hash,
            "receipt_verification_key_manifest_hash": receipt_key_manifest_hash,
            "assembly_verification_trust_manifest_hash": trust_hash,
            "burn_verification_manifest_hash": "sha256:" + "3" * 64,
            "burn_manifest_head_acceptance_hash": "sha256:" + "4" * 64,
        }
        policy_version = "questionnaire-policy/" + hashlib.sha256(
            b"acgs.questionnaire.policy-bundle/v1\0"
            + vector_jcs(policy_preimage)
        ).hexdigest()
        policy_bundle = {
            "schema_version": "QuestionnairePolicyBundle/v1",
            "policy_bundle_id": "questionnaire-default",
            "policy_version": policy_version,
            **{
                field: policy_preimage[field]
                for field in policy_preimage
                if field not in {"schema_version", "policy_bundle_id"}
            },
        }
        return {
            "policy_bundle_preimage": policy_preimage,
            "policy_bundle": policy_bundle,
            "decision_receipt": {
                "policy_bundle_id": "questionnaire-default",
                "policy_version": policy_version,
                "policy_hash": policy_version,
            },
            "assembly_trust_manifest": trust_manifest,
        }

    verified_policy_chain: dict[str, object] = make_burn_policy_chain(
        assembly_trust_manifest
    )

    def make_burn_manifest_envelope(
        preimage: dict[str, object],
        private_scalar: int = 1,
        nonce: int = 11,
    ) -> dict[str, object]:
        candidate_hash = _safe_domain_hash(
            "acgs.questionnaire.receipt-burn-verification-manifest/v1",
            preimage,
        )
        assert candidate_hash is not None
        signature = _p256_sign(
            b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
            + candidate_hash.encode("ascii"),
            private_scalar,
            nonce,
        )
        return {
            "schema_version": "ReceiptBurnVerificationManifest/v1",
            "preimage": preimage,
            "burn_verification_manifest_hash": candidate_hash,
            "root_signature_algorithm": "ECDSA_P256_SHA256",
            "root_signature_encoding": "P1363_BASE64URL_NOPAD",
            "root_signing_key_id": "assembly-root-key-1",
            "root_signature": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode(),
        }

    def burn_manifest_is_accepted(
        envelope: object,
        persisted_store_record: object,
        policy_chain: object,
        requested_manifest_purpose: str = (
            "RECEIPT_BURN_VERIFICATION_MANIFEST_SIGNING"
        ),
        expected_sequence: int = 7,
        expected_predecessor: str = "GENESIS",
        signed_commit_timestamp: str | None = None,
    ) -> bool:
        if not all(
            type(value) is dict
            for value in (envelope, persisted_store_record, policy_chain)
        ):
            return False
        if not all(
            _is_closed_json_value(value)
            for value in (envelope, persisted_store_record, policy_chain)
        ):
            return False
        if set(envelope) != set(burn_manifest):
            return False
        preimage = envelope.get("preimage")
        if type(preimage) is not dict or set(preimage) != set(
            burn_manifest_preimage
        ):
            return False
        candidate_hash = _safe_domain_hash(
            "acgs.questionnaire.receipt-burn-verification-manifest/v1",
            preimage,
        )
        if candidate_hash is None:
            return False
        validated_trust_preimage = validate_verified_assembly_trust_chain(
            policy_chain,
            persisted_store_record.get("commit_timestamp"),
        )
        if validated_trust_preimage is None:
            return False
        try:
            commit_time = parse_utc_microseconds(
                persisted_store_record["commit_timestamp"]
            )
            manifest_valid_from = parse_utc_seconds(preimage["valid_from"])
            manifest_valid_until = parse_utc_seconds(preimage["valid_until"])
            candidate_spki = _canonical_b64u(
                preimage["public_key_spki_der_b64u"]
            )
            root_spki = _canonical_b64u(
                validated_trust_preimage["root_public_key_spki_der_b64u"]
            )
            signature = _canonical_b64u(envelope["root_signature"])
            policy_root_snapshot = validated_trust_preimage[
                "revocation_snapshot"
            ]
            burn_snapshot = preimage["revocation_snapshot"]
            burn_snapshot_fields = {
                "snapshot_sequence",
                "issued_at",
                "revoked_burn_signing_key_ids",
                "revoked_burn_verification_manifest_hashes",
            }
            if (
                type(policy_root_snapshot) is not dict
                or type(burn_snapshot) is not dict
                or set(burn_snapshot) != burn_snapshot_fields
                or type(burn_snapshot["snapshot_sequence"]) is not int
                or burn_snapshot["snapshot_sequence"] < 0
                or type(burn_snapshot["issued_at"]) is not str
                or re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                    burn_snapshot["issued_at"],
                )
                is None
            ):
                return False
            parse_utc_seconds(burn_snapshot["issued_at"])
            revoked_burn_key_ids = burn_snapshot[
                "revoked_burn_signing_key_ids"
            ]
            revoked_burn_manifest_hashes = burn_snapshot[
                "revoked_burn_verification_manifest_hashes"
            ]
            if (
                type(revoked_burn_key_ids) is not list
                or not all(
                    type(value) is str and value
                    for value in revoked_burn_key_ids
                )
                or revoked_burn_key_ids != sorted(set(revoked_burn_key_ids))
                or type(revoked_burn_manifest_hashes) is not list
                or not all(
                    type(value) is str
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                    for value in revoked_burn_manifest_hashes
                )
                or revoked_burn_manifest_hashes
                != sorted(set(revoked_burn_manifest_hashes))
            ):
                return False
        except (KeyError, TypeError, ValueError):
            return False
        candidate_spki_hash = _safe_domain_bytes_hash(
            "acgs.questionnaire.p256-spki/v1",
            candidate_spki,
        )
        burn_snapshot_hash = _safe_domain_hash(
            "acgs.questionnaire.receipt-burn-revocation-snapshot/v1",
            burn_snapshot,
        )
        if candidate_spki_hash is None or burn_snapshot_hash is None:
            return False
        fields_valid = (
            envelope["schema_version"]
            == "ReceiptBurnVerificationManifest/v1"
            and preimage["schema_version"]
            == "ReceiptBurnVerificationManifestPreimage/v1"
            and type(preimage["manifest_id"]) is str
            and bool(preimage["manifest_id"])
            and type(preimage["authority_id"]) is str
            and bool(preimage["authority_id"])
            and envelope["burn_verification_manifest_hash"] == candidate_hash
            and envelope["root_signature_algorithm"] == "ECDSA_P256_SHA256"
            and envelope["root_signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and envelope["root_signing_key_id"]
            == validated_trust_preimage["root_signing_key_id"]
            and persisted_store_record.get("schema_version")
            == "ReceiptBurnStoreRecordPreimage/v1"
            and (
                signed_commit_timestamp is None
                or signed_commit_timestamp
                == persisted_store_record.get("commit_timestamp")
            )
            and manifest_valid_from <= commit_time < manifest_valid_until
            and preimage.get("trust_root_id")
            == validated_trust_preimage.get("trust_root_id")
            and preimage.get("trust_root_version")
            == validated_trust_preimage.get("trust_root_version")
            and requested_manifest_purpose
            in validated_trust_preimage["authorized_manifest_purposes"]
            and requested_manifest_purpose
            == "RECEIPT_BURN_VERIFICATION_MANIFEST_SIGNING"
            and preimage.get("manifest_sequence") == expected_sequence
            and preimage.get("previous_burn_verification_manifest_hash")
            == expected_predecessor
            and preimage.get("key_purpose")
            == "RECEIPT_BURN_ACCEPTANCE_SIGNING"
            and preimage.get("signature_algorithm") == "ECDSA_P256_SHA256"
            and preimage.get("signature_encoding") == "P1363_BASE64URL_NOPAD"
            and preimage.get("signing_key_id") == "receipt-burn-key-1"
            and candidate_spki == burn_spki
            and preimage.get("public_key_spki_sha256") == candidate_spki_hash
            and preimage.get("revocation_snapshot_hash") == burn_snapshot_hash
            and preimage.get("signing_key_id")
            not in policy_root_snapshot["revoked_signing_key_ids"]
            and candidate_hash
            not in policy_root_snapshot["revoked_verification_manifest_hashes"]
            and preimage.get("signing_key_id")
            not in burn_snapshot["revoked_burn_signing_key_ids"]
            and candidate_hash
            not in burn_snapshot[
                "revoked_burn_verification_manifest_hashes"
            ]
        )
        candidate_message = (
            b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
            + candidate_hash.encode("ascii")
        )
        return fields_valid and _safe_p256_verify_spki(
            candidate_message,
            signature,
            root_spki,
        )

    assert burn_manifest_is_accepted(
        burn_manifest,
        manifest_validation_store_record,
        verified_policy_chain,
        signed_commit_timestamp="2026-07-26T22:44:59.000000Z",
    )
    assert not burn_manifest_is_accepted(
        burn_manifest,
        manifest_validation_store_record,
        None,  # type: ignore[arg-type]
    )
    exact_valid_from_record = {
        **manifest_validation_store_record,
        "commit_timestamp": "2026-07-01T00:00:00.000000Z",
    }
    exact_valid_until_record = {
        **manifest_validation_store_record,
        "commit_timestamp": "2026-08-01T00:00:00.000000Z",
    }
    assert burn_manifest_is_accepted(
        burn_manifest,
        exact_valid_from_record,
        verified_policy_chain,
        signed_commit_timestamp="2026-07-01T00:00:00.000000Z",
    )
    assert not burn_manifest_is_accepted(
        burn_manifest,
        exact_valid_until_record,
        verified_policy_chain,
        signed_commit_timestamp="2026-08-01T00:00:00.000000Z",
    )
    for rejected_timestamp in (
        "2026-07-26T22:44:59Z",
        "2026-07-26T22:44:59.000Z",
        "2026-07-26T15:44:59.000000-07:00",
        "2026-06-30T23:59:59.999999Z",
    ):
        assert not burn_manifest_is_accepted(
            burn_manifest,
            {
                **manifest_validation_store_record,
                "commit_timestamp": rejected_timestamp,
            },
            verified_policy_chain,
            signed_commit_timestamp="2026-07-26T22:44:59.000000Z",
        )
    attacker_root_envelope = make_burn_manifest_envelope(
        burn_manifest_preimage,
        private_scalar=2,
        nonce=31,
    )
    assert not burn_manifest_is_accepted(
        attacker_root_envelope,
        manifest_validation_store_record,
        verified_policy_chain,
    )
    assert not burn_manifest_is_accepted(
        burn_manifest,
        manifest_validation_store_record,
        verified_policy_chain,
        requested_manifest_purpose="ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
    )
    assert not burn_manifest_is_accepted(
        burn_manifest,
        manifest_validation_store_record,
        verified_policy_chain,
        requested_manifest_purpose="OUTCOME_SIGNING",
    )
    for rejected_burn_manifest in (
        {
            **burn_manifest_preimage,
            "schema_version": "WrongReceiptBurnManifestPreimage/v1",
        },
        {**burn_manifest_preimage, "manifest_id": ""},
        {**burn_manifest_preimage, "authority_id": ""},
        {**burn_manifest_preimage, "trust_root_id": "attacker-root"},
        {**burn_manifest_preimage, "manifest_sequence": 6},
        {
            **burn_manifest_preimage,
            "previous_burn_verification_manifest_hash": "sha256:" + "0" * 64,
        },
        {**burn_manifest_preimage, "key_purpose": "OUTCOME_SIGNING"},
        {**burn_manifest_preimage, "signature_algorithm": "ED25519"},
        {**burn_manifest_preimage, "signing_key_id": "attacker-key"},
        {**burn_manifest_preimage, "public_key_spki_der_b64u": "AA"},
        {**burn_manifest_preimage, "public_key_spki_sha256": "sha256:" + "0" * 64},
        {**burn_manifest_preimage, "valid_from": "2026-07-27T00:00:00Z"},
        {**burn_manifest_preimage, "valid_until": "2026-07-26T00:00:00Z"},
        {
            **burn_manifest_preimage,
            "revocation_snapshot_hash": "sha256:" + "0" * 64,
        },
    ):
        assert not burn_manifest_is_accepted(
            make_burn_manifest_envelope(rejected_burn_manifest, nonce=37),
            manifest_validation_store_record,
        verified_policy_chain,
        )
    malformed_burn_snapshots = (
        {**burn_revocation_snapshot, "unknown": True},
        {**burn_revocation_snapshot, "snapshot_sequence": "5"},
        {
            **burn_revocation_snapshot,
            "issued_at": "2026-07-01T00:00:00+00:00",
        },
        {
            **burn_revocation_snapshot,
            "revoked_burn_signing_key_ids": ["z-key", "a-key"],
        },
        {
            **burn_revocation_snapshot,
            "revoked_burn_signing_key_ids": ["a-key", "a-key"],
        },
        {
            **burn_revocation_snapshot,
            "revoked_burn_verification_manifest_hashes": ["not-a-digest"],
        },
    )
    for nonce, malformed_burn_snapshot in enumerate(
        malformed_burn_snapshots,
        start=43,
    ):
        malformed_burn_preimage = {
            **burn_manifest_preimage,
            "revocation_snapshot": malformed_burn_snapshot,
            "revocation_snapshot_hash": domain_hash(
                "acgs.questionnaire.receipt-burn-revocation-snapshot/v1",
                vector_jcs(malformed_burn_snapshot),
            ),
        }
        assert not burn_manifest_is_accepted(
            make_burn_manifest_envelope(
                malformed_burn_preimage,
                nonce=nonce,
            ),
            manifest_validation_store_record,
        verified_policy_chain,
        )

    revoked_burn_snapshot = {
        **burn_revocation_snapshot,
        "snapshot_sequence": 6,
        "revoked_burn_signing_key_ids": ["receipt-burn-key-1"],
    }
    revoked_burn_manifest = {
        **burn_manifest_preimage,
        "revocation_snapshot": revoked_burn_snapshot,
        "revocation_snapshot_hash": domain_hash(
            "acgs.questionnaire.receipt-burn-revocation-snapshot/v1",
            vector_jcs(revoked_burn_snapshot),
        ),
    }
    revoked_burn_hash = domain_hash(
        "acgs.questionnaire.receipt-burn-verification-manifest/v1",
        vector_jcs(revoked_burn_manifest),
    )
    revoked_burn_signature = _p256_sign(
        b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
        + revoked_burn_hash.encode("ascii"),
        1,
        29,
    )
    assert _p256_verify(
        b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
        + revoked_burn_hash.encode("ascii"),
        revoked_burn_signature,
        1,
    )
    revoked_burn_envelope = make_burn_manifest_envelope(
        revoked_burn_manifest,
        nonce=29,
    )
    assert not burn_manifest_is_accepted(
        revoked_burn_envelope,
        manifest_validation_store_record,
        verified_policy_chain,
    )
    bad_manifest_signature = burn_manifest_root_signature_raw[:-1] + bytes(
        [burn_manifest_root_signature_raw[-1] ^ 1]
    )
    bad_manifest_envelope = {
        **burn_manifest,
        "root_signature": base64.urlsafe_b64encode(bad_manifest_signature)
        .rstrip(b"=")
        .decode(),
    }
    assert not burn_manifest_is_accepted(
        bad_manifest_envelope,
        manifest_validation_store_record,
        verified_policy_chain,
    )
    for malformed_burn_envelope in (
        {
            key: value
            for key, value in burn_manifest.items()
            if key != "root_signature"
        },
        {**burn_manifest, "unknown": True},
        {
            **burn_manifest,
            "root_signature": burn_manifest["root_signature"] + "=",
        },
    ):
        assert not burn_manifest_is_accepted(
            malformed_burn_envelope,
            manifest_validation_store_record,
            verified_policy_chain,
        )

    manifest_head = {"sequence": 6, "hash": "GENESIS"}
    manifest_acceptances: dict[int, dict[str, object]] = {}
    burn_manifest_append_lock = threading.Lock()

    def append_burn_manifest(envelope: object) -> bool:
        if type(envelope) is not dict or not _is_closed_json_value(envelope):
            return False
        preimage = envelope.get("preimage")
        if type(preimage) is not dict:
            return False
        with burn_manifest_append_lock:
            expected_sequence = int(manifest_head["sequence"]) + 1
            expected_predecessor = str(manifest_head["hash"])
        transaction_timestamp = "2026-07-26T22:44:58.000000Z"
        transaction_validation_record = {
            "schema_version": "ReceiptBurnStoreRecordPreimage/v1",
            "commit_timestamp": transaction_timestamp,
        }
        if not burn_manifest_is_accepted(
            envelope,
            transaction_validation_record,
            verified_policy_chain,
            expected_sequence=expected_sequence,
            expected_predecessor=expected_predecessor,
            signed_commit_timestamp=transaction_timestamp,
        ):
            return False
        candidate_hash = _safe_domain_hash(
            "acgs.questionnaire.receipt-burn-verification-manifest/v1",
            preimage,
        )
        if candidate_hash is None:
            return False
        acceptance = {
            "trust_root_id": preimage["trust_root_id"],
            "trust_root_version": preimage["trust_root_version"],
            "authority_id": preimage["authority_id"],
            "manifest_sequence": expected_sequence,
            "previous_burn_verification_manifest_hash": expected_predecessor,
            "burn_verification_manifest_hash": candidate_hash,
            "accepted_at": transaction_timestamp,
            "store_version": expected_sequence,
        }
        with burn_manifest_append_lock:
            if (
                manifest_head["sequence"] != expected_sequence - 1
                or manifest_head["hash"] != expected_predecessor
                or expected_sequence in manifest_acceptances
            ):
                return False
            manifest_acceptances[expected_sequence] = acceptance
            manifest_head.update(
                sequence=expected_sequence,
                hash=candidate_hash,
            )
            assert manifest_acceptances[expected_sequence] == acceptance
            return True

    for malformed_append in (None, [], "invalid", 7):
        head_before = dict(manifest_head)
        acceptances_before = dict(manifest_acceptances)
        assert not append_burn_manifest(malformed_append)
        assert manifest_head == head_before
        assert manifest_acceptances == acceptances_before
    assert append_burn_manifest(burn_manifest)
    sequence_8_preimage = {
        **burn_manifest_preimage,
        "manifest_id": "receipt-burn-manifest-2",
        "manifest_sequence": 8,
        "previous_burn_verification_manifest_hash": burn_manifest_hash,
    }
    sequence_8_hash = domain_hash(
        "acgs.questionnaire.receipt-burn-verification-manifest/v1",
        vector_jcs(sequence_8_preimage),
    )
    sequence_8_envelope = make_burn_manifest_envelope(
        sequence_8_preimage,
        nonce=13,
    )
    assert append_burn_manifest(sequence_8_envelope)
    assert not append_burn_manifest(burn_manifest)
    fork_a_preimage = {
        **burn_manifest_preimage,
        "manifest_id": "receipt-burn-manifest-3a",
        "manifest_sequence": 9,
        "previous_burn_verification_manifest_hash": sequence_8_hash,
    }
    fork_b_preimage = {**fork_a_preimage, "manifest_id": "receipt-burn-manifest-3b"}
    fork_a_hash = domain_hash(
        "acgs.questionnaire.receipt-burn-verification-manifest/v1",
        vector_jcs(fork_a_preimage),
    )
    fork_a_signature = _p256_sign(
        b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
        + fork_a_hash.encode("ascii"),
        1,
        17,
    )
    fork_a_envelope = make_burn_manifest_envelope(fork_a_preimage, nonce=17)
    fork_b_envelope = make_burn_manifest_envelope(fork_b_preimage, nonce=19)
    assert append_burn_manifest(fork_a_envelope)
    assert not append_burn_manifest(fork_b_envelope)
    saved_manifest_head = dict(manifest_head)
    saved_manifest_acceptances = dict(manifest_acceptances)
    sequence_10_base = {
        **burn_manifest_preimage,
        "manifest_sequence": 10,
        "valid_from": "2026-07-26T22:44:58Z",
        "previous_burn_verification_manifest_hash": fork_a_hash,
    }
    concurrent_burn_envelopes = (
        make_burn_manifest_envelope(
            {**sequence_10_base, "manifest_id": "receipt-burn-manifest-4a"},
            nonce=53,
        ),
        make_burn_manifest_envelope(
            {**sequence_10_base, "manifest_id": "receipt-burn-manifest-4b"},
            nonce=59,
        ),
    )
    burn_append_barrier = threading.Barrier(2)
    concurrent_burn_results: list[bool] = []

    def concurrent_burn_append(envelope: dict[str, object]) -> None:
        burn_append_barrier.wait()
        concurrent_burn_results.append(append_burn_manifest(envelope))

    burn_threads = [
        threading.Thread(target=concurrent_burn_append, args=(envelope,))
        for envelope in concurrent_burn_envelopes
    ]
    for thread in burn_threads:
        thread.start()
    for thread in burn_threads:
        thread.join()
    assert sorted(concurrent_burn_results) == [False, True]
    assert manifest_acceptances[10]["accepted_at"] == (
        "2026-07-26T22:44:58.000000Z"
    )
    assert parse_utc_seconds(sequence_10_base["valid_from"]) == (
        parse_utc_microseconds(manifest_acceptances[10]["accepted_at"])
    )
    with burn_manifest_append_lock:
        manifest_head.clear()
        manifest_head.update(saved_manifest_head)
        manifest_acceptances.clear()
        manifest_acceptances.update(saved_manifest_acceptances)

    for revoked_member, nonce, snapshot_sequence in (
        ("signing_key_id", 31, 5),
        ("manifest_hash", 37, 6),
        ("root_signing_key_id", 41, 7),
    ):
        revoked_root_snapshot = {
            **revocation_snapshot,
            "snapshot_sequence": snapshot_sequence,
            "revoked_signing_key_ids": (
                ["receipt-burn-key-1"]
                if revoked_member == "signing_key_id"
                else (
                    ["assembly-root-key-1"]
                    if revoked_member == "root_signing_key_id"
                    else []
                )
            ),
            "revoked_verification_manifest_hashes": (
                [fork_a_hash] if revoked_member == "manifest_hash" else []
            ),
        }
        revoked_root_snapshot_hash = domain_hash(
            "acgs.questionnaire.assembly-revocation-snapshot/v1",
            vector_jcs(revoked_root_snapshot),
        )
        independently_resigned = _p256_sign(
            b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
            + fork_a_hash.encode("ascii"),
            1,
            nonce,
        )
        assert _p256_verify(
            b"acgs.questionnaire.receipt-burn-verification-manifest-signature/v1\0"
            + fork_a_hash.encode("ascii"),
            independently_resigned,
            1,
        )
        revoked_trust_preimage = {
            **assembly_trust_preimage,
            "revocation_snapshot": revoked_root_snapshot,
            "revocation_snapshot_hash": revoked_root_snapshot_hash,
        }
        revoked_trust_hash = domain_hash(
            "acgs.questionnaire.assembly-verification-trust/v1",
            vector_jcs(revoked_trust_preimage),
        )
        revoked_trust_manifest = {
            "schema_version": "AssemblyVerificationTrustManifest/v1",
            "preimage": revoked_trust_preimage,
            "assembly_verification_trust_manifest_hash": revoked_trust_hash,
        }
        verified_policy_chain.clear()
        verified_policy_chain.update(
            make_burn_policy_chain(revoked_trust_manifest)
        )
        independently_resigned_envelope = {
            **fork_a_envelope,
            "root_signature": base64.urlsafe_b64encode(
                independently_resigned
            )
            .rstrip(b"=")
            .decode(),
        }
        assert not burn_manifest_is_accepted(
            independently_resigned_envelope,
            manifest_validation_store_record,
        verified_policy_chain,
            expected_sequence=9,
            expected_predecessor=sequence_8_hash,
        )
        verified_policy_chain.clear()
        verified_policy_chain.update(
            make_burn_policy_chain(assembly_trust_manifest)
        )

    for chain_member, field in (
        ("policy_bundle", "assembly_verification_trust_manifest_hash"),
        ("decision_receipt", "policy_hash"),
    ):
        original_member = verified_policy_chain[chain_member]
        assert isinstance(original_member, dict)
        verified_policy_chain[chain_member] = {
            **original_member,
            field: "sha256:" + "0" * 64,
        }
        assert not burn_manifest_is_accepted(
            fork_a_envelope,
            manifest_validation_store_record,
        verified_policy_chain,
            expected_sequence=9,
            expected_predecessor=sequence_8_hash,
        )
        verified_policy_chain[chain_member] = original_member

    current_burn_manifest = {
        "schema_version": "ReceiptBurnVerificationManifest/v1",
        "preimage": fork_a_preimage,
        "burn_verification_manifest_hash": fork_a_hash,
        "root_signature_algorithm": "ECDSA_P256_SHA256",
        "root_signature_encoding": "P1363_BASE64URL_NOPAD",
        "root_signing_key_id": "assembly-root-key-1",
        "root_signature": base64.urlsafe_b64encode(fork_a_signature)
        .rstrip(b"=")
        .decode(),
    }
    assert burn_manifest_is_accepted(
        current_burn_manifest,
        manifest_validation_store_record,
        verified_policy_chain,
        expected_sequence=9,
        expected_predecessor=sequence_8_hash,
        signed_commit_timestamp="2026-07-26T22:44:59.000000Z",
    )
    assert not burn_manifest_is_accepted(
        current_burn_manifest,
        {
            **manifest_validation_store_record,
            "commit_timestamp": "2026-07-26T22:44:58.999999Z",
        },
        verified_policy_chain,
        expected_sequence=9,
        expected_predecessor=sequence_8_hash,
        signed_commit_timestamp="2026-07-26T22:44:59.000000Z",
    )
    head_store_record = {
        "schema_version": "BurnManifestHeadStoreRecordPreimage/v1",
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "authority_id": "receipt-burn-authority-1",
        "store_id": "burn-manifest-head-store-1",
        "accepted_sequence": 9,
        "accepted_manifest_hash": fork_a_hash,
        "predecessor_manifest_hash": sequence_8_hash,
        "transaction_id": "burn-head-txn-9",
        "accepted_at": "2026-07-26T22:44:58.000000Z",
        "store_version": 3,
    }
    head_store_record_hash = domain_hash(
        "acgs.questionnaire.burn-manifest-head-store-record/v1",
        vector_jcs(head_store_record),
    )
    head_preimage = {
        "schema_version": "BurnManifestHeadAcceptancePreimage/v1",
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "authority_id": "receipt-burn-authority-1",
        "store_id": "burn-manifest-head-store-1",
        "accepted_sequence": 9,
        "accepted_manifest_hash": fork_a_hash,
        "predecessor_manifest_hash": sequence_8_hash,
        "transaction_id": "burn-head-txn-9",
        "transaction_timestamp": "2026-07-26T22:44:58.000000Z",
        "read_timestamp": "2026-07-26T22:44:58.000001Z",
        "monotonic_generation": 3,
        "store_record_hash": head_store_record_hash,
        "root_binding_hash": assembly_trust_hash,
        "key_purpose": "BURN_MANIFEST_HEAD_ACCEPTANCE_SIGNING",
        "signing_key_id": "assembly-root-key-1",
    }
    head_acceptance_hash = domain_hash(
        "acgs.questionnaire.burn-manifest-head-acceptance/v1",
        vector_jcs(head_preimage),
    )
    head_signature_message = (
        b"acgs.questionnaire.burn-manifest-head-acceptance-signature/v1\0"
        + head_acceptance_hash.encode("ascii")
    )
    head_signature_raw = _p256_sign(head_signature_message, 1, 23)
    head_proof = {
        "schema_version": "BurnManifestHeadAcceptanceReadbackProof/v1",
        "preimage": head_preimage,
        "head_acceptance_hash": head_acceptance_hash,
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "signature": base64.urlsafe_b64encode(head_signature_raw)
        .rstrip(b"=")
        .decode(),
    }

    def head_proof_is_accepted(
        proof: object,
        persisted_record: object,
        verified_burn_manifest: object,
        policy_chain: object,
    ) -> bool:
        proof_fields = {
            "schema_version",
            "preimage",
            "head_acceptance_hash",
            "signature_algorithm",
            "signature_encoding",
            "signature",
        }
        preimage_fields = {
            "schema_version",
            "trust_root_id",
            "trust_root_version",
            "authority_id",
            "store_id",
            "accepted_sequence",
            "accepted_manifest_hash",
            "predecessor_manifest_hash",
            "transaction_id",
            "transaction_timestamp",
            "read_timestamp",
            "monotonic_generation",
            "store_record_hash",
            "root_binding_hash",
            "key_purpose",
            "signing_key_id",
        }
        store_fields = {
            "schema_version",
            "trust_root_id",
            "trust_root_version",
            "authority_id",
            "store_id",
            "accepted_sequence",
            "accepted_manifest_hash",
            "predecessor_manifest_hash",
            "transaction_id",
            "accepted_at",
            "store_version",
        }
        if not all(
            type(value) is dict
            for value in (
                proof,
                persisted_record,
                verified_burn_manifest,
                policy_chain,
            )
        ):
            return False
        if not all(
            _is_closed_json_value(value)
            for value in (
                proof,
                persisted_record,
                verified_burn_manifest,
                policy_chain,
            )
        ):
            return False
        candidate = proof.get("preimage")
        if (
            set(proof) != proof_fields
            or type(candidate) is not dict
            or set(candidate) != preimage_fields
            or set(persisted_record) != store_fields
        ):
            return False
        nonempty_fields = (
            "trust_root_id",
            "authority_id",
            "store_id",
            "transaction_id",
            "key_purpose",
            "signing_key_id",
        )
        if any(
            type(candidate[field]) is not str or not candidate[field]
            for field in nonempty_fields
        ):
            return False
        if any(
            type(persisted_record[field]) is not str
            or not persisted_record[field]
            for field in ("trust_root_id", "authority_id", "store_id", "transaction_id")
        ):
            return False
        if any(
            type(candidate[field]) is not int or candidate[field] < 0
            for field in ("trust_root_version", "accepted_sequence")
        ) or any(
            type(candidate[field]) is not int or candidate[field] <= 0
            for field in ("monotonic_generation",)
        ):
            return False
        if any(
            type(persisted_record[field]) is not int or persisted_record[field] < 0
            for field in ("trust_root_version", "accepted_sequence")
        ) or type(persisted_record["store_version"]) is not int or persisted_record[
            "store_version"
        ] <= 0:
            return False
        if type(policy_chain) is not dict:
            return False
        trust = validate_verified_assembly_trust_chain(
            policy_chain,
            persisted_record.get("accepted_at"),
        )
        burn_preimage = verified_burn_manifest.get("preimage")
        if (
            trust is None
            or type(burn_preimage) is not dict
            or not burn_manifest_is_accepted(
                verified_burn_manifest,
                {
                    "schema_version": "ReceiptBurnStoreRecordPreimage/v1",
                    "commit_timestamp": persisted_record["accepted_at"],
                },
                expected_sequence=persisted_record["accepted_sequence"],
                expected_predecessor=persisted_record[
                    "predecessor_manifest_hash"
                ],
                policy_chain=policy_chain,
            )
        ):
            return False
        signature = proof.get("signature")
        if (
            type(signature) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None
            or "=" in signature
        ):
            return False
        try:
            signature_bytes = base64.urlsafe_b64decode(
                signature + "=" * (-len(signature) % 4)
            )
            if (
                base64.urlsafe_b64encode(signature_bytes)
                .rstrip(b"=")
                .decode()
                != signature
            ):
                return False
            transaction_time = parse_utc_microseconds(
                candidate["transaction_timestamp"]
            )
            read_time = parse_utc_microseconds(candidate["read_timestamp"])
            accepted_at = parse_utc_microseconds(persisted_record["accepted_at"])
            root_valid_from = parse_utc_seconds(trust["valid_from"])
            root_valid_until = parse_utc_seconds(trust["valid_until"])
            root_spki = _canonical_b64u(
                trust["root_public_key_spki_der_b64u"]
            )
        except (KeyError, TypeError, ValueError):
            return False
        candidate_hash = _safe_domain_hash(
            "acgs.questionnaire.burn-manifest-head-acceptance/v1",
            candidate,
        )
        persisted_hash = _safe_domain_hash(
            "acgs.questionnaire.burn-manifest-head-store-record/v1",
            persisted_record,
        )
        if candidate_hash is None or persisted_hash is None:
            return False
        return bool(
            proof["schema_version"]
            == "BurnManifestHeadAcceptanceReadbackProof/v1"
            and proof["head_acceptance_hash"] == candidate_hash
            and proof["signature_algorithm"] == "ECDSA_P256_SHA256"
            and proof["signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and candidate["schema_version"]
            == "BurnManifestHeadAcceptancePreimage/v1"
            and persisted_record["schema_version"]
            == "BurnManifestHeadStoreRecordPreimage/v1"
            and candidate["store_record_hash"] == persisted_hash
            and candidate["trust_root_id"]
            == persisted_record["trust_root_id"]
            == trust["trust_root_id"]
            and candidate["trust_root_version"]
            == persisted_record["trust_root_version"]
            == trust["trust_root_version"]
            and candidate["authority_id"] == persisted_record["authority_id"]
            and candidate["store_id"] == persisted_record["store_id"]
            and candidate["accepted_sequence"]
            == persisted_record["accepted_sequence"]
            == burn_preimage["manifest_sequence"]
            and candidate["accepted_manifest_hash"]
            == persisted_record["accepted_manifest_hash"]
            == verified_burn_manifest["burn_verification_manifest_hash"]
            and candidate["predecessor_manifest_hash"]
            == persisted_record["predecessor_manifest_hash"]
            == burn_preimage["previous_burn_verification_manifest_hash"]
            and candidate["transaction_id"] == persisted_record["transaction_id"]
            and candidate["transaction_timestamp"]
            == persisted_record["accepted_at"]
            and transaction_time == accepted_at <= read_time
            and candidate["monotonic_generation"]
            == persisted_record["store_version"]
            and candidate["root_binding_hash"]
            == _safe_domain_hash(
                "acgs.questionnaire.assembly-verification-trust/v1",
                trust,
            )
            and candidate["key_purpose"]
            == trust["head_acceptance_key_purpose"]
            and candidate["signing_key_id"]
            == trust["root_signing_key_id"]
            and candidate["accepted_manifest_hash"]
            not in trust["revocation_snapshot"][
                "revoked_verification_manifest_hashes"
            ]
            and root_valid_from <= transaction_time <= read_time < root_valid_until
            and _safe_p256_verify_spki(
                b"acgs.questionnaire.burn-manifest-head-acceptance-signature/v1\0"
                + candidate_hash.encode("ascii"),
                signature_bytes,
                root_spki,
            )
        )

    assert set(head_store_record) == {
        "schema_version",
        "trust_root_id",
        "trust_root_version",
        "authority_id",
        "store_id",
        "accepted_sequence",
        "accepted_manifest_hash",
        "predecessor_manifest_hash",
        "transaction_id",
        "accepted_at",
        "store_version",
    }
    assert set(head_preimage) == {
        "schema_version",
        "trust_root_id",
        "trust_root_version",
        "authority_id",
        "store_id",
        "accepted_sequence",
        "accepted_manifest_hash",
        "predecessor_manifest_hash",
        "transaction_id",
        "transaction_timestamp",
        "read_timestamp",
        "monotonic_generation",
        "store_record_hash",
        "root_binding_hash",
        "key_purpose",
        "signing_key_id",
    }
    assert set(head_proof) == {
        "schema_version",
        "preimage",
        "head_acceptance_hash",
        "signature_algorithm",
        "signature_encoding",
        "signature",
    }
    assert head_proof_is_accepted(
        head_proof,
        head_store_record,
        current_burn_manifest,
        verified_policy_chain,
    )
    assert not head_proof_is_accepted(
        head_proof,
        head_store_record,
        current_burn_manifest,
        None,  # type: ignore[arg-type]
    )
    saved_ambient_manifest_head = dict(manifest_head)
    manifest_head.update({"sequence": 404, "hash": "sha256:" + "0" * 64})
    assert head_proof_is_accepted(
        head_proof,
        head_store_record,
        current_burn_manifest,
        verified_policy_chain,
    )
    manifest_head.clear()
    manifest_head.update(saved_ambient_manifest_head)
    bad_head_signature = head_signature_raw[:-1] + bytes(
        [head_signature_raw[-1] ^ 1]
    )
    bad_head_proof = {
        **head_proof,
        "signature": base64.urlsafe_b64encode(bad_head_signature)
        .rstrip(b"=")
        .decode(),
    }
    assert not head_proof_is_accepted(
        bad_head_proof, head_store_record, current_burn_manifest, verified_policy_chain
    )
    for bad_signature in ("", head_proof["signature"] + "=", "!" * 86):
        assert not head_proof_is_accepted(
            {**head_proof, "signature": bad_signature},
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
    for field, replacement in (
        ("accepted_sequence", 7),
        ("accepted_manifest_hash", burn_manifest_hash),
        ("predecessor_manifest_hash", "GENESIS"),
        ("monotonic_generation", 2),
        ("root_binding_hash", "sha256:" + "0" * 64),
        ("key_purpose", "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING"),
    ):
        substituted_head = {
            **head_proof,
            "preimage": {**head_preimage, field: replacement},
        }
        assert not head_proof_is_accepted(
            substituted_head,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )

    for container, field in (
        ("proof", "signature"),
        ("preimage", "authority_id"),
        ("store", "store_id"),
    ):
        if container == "proof":
            malformed_proof = {key: value for key, value in head_proof.items() if key != field}
            assert not head_proof_is_accepted(
                malformed_proof,
                head_store_record,
                current_burn_manifest,
                verified_policy_chain,
            )
            assert not head_proof_is_accepted(
                {**head_proof, "unknown": True},
                head_store_record,
                current_burn_manifest,
                verified_policy_chain,
            )
        elif container == "preimage":
            missing_preimage = {
                key: value for key, value in head_preimage.items() if key != field
            }
            assert not head_proof_is_accepted(
                {**head_proof, "preimage": missing_preimage},
                head_store_record,
                current_burn_manifest,
                verified_policy_chain,
            )
            assert not head_proof_is_accepted(
                {**head_proof, "preimage": {**head_preimage, "unknown": True}},
                head_store_record,
                current_burn_manifest,
                verified_policy_chain,
            )
        else:
            missing_store = {
                key: value for key, value in head_store_record.items() if key != field
            }
            assert not head_proof_is_accepted(
                head_proof,
                missing_store,
                current_burn_manifest,
                verified_policy_chain,
            )
            assert not head_proof_is_accepted(
                head_proof,
                {**head_store_record, "unknown": True},
                current_burn_manifest,
                verified_policy_chain,
            )
    for field, replacement in (
        ("trust_root_id", ""),
        ("trust_root_version", "2"),
        ("authority_id", ""),
        ("store_id", ""),
        ("accepted_sequence", "9"),
        ("transaction_id", ""),
        ("monotonic_generation", 0),
    ):
        assert not head_proof_is_accepted(
            {
                **head_proof,
                "preimage": {**head_preimage, field: replacement},
            },
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
    for field, replacement in (
        ("schema_version", "WrongStoreRecord/v1"),
        ("trust_root_id", "wrong-root"),
        ("trust_root_version", 3),
        ("authority_id", "wrong-authority"),
        ("store_id", "wrong-store"),
        ("accepted_sequence", 8),
        ("accepted_manifest_hash", burn_manifest_hash),
        ("predecessor_manifest_hash", "GENESIS"),
        ("transaction_id", "wrong-transaction"),
        ("accepted_at", "2026-07-26T22:44:58.000001Z"),
        ("store_version", 2),
    ):
        assert not head_proof_is_accepted(
            head_proof,
            {**head_store_record, field: replacement},
            current_burn_manifest,
            verified_policy_chain,
        )
    assert not head_proof_is_accepted(
        {
            **head_proof,
            "preimage": {
                **head_preimage,
                "store_record_hash": "sha256:" + "0" * 64,
            },
        },
        head_store_record,
        current_burn_manifest,
        verified_policy_chain,
    )

    policy_bundle_preimage = {
        "schema_version": "QuestionnairePolicyBundlePreimage/v1",
        "policy_bundle_id": "questionnaire-default",
        "decision_policy_artifact_hash": domain_hash(
            "acgs.questionnaire.decision-policy-artifact/v1",
            b'{"default":"DENY"}',
        ),
        "registry_verification_key_manifest_hash": key_manifest_hash,
        "receipt_verification_key_manifest_hash": receipt_key_manifest_hash,
        "assembly_verification_trust_manifest_hash": assembly_trust_hash,
        "burn_verification_manifest_hash": fork_a_hash,
        "burn_manifest_head_acceptance_hash": head_acceptance_hash,
    }
    policy_hash = "questionnaire-policy/" + hashlib.sha256(
        b"acgs.questionnaire.policy-bundle/v1\0"
        + vector_jcs(policy_bundle_preimage)
    ).hexdigest()
    policy_bundle = {
        "schema_version": "QuestionnairePolicyBundle/v1",
        "policy_bundle_id": policy_bundle_preimage["policy_bundle_id"],
        "policy_version": policy_hash,
        "decision_policy_artifact_hash": (
            policy_bundle_preimage["decision_policy_artifact_hash"]
        ),
        "registry_verification_key_manifest_hash": key_manifest_hash,
        "receipt_verification_key_manifest_hash": receipt_key_manifest_hash,
        "assembly_verification_trust_manifest_hash": assembly_trust_hash,
        "burn_verification_manifest_hash": fork_a_hash,
        "burn_manifest_head_acceptance_hash": head_acceptance_hash,
    }
    assert set(policy_bundle_preimage) == {
        "schema_version",
        "policy_bundle_id",
        "decision_policy_artifact_hash",
        "registry_verification_key_manifest_hash",
        "receipt_verification_key_manifest_hash",
        "assembly_verification_trust_manifest_hash",
        "burn_verification_manifest_hash",
        "burn_manifest_head_acceptance_hash",
    }
    assert set(policy_bundle) == {
        "schema_version",
        "policy_bundle_id",
        "policy_version",
        "decision_policy_artifact_hash",
        "registry_verification_key_manifest_hash",
        "receipt_verification_key_manifest_hash",
        "assembly_verification_trust_manifest_hash",
        "burn_verification_manifest_hash",
        "burn_manifest_head_acceptance_hash",
    }
    policy_archive_preimage = {
        "schema_version": "QuestionnairePolicyArchiveAcceptancePreimage/v1",
        "purpose": "QUESTIONNAIRE_POLICY_BUNDLE_SIGNING",
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "policy_bundle_id": policy_bundle["policy_bundle_id"],
        "policy_version": policy_bundle["policy_version"],
        "receipt_verification_key_manifest_hash": receipt_key_manifest_hash,
        "accepted_at": "2026-07-26T22:45:00Z",
    }
    policy_archive_hash = domain_hash(
        "acgs.questionnaire.policy-archive-acceptance/v1",
        vector_jcs(policy_archive_preimage),
    )
    policy_archive_signature = _p256_sign(
        b"acgs.questionnaire.policy-archive-acceptance-signature/v1\0"
        + policy_archive_hash.encode("ascii"),
        1,
        29,
    )
    policy_archive_acceptance = {
        "schema_version": "QuestionnairePolicyArchiveAcceptance/v1",
        "preimage": policy_archive_preimage,
        "acceptance_hash": policy_archive_hash,
        "signature_algorithm": "ECDSA_P256_SHA256_RAW_RS_LOW_S",
        "signature_b64u": base64.urlsafe_b64encode(
            policy_archive_signature
        ).rstrip(b"=").decode(),
    }
    assembly_manifest_head_store_record = {
        "schema_version": "AssemblyManifestHeadStoreRecordPreimage/v1",
        "trust_root_id": "assembly-root-1",
        "manifest_id": "assembly-manifest-1",
        "manifest_sequence": 7,
        "verification_manifest_hash": "sha256:" + "5" * 64,
        "previous_verification_manifest_hash": "sha256:" + "8" * 64,
        "authority_id": "assembly-authority-1",
        "signing_key_id": "assembly-key-1",
        "monotonic_generation": 1,
        "accepted_at": "2026-07-26T22:45:00Z",
    }
    assembly_manifest_head_store_record_hash = domain_hash(
        "acgs.questionnaire.assembly-manifest-head-store-record/v1",
        vector_jcs(assembly_manifest_head_store_record),
    )
    assembly_manifest_head_proof_preimage = {
        "schema_version": "AssemblyManifestHeadReadbackProofPreimage/v1",
        "store_record_hash": assembly_manifest_head_store_record_hash,
        **{
            field: assembly_manifest_head_store_record[field]
            for field in assembly_manifest_head_store_record
            if field != "schema_version"
        },
    }
    assembly_manifest_head_proof_hash = domain_hash(
        "acgs.questionnaire.assembly-manifest-head-readback-proof/v1",
        vector_jcs(assembly_manifest_head_proof_preimage),
    )
    assembly_manifest_head_proof_signature = _p256_sign(
        b"acgs.questionnaire.assembly-manifest-head-readback/v1\0"
        + assembly_manifest_head_proof_hash.encode("ascii"),
        1,
        43,
    )
    assembly_manifest_head_readback_proof = {
        "schema_version": "AssemblyManifestHeadReadbackProof/v1",
        "preimage": assembly_manifest_head_proof_preimage,
        "proof_hash": assembly_manifest_head_proof_hash,
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "root_signing_key_id": "assembly-root-key-1",
        "key_purpose": "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
        "signature": base64.urlsafe_b64encode(
            assembly_manifest_head_proof_signature
        )
        .rstrip(b"=")
        .decode(),
    }
    assert _p256_verify(
        b"acgs.questionnaire.assembly-manifest-head-readback/v1\0"
        + assembly_manifest_head_proof_hash.encode("ascii"),
        assembly_manifest_head_proof_signature,
        1,
    )
    assembly_head_policy_chain = {
        "policy_bundle_preimage": policy_bundle_preimage,
        "policy_bundle": policy_bundle,
        "decision_receipt": {
            "policy_bundle_id": policy_bundle["policy_bundle_id"],
            "policy_version": policy_bundle["policy_version"],
            "policy_hash": policy_bundle["policy_version"],
        },
        "assembly_trust_manifest": assembly_trust_manifest,
    }

    def assembly_head_proof_is_accepted(
        proof: object,
        store_record: object,
        policy_chain: object,
    ) -> bool:
        if not all(
            type(value) is dict
            for value in (proof, store_record, policy_chain)
        ):
            return False
        if not all(
            _is_closed_json_value(value)
            for value in (proof, store_record, policy_chain)
        ):
            return False
        proof_fields = {
            "schema_version",
            "preimage",
            "proof_hash",
            "signature_algorithm",
            "signature_encoding",
            "root_signing_key_id",
            "key_purpose",
            "signature",
        }
        store_fields = set(assembly_manifest_head_store_record)
        preimage_fields = set(assembly_manifest_head_proof_preimage)
        preimage = proof.get("preimage")
        if (
            set(proof) != proof_fields
            or set(store_record) != store_fields
            or type(preimage) is not dict
            or set(preimage) != preimage_fields
        ):
            return False
        required_ids = (
            "trust_root_id",
            "manifest_id",
            "authority_id",
            "signing_key_id",
        )
        if any(
            type(store_record[field]) is not str
            or not store_record[field]
            for field in required_ids
        ):
            return False
        if (
            type(store_record["manifest_sequence"]) is not int
            or store_record["manifest_sequence"] < 0
            or type(store_record["monotonic_generation"]) is not int
            or store_record["monotonic_generation"] < 1
            or type(store_record["accepted_at"]) is not str
            or re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                store_record["accepted_at"],
            )
            is None
        ):
            return False
        trust = validate_verified_assembly_trust_chain(
            policy_chain,
            store_record["accepted_at"],
        )
        if trust is None:
            return False
        try:
            root_spki = _canonical_b64u(
                trust["root_public_key_spki_der_b64u"]
            )
            signature = _canonical_b64u(proof["signature"])
        except (KeyError, TypeError, ValueError):
            return False
        store_hash = _safe_domain_hash(
            "acgs.questionnaire.assembly-manifest-head-store-record/v1",
            store_record,
        )
        proof_hash = _safe_domain_hash(
            "acgs.questionnaire.assembly-manifest-head-readback-proof/v1",
            preimage,
        )
        if store_hash is None or proof_hash is None:
            return False
        record_members_match = all(
            preimage[field] == store_record[field]
            for field in store_record
            if field != "schema_version"
        )
        return bool(
            proof["schema_version"]
            == "AssemblyManifestHeadReadbackProof/v1"
            and store_record["schema_version"]
            == "AssemblyManifestHeadStoreRecordPreimage/v1"
            and preimage["schema_version"]
            == "AssemblyManifestHeadReadbackProofPreimage/v1"
            and preimage["store_record_hash"] == store_hash
            and proof["proof_hash"] == proof_hash
            and record_members_match
            and proof["signature_algorithm"] == "ECDSA_P256_SHA256"
            and proof["signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and proof["root_signing_key_id"] == trust["root_signing_key_id"]
            and proof["key_purpose"]
            == "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING"
            and proof["key_purpose"] in trust["authorized_manifest_purposes"]
            and store_record["trust_root_id"] == trust["trust_root_id"]
            and store_record["manifest_sequence"]
            >= trust["min_manifest_sequence"]
            and trust["root_signing_key_id"]
            not in trust["revocation_snapshot"]["revoked_signing_key_ids"]
            and store_record["signing_key_id"]
            not in trust["revocation_snapshot"]["revoked_signing_key_ids"]
            and store_record["verification_manifest_hash"]
            not in trust["revocation_snapshot"][
                "revoked_verification_manifest_hashes"
            ]
            and _safe_p256_verify_spki(
                b"acgs.questionnaire.assembly-manifest-head-readback/v1\0"
                + proof_hash.encode("ascii"),
                signature,
                root_spki,
            )
        )

    registry_key_authority_proof = {
        "schema_version": "RegistryKeyAuthorityProof/v1",
        "questionnaire_policy_bundle": policy_bundle,
        "registry_verification_key_manifest": key_manifest,
        "receipt_verification_key_manifest": receipt_key_manifest,
        "questionnaire_policy_archive_acceptance": policy_archive_acceptance,
        "assembly_verification_trust_manifest": assembly_trust_manifest,
        "receipt_burn_verification_manifest": current_burn_manifest,
        "assembly_manifest_head_store_record": (
            assembly_manifest_head_store_record
        ),
        "assembly_manifest_head_readback_proof": (
            assembly_manifest_head_readback_proof
        ),
        "burn_manifest_head_store_record": head_store_record,
        "burn_manifest_head_acceptance_readback_proof": head_proof,
        "decision_policy_artifact_b64u": "eyJkZWZhdWx0IjoiREVOWSJ9",
    }
    registry_proof_fields = {
        "schema_version",
        "questionnaire_policy_bundle",
        "registry_verification_key_manifest",
        "receipt_verification_key_manifest",
        "questionnaire_policy_archive_acceptance",
        "assembly_verification_trust_manifest",
        "receipt_burn_verification_manifest",
        "assembly_manifest_head_store_record",
        "assembly_manifest_head_readback_proof",
        "burn_manifest_head_store_record",
        "burn_manifest_head_acceptance_readback_proof",
        "decision_policy_artifact_b64u",
    }
    assert set(registry_key_authority_proof) == registry_proof_fields
    receipt_expected_args = {"job_id": "job-1"}
    unsigned_registry_receipt = DecisionReceipt(
        receipt_id="mining-receipt-1",
        request_id="mining-request-1",
        tenant_id="questionnaire-tenant",
        actor="questionnaire-miner",
        proposed_action="questionnaire.mine",
        declared_goal="answer questionnaire",
        execution_boundary="questionnaire-worker",
        policy_bundle_id=assembly_head_policy_chain["decision_receipt"][
            "policy_bundle_id"
        ],
        policy_version=assembly_head_policy_chain["decision_receipt"][
            "policy_version"
        ],
        policy_hash=assembly_head_policy_chain["decision_receipt"]["policy_hash"],
        decision="allow",
        matched_rules=["questionnaire-mining"],
        constraints={"require_receipt": True},
        transformations=[],
        approval_chain_summary={
            "validator_id": "questionnaire-policy",
            "proposer": "questionnaire-miner",
        },
        timestamp="2026-07-26T22:44:58+00:00",
        expires_at="2026-07-26T23:00:00+00:00",
        previous_audit_hash="0" * 64,
        audit_event_hash="1" * 64,
        authority="questionnaire.mine",
        validator_id="questionnaire-policy",
        validator_role="validator",
        argument_hash=ToolCall(
            name="questionnaire.mine",
            actor="questionnaire-miner",
            args=receipt_expected_args,
        ).argument_hash(),
        signature_algorithm="ed25519",
        signing_key_id=receipt_signing_key_id,
    )
    registry_receipt_hash = unsigned_registry_receipt.compute_hash()
    _, receipt_signature = _ed25519_sign(
        receipt_signing_seed,
        registry_receipt_hash.encode("utf-8"),
    )
    delivered_registry_receipt = replace(
        unsigned_registry_receipt,
        receipt_hash=registry_receipt_hash,
        signature=receipt_signature.hex(),
    ).to_dict()
    producer_receipt_reference = {
        "produced_by_receipt_id": delivered_registry_receipt["receipt_id"],
        "policy_hash": delivered_registry_receipt["policy_hash"],
    }

    def registry_key_authority_proof_is_accepted(
        proof: object,
        delivered_receipt: object,
        producer_receipt_reference: object,
    ) -> bool:
        receipt_v1_required_fields = {
            "receipt_id", "request_id", "tenant_id", "actor", "subject",
            "proposed_action", "declared_goal", "execution_boundary",
            "policy_bundle_id", "policy_version", "policy_hash", "decision",
            "matched_rules", "constraints", "transformations",
            "approval_chain_summary", "timestamp", "expires_at", "authority",
            "validator_id", "validator_role", "argument_hash",
            "previous_audit_hash", "audit_event_hash", "signature_algorithm",
            "signing_key_id", "receipt_hash", "signature",
        }
        if not all(
            type(value) is dict
            for value in (proof, delivered_receipt, producer_receipt_reference)
        ) or not all(
            _is_closed_json_value(value)
            for value in (proof, delivered_receipt, producer_receipt_reference)
        ):
            return False
        receipt_fields = set(delivered_receipt)
        if not (
            receipt_fields == receipt_v1_required_fields
            or receipt_fields
            == receipt_v1_required_fields | {"action_tier"}
        ):
            return False
        producer_fields = {"produced_by_receipt_id", "policy_hash"}
        try:
            parsed_receipt = DecisionReceipt.from_dict(delivered_receipt)
            computed_receipt_hash = parsed_receipt.compute_hash()
        except (Exception, MemoryError):
            return False
        if (
            set(proof) != registry_proof_fields
            or proof.get("schema_version") != "RegistryKeyAuthorityProof/v1"
            or set(delivered_receipt) != receipt_fields
            or parsed_receipt.to_dict() != delivered_receipt
            or computed_receipt_hash != parsed_receipt.receipt_hash
            or set(producer_receipt_reference) != producer_fields
            or type(delivered_receipt.get("receipt_id")) is not str
            or not delivered_receipt["receipt_id"]
            or type(
                producer_receipt_reference.get("produced_by_receipt_id")
            ) is not str
            or not producer_receipt_reference["produced_by_receipt_id"]
            or producer_receipt_reference["produced_by_receipt_id"]
            != delivered_receipt["receipt_id"]
            or producer_receipt_reference.get("policy_hash")
            != delivered_receipt.get("policy_hash")
        ):
            return False
        embedded_bundle = proof.get("questionnaire_policy_bundle")
        embedded_key_manifest = proof.get(
            "registry_verification_key_manifest"
        )
        embedded_receipt_key_manifest = proof.get(
            "receipt_verification_key_manifest"
        )
        embedded_policy_archive = proof.get(
            "questionnaire_policy_archive_acceptance"
        )
        embedded_trust_manifest = proof.get(
            "assembly_verification_trust_manifest"
        )
        embedded_burn_manifest = proof.get(
            "receipt_burn_verification_manifest"
        )
        embedded_assembly_store = proof.get(
            "assembly_manifest_head_store_record"
        )
        embedded_assembly_proof = proof.get(
            "assembly_manifest_head_readback_proof"
        )
        embedded_burn_store = proof.get("burn_manifest_head_store_record")
        embedded_burn_proof = proof.get(
            "burn_manifest_head_acceptance_readback_proof"
        )
        artifact_b64u = proof.get("decision_policy_artifact_b64u")
        if not all(
            isinstance(value, dict)
            for value in (
                embedded_bundle,
                embedded_key_manifest,
                embedded_receipt_key_manifest,
                embedded_policy_archive,
                embedded_trust_manifest,
                embedded_burn_manifest,
                embedded_assembly_store,
                embedded_assembly_proof,
                embedded_burn_store,
                embedded_burn_proof,
            )
        ) or not isinstance(artifact_b64u, str):
            return False
        try:
            if (
                not artifact_b64u
                or re.fullmatch(r"[A-Za-z0-9_-]+", artifact_b64u) is None
                or len(artifact_b64u) % 4 == 1
            ):
                return False
            artifact_bytes = base64.urlsafe_b64decode(
                artifact_b64u + "=" * (-len(artifact_b64u) % 4)
            )
            if (
                base64.urlsafe_b64encode(artifact_bytes)
                .rstrip(b"=")
                .decode()
                != artifact_b64u
                or not 1 <= len(artifact_bytes) <= 1_048_576
            ):
                return False
            embedded_key_hash = _safe_domain_hash(
                "acgs.questionnaire.registry-verification-keys/v1",
                embedded_key_manifest,
            )
            receipt_key_fields = {
                "schema_version",
                "manifest_id",
                "key_purpose",
                "key_id",
                "status",
                "signature_algorithm",
                "public_key_b64u",
                "valid_from",
                "valid_until",
                "revoked_key_ids",
            }
            if (
                set(embedded_receipt_key_manifest) != receipt_key_fields
                or embedded_receipt_key_manifest["schema_version"]
                != "ReceiptVerificationKeyManifest/v1"
                or embedded_receipt_key_manifest["key_purpose"]
                != "DECISION_RECEIPT_SIGNING"
                or embedded_receipt_key_manifest["status"] != "ACTIVE"
                or embedded_receipt_key_manifest["signature_algorithm"]
                != "ed25519"
                or not all(
                    isinstance(embedded_receipt_key_manifest[field], str)
                    and embedded_receipt_key_manifest[field]
                    for field in ("manifest_id", "key_id", "public_key_b64u")
                )
                or not isinstance(
                    embedded_receipt_key_manifest["revoked_key_ids"], list
                )
                or embedded_receipt_key_manifest["revoked_key_ids"]
                != sorted(set(embedded_receipt_key_manifest["revoked_key_ids"]))
                or not all(
                    isinstance(key_id, str) and key_id
                    for key_id in embedded_receipt_key_manifest[
                        "revoked_key_ids"
                    ]
                )
            ):
                return False
            receipt_key_bytes = _canonical_b64u(
                embedded_receipt_key_manifest["public_key_b64u"]
            )
            receipt_key_valid_from = parse_utc_seconds(
                embedded_receipt_key_manifest["valid_from"]
            )
            receipt_key_valid_until = parse_utc_seconds(
                embedded_receipt_key_manifest["valid_until"]
            )
            archive_fields = {
                "schema_version", "preimage", "acceptance_hash",
                "signature_algorithm", "signature_b64u",
            }
            archive_preimage_fields = {
                "schema_version", "purpose", "trust_root_id",
                "trust_root_version", "policy_bundle_id", "policy_version",
                "receipt_verification_key_manifest_hash", "accepted_at",
            }
            archive_preimage = embedded_policy_archive.get("preimage")
            if (
                set(embedded_policy_archive) != archive_fields
                or not isinstance(archive_preimage, dict)
                or set(archive_preimage) != archive_preimage_fields
                or archive_preimage["schema_version"]
                != "QuestionnairePolicyArchiveAcceptancePreimage/v1"
                or archive_preimage["purpose"]
                != "QUESTIONNAIRE_POLICY_BUNDLE_SIGNING"
                or archive_preimage["trust_root_id"] != "assembly-root-1"
                or archive_preimage["trust_root_version"] != 2
                or embedded_policy_archive["schema_version"]
                != "QuestionnairePolicyArchiveAcceptance/v1"
                or embedded_policy_archive["signature_algorithm"]
                != "ECDSA_P256_SHA256_RAW_RS_LOW_S"
            ):
                return False
            archive_hash = _safe_domain_hash(
                "acgs.questionnaire.policy-archive-acceptance/v1",
                archive_preimage,
            )
            if embedded_key_hash is None or archive_hash is None:
                return False
            archive_signature = _canonical_b64u(
                embedded_policy_archive["signature_b64u"]
            )
            receipt_verification_time = parse_utc_seconds(
                archive_preimage["accepted_at"]
            )
            if (
                embedded_policy_archive["acceptance_hash"] != archive_hash
                or _safe_domain_bytes_hash(
                    "acgs.questionnaire.p256-spki/v1", root_spki
                ) != root_spki_hash
                or not _safe_p256_verify_spki(
                    b"acgs.questionnaire.policy-archive-acceptance-signature/v1\0"
                    + archive_hash.encode("ascii"),
                    archive_signature,
                    root_spki,
                )
                or len(receipt_key_bytes) != 32
                or not receipt_key_valid_from
                <= receipt_verification_time
                < receipt_key_valid_until
                or embedded_receipt_key_manifest["key_id"]
                in embedded_receipt_key_manifest["revoked_key_ids"]
            ):
                return False
            embedded_receipt_key_hash = _safe_domain_hash(
                "acgs.questionnaire.receipt-verification-keys/v1",
                embedded_receipt_key_manifest,
            )
            embedded_trust_preimage = embedded_trust_manifest["preimage"]
            embedded_trust_hash = _safe_domain_hash(
                "acgs.questionnaire.assembly-verification-trust/v1",
                embedded_trust_preimage,
            )
            embedded_burn_hash = embedded_burn_manifest[
                "burn_verification_manifest_hash"
            ]
            embedded_head_hash = embedded_burn_proof[
                "head_acceptance_hash"
            ]
            embedded_burn_validation_record = {
                "schema_version": "ReceiptBurnStoreRecordPreimage/v1",
                "commit_timestamp": embedded_burn_store["accepted_at"],
            }
            embedded_burn_sequence = embedded_burn_store[
                "accepted_sequence"
            ]
            embedded_burn_predecessor = embedded_burn_store[
                "predecessor_manifest_hash"
            ]
            reconstructed_policy_preimage = {
                "schema_version": "QuestionnairePolicyBundlePreimage/v1",
                "policy_bundle_id": embedded_bundle["policy_bundle_id"],
                "decision_policy_artifact_hash": _safe_domain_bytes_hash(
                    "acgs.questionnaire.decision-policy-artifact/v1",
                    artifact_bytes,
                ),
                "registry_verification_key_manifest_hash": (
                    embedded_key_hash
                ),
                "receipt_verification_key_manifest_hash": (
                    embedded_receipt_key_hash
                ),
                "assembly_verification_trust_manifest_hash": (
                    embedded_trust_hash
                ),
                "burn_verification_manifest_hash": embedded_burn_hash,
                "burn_manifest_head_acceptance_hash": embedded_head_hash,
            }
            reconstructed_policy_hash = _safe_domain_hash(
                "acgs.questionnaire.policy-bundle/v1",
                reconstructed_policy_preimage,
            )
            reconstructed_policy_version = (
                None
                if reconstructed_policy_hash is None
                else "questionnaire-policy/"
                + reconstructed_policy_hash.removeprefix("sha256:")
            )
            reconstructed_bundle = {
                "schema_version": "QuestionnairePolicyBundle/v1",
                "policy_bundle_id": reconstructed_policy_preimage[
                    "policy_bundle_id"
                ],
                "policy_version": reconstructed_policy_version,
                **{
                    field: reconstructed_policy_preimage[field]
                    for field in reconstructed_policy_preimage
                    if field not in {"schema_version", "policy_bundle_id"}
                },
            }
        except (Exception, MemoryError):
            return False
        if (
            embedded_key_hash is None
            or archive_hash is None
            or embedded_receipt_key_hash is None
            or embedded_trust_hash is None
            or reconstructed_policy_preimage[
                "decision_policy_artifact_hash"
            ]
            is None
            or reconstructed_policy_version is None
            or embedded_receipt_key_hash
            != embedded_bundle["receipt_verification_key_manifest_hash"]
            or parsed_receipt.signing_key_id
            != embedded_receipt_key_manifest["key_id"]
        ):
            return False

        class BoundReceiptVerifier:
            algorithm = "ed25519"
            key_id = embedded_receipt_key_manifest["key_id"]

            def verify(self, payload: bytes, signature: str) -> bool:
                try:
                    signature_bytes = bytes.fromhex(signature)
                except (TypeError, ValueError):
                    return False
                return _ed25519_verify(
                    receipt_key_bytes, payload, signature_bytes
                )

        try:
            parsed_receipt.verify(
                expected_tenant_id="questionnaire-tenant",
                expected_execution_boundary="questionnaire-worker",
                expected_audit_hash="1" * 64,
                expected_args=receipt_expected_args,
                expected_action="questionnaire.mine",
                expected_policy_hash=embedded_bundle["policy_version"],
                expected_policy_bundle_id=embedded_bundle[
                    "policy_bundle_id"
                ],
                expected_authority="questionnaire.mine",
                expected_actor="questionnaire-miner",
                verifier={
                    embedded_receipt_key_manifest["key_id"]: (
                        BoundReceiptVerifier()
                    )
                },
                require_signature=True,
                require_expiry=True,
                now_iso=archive_preimage["accepted_at"],
                max_clock_skew_seconds=0,
                tool_tier_registry=ToolTierRegistry.from_dict(
                    {"questionnaire.mine": "explore"}
                ),
            )
        except (ReceiptValidationError, TypeError, ValueError):
            return False
        reconstructed_chain = {
            "policy_bundle_preimage": reconstructed_policy_preimage,
            "policy_bundle": reconstructed_bundle,
            "decision_receipt": delivered_receipt,
            "assembly_trust_manifest": embedded_trust_manifest,
        }
        return bool(
            embedded_bundle == reconstructed_bundle
            and archive_preimage["policy_bundle_id"]
            == reconstructed_bundle["policy_bundle_id"]
            and archive_preimage["policy_version"]
            == reconstructed_bundle["policy_version"]
            and archive_preimage["receipt_verification_key_manifest_hash"]
            == embedded_receipt_key_hash
            and archive_preimage["accepted_at"]
            == embedded_assembly_store.get("accepted_at")
            and delivered_receipt["policy_bundle_id"]
            == embedded_bundle["policy_bundle_id"]
            and delivered_receipt["policy_version"]
            == embedded_bundle["policy_version"]
            and delivered_receipt["policy_hash"]
            == embedded_bundle["policy_version"]
            and registry_key_manifest_is_accepted(
                embedded_key_manifest,
                embedded_assembly_store.get("accepted_at"),
            )
            and embedded_key_hash
            == embedded_bundle["registry_verification_key_manifest_hash"]
            and embedded_trust_manifest.get(
                "assembly_verification_trust_manifest_hash"
            )
            == embedded_trust_hash
            == embedded_bundle[
                "assembly_verification_trust_manifest_hash"
            ]
            and validate_verified_assembly_trust_chain(
                reconstructed_chain,
                embedded_assembly_store.get("accepted_at"),
            )
            is not None
            and burn_manifest_is_accepted(
                embedded_burn_manifest,
                embedded_burn_validation_record,
                reconstructed_chain,
                expected_sequence=embedded_burn_sequence,
                expected_predecessor=embedded_burn_predecessor,
                signed_commit_timestamp=embedded_burn_store["accepted_at"],
            )
            and embedded_burn_hash
            == embedded_bundle["burn_verification_manifest_hash"]
            and head_proof_is_accepted(
                embedded_burn_proof,
                embedded_burn_store,
                embedded_burn_manifest,
                reconstructed_chain,
            )
            and embedded_head_hash
            == embedded_bundle["burn_manifest_head_acceptance_hash"]
            and assembly_head_proof_is_accepted(
                embedded_assembly_proof,
                embedded_assembly_store,
                reconstructed_chain,
            )
        )

    assert registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        delivered_registry_receipt,
        producer_receipt_reference,
    )

    def signed_receipt_variant(**changes: object) -> dict[str, object]:
        candidate = replace(
            unsigned_registry_receipt,
            **changes,
            receipt_hash="",
            signature="",
        )
        candidate_hash = candidate.compute_hash()
        _, candidate_signature = _ed25519_sign(
            receipt_signing_seed, candidate_hash.encode("utf-8")
        )
        return replace(
            candidate,
            receipt_hash=candidate_hash,
            signature=candidate_signature.hex(),
        ).to_dict()

    explore_receipt = signed_receipt_variant(action_tier="explore")
    assert registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        explore_receipt,
        {
            **producer_receipt_reference,
            "produced_by_receipt_id": explore_receipt["receipt_id"],
        },
    )

    class CanonicalizationHostile:
        pass

    class HostileString(str):
        accesses = 0

        def encode(self, *args: object, **kwargs: object) -> bytes:
            type(self).accesses += 1
            raise AssertionError("str subclass encode must not run")

    class HostileTime(str):
        accesses = 0

        def endswith(self, *args: object, **kwargs: object) -> bool:
            type(self).accesses += 1
            raise AssertionError("timestamp subclass endswith must not run")

    class HostileList(list[object]):
        accesses = 0

        def __iter__(self):  # type: ignore[no-untyped-def]
            type(self).accesses += 1
            raise AssertionError("list subclass iteration must not run")

    class HostileDict(dict[str, object]):
        accesses = 0

        def items(self):  # type: ignore[no-untyped-def]
            type(self).accesses += 1
            raise AssertionError("dict subclass items must not run")

        def get(self, *args: object, **kwargs: object) -> object:
            type(self).accesses += 1
            raise AssertionError("dict subclass get must not run")

    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict
    over_depth: list[object] = []
    depth_cursor = over_depth
    for _ in range(MAX_JSON_DEPTH + 2):
        nested: list[object] = []
        depth_cursor.append(nested)
        depth_cursor = nested
    over_nodes = [0] * (MAX_JSON_NODES + 1)
    over_node_dict = {
        f"key-{index}": 0 for index in range(MAX_JSON_NODES // 2 + 1)
    }
    over_containers = [[] for _ in range(MAX_JSON_CONTAINERS + 1)]
    hostile_json_values: tuple[object, ...] = (
        b"not-json",
        CanonicalizationHostile(),
        HostileString("hostile"),
        HostileList(["hostile"]),
        HostileDict(hostile="value"),
        cyclic_list,
        cyclic_dict,
        over_depth,
        over_nodes,
        over_node_dict,
        over_containers,
        JSON_SAFE_INTEGER_MAX + 1,
        -JSON_SAFE_INTEGER_MAX - 1,
        1.0,
    )
    assert (MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_JSON_CONTAINERS) == (
        32,
        4096,
        1024,
    )
    assert _is_closed_json_value(JSON_SAFE_INTEGER_MAX)
    assert _is_closed_json_value(-JSON_SAFE_INTEGER_MAX)
    assert not _is_closed_json_value(JSON_SAFE_INTEGER_MAX + 1)
    assert not _is_closed_json_value(-JSON_SAFE_INTEGER_MAX - 1)
    assert not _is_closed_json_value(1.0)
    assert _safe_domain_hash(
        "acgs.questionnaire.safe-integer-boundary/v1",
        JSON_SAFE_INTEGER_MAX,
    ) != _safe_domain_hash(
        "acgs.questionnaire.safe-integer-boundary/v1",
        -JSON_SAFE_INTEGER_MAX,
    )
    manifest_head_before_hostile = dict(manifest_head)
    manifest_acceptances_before_hostile = dict(manifest_acceptances)
    for hostile_value in hostile_json_values:
        assert not _is_closed_json_value(hostile_value)
        assert _safe_canonical_jcs(hostile_value) is None
        assert (
            _safe_domain_hash(
                "acgs.questionnaire.hostile-probe/v1",
                hostile_value,
            )
            is None
        )
        hostile_policy_chain = {
            **verified_policy_chain,
            "policy_bundle_preimage": {
                **verified_policy_chain["policy_bundle_preimage"],
                "decision_policy_artifact_hash": hostile_value,
            },
        }
        hostile_burn_envelope = {
            **burn_manifest,
            "preimage": {
                **burn_manifest_preimage,
                "revoked_at": hostile_value,
            },
        }
        hostile_burn_head_proof = {
            **head_proof,
            "preimage": {
                **head_preimage,
                "read_timestamp": hostile_value,
            },
        }
        hostile_assembly_head_proof = {
            **assembly_manifest_head_readback_proof,
            "preimage": {
                **assembly_manifest_head_proof_preimage,
                "authority_id": hostile_value,
            },
        }
        hostile_registry_proof = {
            **registry_key_authority_proof,
            "decision_policy_artifact_b64u": hostile_value,
        }
        assert (
            validate_verified_assembly_trust_chain(
                hostile_policy_chain,
                "2026-07-26T22:44:59.000000Z",
            )
            is None
        )
        assert not burn_manifest_is_accepted(
            hostile_burn_envelope,
            manifest_validation_store_record,
            verified_policy_chain,
        )
        assert not append_burn_manifest(hostile_burn_envelope)
        assert not head_proof_is_accepted(
            hostile_burn_head_proof,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
        assert not assembly_head_proof_is_accepted(
            hostile_assembly_head_proof,
            assembly_manifest_head_store_record,
            assembly_head_policy_chain,
        )
        assert not registry_key_authority_proof_is_accepted(
            hostile_registry_proof,
            delivered_registry_receipt,
            producer_receipt_reference,
        )
        assert manifest_head == manifest_head_before_hostile
        assert manifest_acceptances == manifest_acceptances_before_hostile
    hostile_root_carriers: tuple[object, ...] = (
        HostileString("root"),
        HostileList(["root"]),
        HostileDict(root="value"),
    )
    for hostile_root in hostile_root_carriers:
        assert (
            validate_verified_assembly_trust_chain(
                hostile_root,
                "2026-07-26T22:44:59.000000Z",
            )
            is None
        )
        assert not burn_manifest_is_accepted(
            hostile_root,
            manifest_validation_store_record,
            verified_policy_chain,
        )
        assert not append_burn_manifest(hostile_root)
        assert not head_proof_is_accepted(
            hostile_root,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
        assert not assembly_head_proof_is_accepted(
            hostile_root,
            assembly_manifest_head_store_record,
            assembly_head_policy_chain,
        )
        assert not registry_key_authority_proof_is_accepted(
            hostile_root,
            delivered_registry_receipt,
            producer_receipt_reference,
        )
    hostile_time = HostileTime("2026-07-26T22:44:59.000000Z")
    assert (
        validate_verified_assembly_trust_chain(
            verified_policy_chain,
            hostile_time,
        )
        is None
    )
    assert not burn_manifest_is_accepted(
        burn_manifest,
        {
            **manifest_validation_store_record,
            "commit_timestamp": hostile_time,
        },
        verified_policy_chain,
    )
    assert not head_proof_is_accepted(
        head_proof,
        {**head_store_record, "accepted_at": hostile_time},
        current_burn_manifest,
        verified_policy_chain,
    )
    assert not assembly_head_proof_is_accepted(
        assembly_manifest_head_readback_proof,
        {
            **assembly_manifest_head_store_record,
            "accepted_at": hostile_time,
        },
        assembly_head_policy_chain,
    )
    assert HostileString.accesses == 0
    assert HostileList.accesses == 0
    assert HostileDict.accesses == 0
    assert HostileTime.accesses == 0

    attacker_seed = b"\x02" * 32
    attacker_public_key, _ = _ed25519_sign(attacker_seed, b"")
    attacker_receipt_manifest = {
        **receipt_key_manifest,
        "key_id": "attacker-receipt-key",
        "public_key_b64u": base64.urlsafe_b64encode(
            attacker_public_key
        ).rstrip(b"=").decode(),
    }
    attacker_receipt_manifest_hash = domain_hash(
        "acgs.questionnaire.receipt-verification-keys/v1",
        vector_jcs(attacker_receipt_manifest),
    )
    attacker_policy_preimage = {
        **policy_bundle_preimage,
        "receipt_verification_key_manifest_hash": (
            attacker_receipt_manifest_hash
        ),
    }
    attacker_policy_version = "questionnaire-policy/" + hashlib.sha256(
        b"acgs.questionnaire.policy-bundle/v1\0"
        + vector_jcs(attacker_policy_preimage)
    ).hexdigest()
    attacker_bundle = {
        **policy_bundle,
        "policy_version": attacker_policy_version,
        "receipt_verification_key_manifest_hash": (
            attacker_receipt_manifest_hash
        ),
    }
    attacker_unsigned_receipt = replace(
        unsigned_registry_receipt,
        policy_version=attacker_policy_version,
        policy_hash=attacker_policy_version,
        signing_key_id="attacker-receipt-key",
        receipt_hash="",
        signature="",
    )
    attacker_receipt_hash = attacker_unsigned_receipt.compute_hash()
    _, attacker_receipt_signature = _ed25519_sign(
        attacker_seed, attacker_receipt_hash.encode("utf-8")
    )
    attacker_receipt = replace(
        attacker_unsigned_receipt,
        receipt_hash=attacker_receipt_hash,
        signature=attacker_receipt_signature.hex(),
    ).to_dict()
    assert not registry_key_authority_proof_is_accepted(
        {
            **registry_key_authority_proof,
            "questionnaire_policy_bundle": attacker_bundle,
            "receipt_verification_key_manifest": attacker_receipt_manifest,
        },
        attacker_receipt,
        {
            "produced_by_receipt_id": attacker_receipt["receipt_id"],
            "policy_hash": attacker_policy_version,
        },
    )

    for invalid_index, invalid_receipt in enumerate((
        signed_receipt_variant(decision="deny"),
        signed_receipt_variant(decision="escalate"),
        signed_receipt_variant(proposed_action="questionnaire.other"),
        signed_receipt_variant(
            actor="other-miner",
            approval_chain_summary={
                "validator_id": "questionnaire-policy",
                "proposer": "other-miner",
            },
        ),
        signed_receipt_variant(authority=""),
        signed_receipt_variant(validator_id=""),
        signed_receipt_variant(expires_at="2026-07-26T22:44:59+00:00"),
        signed_receipt_variant(audit_event_hash="3" * 64),
        signed_receipt_variant(execution_boundary="other-worker"),
        signed_receipt_variant(argument_hash="4" * 64),
        signed_receipt_variant(
            receipt_schema_version="gove-zone/decision-receipt/v1"
        ),
        signed_receipt_variant(
            receipt_schema_version="gove-zone/decision-receipt/v2"
        ),
        signed_receipt_variant(signing_key_id="unknown-receipt-key"),
    )):
        assert not registry_key_authority_proof_is_accepted(
            registry_key_authority_proof,
            invalid_receipt,
            {
                **producer_receipt_reference,
                "produced_by_receipt_id": invalid_receipt["receipt_id"],
                "policy_hash": invalid_receipt["policy_hash"],
            },
        ), (invalid_index, invalid_receipt)

    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        {**delivered_registry_receipt, "trust_epoch": 1},
        producer_receipt_reference,
    )

    for invalid_receipt_manifest in (
        {**receipt_key_manifest, "status": "REVOKED"},
        {
            **receipt_key_manifest,
            "revoked_key_ids": [receipt_signing_key_id],
        },
        {**receipt_key_manifest, "key_purpose": "OUTCOME_SIGNING"},
        {**receipt_key_manifest, "key_id": ""},
        {**receipt_key_manifest, "signature_algorithm": "none"},
        {**receipt_key_manifest, "public_key_b64u": "A" * 43},
        {**receipt_key_manifest, "valid_from": "2026-07-27T00:00:00Z"},
        {**receipt_key_manifest, "valid_until": "2026-07-26T22:45:00Z"},
        {**receipt_key_manifest, "revoked_key_ids": ["z", "a"]},
        {**receipt_key_manifest, "unknown": True},
    ):
        assert not registry_key_authority_proof_is_accepted(
            {
                **registry_key_authority_proof,
                "receipt_verification_key_manifest": (
                    invalid_receipt_manifest
                ),
            },
            delivered_registry_receipt,
            producer_receipt_reference,
        )
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        {
            **delivered_registry_receipt,
            "policy_hash": "questionnaire-policy/" + "0" * 64,
        },
        producer_receipt_reference,
    )
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        delivered_registry_receipt,
        {
            **producer_receipt_reference,
            "policy_hash": "questionnaire-policy/" + "0" * 64,
        },
    )
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        {**delivered_registry_receipt, "receipt_id": "same-policy-wrong-id"},
        producer_receipt_reference,
    )
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        delivered_registry_receipt,
        {
            **producer_receipt_reference,
            "produced_by_receipt_id": "same-policy-wrong-id",
        },
    )
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        {**delivered_registry_receipt, "receipt_hash": "0" * 64},
        producer_receipt_reference,
    )
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        {**delivered_registry_receipt, "signature": "00" * 64},
        producer_receipt_reference,
    )
    coordinated_receipt_substitution = {
        **delivered_registry_receipt,
        "receipt_id": "coordinated-substitution",
    }
    assert not registry_key_authority_proof_is_accepted(
        registry_key_authority_proof,
        coordinated_receipt_substitution,
        {
            **producer_receipt_reference,
            "produced_by_receipt_id": "coordinated-substitution",
        },
    )
    for malformed_proof, malformed_receipt, malformed_reference in (
        (None, delivered_registry_receipt, producer_receipt_reference),
        ([], delivered_registry_receipt, producer_receipt_reference),
        (registry_key_authority_proof, None, producer_receipt_reference),
        (registry_key_authority_proof, [], producer_receipt_reference),
        (registry_key_authority_proof, delivered_registry_receipt, None),
        (registry_key_authority_proof, delivered_registry_receipt, []),
    ):
        assert not registry_key_authority_proof_is_accepted(
            malformed_proof,
            malformed_receipt,
            malformed_reference,
        )
    first_registry_key = key_manifest["keys"][0]
    assert isinstance(first_registry_key, dict)
    malformed_registry_manifests = (
        {**key_manifest, "unknown": True},
        {**key_manifest, "keys": list(reversed(key_manifest["keys"]))},
        {**key_manifest, "keys": [first_registry_key, first_registry_key]},
        {
            **key_manifest,
            "keys": [
                {
                    field: value
                    for field, value in first_registry_key.items()
                    if field != "purpose"
                },
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {**first_registry_key, "unknown": True},
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {**first_registry_key, "purpose": "OUTCOME"},
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {**first_registry_key, "status": "PENDING"},
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {**first_registry_key, "signature_alg": "ECDSA"},
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {**first_registry_key, "public_key_b64u": "AA"},
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {
                    **first_registry_key,
                    "not_before": "2026-01-01T00:00:00+00:00",
                },
                *key_manifest["keys"][1:],
            ],
        },
        {
            **key_manifest,
            "keys": [
                {
                    **first_registry_key,
                    "not_after": "2026-07-26T22:45:00Z",
                },
                *key_manifest["keys"][1:],
            ],
        },
    )
    for malformed_registry_manifest in malformed_registry_manifests:
        assert not registry_key_manifest_is_accepted(
            malformed_registry_manifest,
            "2026-07-26T22:45:00Z",
        )
    hostile_registry_inputs = (
        HostileDict(key_manifest),
        {**key_manifest, "keys": HostileList(key_manifest["keys"])},
        {
            **key_manifest,
            "keys": [
                HostileDict(first_registry_key),
                *key_manifest["keys"][1:],
            ],
        },
    )
    registry_state_before_hostile = (
        dict(manifest_head),
        dict(manifest_acceptances),
    )
    for hostile_registry_input in hostile_registry_inputs:
        assert not registry_key_manifest_is_accepted(
            hostile_registry_input,
            "2026-07-26T22:45:00Z",
        )
    hostile_registry_time = HostileTime("2026-07-26T22:45:00Z")
    assert not registry_key_manifest_is_accepted(
        key_manifest,
        hostile_registry_time,
    )
    assert not registry_key_manifest_is_accepted(
        {
            **key_manifest,
            "keys": [
                {**first_registry_key, "not_before": hostile_registry_time},
                *key_manifest["keys"][1:],
            ],
        },
        "2026-07-26T22:45:00Z",
    )
    assert HostileDict.accesses == 0
    assert HostileList.accesses == 0
    assert HostileTime.accesses == 0
    assert (manifest_head, manifest_acceptances) == registry_state_before_hostile
    for authority_member, replacement in (
        (
            "registry_verification_key_manifest",
            {**key_manifest, "manifest_id": "substituted-registry"},
        ),
        (
            "receipt_burn_verification_manifest",
            {
                **current_burn_manifest,
                "root_signature": current_burn_manifest["root_signature"] + "=",
            },
        ),
        (
            "burn_manifest_head_store_record",
            {**head_store_record, "store_version": 2},
        ),
        (
            "burn_manifest_head_acceptance_readback_proof",
            {**head_proof, "signature": head_proof["signature"] + "="},
        ),
        ("decision_policy_artifact_b64u", "QQ"),
    ):
        assert not registry_key_authority_proof_is_accepted(
            {
                **registry_key_authority_proof,
                authority_member: replacement,
            },
            delivered_registry_receipt,
            producer_receipt_reference,
        )

    def sign_assembly_head_record(
        store_record: dict[str, object],
        nonce: int,
    ) -> dict[str, object]:
        store_hash = domain_hash(
            "acgs.questionnaire.assembly-manifest-head-store-record/v1",
            vector_jcs(store_record),
        )
        proof_preimage = {
            "schema_version": "AssemblyManifestHeadReadbackProofPreimage/v1",
            "store_record_hash": store_hash,
            **{
                field: store_record[field]
                for field in store_record
                if field != "schema_version"
            },
        }
        proof_hash = domain_hash(
            "acgs.questionnaire.assembly-manifest-head-readback-proof/v1",
            vector_jcs(proof_preimage),
        )
        signature = _p256_sign(
            b"acgs.questionnaire.assembly-manifest-head-readback/v1\0"
            + proof_hash.encode("ascii"),
            1,
            nonce,
        )
        return {
            "schema_version": "AssemblyManifestHeadReadbackProof/v1",
            "preimage": proof_preimage,
            "proof_hash": proof_hash,
            "signature_algorithm": "ECDSA_P256_SHA256",
            "signature_encoding": "P1363_BASE64URL_NOPAD",
            "root_signing_key_id": "assembly-root-key-1",
            "key_purpose": "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
            "signature": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode(),
        }

    stale_head_store_record = {
        **assembly_manifest_head_store_record,
        "manifest_sequence": 6,
    }
    assert not assembly_head_proof_is_accepted(
        sign_assembly_head_record(stale_head_store_record, 47),
        stale_head_store_record,
        assembly_head_policy_chain,
    )
    for malformed_proof in (
        {
            key: value
            for key, value in assembly_manifest_head_readback_proof.items()
            if key != "signature"
        },
        {**assembly_manifest_head_readback_proof, "unknown": True},
        {
            **assembly_manifest_head_readback_proof,
            "preimage": {
                key: value
                for key, value in assembly_manifest_head_proof_preimage.items()
                if key != "authority_id"
            },
        },
        {
            **assembly_manifest_head_readback_proof,
            "preimage": {
                **assembly_manifest_head_proof_preimage,
                "unknown": True,
            },
        },
    ):
        assert not assembly_head_proof_is_accepted(
            malformed_proof,
            assembly_manifest_head_store_record,
            assembly_head_policy_chain,
        )
    for missing_field in (
        "assembly_manifest_head_store_record",
        "assembly_manifest_head_readback_proof",
    ):
        assert not registry_key_authority_proof_is_accepted(
            {
                key: value
                for key, value in registry_key_authority_proof.items()
                if key != missing_field
            },
            delivered_registry_receipt,
            producer_receipt_reference,
        )
    assert not registry_key_authority_proof_is_accepted(
        {**registry_key_authority_proof, "unknown": True},
        delivered_registry_receipt,
        producer_receipt_reference,
    )
    for bad_accepted_at in (None, "not-a-time"):
        malformed_assembly_store = dict(
            assembly_manifest_head_store_record
        )
        if bad_accepted_at is None:
            malformed_assembly_store.pop("accepted_at")
        else:
            malformed_assembly_store["accepted_at"] = bad_accepted_at
        assert not registry_key_authority_proof_is_accepted(
            {
                **registry_key_authority_proof,
                "assembly_manifest_head_store_record": (
                    malformed_assembly_store
                ),
            },
            delivered_registry_receipt,
            producer_receipt_reference,
        )
    assert not assembly_head_proof_is_accepted(
        {
            **assembly_manifest_head_readback_proof,
            "signature": assembly_manifest_head_readback_proof["signature"]
            + "=",
        },
        assembly_manifest_head_store_record,
        assembly_head_policy_chain,
    )
    for field, replacement in (
        ("manifest_sequence", 6),
        ("verification_manifest_hash", "sha256:" + "0" * 64),
        ("previous_verification_manifest_hash", "sha256:" + "0" * 64),
        ("monotonic_generation", 0),
        ("authority_id", ""),
    ):
        assert not assembly_head_proof_is_accepted(
            assembly_manifest_head_readback_proof,
            {**assembly_manifest_head_store_record, field: replacement},
            assembly_head_policy_chain,
        )
    expired_trust_preimage = {
        **assembly_trust_preimage,
        "valid_until": "2026-07-26T22:45:00Z",
    }
    expired_trust_hash = domain_hash(
        "acgs.questionnaire.assembly-verification-trust/v1",
        vector_jcs(expired_trust_preimage),
    )
    expired_trust_manifest = {
        "schema_version": "AssemblyVerificationTrustManifest/v1",
        "preimage": expired_trust_preimage,
        "assembly_verification_trust_manifest_hash": expired_trust_hash,
    }
    assert not assembly_head_proof_is_accepted(
        assembly_manifest_head_readback_proof,
        assembly_manifest_head_store_record,
        make_burn_policy_chain(expired_trust_manifest),
    )
    revoked_head_snapshot = {
        **revocation_snapshot,
        "revoked_signing_key_ids": ["assembly-root-key-1"],
    }
    revoked_head_trust_preimage = {
        **assembly_trust_preimage,
        "revocation_snapshot": revoked_head_snapshot,
        "revocation_snapshot_hash": domain_hash(
            "acgs.questionnaire.assembly-revocation-snapshot/v1",
            vector_jcs(revoked_head_snapshot),
        ),
    }
    revoked_head_trust_hash = domain_hash(
        "acgs.questionnaire.assembly-verification-trust/v1",
        vector_jcs(revoked_head_trust_preimage),
    )
    revoked_head_trust_manifest = {
        "schema_version": "AssemblyVerificationTrustManifest/v1",
        "preimage": revoked_head_trust_preimage,
        "assembly_verification_trust_manifest_hash": revoked_head_trust_hash,
    }
    revoked_root_policy_chain = make_burn_policy_chain(
        revoked_head_trust_manifest
    )
    assert not assembly_head_proof_is_accepted(
        assembly_manifest_head_readback_proof,
        assembly_manifest_head_store_record,
        revoked_root_policy_chain,
    )
    assert not head_proof_is_accepted(
        head_proof,
        head_store_record,
        current_burn_manifest,
        revoked_root_policy_chain,
    )
    substituted_head_policy_chain = {
        **assembly_head_policy_chain,
        "policy_bundle": {
            **policy_bundle,
            "assembly_verification_trust_manifest_hash": (
                "sha256:" + "0" * 64
            ),
        },
    }
    assert not head_proof_is_accepted(
        head_proof,
        head_store_record,
        current_burn_manifest,
        substituted_head_policy_chain,
    )
    revoked_burn_head_snapshot = {
        **revocation_snapshot,
        "snapshot_sequence": 9,
        "revoked_verification_manifest_hashes": [fork_a_hash],
    }
    revoked_burn_head_trust_preimage = {
        **assembly_trust_preimage,
        "revocation_snapshot": revoked_burn_head_snapshot,
        "revocation_snapshot_hash": domain_hash(
            "acgs.questionnaire.assembly-revocation-snapshot/v1",
            vector_jcs(revoked_burn_head_snapshot),
        ),
    }
    revoked_burn_head_trust_hash = domain_hash(
        "acgs.questionnaire.assembly-verification-trust/v1",
        vector_jcs(revoked_burn_head_trust_preimage),
    )
    revoked_burn_head_trust_manifest = {
        "schema_version": "AssemblyVerificationTrustManifest/v1",
        "preimage": revoked_burn_head_trust_preimage,
        "assembly_verification_trust_manifest_hash": (
            revoked_burn_head_trust_hash
        ),
    }
    assert not head_proof_is_accepted(
        head_proof,
        head_store_record,
        current_burn_manifest,
        make_burn_policy_chain(revoked_burn_head_trust_manifest),
    )
    revoked_assembly_manifest_snapshot = {
        **revocation_snapshot,
        "snapshot_sequence": 8,
        "revoked_verification_manifest_hashes": [
            assembly_manifest_head_store_record[
                "verification_manifest_hash"
            ]
        ],
    }
    revoked_assembly_manifest_trust_preimage = {
        **assembly_trust_preimage,
        "revocation_snapshot": revoked_assembly_manifest_snapshot,
        "revocation_snapshot_hash": domain_hash(
            "acgs.questionnaire.assembly-revocation-snapshot/v1",
            vector_jcs(revoked_assembly_manifest_snapshot),
        ),
    }
    revoked_assembly_manifest_trust_hash = domain_hash(
        "acgs.questionnaire.assembly-verification-trust/v1",
        vector_jcs(revoked_assembly_manifest_trust_preimage),
    )
    revoked_assembly_manifest_trust = {
        "schema_version": "AssemblyVerificationTrustManifest/v1",
        "preimage": revoked_assembly_manifest_trust_preimage,
        "assembly_verification_trust_manifest_hash": (
            revoked_assembly_manifest_trust_hash
        ),
    }
    assert not assembly_head_proof_is_accepted(
        assembly_manifest_head_readback_proof,
        assembly_manifest_head_store_record,
        make_burn_policy_chain(revoked_assembly_manifest_trust),
    )

    assert head_proof_is_accepted(
        registry_key_authority_proof[
            "burn_manifest_head_acceptance_readback_proof"
        ],
        registry_key_authority_proof["burn_manifest_head_store_record"],
        registry_key_authority_proof[
            "receipt_burn_verification_manifest"
        ],
        verified_policy_chain,
    )
    missing_head_store_record = {
        key: value
        for key, value in registry_key_authority_proof.items()
        if key != "burn_manifest_head_store_record"
    }
    assert set(missing_head_store_record) != set(registry_key_authority_proof)
    substituted_head_store_record = {
        **registry_key_authority_proof,
        "burn_manifest_head_store_record": {
            **head_store_record,
            "store_version": 2,
        },
    }
    assert not head_proof_is_accepted(
        substituted_head_store_record[
            "burn_manifest_head_acceptance_readback_proof"
        ],
        substituted_head_store_record["burn_manifest_head_store_record"],
        substituted_head_store_record[
            "receipt_burn_verification_manifest"
        ],
        verified_policy_chain,
    )
    assert key_manifest_hash == (
        "sha256:db4d119fc84c37631ef4b7c58295aba5627f04c38da45633a959e6eb26ceecd1"
    )
    assert set(assembly_trust_manifest) == {
        "schema_version",
        "preimage",
        "assembly_verification_trust_manifest_hash",
    }
    assert assembly_trust_hash == (
        "sha256:923f98c43c9ade6ffac7e85aff5c0f6a"
        "e9b46aa60423bfe7d29dc2d75aaaba6b"
    )
    for field, replacement in (
        ("trust_root_id", "attacker-root"),
        ("trust_root_version", 1),
        ("authorized_manifest_purposes", ["OUTCOME_SIGNING"]),
        ("valid_from", "2026-07-02T00:00:00Z"),
        ("valid_until", "2026-07-31T00:00:00Z"),
        ("head_acceptance_key_purpose", "OUTCOME_SIGNING"),
        ("predecessor_signing_key_purpose", "OUTCOME_SIGNING"),
        ("predecessor_signing_domain", "acgs.questionnaire.wrong-domain/v1"),
        ("root_public_key_spki_der_b64u", "AA"),
        ("root_public_key_spki_sha256", "sha256:" + "0" * 64),
        ("min_manifest_sequence", 6),
        ("revocation_snapshot_hash", "sha256:" + "0" * 64),
    ):
        substituted_trust = {**assembly_trust_preimage, field: replacement}
        assert domain_hash(
            "acgs.questionnaire.assembly-verification-trust/v1",
            vector_jcs(substituted_trust),
        ) != assembly_trust_hash
    assert fork_a_hash == (
        "sha256:60364b456803f3bcfe69cc8f425e6c765"
        "333b2cc2d28c52887c28c75786bd778"
    )
    assert head_acceptance_hash == (
        "sha256:8648e3e87ed07345a53968938afe3bee"
        "08f756d2f3db20429716c1b226560078"
    )
    assert head_proof["signature"] == (
        "DpHHI5wmQNfSij451Fg_pjwLwKXfZKT-Zy5XMEXKeJZjY0XpeaxgxqsXMQyNRF7a"
        "JhdwZRlWoeUq6fL7UkA8yQ"
    )
    assert policy_hash == (
        "questionnaire-policy/362f29863ccc36786ff47b4943e33be587ecc1d7d5362f1f26f63ec456a8c277"
    )
    changed_rule_preimage = {
        **policy_bundle_preimage,
        "decision_policy_artifact_hash": domain_hash(
            "acgs.questionnaire.decision-policy-artifact/v1",
            b'{"default":"ALLOW"}',
        ),
    }
    changed_rule_policy_hash = "questionnaire-policy/" + hashlib.sha256(
        b"acgs.questionnaire.policy-bundle/v1\0"
        + vector_jcs(changed_rule_preimage)
    ).hexdigest()
    assert changed_rule_policy_hash == (
        "questionnaire-policy/05de26503f630e07e1a354b852fb512dbf391c33a56b99d1caf41a0141368e42"
    )
    assert changed_rule_policy_hash != policy_hash
    wrong_id_preimage = {
        **policy_bundle_preimage,
        "policy_bundle_id": "wrong",
    }
    wrong_id_policy_hash = "questionnaire-policy/" + hashlib.sha256(
        b"acgs.questionnaire.policy-bundle/v1\0"
        + vector_jcs(wrong_id_preimage)
    ).hexdigest()
    assert wrong_id_policy_hash != policy_bundle["policy_version"]
    wrong_version_bundle = {
        **policy_bundle,
        "policy_version": "questionnaire-policy/" + "0" * 64,
    }
    assert wrong_version_bundle["policy_version"] != policy_hash
    substituted_trust_preimage = {
        **policy_bundle_preimage,
        "assembly_verification_trust_manifest_hash": "sha256:" + "0" * 64,
    }
    assert "questionnaire-policy/" + hashlib.sha256(
        b"acgs.questionnaire.policy-bundle/v1\0"
        + vector_jcs(substituted_trust_preimage)
    ).hexdigest() != policy_hash
    for substituted_field in (
        "burn_verification_manifest_hash",
        "burn_manifest_head_acceptance_hash",
    ):
        substituted_burn_preimage = {
            **policy_bundle_preimage,
            substituted_field: "sha256:" + "0" * 64,
        }
        assert "questionnaire-policy/" + hashlib.sha256(
            b"acgs.questionnaire.policy-bundle/v1\0"
            + vector_jcs(substituted_burn_preimage)
        ).hexdigest() != policy_hash
    assert policy_bundle["burn_verification_manifest_hash"] == fork_a_hash
    assert head_preimage["accepted_manifest_hash"] == fork_a_hash
    assert current_burn_manifest["burn_verification_manifest_hash"] == fork_a_hash

    verifier_state_before_backend_faults = (
        dict(manifest_head),
        dict(manifest_acceptances),
    )

    def assert_nth_hash_failure_is_closed(
        operation: Callable[[], object],
        nth_call: int,
    ) -> None:
        original_sha256 = hashlib.sha256
        calls = 0

        def fail_nth_hash(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == nth_call:
                raise RuntimeError(f"injected sha256 failure #{nth_call}")
            return original_sha256(*args, **kwargs)

        with monkeypatch.context() as patcher:
            patcher.setattr(hashlib, "sha256", fail_nth_hash)
            result = operation()
        assert result is False or result is None
        assert calls >= nth_call
        assert (
            dict(manifest_head),
            dict(manifest_acceptances),
        ) == verifier_state_before_backend_faults

    backend_failure_operations = (
        lambda: validate_verified_assembly_trust_chain(
            verified_policy_chain,
            "2026-07-26T22:44:59.000000Z",
        ),
        lambda: burn_manifest_is_accepted(
            burn_manifest,
            manifest_validation_store_record,
            verified_policy_chain,
        ),
        lambda: head_proof_is_accepted(
            head_proof,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        ),
        lambda: registry_key_authority_proof_is_accepted(
            registry_key_authority_proof,
            delivered_registry_receipt,
            producer_receipt_reference,
        ),
    )
    for operation in backend_failure_operations:
        for nth_call in (2, 4):
            assert_nth_hash_failure_is_closed(operation, nth_call)

    def exploding_p256_verifier(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("injected P-256 verifier backend failure")

    with monkeypatch.context() as patcher:
        patcher.setitem(
            globals(),
            "_p256_verify_spki",
            exploding_p256_verifier,
        )
        assert not head_proof_is_accepted(
            head_proof,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
    assert (
        dict(manifest_head),
        dict(manifest_acceptances),
    ) == verifier_state_before_backend_faults

    def exploding_jcs(value: object) -> bytes:
        raise RuntimeError(f"injected JCS failure for {type(value).__name__}")

    with monkeypatch.context() as patcher:
        patcher.setitem(globals(), "_canonical_jcs", exploding_jcs)
        assert not head_proof_is_accepted(
            head_proof,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
    assert (
        dict(manifest_head),
        dict(manifest_acceptances),
    ) == verifier_state_before_backend_faults

    def exploding_spki_constructor(private_scalar: int) -> bytes:
        raise RuntimeError(
            f"injected P-256 SPKI constructor failure for {private_scalar}"
        )

    with monkeypatch.context() as patcher:
        patcher.setitem(globals(), "_p256_spki", exploding_spki_constructor)
        assert (
            validate_verified_assembly_trust_chain(
                verified_policy_chain,
                "2026-07-26T22:44:59.000000Z",
            )
            is None
        )
    assert (
        dict(manifest_head),
        dict(manifest_acceptances),
    ) == verifier_state_before_backend_faults

    def decode_policy_artifact_b64u(value: str) -> bytes:
        if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("non-canonical base64url alphabet")
        if len(value) % 4 == 1:
            raise ValueError("invalid base64url length")
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        if canonical != value or not 1 <= len(raw) <= 1_048_576:
            raise ValueError("non-canonical or out-of-range policy artifact")
        return raw

    valid_policy_artifact_b64u = "eyJkZWZhdWx0IjoiREVOWSJ9"
    assert decode_policy_artifact_b64u(valid_policy_artifact_b64u) == (
        b'{"default":"DENY"}'
    )
    for invalid_artifact_b64u in (
        "",
        valid_policy_artifact_b64u + "=",
        valid_policy_artifact_b64u + " ",
        "A",
        "AB",
    ):
        try:
            decode_policy_artifact_b64u(invalid_artifact_b64u)
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"accepted malformed policy artifact: {invalid_artifact_b64u!r}"
            )

    malformed_authority_objects: tuple[object, ...] = (
        None,
        [],
        "not-an-object",
        7,
    )
    for malformed in malformed_authority_objects:
        assert not registry_key_manifest_is_accepted(
            malformed,
            "2026-07-26T22:45:00Z",
        )
        assert not burn_manifest_is_accepted(
            malformed,
            manifest_validation_store_record,
            verified_policy_chain,
        )
        assert not burn_manifest_is_accepted(
            burn_manifest,
            malformed,
            verified_policy_chain,
        )
        assert not burn_manifest_is_accepted(
            burn_manifest,
            manifest_validation_store_record,
            malformed,
        )
        assert not head_proof_is_accepted(
            malformed,
            head_store_record,
            current_burn_manifest,
            verified_policy_chain,
        )
        assert not head_proof_is_accepted(
            head_proof,
            malformed,
            current_burn_manifest,
            verified_policy_chain,
        )
        assert not head_proof_is_accepted(
            head_proof,
            head_store_record,
            malformed,
            verified_policy_chain,
        )
        assert not head_proof_is_accepted(
            head_proof,
            head_store_record,
            current_burn_manifest,
            malformed,
        )
        assert not assembly_head_proof_is_accepted(
            malformed,
            assembly_manifest_head_store_record,
            assembly_head_policy_chain,
        )
        assert not assembly_head_proof_is_accepted(
            assembly_manifest_head_readback_proof,
            malformed,
            assembly_head_policy_chain,
        )
        assert not assembly_head_proof_is_accepted(
            assembly_manifest_head_readback_proof,
            assembly_manifest_head_store_record,
            malformed,
        )

    for token in (
        *expected,
        key_manifest_hash,
        assembly_trust_hash,
        burn_manifest_hash,
        head_acceptance_hash,
        policy_hash,
        changed_rule_policy_hash,
        "file_bytes are the exact Git blob bytes",
        "excerpt_bytes = UTF8(excerpt)",
        "no archive repacking, newline conversion, text decoding",
        "decoded bytes against an allowlisted registry key",
        "linearizable authenticated-head authority",
        "unique 128-bit request_nonce",
        "Caller-supplied or cached checkpoints are never accepted",
        "durable high-water tuple keyed by registry_id/classifier_id/classifier_version",
        "including REVOKED checkpoints",
        "replaying sequence 7 ACTIVE after observing sequence 8 REVOKED is denied",
        "excerpt_bytes == range_bytes",
        "subsequence, trimmed range, or model-selected byte window is invalid",
        "Online validation is not the proof archive",
        "complete signed entry_envelope",
        "complete signed checkpoint_envelope",
        "immutable verification-key manifest",
        "signatures are never recomputed",
        "RegistryVerificationKeyManifest/v1",
        "schema_version is exactly RegistryVerificationKeyManifest/v1",
        "closed-validates every key record",
        "with unique key IDs",
        "signature_alg = \"Ed25519\"",
        "public_key_b64u",
        "without = padding, of exactly 32 raw Ed25519 public-key bytes",
        "decodes to exactly 64 raw Ed25519 signature bytes",
        "non-canonical re-encoding",
        "not_before <= t < not_after",
        "registry_verification_key_manifest_hash",
        "receipt_verification_key_manifest_hash",
        "assembly_verification_trust_manifest_hash",
        "AssemblyVerificationTrustManifest/v1",
        "AssemblyVerificationTrustManifestPreimage/v1",
        "authorized_manifest_purposes",
        "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING",
        "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
        "RECEIPT_BURN_VERIFICATION_MANIFEST_SIGNING",
        "predecessor_signing_key_purpose",
        "predecessor_signing_domain",
        "acgs.questionnaire.assembly-verification-trust/v1\\0",
        "acgs.questionnaire.assembly-revocation-snapshot/v1\\0",
        "root_public_key_spki_der_b64u",
        "complete artifact, including exact root SPKI DER bytes",
        "acgs.questionnaire.registry-verification-keys/v1\\0",
        "ReceiptVerificationKeyManifest/v1",
        "acgs.questionnaire.receipt-verification-keys/v1\\0",
        "DECISION_RECEIPT_SIGNING",
        "resolves the receipt verification key solely from this embedded",
        "no ambient public key or caller-supplied key id is authority",
        "QuestionnairePolicyArchiveAcceptance/v1",
        "QUESTIONNAIRE_POLICY_BUNDLE_SIGNING",
        "independently pinned current archive-root SPKI digest",
        "verification_time is not a caller clock or fixture",
        "explicitly shipped-receipt-v1-only",
        "field set is protocol-defined, never inferred from a fixture",
        "DecisionReceipt.verify(require_signature=True, require_expiry=True)",
        'Only shipped decision="allow" is executable',
        "append_burn_manifest",
        "leaves head, acceptance, consumption, and invocation stores unchanged",
        "QuestionnairePolicyBundle/v1",
        (
            "contains exactly schema_version, policy_bundle_id, policy_version, "
            "decision_policy_artifact_hash, "
            "registry_verification_key_manifest_hash, "
            "receipt_verification_key_manifest_hash, "
            "assembly_verification_trust_manifest_hash, "
            "burn_verification_manifest_hash, and "
            "burn_manifest_head_acceptance_hash"
        ),
        "ReceiptBurnVerificationManifestPreimage/v1",
        "ReceiptBurnVerificationManifest/v1",
        "RECEIPT_BURN_ACCEPTANCE_SIGNING",
        "previous_burn_verification_manifest_hash",
        "linearizable, append-only high-water store",
        "two concurrent valid candidates for the same predecessor/sequence",
        "one authoritative transaction timestamp",
        "validation and persisted accepted_at",
        "complete authenticated policy chain is mandatory",
        "no ambient or optional fallback",
        "ambient process head variables",
        "manifest_sequence == accepted_sequence + 1",
        "sequence 7 after accepted sequence 9",
        "authority-authenticated immutable read-back proof",
        "BurnManifestHeadStoreRecordPreimage/v1",
        "burn_manifest_head_store_record",
        "No external database row or caller-supplied record",
        "BurnManifestHeadAcceptancePreimage/v1",
        "BurnManifestHeadAcceptanceReadbackProof/v1",
        "burn_manifest_head_acceptance_hash",
        "acgs.questionnaire.burn-manifest-head-acceptance/v1\\0",
        "burn-manifest-head-acceptance-signature/v1\\0",
        "BURN_MANIFEST_HEAD_ACCEPTANCE_SIGNING",
        "latest accepted high-water value",
        "valid_from <= t < valid_until",
        "signing_key_id not in revoked_signing_key_ids",
        "burn_verification_manifest_hash not in",
        "root_signing_key_id not in revoked_signing_key_ids",
        "Membership in any of those positions fails even when the candidate was freshly",
        "nested burn revocation snapshot",
        "cross-purpose use, an unauthorized domain",
        "acgs.questionnaire.receipt-burn-revocation-snapshot/v1\\0",
        "acgs.questionnaire.receipt-burn-verification-manifest/v1\\0",
        "receipt-burn-verification-manifest-signature/v1\\0",
        "receipt_burn_verification_manifest",
        "schema_version is exactly QuestionnairePolicyBundle/v1",
        "QuestionnairePolicyBundlePreimage/v1",
        'schema_version = "QuestionnairePolicyBundlePreimage/v1"',
        "It excludes only the derived policy_version",
        "Policy.version = policy_version",
        (
            "bundle.policy_bundle_id == DecisionReceipt.policy_bundle_id and "
            "bundle.policy_version == DecisionReceipt.policy_version == "
            "DecisionReceipt.policy_hash == derived_policy_version"
        ),
        "wrong bundle id, wrong version, or legacy semantic version fails closed",
        "acgs.questionnaire.decision-policy-artifact/v1\\0",
        "exact immutable artifact loaded by the policy engine",
        "No parsing, re-serialization, normalization, or rule-subset projection",
        "acgs.questionnaire.policy-bundle/v1\\0",
        "questionnaire-policy/",
        "derived value therefore identifies the complete decision-policy bytes",
        "cross-implementation known vector",
        "proving that an ALLOW/DENY rule change cannot preserve the receipt policy hash",
        "Implementations must freeze both values",
        "RegistryKeyAuthorityProof/v1",
        "schema_version is exactly RegistryKeyAuthorityProof/v1",
        "decision_policy_artifact_b64u",
        "inherits only the encoding-canonicality rules above",
        "must contain 1..1,048,576 bytes",
        "32-byte key and 64-byte signature length rules do not apply",
        "accepted 18-byte value",
        "Empty, oversized, malformed, or non-canonically encoded artifacts fail closed",
        "recomputes decision_policy_artifact_hash",
        "recomputes registry_verification_key_manifest_hash",
        "enforces the bundle/receipt id and version equalities above",
        "complete serialized delivered DecisionReceipt",
        "DecisionReceipt.to_dict()",
        "DecisionReceipt.from_dict",
        "DecisionReceipt._hash_payload()",
        "producer_receipt_reference",
        "produced_by_receipt_id == delivered_receipt.receipt_id",
        "producer_receipt_reference.policy_hash == delivered_receipt.policy_hash",
        "coordinated substitution changing both receipt IDs",
        "same policy hash with a different receipt identity",
        "Every public verifier or append/register entry point",
        "before any key-set, .get, or index operation",
        "malformed non-object proof",
        "no ambient fixture receipt",
        "entry envelope must resolve a key whose purpose is exactly ENTRY",
        "checkpoint envelope must resolve a key whose purpose is exactly CHECKPOINT",
        "Purpose-swapped keys fail closed",
        "For both the resolved ENTRY and CHECKPOINT key",
        "future, expired, empty, reversed, or malformed key intervals fail closed",
        "derives the content-addressed policy version",
        "DecisionReceipt.policy_hash",
        "same exact objects are embedded in the delivered proof pack",
        "OutcomeEvent.timestamp",
        "AppendAcceptanceUnsignedPreimage.commit_timestamp",
        "Immediately before the durable finalize transaction",
        "crash-recovered or delayed finalizer may not reuse the expired candidate",
        "Missing policy artifact or policy/key proof",
        "remote pointer or mutable cache is not a substitute",
        "Delete either signed envelope or its archive",
        "policy bundle, policy artifact, policy artifact digest, manifest digest, manifest key",
        (
            "schema version, bundle id, bundle version, key purpose, "
            "public-key encoding, signature encoding, "
            "key validity interval"
        ),
        "crash-recover finalization",
        "outside the checkpoint interval",
        "rebuild the preimage under a fresh checkpoint",
        "archive write/read uncertain",
        "raw/uppercase/malformed artifact or excerpt hashes",
        "high-water-store failure or uncertain commit",
        "registry rollback",
    ):
        assert token in normalized


def test_questionnaire_manifest_head_authority_contracts_are_closed() -> None:
    text = re.sub(r"\s+", " ", _read(QUESTIONNAIRE_SPEC))
    for token in (
        "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING",
        "next_sequence == predecessor_sequence + 1",
        "atomic create-if-absent operation",
        "sequence-99 first head",
        "present, parseable `accepted_at`",
        "two concurrent valid candidates for the same predecessor/sequence",
        "ambient process head variables",
        "complete serialized delivered `DecisionReceipt`",
        "no ambient fixture receipt",
    ):
        assert token in text


def test_questionnaire_outcome_payment_and_spend_fail_closed_contracts() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "product-owned canonical `OutcomeEvent`",
        "product-owned outcome wrapper",
        "Pinned canonical-event schema",
        "raw value returned by `execute_with_receipt`",
        "outcome_hash",
        "result_hash",
        "receipt_id",
        "DecisionReceipt.audit_event_hash",
        "OutcomePayloadPreimage",
        "KMS.Sign(\"acgs-outcome-v1\" || outcome_hash)",
        "allowlisted outcome-signing key",
        "actor/action/argument bindings",
        "blocks every dependent delivery",
        "provider-signed event",
        "quote id and quote version",
        "exact amount",
        "currency",
        "settled status",
        "operation-wide worst-case maximum",
        "all bounded attempts",
        "capped input tokens",
        "capped output tokens",
        "maximum attempt count",
        "zero Gemini calls",
        "reconcile total actual provider usage once",
        "nonempty, timezone-aware `expires_at`",
        "explicitly selects `require_expiry=True`",
        "plain `execute_with_receipt` default is `require_expiry=False`",
        "shared atomic burn-before-execute authority",
        "receipt_consumptions/{receipt_anchor}",
        "exactly one tool call occurs",
        "Cross-worker receipt replay",
        "Shared receipt-anchor burn",
        "not implied by the plain runtime default",
    ):
        assert token in normalized
    assert "Receipt.result_hash" not in text
    assert "only a dispatched" not in text


def test_questionnaire_ambiguous_dispatch_never_reopens_spend_ceiling() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regression = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regression).replace("`", "").replace("**", "")
    for token in (
        "only a failure proven to occur before the durable dispatch-intent commit",
        "PROVABLY_UNDISPATCHED",
        "DISPATCH_AMBIGUOUS",
        "timeout after send but before response",
        "transport error, a lost response, or missing usage metadata",
        "may have been accepted and charged",
        "charges the operation-wide capped reserved maximum",
        "retains an equivalent quarantine hold",
        "MUST NOT reopen that budget",
        "Authoritative usage may reconcile downward idempotently",
        "never below already known spend",
        "cannot exceed the job ceiling",
        "timeout after the provider path records dispatch",
        "refuses a later operation that would exceed the job ceiling",
        "real provider-adapter and shared-ledger path",
        "capped hold must remain visible to the other worker",
    ):
        assert token in normalized


def test_questionnaire_dispatch_and_usage_are_durably_exactly_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regression = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regression).replace("`", "").replace("**", "")

    for token in (
        "durable write-ahead CAS",
        "RESERVED -> DISPATCH_AMBIGUOUS",
        "DispatchIntent",
        "job_id",
        "reservation_id",
        "attempt_id",
        "provider_request_id",
        "idempotency_key",
        "provider_account_id",
        "model_id",
        "model_version",
        "capped_attempt_max_minor_units",
        "dispatch_sequence",
        "Only after a successful and certain commit",
        "uncertain commit status makes zero provider calls",
        "crash after the CAS but before send retains the full hold",
        "UsageRecord",
        "usage_record_id",
        "input_tokens",
        "output_tokens",
        "cost",
        "currency",
        "issued_at",
        "exact typed equality—including billing rule/version, minor-unit cap, ISO currency, and "
        "exponent—with the stored",
        "consumes usage_record_id atomically",
        "wrong, stale, mismatched, unauthenticated, or replayed record",
        "no valid UsageRecord exists, the capped maximum remains held",
        "Crash after CAS-before-send and after send-before-response",
        "Exactly one durable monotonic DispatchIntent CAS",
    ):
        assert token in normalized


def test_questionnaire_retry_authority_and_usage_attestor_fail_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions).replace("`", "").replace("**", "")

    for token in (
        "reservation immutably pins max_attempts",
        "expected next and unused attempt_id set",
        "price schedule and version",
        "sum of all authorized attempt caps",
        "Over-limit or duplicate attempts",
        "validation failure, store failure, or uncertain transaction outcome",
        "zero provider calls",
        "ProviderUsageAttestor",
        "pinned/allowlisted provider account",
        "read-only usage-API credential",
        "both provider_request_id and idempotency_key",
        "issuer_id",
        "issuer_version",
        "signing_key_id",
        "expires_at",
        "dedicated KMS attestation key",
        "no direct spend-ledger write, hold-release, reconciliation, or provider dispatch grant",
        "key rotation/revocation",
        "unknown/revoked issuer or key",
        "forged/wrong-key signature",
        "no authoritative provider record exists",
        "attempt beyond max_attempts",
        "cumulative authorized cap above the operation maximum",
        "Each must fail before DispatchIntent commit and make zero provider calls",
        "attestor principal has no direct ledger-write/release grant and no provider "
        "dispatch grant",
    ):
        assert token in normalized


def test_questionnaire_dispatch_digest_and_usage_signature_are_canonical() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("| Untrusted | Consequence |")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions + trust)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "input_token_cap",
        "output_token_cap",
        "price_schedule_id",
        "price_schedule_version",
        "input_unit_price",
        "output_unit_price",
        "provider_request_config_hash",
        "ACGS-PROVIDER-REQUEST-CONFIG-V1\\0 || JCS(config)",
        "every provider request option that can alter cost or limits",
        "constructs the network request only from the committed DispatchIntent values",
        "Immediately before TLS handoff",
        "same-dollar-cap request with different token limits",
        "signature-excluded preimage",
        'signature_algorithm = "EC_SIGN_P256_SHA256"',
        "ACGS-PROVIDER-USAGE-ATTESTATION-V1\\0",
        "RFC 8785 JCS",
        "usage_record_hash = hex(SHA256",
        "signature is the base64-encoded Cloud KMS",
        "recomputes and exactly compares usage_record_hash",
        "unknown algorithms",
        "valid low-usage signature is nevertheless mediated co-authorization",
        "Compromise of the attestor or attestation key can therefore falsely lower a hold",
        "Tamper each signed-envelope field",
        "retain the full hold on every failure",
    ):
        assert token in normalized


def test_questionnaire_transport_bytes_and_usage_values_are_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "ProviderTransportEnvelope",
        'fixed scheme = "https"',
        "allowlisted host",
        "allowlisted path",
        "normalized_query",
        "RFC 3986 percent-encoded",
        "semantic_headers",
        "semantic_options",
        "body_sha256",
        "body_b64",
        "exact emitted body bytes",
        "ACGS-PROVIDER-TRANSPORT-V1\\0",
        "sends those exact bytes without JSON parsing or reserialization",
        "Immediately before TLS handoff",
        "alternate body encoding",
        "unknown field or option injection",
        "post-hash body mutation",
        "The status/value contract is closed",
        "FINAL_SUCCEEDED",
        "FINAL_FAILED_CHARGED",
        "FINAL_NOT_CHARGED",
        "cost_minor_units",
        "currency_minor_unit_exponent",
        "billing_rule_id",
        "billing_rule_version",
        "exact pinned ISO 4217 currency",
        "JSON integers only",
        "Unknown, pending, provider-error, unrecognized",
        "nonzero fields on FINAL_NOT_CHARGED",
        "Only a complete valid terminal record",
        "Every case must retain the full hold",
    ):
        assert token in normalized


def test_questionnaire_money_and_transport_maps_are_canonical_and_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "capped_attempt_max_minor_units",
        "operation_wide_max_minor_units",
        "currency_minor_unit_exponent",
        "base-10 JSON integers",
        "exact minor units",
        "bounded to 0..2^63-1",
        "sole monetary-string exemption",
        r"0|[1-9][0-9]*(\.[0-9]*[1-9])?",
        "never strings, floats, or exponent notation",
        "string-encoded cost/cap values",
        "major-unit values placed in minor-unit fields",
        "comparison performed under mismatched units",
        "closed semantic_headers map",
        "closed semantic_options map",
        "all emitted fields that can alter provider interpretation",
        "Content-Encoding",
        "API version",
        "vendor feature flags",
        "routing flags",
        "Authorization credential value",
        "Content-Length derived exactly from the committed body bytes",
        "trace id only when",
        "Any other emitted header or option must be present in the closed map or absent",
        "three enumerated runtime-derived exclusions",
        "must make zero provider calls",
    ):
        assert token in normalized


def test_questionnaire_credential_account_and_billing_rules_are_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("| Untrusted | Consequence |")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions + trust)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "provider_credential_binding_id",
        "workload_identity_principal",
        "workload_identity_issuer",
        "workload_identity_audience",
        "credential_mapping_version",
        "credential_min_valid_until",
        "exact provider_account_id",
        "billing_rule_id",
        "billing_rule_version",
        "ProviderCredentialInjector",
        "only component allowed to read the workload credential store",
        "short-lived credential",
        "Authorization secret is excluded from hashes and logs",
        "binding id, mapping version, exact provider_account_id",
        "re-resolves and validates credential binding/mapping version",
        "revocation state, and sufficient credential expiry",
        "wrong, rotated, revoked, expired",
        "makes zero provider calls",
        "read-only usage role of the same provider_credential_binding_id",
        "signature-excluded preimage contains every field listed above",
        "wrong billing rule/version",
        "usage attestor must query the same committed account/binding namespace",
        "retains the full hold",
        "compromise can substitute credentials/accounts and dispatch paid calls",
    ):
        assert token in normalized


def test_questionnaire_outcome_chain_is_signed_and_offline_verifiable() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    outcome = text.partition("product-owned canonical `OutcomeEvent` schema")[2]
    outcome = outcome.partition("### 2.6.1")[0]
    trust = text.partition("The product outcome chain has two authentication boundaries")[2]
    trust = trust.partition("### 6.3")[0]
    offline = text.partition("### 8.6 Receipt chain verification")[2]
    offline = offline.partition("### 8.7")[0]
    signing_test = text.partition("### 8.7 Signing-mode assertion")[2]
    signing_test = signing_test.partition("## 9.")[0]
    normalized = re.sub(r"\s+", " ", outcome + trust + offline + signing_test)
    for token in (
        "OutcomePayloadPreimage",
        "CAS-reserves the current head before any event signature is issued",
        "OutcomeReservation",
        "payload_hash",
        "OutcomeEventUnsignedPreimage",
        "previous_outcome_hash",
        "signature_algorithm` / `signing_key_id",
        "KMS signature",
        "ordering avoids self-reference",
        "AppendAcceptanceUnsignedPreimage",
        "matching finalizer-signed, `ATTESTED` `AppendAcceptance`",
        "orphan and remains unacceptable",
        "without both the event-signing and append-acceptance keys",
        "cannot rewrite or rechain events that the verifier will accept",
        "tamper status, result hash, or error hash",
        "unknown/revoked/wrong key",
        "no two accepted events share a predecessor",
        "single genesis",
        "unique predecessor per accepted event",
        "two product wrappers concurrently against one head",
        "rejected contender receives no signature",
        "orphan signature is rejected online and offline",
        "COMMITTED_PENDING_SIGNATURE",
        "current head's row is not `ATTESTED`",
        "finalizer never signs a precommit or aborted reservation",
        "crash before the finalize transaction advances no head",
        "crash after finalize but before signing",
        "crash after KMS signing but before signature storage",
        "No event is exposed to consumers or accepted offline before `ATTESTED`",
    ):
        assert token in normalized


def test_questionnaire_failed_outcome_is_redacted_hashed_and_exclusive() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("product-owned canonical `OutcomeEvent` schema")[2]
    schema = schema.partition("### 2.6.1")[0]
    regression = text.partition("### 8.7 Signing-mode assertion")[2].partition("## 9.")[0]
    normalized = re.sub(r"\s+", " ", schema + regression)
    for token in (
        "`error_hash`",
        "nonnull iff `FAILED`",
        "Exactly one outcome hash is populated",
        "null `error_hash`/`error_envelope`",
        "null `result_hash`",
        "stable redacted envelope",
        "{schema_version, error_class, error_code, safe_message_hash, retryable}",
        "error_hash = SHA256(canonical(ErrorEnvelope))",
        "no raw exception text, stack, request payload, credential, or secret",
        "event signature covers the failure binding",
        "Tamper the error class, code, safe-message hash, retryability",
        "status/result/error exclusivity",
    ):
        assert token in normalized


def test_questionnaire_trust_tcb_names_every_security_authority() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("| Untrusted | Consequence |")[0]
    normalized = re.sub(r"\s+", " ", trust)
    for token in (
        "policy kernel and receipt verifier",
        "Receipt signer and receipt-key custody",
        "Shared receipt-burn authority and Firestore consumption store",
        "Spend ledger and Firestore transaction authority",
        "`ProviderCredentialInjector` principal, workload credential mapping store",
        "short-lived credential issuer",
        "compromise can substitute credentials/accounts",
        "`ProviderUsageAttestor`, pinned provider account/API endpoint",
        "read-only usage credential, and KMS attestation key custody",
        "has no direct ledger-write/release grant",
        "signature co-authorizes downward reconciliation",
        "compromise can falsely release holds",
        "Payment webhook signature verifier and event store",
        "Provider-approval signature verifier, allowlisted approval keys",
        "single-use approval event store",
        "Product executor and side-effect credential boundary",
        "Outcome canonicalizer, event signer, and outcome-signing key custody",
        "`OutcomeAppendAuthority` identity and reservation/finalization store",
        "Dedicated acceptance-finalizer identity and append-acceptance key custody",
        "narrowly scoped reservation/finalize transaction grants",
        "Ordinary sink/store writers have neither event-signing nor acceptance-signing authority",
        "Semantic adjudicator, allowlisted rules, identities, and keys",
        "authority-completeness set",
        "Missing or ambiguous ownership is release-blocking",
        "necessarily in the TCB",
        "least-privilege short-lived credentials",
        "compromise can bypass the receipt gate",
    ):
        assert token in normalized


def test_questionnaire_escalation_and_transform_authority_fail_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "provider-authenticated approval event",
        "fresh proposal and fresh policy evaluation",
        "non-executable escalation receipt is never reused or upgraded",
        "original arguments never execute",
        "wrong-proposal",
        "new exact rewritten `TRANSFORM`",
    ):
        assert token in normalized


def test_questionnaire_uses_stable_shipped_symbols_not_line_citations() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    assert not re.search(r"(?:receipt|kernel|signing)\.py:\d", text)
    assert "f4a700824f597ecf77ff581f6301dfec6db252fd" in text

    expected = {
        "packages/gove-zone/src/gove_zone/kernel.py": {"evaluate_and_append", "simulate"},
        "packages/gove-zone/src/gove_zone/receipt.py": {"DecisionReceipt", "from_record"},
        "packages/gove-zone/src/gove_zone/executor.py": {
            "execute_with_receipt",
            "GovernedExecutor",
        },
        "packages/gove-zone/src/gove_zone/proofpack.py": {"generate_proof_pack", "verify_pack"},
    }
    for relative, names in expected.items():
        symbols = _python_symbols(relative)
        assert names <= symbols, f"missing documented symbols in {relative}: {names - symbols}"


def test_questionnaire_legal_boundary_is_counsel_pending_not_a_legal_conclusion() -> None:
    prose = _prose(_read(QUESTIONNAIRE_SPEC))
    assert "chosen boundary pending counsel" in prose
    assert "primary sources reviewed on 2026-07-25" in prose
    assert "not a definitive legal conclusion" in prose
    assert "only lawful shape available" not in prose
    assert "is legal to print" not in prose
    assert "there is no third-party assessment role to sell into" not in prose


def test_site_copy_preserves_the_four_verdict_execution_invariant() -> None:
    text = _read(SITE_DECK)
    for verdict in ("ALLOW", "DENY", "TRANSFORM", "ESCALATE"):
        assert verdict in text
    assert "Only ALLOW and TRANSFORM can authorize a side effect" in text
    assert "Sends only the approved" in text
    assert "Fail closed. No tool call." in text


def test_site_copy_qualifies_principal_authz_and_mcp_gateway_scope() -> None:
    text = _read(SITE_DECK)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "Not a complete IAM / FGA system",
        "opt-in `authz_enforce`",
        "configured `PrincipalRegistry`",
        "application-supplied",
        "not a general MCP gateway",
        "shipped alpha `adapters.mcp_gateway`",
        "receipt-gated proxy only for explicitly wired MCP calls",
        "transport hardening, MCP identity, deployment, and unwired servers",
    ):
        assert token in normalized


def test_physical_profile_does_not_overclaim_the_shipped_replay_ledger() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "ReceiptConsumptionLedger(path, checkpoint=True)",
        ".consume(receipt)",
        "receipt-anchor-only reference",
        "constructor configuration, not an external expected-tail argument",
        "API has no `mar_nonce` or composite transaction",
        "separate profile-local composite receipt-plus-`mar_nonce` burn authority",
        "one durable transaction/lock and protected checkpoint",
        "REQUIRED but UNIMPLEMENTED",
        "fail closed at activation until it exists",
        "single- and redundant-controller modes both fail closed",
        "non-authoritative reference code",
        "outside the Security TCB",
        "excluded from the claim that compromise can mint accepted motion",
        "dotted diagram edge is descriptive",
    ):
        assert token in normalized
    assert "consume(receipt, checkpoint=True)" not in text
    assert "published `ReceiptConsumptionLedger.consume" not in text


def test_physical_deactivate_acknowledges_an_already_terminal_lease() -> None:
    lifecycle = _rfc().partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", lifecycle)
    ordered = (
        "publish an allocation-bound revoke request",
        "stop scheduling and wait for RT quiescence",
        "already `CONSUMED`, `REVOKED`, or `EXPIRED`",
        "directly acknowledges the observed terminal generation",
        "return only after terminal acknowledgement",
    )
    positions = [normalized.index(token) for token in ordered]
    assert positions == sorted(positions)
    assert "without attempting a transition" in normalized


def test_questionnaire_outcome_signing_grant_is_distinct_and_single_use() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    section = text.partition("The trusted linearizable `OutcomeAppendAuthority`")[2]
    section = section.partition("> **Signing is on by default")[0]
    normalized = re.sub(r"\s+", " ", section)
    for token in (
        "distinct signing-grant state",
        "UNUSED|CLAIMED|USED",
        "signing_grant_nonce",
        "issuing one signature never consumes the append reservation",
        "CASes the distinct signing grant from `UNUSED` to `CLAIMED`",
        "idempotency key derived from the reservation id, nonce, and event hash",
        "`CLAIMED -> USED`",
        "cannot sign another hash",
        "`USED` cannot sign again",
        "without changing append status `ACTIVE`",
        "requires signing-grant state `USED`",
        "exact stored nonce/event-hash/signature reference",
    ):
        assert token in normalized


def test_questionnaire_retry_hold_keeps_all_remaining_attempt_maxima() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regression = text.partition("### 8.3.7 Two-worker spend concurrency")[2]
    regression = regression.partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regression)
    for token in (
        "retains the capped maximum for every unused or ambiguous remaining attempt",
        "cannot release retry headroom early",
        "SpendOperation.state",
        "OPEN|SUCCEEDED|FAILED|ESCALATED|CANCELLED",
        "atomically requires `SpendOperation.state == OPEN`",
        "No reconciliation may release the maximum for a not-yet-terminal retry slot",
        "CAS `OPEN -> SUCCEEDED|FAILED|ESCALATED|CANCELLED`",
        "atomically retire every unused attempt slot",
        "release only caps proven unreachable",
        "same operation row/version",
        "one linearization winner",
        "terminalization wins",
        "non-`OPEN` state and makes zero provider calls",
        "retry intent wins",
        "cap remains charged or held",
        "no schedule can both authorize the retry and release its cap",
    ):
        assert token in normalized

    terminal = normalized.index(
        "CAS `OPEN -> SUCCEEDED|FAILED|ESCALATED|CANCELLED`"
    )
    retire = normalized.index("atomically retire every unused attempt slot", terminal)
    release = normalized.index("release only caps proven unreachable", retire)
    assert terminal < retire < release


def test_physical_projection_is_bound_from_policy_evaluation_through_arming() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "`DecisionRecord.argument_hash`, not raw `ToolCall.args`",
        "side store",
        "is not authoritative by itself",
        "There is only one authoritative projection",
        "canonical_tool_arguments.physical_contract_projection",
        "Neither the preimage nor the artifact accepts a second projection copy",
        "PerMotionBindingPreimage/v0",
        "total one-to-one projection",
        "`trajectory.trajectory_digest`",
        "`trajectory.block_size_ticks`",
        "`compiler.input_plan_digest`",
        "`MAR.lease`",
        "canonical_tool_arguments.per_motion_binding",
        "acgs.physical.per-motion-binding/v0\\0",
        "aliases `artifact_digest`, `trajectory_root`, `block_size`",
        "cross-binding map is total and closed",
        "MAR.constraints.physical.trajectory.*",
        "receipt constraint cannot substitute a second copy",
        "The per-motion preimage excludes `per_motion_binding_hash`",
        "preimage.tool == ToolCall.name == DecisionRecord.tool",
        "DecisionReceipt.proposed_action",
        "preimage.actor == ToolCall.actor == DecisionRecord.actor",
        "DecisionReceipt.actor",
        "Any actor or tool substitution fails",
        "The preimage excludes `evaluated_motion_preimage_hash`",
        "acgs.physical.evaluated-motion-preimage/v0\\0",
        "The artifact excludes `evaluated_motion_artifact_hash`",
        "acgs.physical.evaluated-motion-artifact/v0\\0",
        "Unknown fields, non-JSON values, alternate digest encodings",
        "before finalize, mint, and activation",
        "preimage.argument_hash == decision_record_argument_hash",
        "constraints.physical_evaluated_binding",
        "solely from the finalized artifact",
        "never accepts this constraint object from a caller",
        "call.argument_hash() == audited.record.argument_hash",
        "DecisionReceipt.from_record",
        "signed receipt constraints",
        "exact equality across artifact",
        "DecisionReceipt.argument_hash",
    ):
        assert token in normalized
    assert "audited.record.tool_call.arguments" not in text

    projection = {
        "profile": "STRICT",
        "compiler": {
            "compiler_digest": "sha256:" + "0" * 64,
            "compiler_version": "compiler/v1",
        },
        "safety_contract": {"contract_version": "contract/v1"},
    }
    projection_bytes = json.dumps(
        projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    projection_hash = "sha256:" + hashlib.sha256(
        b"acgs.physical.contract-projection/v0\0" + projection_bytes
    ).hexdigest()

    def digest(char: str) -> str:
        return "sha256:" + char * 64

    per_motion = {
        "schema_version": "PerMotionBindingPreimage/v0",
        "motion_id": "motion-1",
        "trajectory": {
            "trajectory_digest": digest("1"),
            "merkle_root": digest("2"),
            "block_size_ticks": 256,
            "block_count": 1,
            "duration_ms": 100,
            "encoding": "f64le",
        },
        "compiler": {"input_plan_digest": digest("3")},
        "initial_state": {
            "joint_position_hash": digest("4"),
            "joint_position": [0, 1],
            "tolerance_rad": 0.01,
            "observation_timestamp": "2026-07-26T22:40:00Z",
            "observation_max_age_ms": 200,
            "perception_digest": digest("5"),
        },
        "lease": {
            "nonce": "nonce-1",
            "sequence_lo": 0,
            "sequence_hi": 0,
            "max_duration_ms": 100,
            "actuator_group": "arm-0/joints",
        },
        "source_hash": digest("6"),
        "source_revision": "rev-1",
    }
    per_motion_bytes = json.dumps(
        per_motion, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    per_motion_hash = "sha256:" + hashlib.sha256(
        b"acgs.physical.per-motion-binding/v0\0" + per_motion_bytes
    ).hexdigest()
    arguments = {
        "motion_id": "motion-1",
        "physical_contract_projection": projection,
        "physical_contract_projection_hash": projection_hash,
        "per_motion_binding": per_motion,
        "per_motion_binding_hash": per_motion_hash,
    }
    arguments_bytes = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    argument_hash = hashlib.sha256(arguments_bytes).hexdigest()
    preimage = {
        "schema_version": "EvaluatedMotionPreimage/v0",
        "tool": "robot.motion.execute",
        "actor": "operator-1",
        "canonical_tool_arguments": arguments,
        "argument_hash": argument_hash,
        "per_motion_binding_hash": per_motion_hash,
    }
    preimage_bytes = json.dumps(
        preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    preimage_hash = "sha256:" + hashlib.sha256(
        b"acgs.physical.evaluated-motion-preimage/v0\0" + preimage_bytes
    ).hexdigest()
    artifact = {
        "schema_version": "EvaluatedMotionArtifact/v0",
        "preimage": preimage,
        "evaluated_motion_preimage_hash": preimage_hash,
        "decision_event_id": "decision-1",
        "decision_record_argument_hash": argument_hash,
        "audit_event_hash": "a" * 64,
        "previous_audit_hash": "b" * 64,
    }
    artifact_bytes = json.dumps(
        artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    artifact_hash = "sha256:" + hashlib.sha256(
        b"acgs.physical.evaluated-motion-artifact/v0\0" + artifact_bytes
    ).hexdigest()
    assert projection_hash == (
        "sha256:d1af75ca6dfb86818771cbe47cb838d5"
        "36e29c2f11f6060ea122dc038665b2c0"
    )
    assert per_motion_hash == (
        "sha256:c194bdc0e8c88f98cc542b964bf08864"
        "1fd0967ac01c264753aa4bd9d39cd9ec"
    )
    assert argument_hash == (
        "69e156017a2b66ee90f1f8cf82bc54a5"
        "c59ce3487041135bfc4e98ee4451d458"
    )
    assert preimage_hash == (
        "sha256:cdb1d2466b2128830f63bad5f5f87335"
        "1639374eb24595058852a5d77b7aa340"
    )
    assert artifact_hash == (
        "sha256:862c75eb2fe6c51da02dccf522b821ca"
        "59e17115758aa789bdef0ed6d5f26cda"
    )
    mutated_projection = {
        **projection,
        "safety_contract": {"contract_version": "contract/v2"},
    }
    mutated_arguments = {
        **arguments,
        "physical_contract_projection": mutated_projection,
    }
    mutated_bytes = json.dumps(
        mutated_arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert hashlib.sha256(mutated_bytes).hexdigest() != argument_hash
    assert mutated_arguments["physical_contract_projection_hash"] != (
        "sha256:"
        + hashlib.sha256(
            b"acgs.physical.contract-projection/v0\0"
            + json.dumps(
                mutated_projection,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
    )
    mutated_per_motion = {
        **per_motion,
        "trajectory": {**per_motion["trajectory"], "duration_ms": 101},
    }
    mutated_per_motion_bytes = json.dumps(
        mutated_per_motion,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert (
        "sha256:"
        + hashlib.sha256(
            b"acgs.physical.per-motion-binding/v0\0" + mutated_per_motion_bytes
        ).hexdigest()
        != per_motion_hash
    )
    assert "per_motion_binding_hash" not in per_motion
    assert "argument_hash" not in per_motion
    assert "evaluated_motion_preimage_hash" not in per_motion
    for forbidden_alias in (
        "artifact_digest",
        "trajectory_root",
        "block_size",
        "input_plan_digest",
        "lease_request",
    ):
        mixed_name_binding = {**per_motion, forbidden_alias: "forbidden"}
        assert set(mixed_name_binding) != set(per_motion)

    for field, replacement in (
        ("tool", "robot.motion.other"),
        ("actor", "operator-2"),
    ):
        substituted_preimage = {**preimage, field: replacement}
        substituted_bytes = json.dumps(
            substituted_preimage,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        substituted_hash = "sha256:" + hashlib.sha256(
            b"acgs.physical.evaluated-motion-preimage/v0\0" + substituted_bytes
        ).hexdigest()
        assert substituted_hash != preimage_hash

    assert set(preimage) == {
        "schema_version",
        "tool",
        "actor",
        "canonical_tool_arguments",
        "argument_hash",
        "per_motion_binding_hash",
    }
    assert "physical_contract_projection" not in preimage

    frozen = normalized.index("freezes the actual `ToolCall.args`")
    evaluated = normalized.index("Kernel.evaluate_and_append(call)", frozen)
    finalized = normalized.index(
        "finalizes the content-addressed artifact", evaluated
    )
    minted = normalized.index("DecisionReceipt.from_record", finalized)
    activated = normalized.index(
        "load the content-addressed `EvaluatedMotionArtifact/v0`", minted
    )
    assert frozen < evaluated < finalized < minted < activated


def test_questionnaire_success_result_envelope_is_typed_and_byte_canonical() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    section = text.partition("A successful result uses one closed canonical")[2]
    section = section.partition("The product first constructs canonical")[0]
    normalized = re.sub(r"\s+", " ", section).replace("`", "")
    for token in (
        "SuccessfulResultEnvelope/v1",
        (
            "schema_version, result_kind, encoding, payload_hash, "
            "payload_length, and payload_b64"
        ),
        "allowlisted tool-specific type tag",
        "different result types cannot collide",
        "RAW_BYTES",
        "UTF8_TEXT",
        "JCS_JSON",
        "exact returned bytes",
        "strict UTF-8 bytes of the unchanged string",
        "RFC 8785 JCS encoded as UTF-8",
        "RFC 4648 base64 with required padding",
        "inner payload digest and outer envelope digest are distinct",
        "acgs.questionnaire.success-payload/v1\\0",
        "acgs.questionnaire.success-result/v1\\0",
        "OutcomeEvent.result_hash always means only the outer envelope digest",
        "Proof material carries the complete SuccessfulResultEnvelope/v1",
        "inner-hash substitution",
        "raw/text/JSON reinterpretation",
    ):
        assert token in normalized

    payload = b"{}"
    inner = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.success-payload/v1\0"
        + b"QA_RESULT\0JCS_JSON\0"
        + payload
    ).hexdigest()
    envelope = {
        "schema_version": "SuccessfulResultEnvelope/v1",
        "result_kind": "QA_RESULT",
        "encoding": "JCS_JSON",
        "payload_hash": inner,
        "payload_length": len(payload),
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }
    envelope_bytes = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    outer = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.success-result/v1\0" + envelope_bytes
    ).hexdigest()
    assert inner == (
        "sha256:308d772c8c53751e2eb901b230d9228c"
        "bef1beaa6338fbe5ce05181f5cce5dcf"
    )
    assert outer == (
        "sha256:33f1915bec956ebd3ec93567cd0bbe41"
        "cab3498fec6476e7fba2913b7e335b47"
    )
    assert inner != outer

    mining = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2].partition(
        "### 2.4 Response"
    )[0]
    qa = text.partition("### 2.3.1 CitationQARecord")[2].partition(
        "### 2.3.2 SemanticAdjudicationRecord"
    )[0]
    regression = text.partition("### 8.3.10 Immutable assertion-level QA lineage")[2]
    for token in (
        "mining_result_hash is the envelope's inner payload_hash",
        "OutcomeEvent.result_hash is the distinct outer envelope hash",
        "successful_result_envelope",
        "outcome_result_hash",
        "inner/outer hash swap",
    ):
        assert token in re.sub(r"\s+", " ", mining).replace("`", "")
    for token in (
        "qa_result_hash is its inner payload_hash",
        "OutcomeEvent.result_hash is its distinct outer envelope hash",
        "proof material retains the complete envelope",
    ):
        assert token in re.sub(r"\s+", " ", qa).replace("`", "")
    assert "inner qa_result_hash" in regression.replace("`", "")
    assert "outer OutcomeEvent.result_hash" in regression.replace("`", "")


def test_qa_result_preimage_is_closed_acyclic_and_byte_exact() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    section = text.partition("### 2.3.1 CitationQARecord")[2]
    section = section.partition("#### ContradictionRecord")[0]
    normalized = re.sub(r"\s+", " ", section)
    for token in (
        "closed acyclic `QAResultPreimage/v1`",
        "canonical QA `ToolCall` arguments are a closed object containing exactly",
        "`evidence_id`, `source_evidence_hash`, and `producer_lineage_hash`",
        "receipt `argument_hash` must cover those exact canonical bytes",
        "exact `producer_lineage_hash` equality",
        "authenticated `MiningOutcomeEnvelope`",
        "Substituting a valid lineage from another mining result",
        "`result_kind`",
        "`contradiction_candidate`",
        "Unknown fields and alternate types are forbidden",
        "explicitly excludes `qa_result_hash`",
        "outer `OutcomeEvent.result_hash`",
        "`qa_outcome_hash`",
        "every finalized `contradiction_record_id`",
        "every semantic-adjudication id",
        "freeze `QAResultPreimage/v1`",
        "then finalize `CitationQARecord`",
        "closed acyclic `CitationQARecordPreimage/v1`",
        "It excludes `citation_qa_record_hash`",
        "acgs.questionnaire.citation-qa-record/v1\\0",
        "contains only these recomputed hashes",
        "ordered by `(assertion_id, evidence_id, citation_qa_record_id)`",
        "requires byte-for-byte equality",
        "missing field, substituted binding, unknown field",
    ):
        assert token in normalized

    preimage = {
        "schema_version": "QAResultPreimage/v1",
        "result_kind": "QA_RESULT",
        "citation_qa_record_id": "qa-1",
        "job_id": "job-1",
        "question_id": "q-1",
        "response_id": "resp-1",
        "response_version": 1,
        "answer_hash": "sha256:" + "b" * 64,
        "assertion_id": "as-1",
        "assertion_hash": "sha256:" + "a" * 64,
        "evidence_id": "ev-1",
        "source_evidence_hash": "sha256:" + "c" * 64,
        "producer_lineage_hash": "sha256:" + "d" * 64,
        "deterministic_check_passed": True,
        "qa_verdict": "PASS",
        "qa_rationale": "supported",
        "qa_receipt_id": "qa-rec-1",
        "contradiction_candidate": None,
    }
    qa_arguments = {
        key: preimage[key]
        for key in (
            "job_id",
            "question_id",
            "response_id",
            "response_version",
            "answer_hash",
            "assertion_id",
            "assertion_hash",
            "evidence_id",
            "source_evidence_hash",
            "producer_lineage_hash",
        )
    }
    qa_argument_bytes = json.dumps(
        qa_arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    qa_argument_hash = hashlib.sha256(qa_argument_bytes).hexdigest()
    substituted_arguments = {
        **qa_arguments,
        "producer_lineage_hash": "sha256:" + "9" * 64,
    }
    substituted_argument_bytes = json.dumps(
        substituted_arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert hashlib.sha256(substituted_argument_bytes).hexdigest() != qa_argument_hash

    payload = json.dumps(
        preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert len(payload) == 734
    inner = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.success-payload/v1\0"
        + b"QA_RESULT\0JCS_JSON\0"
        + payload
    ).hexdigest()
    envelope = {
        "schema_version": "SuccessfulResultEnvelope/v1",
        "result_kind": "QA_RESULT",
        "encoding": "JCS_JSON",
        "payload_hash": inner,
        "payload_length": len(payload),
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }
    outer = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.success-result/v1\0"
        + json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    assert inner == (
        "sha256:ff7095e6bae2d19139fbb7e73c056c7d"
        "e1a7130ffde47319b44d5474c40b6063"
    )
    assert outer == (
        "sha256:07f5886ce181cd243494fe83badcef00c"
        "7797c35124405bfb5e7564b36739cd1"
    )
    final_record_preimage = {
        "schema_version": "CitationQARecordPreimage/v1",
        **{
            key: preimage[key]
            for key in (
                "citation_qa_record_id",
                "job_id",
                "question_id",
                "response_id",
                "response_version",
                "answer_hash",
                "assertion_id",
                "assertion_hash",
                "evidence_id",
                "source_evidence_hash",
                "producer_lineage_hash",
                "deterministic_check_passed",
                "qa_verdict",
                "qa_rationale",
                "qa_receipt_id",
            )
        },
        "qa_result_hash": inner,
        "qa_successful_result_envelope": envelope,
        "qa_outcome_hash": "sha256:" + "e" * 64,
        "contradiction_record_id": None,
        "contradiction_record_hash": None,
        "semantic_adjudication_record_id": "sem-1",
        "semantic_adjudication_event_hash": "sha256:" + "f" * 64,
        "semantic_adjudication_signature": "sig-1",
        "semantic_signing_key_id": "sem-key-1",
        "semantic_evidence_binding_hash": "sha256:" + "1" * 64,
    }
    final_record_bytes = json.dumps(
        final_record_preimage,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    final_record_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.citation-qa-record/v1\0" + final_record_bytes
    ).hexdigest()
    assert len(final_record_bytes) == 2506
    assert final_record_hash == (
        "sha256:6f24a9ceec24637d7aa61a8caede0ad2"
        "c69903fd778668016982f7ddf962e9a5"
    )
    assert "citation_qa_record_hash" not in final_record_preimage
    substituted_final = {
        **final_record_preimage,
        "semantic_adjudication_record_id": "sem-2",
    }
    assert json.dumps(
        substituted_final,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8") != final_record_bytes

    assert not {
        "qa_result_hash",
        "qa_successful_result_envelope",
        "qa_outcome_hash",
        "contradiction_record_id",
        "contradiction_record_hash",
        "semantic_adjudication_record_id",
    } & preimage.keys()

    missing = dict(preimage)
    missing.pop("evidence_id")
    substituted = dict(preimage, assertion_id="as-2")
    unknown = dict(preimage, qa_outcome_hash="sha256:" + "e" * 64)
    for invalid in (missing, substituted, unknown):
        invalid_bytes = json.dumps(
            invalid, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        assert invalid_bytes != payload

    receipt_checked = normalized.index("validate the QA receipt")
    frozen = normalized.index("freeze `QAResultPreimage/v1`", receipt_checked)
    enveloped = normalized.index("construct `SuccessfulResultEnvelope/v1`", frozen)
    outcome = normalized.index("append and attest its `OutcomeEvent`", enveloped)
    contradiction = normalized.index("convert any authenticated", outcome)
    semantic = normalized.index("obtain the independent semantic event", contradiction)
    finalized = normalized.index("then finalize `CitationQARecord`", semantic)
    assert receipt_checked < frozen < enveloped < outcome < contradiction < semantic
    assert semantic < finalized


def test_partial_support_annotations_do_not_mutate_frozen_answer_lineage(
    monkeypatch,
) -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    response = text.partition("### 2.4 Response")[2].partition("### 2.5 Gap")[0]
    normalized = re.sub(r"\s+", " ", response)
    for token in (
        "PresentationAnnotationPreimage/v1",
        "PresentationAnnotation/v1",
        "it excludes `presentation_annotation_hash`",
        "acgs.questionnaire.presentation-annotation/v1\\0",
        "PresentationAnnotationAuthority",
        "trusted append-only",
        "assertion_index, annotation_kind, presentation_annotation_id",
        "acgs.questionnaire.presentation-annotation-set/v1\\0",
        "each member that fails the full Evidence + QA + semantic support predicate",
        "exactly one annotation",
        "Every supported member has zero annotations",
        "canonical empty-set root",
        "presentation_annotation_set_root",
        "acyclic two-stage content/authority layering",
        "ContentManifestPreimage/v1",
        "ordered_payload_artifacts",
        "Membership is exact",
        "acgs.questionnaire.content-manifest/v1\\0",
        "no `AssemblyLineagePreimage/v1`",
        "no assembly acceptance/proof/archive file",
        "no detached outer index",
        "AssemblyLineagePreimage/v1",
        "ordered_citation_qa_record_hashes",
        "ordered_semantic_adjudication_event_hashes",
        "ordered_contradiction_record_hashes",
        "It excludes `assembly_lineage_hash`",
        "acgs.questionnaire.assembly-lineage/v1\\0",
        "AssemblyVerificationManifestPreimage/v1",
        "acgs.questionnaire.assembly-verification-manifest/v1\\0",
        "AssemblyVerificationManifestEnvelope/v1",
        "explicit accepted-at RFC 3339 instant",
        "already verified policy trust chain",
        "complete policy-bundle preimage, materialized bundle, `DecisionReceipt`",
        "canonically decodes and verifies the envelope's own `root_signature`",
        "never accepts an out-of-band signature or public key",
        "validate_verified_assembly_trust_chain",
        "exact leaf `authority_id`, `signing_key_id`, sequence, predecessor",
        "own linearizable high-water lookup",
        "caller-supplied head object has no authority",
        "before any store mutation",
        "no implicit missing-row genesis",
        "atomic compare-and-swap transaction",
        "Two concurrent authenticated candidates for one successor",
        "AssemblyManifestHeadStoreRecordPreimage/v1",
        "AssemblyManifestHeadReadbackProof/v1",
        "`RegistryKeyAuthorityProof/v1` validation invokes this verifier",
        "public_key_spki_der_b64u",
        "acgs.questionnaire.p256-spki/v1\\0",
        "assembly-verification-manifest-signature/v1\\0",
        "AssemblyVerificationTrustManifest/v1",
        "root key is not learned from this envelope",
        "durable verifier high-water store",
        "P1363_BASE64URL_NOPAD",
        "low-S",
        "AssemblyToolArguments/v1",
        "ToolCall.argument_hash()",
        "Mapping[str, JSONValue]",
        "canonical_json(dict(ToolCall.args))",
        "RFC 8785/JCS hashes elsewhere",
        "shared receipt-burn authority consumes the receipt anchor once",
        "ReceiptAnchorPreimage/v1",
        "acgs.questionnaire.receipt-anchor/v1\\0",
        "key is selected solely by the decision audit hash",
        "neither selects or changes the consumption key",
        "Re-minting, re-signing, changing expiry, subject, or signing key",
        "receipt_consumptions/{receipt_anchor}",
        "linearizable create-if-absent",
        "ReceiptBurnAcceptancePreimage/v1",
        "ReceiptBurnStoreRecordPreimage/v1",
        "closed verified-grant table",
        "DecisionReceipt.verify(...)",
        "independently authenticated policy archive",
        "QuestionnairePolicyBundle.receipt_verification_key_manifest_hash",
        "caller-supplied verifier map",
        "DecisionReceipt.decision == \"allow\"",
        "authoritative assembly-head store/readback record",
        "must equal archive `accepted_at`",
        "same instant",
        "mixed or nested values fail closed",
        "partially projected same-audit remint never",
        "ReceiptBurnAcceptance/v1",
        "YYYY-MM-DDTHH:MM:SS.ffffffZ",
        "obtained from the durable store's trusted commit clock",
        "callers cannot supply or override it",
        "acgs.questionnaire.receipt-burn-acceptance/v1\\0",
        "receipt-burn-acceptance-signature/v1\\0",
        "AssemblyAcceptancePreimage/v1",
        "`assembly_receipt_id`, `assembly_receipt_hash`",
        "`assembly_burn_acceptance_hash`",
        "`assembly_burn_acceptance_signature`",
        "`burn_verification_manifest_hash`",
        "`assembly_outcome_hash`",
        "preimage excludes `assembly_acceptance_hash`, `signature`",
        "acgs.questionnaire.assembly-acceptance/v1\\0",
        "AssemblyAcceptance/v1",
        "immutable assembly-acceptance store",
        "embedded in the proof pack",
        "without network or store access",
        "online-only audit check",
        "FinalPackIndex/v1",
        "never an input to the content manifest",
        "A recomputed unkeyed replacement",
        "self-inclusion, cycle",
        "has no delivery authority",
        "cannot change `answer_text`, `answer_hash`, assertion byte spans",
        "new response version",
        "complete resegmentation, mining, QA, and semantic adjudication",
    ):
        assert token in normalized
    trust_contract = text.partition(
        "The closed `AssemblyVerificationTrustManifest/v1` artifact"
    )[2].partition(
        "The closed root-signed `ReceiptBurnVerificationManifestPreimage/v1`"
    )[0]
    for token in (
        "literal `Z` and no fraction or offset",
        "sorted duplicate-free `list[str]`",
    ):
        assert token in trust_contract
    tool_args = normalized.index("AssemblyToolArguments/v1")
    receipt = normalized.index("Only a signed, unexpired `ALLOW` receipt", tool_args)
    burn = normalized.index("consumes the receipt anchor once", receipt)
    outcome = normalized.index("accepted successful `OutcomeEvent`", burn)
    acceptance = normalized.index("AssemblyAcceptancePreimage/v1", outcome)
    assert tool_args < receipt < burn < outcome < acceptance
    assert "marked inline in answer_text" not in text

    regression = text.partition("For a partially supported response")[2].partition(
        "### 8.3.12"
    )[0]
    for token in (
        "each unsupported/adverse member has exactly one",
        "each supported member has none",
        "Recompute the ordered annotation-set root, exact payload membership",
        "`content_manifest_hash`, `assembly_lineage_hash`, signed acceptance",
        "add self-inclusion, omit an expected payload",
        "feed the detached index back into a preimage",
        "proof-pack-supplied trust root",
        "expired, not-yet-valid, revoked, or rolled-back manifest",
        "Valid P-256 vectors must verify",
        "assembly `DecisionReceipt`",
        "`DENY`, `ESCALATE`, or `TRANSFORM`",
        "zero pack writes before a valid burn",
        "replay its signed envelope",
        "mutate the audit member of `ReceiptAnchorPreimage/v1`",
        "same `receipt_consumptions/{receipt_anchor}` key",
        "wrong root/purpose/domain/key/algorithm",
        "accepted outcome and closed signed",
        "append-only annotation authority refuses mutation",
        "frozen answer bytes/hash/spans never change",
    ):
        assert token in re.sub(r"\s+", " ", regression)

    trust = text.partition("### 6.1 Threat model — what is trusted")[2].partition(
        "### 6.2 Prompt injection"
    )[0]
    for token in (
        "`PresentationAnnotationAuthority` identity and append-only annotation store",
        "`AssemblyAuthority`, receipt-gated assembly executor",
        "dedicated KMS key custody",
        "Assembly verification trust-root keys",
        "monotonic manifest high-water store",
        "compromise can substitute an assembly verification key",
        "purpose-bound signing key/trust manifest",
    ):
        assert token in trust

    universal_gate = text.partition("### 3.2 The universal gate")[2].partition(
        "### 3.3 Step gates"
    )[0]
    for token in (
        "Assembly is not an exception",
        "`AssemblyToolArguments/v1`",
        "`ALLOW` `DecisionReceipt`",
        "burns it once before writing bytes",
        "accepted successful `OutcomeEvent`",
        "zero pack writes",
    ):
        assert token in universal_gate

    def digest(char: str) -> str:
        return "sha256:" + char * 64

    def domain_hash(domain: str, payload: bytes) -> str:
        return "sha256:" + hashlib.sha256(
            domain.encode("ascii") + b"\0" + payload
        ).hexdigest()

    def vector_jcs(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def is_closed_json_value(value: object) -> bool:
        return _is_closed_json_value(value)

    content = {
        "schema_version": "ContentManifestPreimage/v1",
        "job_id": "job-1",
        "question_id": "q-1",
        "response_id": "resp-1",
        "response_version": 1,
        "answer_hash": digest("a"),
        "assertion_manifest_hash": digest("b"),
        "response_lineage_hash": digest("c"),
        "presentation_annotation_set_root": digest("f"),
        "ordered_payload_artifacts": [
            {
                "relative_path": "answer.json",
                "artifact_kind": "RESPONSE",
                "media_type": "application/json",
                "byte_length": 2,
                "artifact_hash": digest("2"),
            },
            {
                "relative_path": "qa/qa-1.json",
                "artifact_kind": "CITATION_QA_RECORD",
                "media_type": "application/json",
                "byte_length": 3,
                "artifact_hash": digest("3"),
            },
        ],
    }
    content_bytes = json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    content_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.content-manifest/v1\0" + content_bytes
    ).hexdigest()
    assert len(content_bytes) == 958
    assert content_hash == (
        "sha256:a6b4216511d36b6c26ca3d146140f65b"
        "cc850e926466c1482a27ef2b504bf0a6"
    )
    forbidden_content_fields = {
        "content_manifest_hash",
        "assembly_lineage_hash",
        "assembly_acceptance_hash",
        "final_pack_index_hash",
    }
    assert not forbidden_content_fields & content.keys()
    for forbidden_field in forbidden_content_fields:
        self_including_content = {**content, forbidden_field: digest("9")}
        assert set(self_including_content) != set(content)
        assert json.dumps(
            self_including_content,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") != content_bytes

    assembly = {
        "schema_version": "AssemblyLineagePreimage/v1",
        "job_id": "job-1",
        "question_id": "q-1",
        "response_id": "resp-1",
        "response_version": 1,
        "answer_hash": digest("a"),
        "assertion_manifest_hash": digest("b"),
        "response_lineage_hash": digest("c"),
        "ordered_citation_qa_record_hashes": [digest("d")],
        "ordered_semantic_adjudication_event_hashes": [digest("e")],
        "ordered_contradiction_record_hashes": [],
        "presentation_annotation_set_root": digest("f"),
        "content_manifest_hash": content_hash,
    }
    assembly_bytes = json.dumps(
        assembly, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assembly_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.assembly-lineage/v1\0" + assembly_bytes
    ).hexdigest()
    assert len(assembly_bytes) == 895
    assert assembly_hash == (
        "sha256:47e9884130e25c9a923fed28043e445d"
        "0fe22283b26c5e7e78fc094828ae2657"
    )
    assembly_spki = _p256_spki(2)
    assembly_spki_b64u = base64.urlsafe_b64encode(assembly_spki).rstrip(b"=").decode()
    assembly_spki_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.p256-spki/v1\0" + assembly_spki
    ).hexdigest()
    verification_manifest = {
        "schema_version": "AssemblyVerificationManifestPreimage/v1",
        "manifest_id": "assembly-manifest-1",
        "manifest_sequence": 7,
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "authority_id": "assembly-authority-1",
        "key_purpose": "ASSEMBLY_ACCEPTANCE_SIGNING",
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "signing_key_id": "assembly-key-1",
        "public_key_spki_der_b64u": assembly_spki_b64u,
        "public_key_spki_sha256": assembly_spki_hash,
        "valid_from": "2026-07-01T00:00:00Z",
        "valid_until": "2026-08-01T00:00:00Z",
        "revoked_at": None,
        "previous_verification_manifest_hash": digest("8"),
    }
    assert set(verification_manifest) == {
        "schema_version",
        "manifest_id",
        "manifest_sequence",
        "trust_root_id",
        "trust_root_version",
        "authority_id",
        "key_purpose",
        "signature_algorithm",
        "signature_encoding",
        "signing_key_id",
        "public_key_spki_der_b64u",
        "public_key_spki_sha256",
        "valid_from",
        "valid_until",
        "revoked_at",
        "previous_verification_manifest_hash",
    }
    verification_manifest_bytes = json.dumps(
        verification_manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    verification_manifest_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.assembly-verification-manifest/v1\0"
        + verification_manifest_bytes
    ).hexdigest()
    assert len(verification_manifest_bytes) == 832
    assert verification_manifest_hash == (
        "sha256:89155b6f6020157d52e361bf0091875b"
        "b58941a70220ced64ec0c79d2876745c"
    )

    manifest_signature_message = (
        b"acgs.questionnaire.assembly-verification-manifest-signature/v1\0"
        + verification_manifest_hash.encode("ascii")
    )
    root_signature_raw = _p256_sign(manifest_signature_message, 1, 3)
    root_signature = base64.urlsafe_b64encode(root_signature_raw).rstrip(b"=").decode()
    assert root_signature == (
        "Xsvk0aYzCkTI9--VHUvxZebGtyHvramF-0FmG8bn_WxMykOTAZT62Io4Z7V_"
        "hhsLKAGMNa6vPW1ZCi7uvv2tnw"
    )
    assert len(root_signature) == 86
    assert "=" not in root_signature
    assert _p256_verify(manifest_signature_message, root_signature_raw, 1)
    assert not _p256_verify(manifest_signature_message, root_signature_raw, 2)
    verification_manifest_envelope = {
        "schema_version": "AssemblyVerificationManifestEnvelope/v1",
        "preimage": verification_manifest,
        "verification_manifest_hash": verification_manifest_hash,
        "root_signature_algorithm": "ECDSA_P256_SHA256",
        "root_signature_encoding": "P1363_BASE64URL_NOPAD",
        "root_signing_key_id": "assembly-root-key-1",
        "root_signature": root_signature,
    }
    assert set(verification_manifest_envelope) == {
        "schema_version",
        "preimage",
        "verification_manifest_hash",
        "root_signature_algorithm",
        "root_signature_encoding",
        "root_signing_key_id",
        "root_signature",
    }

    manifest_envelope_fields = {
        "schema_version",
        "preimage",
        "verification_manifest_hash",
        "root_signature_algorithm",
        "root_signature_encoding",
        "root_signing_key_id",
        "root_signature",
    }
    manifest_preimage_fields = set(verification_manifest)

    def parse_rfc3339_instant(value: object) -> datetime:
        if type(value) is not str:
            raise ValueError("not a timezone-aware RFC 3339 instant")
        try:
            if re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
                value,
            ) is None:
                raise ValueError("not a timezone-aware RFC 3339 instant")
            normalized = (
                value[:-1] + "+00:00" if value.endswith("Z") else value
            )
            parsed = datetime.fromisoformat(normalized)
        except Exception as error:
            raise ValueError("not a timezone-aware RFC 3339 instant") from error
        if parsed.tzinfo is None:
            raise ValueError("timezone is required")
        return parsed.astimezone(UTC)

    def canonical_b64u(value: object) -> bytes:
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
            or "=" in value
        ):
            raise ValueError("non-canonical base64url")
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
            raise ValueError("non-canonical base64url")
        return decoded

    def make_manifest_envelope(
        preimage: dict[str, object],
        nonce: int,
        private_scalar: int = 1,
    ) -> dict[str, object]:
        candidate_hash = domain_hash(
            "acgs.questionnaire.assembly-verification-manifest/v1",
            vector_jcs(preimage),
        )
        signature = _p256_sign(
            b"acgs.questionnaire.assembly-verification-manifest-signature/v1\0"
            + candidate_hash.encode("ascii"),
            private_scalar,
            nonce,
        )
        return {
            "schema_version": "AssemblyVerificationManifestEnvelope/v1",
            "preimage": preimage,
            "verification_manifest_hash": candidate_hash,
            "root_signature_algorithm": "ECDSA_P256_SHA256",
            "root_signature_encoding": "P1363_BASE64URL_NOPAD",
            "root_signing_key_id": "assembly-root-key-1",
            "root_signature": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode(),
        }

    assembly_root_snapshot = {
        "snapshot_sequence": 4,
        "issued_at": "2026-07-01T00:00:00Z",
        "revoked_signing_key_ids": [],
        "revoked_verification_manifest_hashes": [],
    }
    assembly_root_preimage = {
        "schema_version": "AssemblyVerificationTrustManifestPreimage/v1",
        "trust_root_id": "assembly-root-1",
        "trust_root_version": 2,
        "root_signing_key_id": "assembly-root-key-1",
        "authorized_manifest_purposes": [
            "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING",
            "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
            "RECEIPT_BURN_VERIFICATION_MANIFEST_SIGNING",
        ],
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "root_public_key_spki_der_b64u": base64.urlsafe_b64encode(_p256_spki(1))
        .rstrip(b"=")
        .decode(),
        "root_public_key_spki_sha256": domain_hash(
            "acgs.questionnaire.p256-spki/v1",
            _p256_spki(1),
        ),
        "min_manifest_sequence": 7,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "head_acceptance_key_purpose": "BURN_MANIFEST_HEAD_ACCEPTANCE_SIGNING",
        "predecessor_signing_key_purpose": (
            "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING"
        ),
        "predecessor_signing_domain": (
            "acgs.questionnaire.assembly-manifest-predecessor-signature/v1"
        ),
        "revocation_snapshot": assembly_root_snapshot,
        "revocation_snapshot_hash": domain_hash(
            "acgs.questionnaire.assembly-revocation-snapshot/v1",
            vector_jcs(assembly_root_snapshot),
        ),
    }

    assembly_head_lock = threading.Lock()
    assembly_head_store: dict[tuple[str, str], dict[str, object]] = {}
    assembly_authenticated_predecessors: dict[
        tuple[str, str], dict[str, object]
    ] = {}
    assembly_predecessor_lock = threading.Lock()
    assembly_head_generation = 0
    assembly_head_lookup_uncertain = False
    predecessor_preimage_fields = {
        "schema_version",
        "trust_root_id",
        "trust_root_version",
        "manifest_id",
        "predecessor_sequence",
        "next_sequence",
        "predecessor_manifest_hash",
        "signing_key_purpose",
        "policy_bundle_id",
        "policy_version",
    }
    predecessor_envelope_fields = {
        "schema_version",
        "preimage",
        "predecessor_record_hash",
        "signature_algorithm",
        "signature_encoding",
        "root_signing_key_id",
        "signature",
    }

    def make_authenticated_assembly_predecessor(
        manifest_id: str,
        predecessor_sequence: int,
        predecessor_hash: str,
        policy_chain: dict[str, object],
        nonce: int,
        signing_key_purpose: str = (
            "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING"
        ),
    ) -> dict[str, object]:
        policy_bundle_value = policy_chain["policy_bundle"]
        trust_manifest_value = policy_chain["assembly_trust_manifest"]
        assert isinstance(policy_bundle_value, dict)
        assert isinstance(trust_manifest_value, dict)
        trust_preimage_value = trust_manifest_value["preimage"]
        assert isinstance(trust_preimage_value, dict)
        preimage = {
            "schema_version": "AssemblyManifestPredecessorPreimage/v1",
            "trust_root_id": trust_preimage_value["trust_root_id"],
            "trust_root_version": trust_preimage_value[
                "trust_root_version"
            ],
            "manifest_id": manifest_id,
            "predecessor_sequence": predecessor_sequence,
            "next_sequence": predecessor_sequence + 1,
            "predecessor_manifest_hash": predecessor_hash,
            "signing_key_purpose": signing_key_purpose,
            "policy_bundle_id": policy_bundle_value["policy_bundle_id"],
            "policy_version": policy_bundle_value["policy_version"],
        }
        record_hash = domain_hash(
            "acgs.questionnaire.assembly-manifest-predecessor/v1",
            vector_jcs(preimage),
        )
        signing_domain = trust_preimage_value[
            "predecessor_signing_domain"
        ]
        assert isinstance(signing_domain, str)
        signature = _p256_sign(
            signing_domain.encode("ascii")
            + b"\0"
            + record_hash.encode("ascii"),
            1,
            nonce,
        )
        return {
            "schema_version": "AssemblyManifestPredecessorEnvelope/v1",
            "preimage": preimage,
            "predecessor_record_hash": record_hash,
            "signature_algorithm": "ECDSA_P256_SHA256",
            "signature_encoding": "P1363_BASE64URL_NOPAD",
            "root_signing_key_id": "assembly-root-key-1",
            "signature": base64.urlsafe_b64encode(signature)
            .rstrip(b"=")
            .decode(),
        }

    def register_authenticated_assembly_predecessor(
        envelope: object,
        policy_chain: object,
    ) -> bool:
        if type(envelope) is not dict or type(policy_chain) is not dict:
            return False
        if not _is_closed_json_value(envelope):
            return False
        preimage = envelope.get("preimage")
        if (
            set(envelope) != predecessor_envelope_fields
            or type(preimage) is not dict
            or set(preimage) != predecessor_preimage_fields
            or preimage.get("schema_version")
            != "AssemblyManifestPredecessorPreimage/v1"
            or envelope.get("schema_version")
            != "AssemblyManifestPredecessorEnvelope/v1"
        ):
            return False
        trust = validate_verified_assembly_trust_chain(
            policy_chain,
            "2026-07-26T22:45:00Z",
        )
        if trust is None:
            return False
        try:
            root_spki = _canonical_b64u(
                trust["root_public_key_spki_der_b64u"]
            )
            signature = _canonical_b64u(envelope["signature"])
            policy_bundle_value = policy_chain["policy_bundle"]
            if type(policy_bundle_value) is not dict:
                return False
        except (KeyError, TypeError, ValueError):
            return False
        record_hash = _safe_domain_hash(
            "acgs.questionnaire.assembly-manifest-predecessor/v1",
            preimage,
        )
        if record_hash is None:
            return False
        fields_valid = (
            envelope["predecessor_record_hash"] == record_hash
            and envelope["signature_algorithm"] == "ECDSA_P256_SHA256"
            and envelope["signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and envelope["root_signing_key_id"]
            == trust["root_signing_key_id"]
            and preimage["trust_root_id"] == trust["trust_root_id"]
            and preimage["trust_root_version"]
            == trust["trust_root_version"]
            and type(preimage["manifest_id"]) is str
            and bool(preimage["manifest_id"])
            and type(preimage["predecessor_sequence"]) is int
            and preimage["predecessor_sequence"] >= 0
            and type(preimage["next_sequence"]) is int
            and preimage["next_sequence"]
            == preimage["predecessor_sequence"] + 1
            and preimage["signing_key_purpose"]
            == trust["predecessor_signing_key_purpose"]
            and preimage["signing_key_purpose"]
            in trust["authorized_manifest_purposes"]
            and type(preimage["predecessor_manifest_hash"]) is str
            and re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                preimage["predecessor_manifest_hash"],
            )
            is not None
            and preimage["policy_bundle_id"]
            == policy_bundle_value["policy_bundle_id"]
            and preimage["policy_version"]
            == policy_bundle_value["policy_version"]
        )
        predecessor_domain = trust["predecessor_signing_domain"]
        if type(predecessor_domain) is not str:
            return False
        if not fields_valid or not _safe_p256_verify_spki(
            predecessor_domain.encode("ascii")
            + b"\0"
            + record_hash.encode("ascii"),
            signature,
            root_spki,
        ):
            return False
        key = (
            str(preimage["trust_root_id"]),
            str(preimage["manifest_id"]),
        )
        predecessor_record = {
            "predecessor_record_hash": record_hash,
            "predecessor_sequence": preimage["predecessor_sequence"],
            "next_sequence": preimage["next_sequence"],
            "predecessor_manifest_hash": preimage[
                "predecessor_manifest_hash"
            ],
            "signing_key_purpose": preimage["signing_key_purpose"],
        }
        with assembly_predecessor_lock:
            existing = assembly_authenticated_predecessors.get(key)
            if existing is not None:
                return existing == predecessor_record
            assembly_authenticated_predecessors[key] = predecessor_record
        return True

    def publish_assembly_manifest_head(
        envelope: object,
        policy_chain: object,
    ) -> bool:
        nonlocal assembly_head_generation
        if type(envelope) is not dict or type(policy_chain) is not dict:
            return False
        if not is_closed_json_value(envelope):
            return False
        candidate_preimage = envelope.get("preimage")
        if (
            set(envelope) != manifest_envelope_fields
            or type(candidate_preimage) is not dict
            or set(candidate_preimage) != manifest_preimage_fields
            or candidate_preimage.get("schema_version")
            != "AssemblyVerificationManifestPreimage/v1"
        ):
            return False
        validated_trust = validate_verified_assembly_trust_chain(
            policy_chain,
            "2026-07-26T22:45:00Z",
        )
        required_ids = (
            "manifest_id",
            "trust_root_id",
            "authority_id",
            "signing_key_id",
            "key_purpose",
        )
        if (
            validated_trust is None
            or any(
                type(candidate_preimage[field]) is not str
                or not candidate_preimage[field]
                for field in required_ids
            )
            or type(candidate_preimage["manifest_sequence"]) is not int
            or type(candidate_preimage["trust_root_version"]) is not int
        ):
            return False
        try:
            root_spki = _canonical_b64u(
                validated_trust["root_public_key_spki_der_b64u"]
            )
            leaf_spki = _canonical_b64u(
                candidate_preimage["public_key_spki_der_b64u"]
            )
            signature = _canonical_b64u(envelope["root_signature"])
            accepted_at = parse_rfc3339_instant("2026-07-26T22:45:00Z")
            leaf_valid_from = parse_rfc3339_instant(
                candidate_preimage["valid_from"]
            )
            leaf_valid_until = parse_rfc3339_instant(
                candidate_preimage["valid_until"]
            )
        except (KeyError, TypeError, ValueError):
            return False
        candidate_hash = _safe_domain_hash(
            "acgs.questionnaire.assembly-verification-manifest/v1",
            candidate_preimage,
        )
        leaf_spki_hash = _safe_domain_bytes_hash(
            "acgs.questionnaire.p256-spki/v1",
            leaf_spki,
        )
        if candidate_hash is None or leaf_spki_hash is None:
            return False
        candidate_message = (
            b"acgs.questionnaire.assembly-verification-manifest-signature/v1\0"
            + candidate_hash.encode("ascii")
        )
        if not (
            envelope["schema_version"]
            == "AssemblyVerificationManifestEnvelope/v1"
            and envelope["verification_manifest_hash"] == candidate_hash
            and envelope["root_signature_algorithm"] == "ECDSA_P256_SHA256"
            and envelope["root_signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and envelope["root_signing_key_id"]
            == validated_trust["root_signing_key_id"]
            and candidate_preimage.get("trust_root_id")
            == validated_trust["trust_root_id"]
            and candidate_preimage.get("trust_root_version")
            == validated_trust["trust_root_version"]
            and candidate_preimage.get("authority_id")
            == "assembly-authority-1"
            and candidate_preimage.get("signing_key_id") == "assembly-key-1"
            and candidate_preimage.get("key_purpose")
            == "ASSEMBLY_ACCEPTANCE_SIGNING"
            and candidate_preimage.get("signature_algorithm")
            == "ECDSA_P256_SHA256"
            and candidate_preimage.get("signature_encoding")
            == "P1363_BASE64URL_NOPAD"
            and leaf_spki == assembly_spki
            and candidate_preimage.get("public_key_spki_sha256")
            == leaf_spki_hash
            and leaf_valid_from <= accepted_at < leaf_valid_until
            and candidate_preimage.get("revoked_at") is None
            and candidate_preimage.get("manifest_sequence")
            >= validated_trust["min_manifest_sequence"]
            and "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING"
            in validated_trust["authorized_manifest_purposes"]
            and validated_trust["root_signing_key_id"]
            not in validated_trust["revocation_snapshot"][
                "revoked_signing_key_ids"
            ]
            and candidate_preimage.get("signing_key_id")
            not in validated_trust["revocation_snapshot"][
                "revoked_signing_key_ids"
            ]
            and candidate_hash
            not in validated_trust["revocation_snapshot"][
                "revoked_verification_manifest_hashes"
            ]
            and _safe_p256_verify_spki(candidate_message, signature, root_spki)
        ):
            return False
        key = (
            str(candidate_preimage["trust_root_id"]),
            str(candidate_preimage["manifest_id"]),
        )
        with assembly_head_lock:
            current = assembly_head_store.get(key)
            if current is not None:
                if (
                    current["manifest_sequence"]
                    == candidate_preimage["manifest_sequence"]
                    and current["verification_manifest_hash"] == candidate_hash
                ):
                    return True
                if not (
                    candidate_preimage["manifest_sequence"]
                    == int(current["manifest_sequence"]) + 1
                    and candidate_preimage[
                        "previous_verification_manifest_hash"
                    ]
                    == current["verification_manifest_hash"]
                ):
                    return False
            else:
                predecessor = assembly_authenticated_predecessors.get(key)
                if (
                    predecessor is None
                    or predecessor["predecessor_manifest_hash"]
                    != candidate_preimage[
                        "previous_verification_manifest_hash"
                    ]
                    or predecessor["next_sequence"]
                    != candidate_preimage["manifest_sequence"]
                    or predecessor["signing_key_purpose"]
                    != "ASSEMBLY_MANIFEST_PREDECESSOR_SIGNING"
                ):
                    return False
            assembly_head_generation += 1
            assembly_head_store[key] = {
                "manifest_sequence": candidate_preimage["manifest_sequence"],
                "verification_manifest_hash": candidate_hash,
                "previous_verification_manifest_hash": candidate_preimage[
                    "previous_verification_manifest_hash"
                ],
                "authority_id": candidate_preimage["authority_id"],
                "signing_key_id": candidate_preimage["signing_key_id"],
                "generation": assembly_head_generation,
                "accepted_at": "2026-07-26T22:45:00Z",
            }
            return True

    def lookup_assembly_manifest_head(
        trust_root_id: str,
        manifest_id: str,
    ) -> dict[str, object] | None:
        if assembly_head_lookup_uncertain:
            return None
        with assembly_head_lock:
            current = assembly_head_store.get((trust_root_id, manifest_id))
            return None if current is None else dict(current)

    policy_receipt_signing_seed = b"\x09" * 32
    policy_receipt_public_key, _ = _ed25519_sign(
        policy_receipt_signing_seed,
        b"",
    )
    policy_receipt_key_id = "questionnaire-receipt-key-assembly-1"
    policy_receipt_key_manifest = {
        "schema_version": "ReceiptVerificationKeyManifest/v1",
        "manifest_id": "questionnaire-receipt-keys/assembly-v1",
        "key_purpose": "DECISION_RECEIPT_SIGNING",
        "key_id": policy_receipt_key_id,
        "status": "ACTIVE",
        "signature_algorithm": "ed25519",
        "public_key_b64u": base64.urlsafe_b64encode(
            policy_receipt_public_key
        ).rstrip(b"=").decode(),
        "valid_from": "2026-07-01T00:00:00Z",
        "valid_until": "2026-08-01T00:00:00Z",
        "revoked_key_ids": [],
    }

    def make_manifest_policy_chain(
        trust_preimage: dict[str, object],
        candidate_preimage: dict[str, object] = verification_manifest,
        receipt_key_manifest: dict[str, object] | None = None,
        archive_accepted_at: str = "2026-07-26T22:45:00Z",
    ) -> dict[str, object]:
        selected_receipt_manifest = (
            policy_receipt_key_manifest
            if receipt_key_manifest is None
            else receipt_key_manifest
        )
        selected_receipt_manifest_hash = domain_hash(
            "acgs.questionnaire.receipt-verification-keys/v1",
            vector_jcs(selected_receipt_manifest),
        )
        trust_hash = domain_hash(
            "acgs.questionnaire.assembly-verification-trust/v1",
            vector_jcs(trust_preimage),
        )
        policy_preimage = {
            "schema_version": "QuestionnairePolicyBundlePreimage/v1",
            "policy_bundle_id": "questionnaire-default",
            "decision_policy_artifact_hash": digest("1"),
            "registry_verification_key_manifest_hash": digest("2"),
            "receipt_verification_key_manifest_hash": (
                selected_receipt_manifest_hash
            ),
            "assembly_verification_trust_manifest_hash": trust_hash,
            "burn_verification_manifest_hash": digest("3"),
            "burn_manifest_head_acceptance_hash": digest("4"),
        }
        policy_version = "questionnaire-policy/" + hashlib.sha256(
            b"acgs.questionnaire.policy-bundle/v1\0"
            + vector_jcs(policy_preimage)
        ).hexdigest()
        policy_bundle = {
            "schema_version": "QuestionnairePolicyBundle/v1",
            "policy_bundle_id": policy_preimage["policy_bundle_id"],
            "policy_version": policy_version,
            **{
                field: policy_preimage[field]
                for field in policy_preimage
                if field not in {"schema_version", "policy_bundle_id"}
            },
        }
        policy_archive_preimage = {
            "schema_version": "QuestionnairePolicyArchiveAcceptancePreimage/v1",
            "purpose": "QUESTIONNAIRE_POLICY_BUNDLE_SIGNING",
            "trust_root_id": trust_preimage["trust_root_id"],
            "trust_root_version": trust_preimage["trust_root_version"],
            "policy_bundle_id": policy_bundle["policy_bundle_id"],
            "policy_version": policy_bundle["policy_version"],
            "receipt_verification_key_manifest_hash": (
                selected_receipt_manifest_hash
            ),
            "accepted_at": archive_accepted_at,
        }
        policy_archive_hash = domain_hash(
            "acgs.questionnaire.policy-archive-acceptance/v1",
            vector_jcs(policy_archive_preimage),
        )
        policy_archive_signature = _p256_sign(
            b"acgs.questionnaire.policy-archive-acceptance-signature/v1\0"
            + policy_archive_hash.encode("ascii"),
            1,
            71,
        )
        policy_chain = {
            "policy_bundle_preimage": policy_preimage,
            "policy_bundle": policy_bundle,
            "decision_receipt": {
                "policy_bundle_id": "questionnaire-default",
                "policy_version": policy_version,
                "policy_hash": policy_version,
            },
            "assembly_trust_manifest": {
                "schema_version": "AssemblyVerificationTrustManifest/v1",
                "preimage": trust_preimage,
                "assembly_verification_trust_manifest_hash": trust_hash,
            },
            "receipt_verification_key_manifest": selected_receipt_manifest,
            "policy_archive_acceptance": {
                "schema_version": "QuestionnairePolicyArchiveAcceptance/v1",
                "preimage": policy_archive_preimage,
                "acceptance_hash": policy_archive_hash,
                "signature_algorithm": "ECDSA_P256_SHA256_RAW_RS_LOW_S",
                "signature_b64u": base64.urlsafe_b64encode(
                    policy_archive_signature
                ).rstrip(b"=").decode(),
            },
        }
        return policy_chain

    def manifest_is_accepted(
        envelope: object,
        accepted_at_value: object,
        verified_policy_chain: object,
    ) -> bool:
        if type(envelope) is not dict or type(verified_policy_chain) is not dict:
            return False
        if not is_closed_json_value(envelope):
            return False
        candidate = envelope.get("preimage")
        if (
            set(envelope) != manifest_envelope_fields
            or type(candidate) is not dict
            or set(candidate) != manifest_preimage_fields
        ):
            return False
        required_ids = (
            "manifest_id",
            "trust_root_id",
            "authority_id",
            "key_purpose",
            "signing_key_id",
        )
        if any(
            type(candidate[field]) is not str or not candidate[field]
            for field in required_ids
        ):
            return False
        if (
            type(candidate["manifest_sequence"]) is not int
            or candidate["manifest_sequence"] < 0
            or type(candidate["trust_root_version"]) is not int
            or candidate["trust_root_version"] < 0
        ):
            return False
        validated_trust_preimage = validate_verified_assembly_trust_chain(
            verified_policy_chain,
            accepted_at_value,
        )
        if validated_trust_preimage is None:
            return False
        try:
            accepted_at = parse_rfc3339_instant(accepted_at_value)
            leaf_valid_from = parse_rfc3339_instant(candidate["valid_from"])
            leaf_valid_until = parse_rfc3339_instant(candidate["valid_until"])
            policy_preimage = verified_policy_chain["policy_bundle_preimage"]
            policy_bundle = verified_policy_chain["policy_bundle"]
            receipt = verified_policy_chain["decision_receipt"]
            trust_manifest = verified_policy_chain["assembly_trust_manifest"]
            if not all(
                type(item) is dict
                for item in (
                    policy_preimage,
                    policy_bundle,
                    receipt,
                    trust_manifest,
                )
            ):
                return False
            trust_preimage = validated_trust_preimage
            root_valid_from = parse_rfc3339_instant(trust_preimage["valid_from"])
            root_valid_until = parse_rfc3339_instant(trust_preimage["valid_until"])
            root_spki = canonical_b64u(
                trust_preimage["root_public_key_spki_der_b64u"]
            )
            leaf_spki = canonical_b64u(candidate["public_key_spki_der_b64u"])
            signature = canonical_b64u(envelope["root_signature"])
        except (KeyError, TypeError, ValueError):
            return False
        if len(signature) != 64:
            return False
        candidate_hash = _safe_domain_hash(
            "acgs.questionnaire.assembly-verification-manifest/v1",
            candidate,
        )
        if candidate_hash is None:
            return False
        manifest_head = lookup_assembly_manifest_head(
            str(candidate["trust_root_id"]),
            str(candidate["manifest_id"]),
        )
        if manifest_head is None:
            return False
        trust_hash = _safe_domain_hash(
            "acgs.questionnaire.assembly-verification-trust/v1",
            trust_preimage,
        )
        policy_payload = _safe_canonical_jcs(policy_preimage)
        policy_version = _safe_domain_bytes_hash(
            "acgs.questionnaire.policy-bundle/v1",
            policy_payload,
            "questionnaire-policy/",
        )
        root_spki_hash = _safe_domain_bytes_hash(
            "acgs.questionnaire.p256-spki/v1",
            root_spki,
        )
        leaf_spki_hash = _safe_domain_bytes_hash(
            "acgs.questionnaire.p256-spki/v1",
            leaf_spki,
        )
        pinned_root_spki = _safe_pinned_assembly_root_spki()
        if (
            trust_hash is None
            or policy_payload is None
            or policy_version is None
            or root_spki_hash is None
            or leaf_spki_hash is None
            or pinned_root_spki is None
        ):
            return False
        snapshot = trust_preimage.get("revocation_snapshot")
        if type(snapshot) is not dict:
            return False
        expected_bundle = {
            "schema_version": "QuestionnairePolicyBundle/v1",
            "policy_bundle_id": policy_preimage["policy_bundle_id"],
            "policy_version": policy_version,
            **{
                field: policy_preimage[field]
                for field in policy_preimage
                if field not in {"schema_version", "policy_bundle_id"}
            },
        }
        return bool(
            envelope["schema_version"]
            == "AssemblyVerificationManifestEnvelope/v1"
            and envelope["verification_manifest_hash"] == candidate_hash
            and envelope["root_signature_algorithm"] == "ECDSA_P256_SHA256"
            and envelope["root_signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and envelope["root_signing_key_id"]
            == trust_preimage["root_signing_key_id"]
            and candidate["schema_version"]
            == "AssemblyVerificationManifestPreimage/v1"
            and policy_bundle == expected_bundle
            and receipt["policy_bundle_id"] == policy_preimage["policy_bundle_id"]
            and receipt["policy_version"]
            == receipt["policy_hash"]
            == policy_bundle["policy_version"]
            == policy_version
            and policy_bundle["assembly_verification_trust_manifest_hash"]
            == trust_manifest["assembly_verification_trust_manifest_hash"]
            == trust_hash
            and candidate["trust_root_id"] == trust_preimage["trust_root_id"]
            and candidate["trust_root_version"]
            == trust_preimage["trust_root_version"]
            and root_spki == pinned_root_spki
            and trust_preimage["root_public_key_spki_sha256"]
            == root_spki_hash
            and trust_preimage["signature_algorithm"] == "ECDSA_P256_SHA256"
            and trust_preimage["signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING"
            in trust_preimage["authorized_manifest_purposes"]
            and root_valid_from <= accepted_at < root_valid_until
            and leaf_valid_from <= accepted_at < leaf_valid_until
            and trust_preimage["root_signing_key_id"]
            not in snapshot["revoked_signing_key_ids"]
            and candidate["signing_key_id"]
            not in snapshot["revoked_signing_key_ids"]
            and candidate_hash
            not in snapshot["revoked_verification_manifest_hashes"]
            and candidate["manifest_sequence"]
            == manifest_head["manifest_sequence"]
            and candidate["manifest_sequence"]
            >= trust_preimage["min_manifest_sequence"]
            and candidate_hash == manifest_head["verification_manifest_hash"]
            and candidate["previous_verification_manifest_hash"]
            == manifest_head["previous_verification_manifest_hash"]
            and candidate["authority_id"] == manifest_head["authority_id"]
            and candidate["signing_key_id"] == manifest_head["signing_key_id"]
            and candidate["key_purpose"] == "ASSEMBLY_ACCEPTANCE_SIGNING"
            and candidate["signature_algorithm"] == "ECDSA_P256_SHA256"
            and candidate["signature_encoding"] == "P1363_BASE64URL_NOPAD"
            and leaf_spki == assembly_spki
            and candidate["public_key_spki_sha256"] == leaf_spki_hash
            and candidate["revoked_at"] is None
            and _safe_p256_verify_spki(
                b"acgs.questionnaire.assembly-verification-manifest-signature/v1\0"
                + candidate_hash.encode("ascii"),
                signature,
                root_spki,
            )
        )

    manifest_policy_chain = make_manifest_policy_chain(assembly_root_preimage)
    initial_predecessor = make_authenticated_assembly_predecessor(
        "assembly-manifest-1",
        6,
        digest("8"),
        manifest_policy_chain,
        89,
    )
    invalid_digest_predecessor = {
        **initial_predecessor,
        "predecessor_record_hash": digest("0"),
    }
    initial_head_key = ("assembly-root-1", "assembly-manifest-1")
    assert not register_authenticated_assembly_predecessor(
        invalid_digest_predecessor,
        manifest_policy_chain,
    )
    assert initial_head_key not in assembly_authenticated_predecessors
    assert initial_head_key not in assembly_head_store
    assert register_authenticated_assembly_predecessor(
        initial_predecessor,
        manifest_policy_chain,
    )
    wrong_purpose_predecessor = make_authenticated_assembly_predecessor(
        "assembly-manifest-wrong-purpose",
        6,
        digest("8"),
        manifest_policy_chain,
        91,
        "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
    )
    assert not register_authenticated_assembly_predecessor(
        wrong_purpose_predecessor,
        manifest_policy_chain,
    )
    conflicting_predecessor = make_authenticated_assembly_predecessor(
        "assembly-manifest-1",
        5,
        digest("7"),
        manifest_policy_chain,
        93,
    )
    saved_predecessor = dict(
        assembly_authenticated_predecessors[initial_head_key]
    )
    assert not register_authenticated_assembly_predecessor(
        conflicting_predecessor,
        manifest_policy_chain,
    )
    assert (
        assembly_authenticated_predecessors[initial_head_key]
        == saved_predecessor
    )
    sequence_99_envelope = make_manifest_envelope(
        {**verification_manifest, "manifest_sequence": 99},
        95,
    )
    assert not publish_assembly_manifest_head(
        sequence_99_envelope,
        manifest_policy_chain,
    )
    assert initial_head_key not in assembly_head_store
    assert publish_assembly_manifest_head(
        verification_manifest_envelope,
        manifest_policy_chain,
    )
    assert manifest_is_accepted(
        verification_manifest_envelope,
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    initial_head = dict(assembly_head_store[initial_head_key])

    class HostileJsonValue:
        pass

    class HostileManifestString(str):
        accesses = 0

        def encode(self, *args: object, **kwargs: object) -> bytes:
            type(self).accesses += 1
            raise AssertionError("str subclass encode must not run")

    class HostileManifestTime(str):
        accesses = 0

        def endswith(self, *args: object, **kwargs: object) -> bool:
            type(self).accesses += 1
            raise AssertionError("timestamp subclass endswith must not run")

    class HostileManifestList(list[object]):
        accesses = 0

        def __iter__(self):  # type: ignore[no-untyped-def]
            type(self).accesses += 1
            raise AssertionError("list subclass iteration must not run")

    class HostileManifestDict(dict[str, object]):
        accesses = 0

        def items(self):  # type: ignore[no-untyped-def]
            type(self).accesses += 1
            raise AssertionError("dict subclass items must not run")

        def get(self, *args: object, **kwargs: object) -> object:
            type(self).accesses += 1
            raise AssertionError("dict subclass get must not run")

        def __eq__(self, other: object) -> bool:
            type(self).accesses += 1
            raise AssertionError("dict subclass equality must not run")

    cyclic_manifest_list: list[object] = []
    cyclic_manifest_list.append(cyclic_manifest_list)
    cyclic_manifest_dict: dict[str, object] = {}
    cyclic_manifest_dict["self"] = cyclic_manifest_dict
    over_depth_manifest: list[object] = []
    manifest_depth_cursor = over_depth_manifest
    for _ in range(MAX_JSON_DEPTH + 2):
        nested_manifest: list[object] = []
        manifest_depth_cursor.append(nested_manifest)
        manifest_depth_cursor = nested_manifest
    over_node_manifest = [0] * (MAX_JSON_NODES + 1)
    over_node_manifest_dict = {
        f"key-{index}": 0 for index in range(MAX_JSON_NODES // 2 + 1)
    }
    all_hostile_manifest_values: tuple[object, ...] = (
        b"not-json",
        HostileJsonValue(),
        HostileManifestString("hostile"),
        HostileManifestList(["hostile"]),
        HostileManifestDict(hostile="value"),
        cyclic_manifest_list,
        cyclic_manifest_dict,
        over_depth_manifest,
        over_node_manifest,
        over_node_manifest_dict,
        JSON_SAFE_INTEGER_MAX + 1,
        -JSON_SAFE_INTEGER_MAX - 1,
        1.0,
    )
    hostile_policy_preimage_chain = {
        **manifest_policy_chain,
        "policy_bundle_preimage": {
            **manifest_policy_chain["policy_bundle_preimage"],
            "decision_policy_artifact_hash": b"not-json",
        },
    }
    hostile_trust_manifest_chain = {
        **manifest_policy_chain,
        "assembly_trust_manifest": {
            **manifest_policy_chain["assembly_trust_manifest"],
            "assembly_verification_trust_manifest_hash": HostileJsonValue(),
        },
    }
    original_trust_preimage = manifest_policy_chain[
        "assembly_trust_manifest"
    ]["preimage"]
    hostile_revocation_snapshot_chain = {
        **manifest_policy_chain,
        "assembly_trust_manifest": {
            **manifest_policy_chain["assembly_trust_manifest"],
            "preimage": {
                **original_trust_preimage,
                "revocation_snapshot": {
                    **original_trust_preimage["revocation_snapshot"],
                    "revoked_signing_key_ids": [
                        "root-key-2",
                        [HostileJsonValue()],
                    ],
                },
            },
        },
    }
    bounded_hostile_policy_chains = tuple(
        {
            **manifest_policy_chain,
            "policy_bundle_preimage": {
                **manifest_policy_chain["policy_bundle_preimage"],
                "decision_policy_artifact_hash": hostile_value,
            },
        }
        for hostile_value in all_hostile_manifest_values
    )
    hostile_trust_policy_chains = (
        hostile_policy_preimage_chain,
        hostile_trust_manifest_chain,
        hostile_revocation_snapshot_chain,
        *bounded_hostile_policy_chains,
    )
    for hostile_policy_chain in hostile_trust_policy_chains:
        assert (
            validate_verified_assembly_trust_chain(
                hostile_policy_chain,
                "2026-07-26T22:45:00Z",
            )
            is None
        )
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            hostile_policy_chain,
        )
        assert assembly_head_store[initial_head_key] == initial_head

    hostile_manifest_envelopes = tuple(
        {
            **verification_manifest_envelope,
            "preimage": {
                **verification_manifest,
                "revoked_at": hostile_value,
            },
        }
        for hostile_value in all_hostile_manifest_values
    )
    hostile_predecessor_envelopes = tuple(
        {
            **initial_predecessor,
            "preimage": {
                **initial_predecessor["preimage"],
                "manifest_id": hostile_value,
            },
        }
        for hostile_value in all_hostile_manifest_values
    )
    for hostile_predecessor_envelope in hostile_predecessor_envelopes:
        assert not register_authenticated_assembly_predecessor(
            hostile_predecessor_envelope,
            manifest_policy_chain,
        )
        assert (
            assembly_authenticated_predecessors[initial_head_key]
            == saved_predecessor
        )
    for hostile_manifest_envelope in hostile_manifest_envelopes:
        assert not manifest_is_accepted(
            hostile_manifest_envelope,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
        assert not publish_assembly_manifest_head(
            hostile_manifest_envelope,
            manifest_policy_chain,
        )
    unsigned_envelope = {
        key: value
        for key, value in verification_manifest_envelope.items()
        if key != "root_signature"
    }
    malformed_envelope = {
        **verification_manifest_envelope,
        "unknown": True,
    }
    attacker_envelope = make_manifest_envelope(
        verification_manifest,
        109,
        private_scalar=2,
    )
    signed_wrong_schema_envelope = make_manifest_envelope(
        {
            **verification_manifest,
            "schema_version": "WrongAssemblyManifestPreimage/v1",
        },
        113,
    )
    for poisoned_candidate in (
        unsigned_envelope,
        malformed_envelope,
        attacker_envelope,
        signed_wrong_schema_envelope,
    ):
        assert not publish_assembly_manifest_head(
            poisoned_candidate,
            manifest_policy_chain,
        )
        assert assembly_head_store[initial_head_key] == initial_head
    del assembly_head_store[initial_head_key]
    assert not manifest_is_accepted(
        verification_manifest_envelope,
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    assembly_head_store[initial_head_key] = initial_head
    assembly_head_lookup_uncertain = True
    assert not manifest_is_accepted(
        verification_manifest_envelope,
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    assembly_head_lookup_uncertain = False
    for field, replacement in (
        ("manifest_sequence", 6),
        ("verification_manifest_hash", digest("0")),
        ("previous_verification_manifest_hash", digest("7")),
        ("authority_id", "fabricated-authority"),
        ("signing_key_id", "fabricated-key"),
    ):
        assembly_head_store[initial_head_key] = {
            **initial_head,
            field: replacement,
        }
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
    assembly_head_store[initial_head_key] = initial_head

    race_candidate_a = {
        **verification_manifest,
        "manifest_id": "assembly-manifest-race",
    }
    race_candidate_b = {
        **race_candidate_a,
        "valid_until": "2026-08-02T00:00:00Z",
    }
    race_results: list[bool] = []
    assert register_authenticated_assembly_predecessor(
        make_authenticated_assembly_predecessor(
            "assembly-manifest-race",
            6,
            digest("8"),
            manifest_policy_chain,
            97,
        ),
        manifest_policy_chain,
    )

    def race_publish(candidate: dict[str, object], nonce: int) -> None:
        race_results.append(
            publish_assembly_manifest_head(
                make_manifest_envelope(candidate, nonce),
                manifest_policy_chain,
            )
        )

    race_threads = [
        threading.Thread(target=race_publish, args=(candidate, nonce))
        for candidate, nonce in (
            (race_candidate_a, 103),
            (race_candidate_b, 107),
        )
    ]
    for thread in race_threads:
        thread.start()
    for thread in race_threads:
        thread.join()
    assert sorted(race_results) == [False, True]

    exact_valid_from_manifest = {
        **verification_manifest,
        "manifest_id": "assembly-manifest-exact-valid-from",
        "valid_from": "2026-07-26T22:45:00Z",
    }
    exact_valid_from_envelope = make_manifest_envelope(
        exact_valid_from_manifest,
        41,
    )
    exact_valid_from_policy_chain = make_manifest_policy_chain(
        assembly_root_preimage,
        exact_valid_from_manifest,
    )
    assert register_authenticated_assembly_predecessor(
        make_authenticated_assembly_predecessor(
            "assembly-manifest-exact-valid-from",
            6,
            digest("8"),
            exact_valid_from_policy_chain,
            101,
        ),
        exact_valid_from_policy_chain,
    )
    assert publish_assembly_manifest_head(
        exact_valid_from_envelope,
        exact_valid_from_policy_chain,
    )
    assert manifest_is_accepted(
        exact_valid_from_envelope,
        "2026-07-26T22:45:00Z",
        exact_valid_from_policy_chain,
    )
    exact_valid_until_manifest = {
        **verification_manifest,
        "valid_until": "2026-07-26T22:45:00Z",
    }
    exact_valid_until_envelope = make_manifest_envelope(
        exact_valid_until_manifest,
        43,
    )
    assert not manifest_is_accepted(
        exact_valid_until_envelope,
        "2026-07-26T22:45:00Z",
        make_manifest_policy_chain(
            assembly_root_preimage,
            exact_valid_until_manifest,
        ),
    )
    for nonce, time_isolated_manifest in (
        (47, {**verification_manifest, "valid_from": "2026-07-26T16:00:00-07:00"}),
        (53, {**verification_manifest, "valid_until": "2026-07-26T15:00:00-07:00"}),
        (59, {**verification_manifest, "valid_from": "2026-07-26T22:44:00"}),
    ):
        assert not manifest_is_accepted(
            make_manifest_envelope(time_isolated_manifest, nonce),
            "2026-07-26T22:45:00Z",
            make_manifest_policy_chain(
                assembly_root_preimage,
                time_isolated_manifest,
            ),
        )
    for nonce, field, replacement in (
        (61, "signing_key_id", "attacker-key"),
        (67, "authority_id", "attacker-authority"),
        (71, "previous_verification_manifest_hash", digest("7")),
        (73, "trust_root_id", "attacker-root"),
        (79, "manifest_id", ""),
        (83, "manifest_sequence", "7"),
    ):
        rejected = {**verification_manifest, field: replacement}
        assert not manifest_is_accepted(
            make_manifest_envelope(rejected, nonce),
            "2026-07-26T22:45:00Z",
            make_manifest_policy_chain(assembly_root_preimage, rejected),
        )
    assert not manifest_is_accepted(
        {**verification_manifest_envelope, "unknown": True},
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    assert not manifest_is_accepted(
        {
            key: value
            for key, value in verification_manifest_envelope.items()
            if key != "root_signature"
        },
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    missing_leaf_field = {
        key: value
        for key, value in verification_manifest.items()
        if key != "authority_id"
    }
    assert not manifest_is_accepted(
        make_manifest_envelope(missing_leaf_field, 73),
        "2026-07-26T22:45:00Z",
        make_manifest_policy_chain(
            assembly_root_preimage,
            missing_leaf_field,
        ),
    )
    assert not manifest_is_accepted(
        {
            **verification_manifest_envelope,
            "verification_manifest_hash": digest("0"),
        },
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    for bad_signature in (
        "",
        verification_manifest_envelope["root_signature"] + "=",
        "A" * 86,
    ):
        assert not manifest_is_accepted(
            {
                **verification_manifest_envelope,
                "root_signature": bad_signature,
            },
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
    wrong_root_envelope = {
        **verification_manifest_envelope,
        "root_signing_key_id": "attacker-root-key",
    }
    assert not manifest_is_accepted(
        wrong_root_envelope,
        "2026-07-26T22:45:00Z",
        manifest_policy_chain,
    )
    expired_root = {
        **assembly_root_preimage,
        "valid_until": "2026-07-26T22:45:00Z",
    }
    assert not manifest_is_accepted(
        verification_manifest_envelope,
        "2026-07-26T22:45:00Z",
        make_manifest_policy_chain(expired_root),
    )
    revoked_root_snapshot = {
        **assembly_root_snapshot,
        "revoked_signing_key_ids": ["assembly-root-key-1"],
    }
    revoked_root = {
        **assembly_root_preimage,
        "revocation_snapshot": revoked_root_snapshot,
        "revocation_snapshot_hash": domain_hash(
            "acgs.questionnaire.assembly-revocation-snapshot/v1",
            vector_jcs(revoked_root_snapshot),
        ),
    }
    assert not manifest_is_accepted(
        verification_manifest_envelope,
        "2026-07-26T22:45:00Z",
        make_manifest_policy_chain(revoked_root),
    )
    def trust_with_snapshot(
        snapshot: dict[str, object],
    ) -> dict[str, object]:
        return {
            **assembly_root_preimage,
            "revocation_snapshot": snapshot,
            "revocation_snapshot_hash": domain_hash(
                "acgs.questionnaire.assembly-revocation-snapshot/v1",
                vector_jcs(snapshot),
            ),
        }

    for invalid_trust in (
        {
            **assembly_root_preimage,
            "authorized_manifest_purposes": list(
                reversed(
                    assembly_root_preimage["authorized_manifest_purposes"]
                )
            ),
        },
        {
            **assembly_root_preimage,
            "authorized_manifest_purposes": [
                *assembly_root_preimage["authorized_manifest_purposes"],
                "ASSEMBLY_VERIFICATION_MANIFEST_SIGNING",
            ],
        },
        {
            **assembly_root_preimage,
            "authorized_manifest_purposes": [
                *assembly_root_preimage["authorized_manifest_purposes"],
                "OUTCOME_SIGNING",
            ],
        },
        {
            **assembly_root_preimage,
            "predecessor_signing_key_purpose": "OUTCOME_SIGNING",
        },
        {
            **assembly_root_preimage,
            "predecessor_signing_domain": "acgs.questionnaire.wrong-domain/v1",
        },
        {**assembly_root_preimage, "unknown": True},
        {
            key: value
            for key, value in assembly_root_preimage.items()
            if key != "root_signing_key_id"
        },
        {**assembly_root_preimage, "root_signing_key_id": ""},
        {**assembly_root_preimage, "trust_root_version": "2"},
        {
            **assembly_root_preimage,
            "revocation_snapshot": {**assembly_root_snapshot, "unknown": True},
        },
        {
            **assembly_root_preimage,
            "revocation_snapshot": {
                key: value
                for key, value in assembly_root_snapshot.items()
                if key != "issued_at"
            },
        },
        {
            **assembly_root_preimage,
            "revocation_snapshot": {
                **assembly_root_snapshot,
                "snapshot_sequence": "4",
            },
        },
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "revoked_signing_key_ids": ["key-b", "key-a"],
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "revoked_signing_key_ids": ["key-a", "key-a"],
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "revoked_signing_key_ids": [1],
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "revoked_verification_manifest_hashes": [
                    digest("b"),
                    digest("a"),
                ],
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "revoked_verification_manifest_hashes": [
                    digest("a"),
                    digest("a"),
                ],
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "issued_at": "2026-06-30T17:00:00-07:00",
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "issued_at": "2026-07-01T00:00:00.000000Z",
            }
        ),
        trust_with_snapshot(
            {
                **assembly_root_snapshot,
                "issued_at": "2026-07-01T00:00:00",
            }
        ),
        {**assembly_root_preimage, "valid_from": "2025-12-31T16:00:00-08:00"},
        {**assembly_root_preimage, "valid_until": "2027-01-01T00:00:00.0Z"},
        {**assembly_root_preimage, "valid_from": "2026-01-01T00:00:00"},
        {
            **assembly_root_preimage,
            "revocation_snapshot_hash": digest("0"),
        },
        {
            **assembly_root_preimage,
            "root_public_key_spki_der_b64u": "AA",
        },
        {
            **assembly_root_preimage,
            "root_public_key_spki_sha256": digest("0"),
        },
    ):
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            make_manifest_policy_chain(invalid_trust),
        )
    for revoked_field, revoked_value in (
        ("revoked_signing_key_ids", ["assembly-key-1"]),
        (
            "revoked_verification_manifest_hashes",
            [verification_manifest_hash],
        ),
    ):
        revoked_leaf_snapshot = {
            **assembly_root_snapshot,
            revoked_field: revoked_value,
        }
        revoked_leaf_root = {
            **assembly_root_preimage,
            "revocation_snapshot": revoked_leaf_snapshot,
            "revocation_snapshot_hash": domain_hash(
                "acgs.questionnaire.assembly-revocation-snapshot/v1",
                vector_jcs(revoked_leaf_snapshot),
            ),
        }
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            make_manifest_policy_chain(revoked_leaf_root),
        )

    assembly_arguments = {
        "schema_version": "AssemblyToolArguments/v1",
        "assembly_event_id": "assembly-1",
        "job_id": "job-1",
        "question_id": "q-1",
        "response_id": "resp-1",
        "response_version": 1,
        "answer_hash": digest("a"),
        "assertion_manifest_hash": digest("b"),
        "presentation_annotation_set_root": digest("f"),
        "content_manifest_hash": content_hash,
        "assembly_lineage_hash": assembly_hash,
        "verification_manifest_hash": verification_manifest_hash,
    }
    assert set(assembly_arguments) == {
        "schema_version",
        "assembly_event_id",
        "job_id",
        "question_id",
        "response_id",
        "response_version",
        "answer_hash",
        "assertion_manifest_hash",
        "presentation_annotation_set_root",
        "content_manifest_hash",
        "assembly_lineage_hash",
        "verification_manifest_hash",
    }
    assembly_argument_bytes = json.dumps(
        assembly_arguments,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assembly_call = ToolCall(
        name="questionnaire.pack.assemble",
        actor="assembly-authority-1",
        args=assembly_arguments,
    )
    assembly_argument_hash = assembly_call.argument_hash()
    assert assembly_argument_hash == hashlib.sha256(assembly_argument_bytes).hexdigest()
    assert assembly_argument_hash == (
        "98f5a3678ac4d296cc22d7efbc84fc22"
        "d3e5c32b53f5298a7762a6e83b786e1f"
    )
    for field, replacement in (
        ("assembly_event_id", "assembly-2"),
        ("content_manifest_hash", digest("5")),
        ("assembly_lineage_hash", digest("6")),
        ("verification_manifest_hash", digest("7")),
    ):
        substituted_arguments = {**assembly_arguments, field: replacement}
        substituted_argument_bytes = json.dumps(
            substituted_arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        substituted_call = assembly_call.with_args(substituted_arguments)
        assert substituted_call.argument_hash() == hashlib.sha256(
            substituted_argument_bytes
        ).hexdigest()
        assert substituted_call.argument_hash() != assembly_argument_hash

    class ResolvedReceiptVerifier:
        algorithm = "ed25519"

        def __init__(self, key_id: str, public_key: bytes) -> None:
            self.key_id = key_id
            self._public_key = public_key

        def verify(self, payload: bytes, signature: str) -> bool:
            try:
                signature_bytes = bytes.fromhex(signature)
            except (TypeError, ValueError):
                return False
            return _ed25519_verify(
                self._public_key,
                payload,
                signature_bytes,
            )

    def resolve_policy_receipt_verifier(
        policy_chain: object,
        accepted_at_value: object,
        assembly_manifest_envelope: object,
        assembly_head_record: object,
    ) -> ResolvedReceiptVerifier | None:
        if (
            type(policy_chain) is not dict
            or type(assembly_manifest_envelope) is not dict
            or type(assembly_head_record) is not dict
            or not all(
                is_closed_json_value(item)
                for item in (
                    policy_chain,
                    assembly_manifest_envelope,
                    assembly_head_record,
                )
            )
            or type(accepted_at_value) is not str
            or re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                accepted_at_value,
            )
            is None
            or not manifest_is_accepted(
                assembly_manifest_envelope,
                accepted_at_value,
                policy_chain,
            )
        ):
            return None
        candidate_manifest = assembly_manifest_envelope.get("preimage")
        if type(candidate_manifest) is not dict:
            return None
        authenticated_head = lookup_assembly_manifest_head(
            candidate_manifest.get("trust_root_id"),
            candidate_manifest.get("manifest_id"),
        )
        if (
            type(authenticated_head) is not dict
            or authenticated_head != assembly_head_record
            or authenticated_head.get("accepted_at") != accepted_at_value
        ):
            return None
        validated_trust = validate_verified_assembly_trust_chain(
            policy_chain,
            accepted_at_value,
        )
        if validated_trust is None:
            return None
        try:
            policy_bundle = policy_chain["policy_bundle"]
            manifest = policy_chain["receipt_verification_key_manifest"]
            archive = policy_chain["policy_archive_acceptance"]
            if not all(
                type(item) is dict
                for item in (policy_bundle, manifest, archive)
            ):
                return None
            archive_preimage = archive["preimage"]
            if type(archive_preimage) is not dict:
                return None
            if set(manifest) != {
                "schema_version",
                "manifest_id",
                "key_purpose",
                "key_id",
                "status",
                "signature_algorithm",
                "public_key_b64u",
                "valid_from",
                "valid_until",
                "revoked_key_ids",
            } or set(archive) != {
                "schema_version",
                "preimage",
                "acceptance_hash",
                "signature_algorithm",
                "signature_b64u",
            } or set(archive_preimage) != {
                "schema_version",
                "purpose",
                "trust_root_id",
                "trust_root_version",
                "policy_bundle_id",
                "policy_version",
                "receipt_verification_key_manifest_hash",
                "accepted_at",
            } or not all(
                is_closed_json_value(item)
                for item in (manifest, archive, archive_preimage)
            ):
                return None
            for timestamp_value in (
                manifest["valid_from"],
                manifest["valid_until"],
                archive_preimage["accepted_at"],
            ):
                if (
                    type(timestamp_value) is not str
                    or re.fullmatch(
                        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                        timestamp_value,
                    )
                    is None
                ):
                    return None
            public_key = canonical_b64u(manifest["public_key_b64u"])
            archive_signature = canonical_b64u(archive["signature_b64u"])
            accepted_at = parse_rfc3339_instant(accepted_at_value)
            key_valid_from = parse_rfc3339_instant(manifest["valid_from"])
            key_valid_until = parse_rfc3339_instant(manifest["valid_until"])
        except (KeyError, TypeError, ValueError):
            return None
        revoked_key_ids = manifest["revoked_key_ids"]
        if (
            manifest["schema_version"] != "ReceiptVerificationKeyManifest/v1"
            or type(manifest["manifest_id"]) is not str
            or not manifest["manifest_id"]
            or manifest["key_purpose"] != "DECISION_RECEIPT_SIGNING"
            or type(manifest["key_id"]) is not str
            or not manifest["key_id"]
            or manifest["status"] != "ACTIVE"
            or manifest["signature_algorithm"] != "ed25519"
            or len(public_key) != 32
            or type(revoked_key_ids) is not list
            or not all(
                type(key_id) is str and key_id
                for key_id in revoked_key_ids
            )
            or revoked_key_ids != sorted(set(revoked_key_ids))
            or manifest["key_id"] in revoked_key_ids
            or not key_valid_from <= accepted_at < key_valid_until
            or archive["schema_version"]
            != "QuestionnairePolicyArchiveAcceptance/v1"
            or archive_preimage["schema_version"]
            != "QuestionnairePolicyArchiveAcceptancePreimage/v1"
            or archive_preimage["purpose"]
            != "QUESTIONNAIRE_POLICY_BUNDLE_SIGNING"
            or archive_preimage["trust_root_id"]
            != validated_trust["trust_root_id"]
            or archive_preimage["trust_root_version"]
            != validated_trust["trust_root_version"]
            or archive_preimage["policy_bundle_id"]
            != policy_bundle["policy_bundle_id"]
            or archive_preimage["policy_version"]
            != policy_bundle["policy_version"]
            or archive_preimage["accepted_at"] != accepted_at_value
            or archive["signature_algorithm"]
            != "ECDSA_P256_SHA256_RAW_RS_LOW_S"
            or len(archive_signature) != 64
        ):
            return None
        manifest_hash = _safe_domain_hash(
            "acgs.questionnaire.receipt-verification-keys/v1",
            manifest,
        )
        archive_hash = _safe_domain_hash(
            "acgs.questionnaire.policy-archive-acceptance/v1",
            archive_preimage,
        )
        pinned_root_spki = _safe_pinned_assembly_root_spki()
        if (
            manifest_hash is None
            or archive_hash is None
            or pinned_root_spki is None
        ):
            return None
        if (
            policy_bundle["receipt_verification_key_manifest_hash"]
            != manifest_hash
            or archive_preimage["receipt_verification_key_manifest_hash"]
            != manifest_hash
            or archive["acceptance_hash"] != archive_hash
            or not _safe_p256_verify_spki(
                b"acgs.questionnaire.policy-archive-acceptance-signature/v1\0"
                + archive_hash.encode("ascii"),
                archive_signature,
                pinned_root_spki,
            )
        ):
            return None
        return ResolvedReceiptVerifier(
            str(manifest["key_id"]),
            public_key,
        )

    resolved_receipt_verifier = resolve_policy_receipt_verifier(
        manifest_policy_chain,
        "2026-07-26T22:45:00Z",
        verification_manifest_envelope,
        initial_head,
    )
    assert resolved_receipt_verifier is not None
    assert (
        resolve_policy_receipt_verifier(
            manifest_policy_chain,
            "2026-07-26T22:44:59Z",
            verification_manifest_envelope,
            initial_head,
        )
        is None
    )
    mismatched_archive_chain = make_manifest_policy_chain(
        assembly_root_preimage,
        archive_accepted_at="2026-07-26T22:45:01Z",
    )
    assert (
        resolve_policy_receipt_verifier(
            mismatched_archive_chain,
            "2026-07-26T22:45:00Z",
            verification_manifest_envelope,
            initial_head,
        )
        is None
    )
    for noncanonical_archive_time in (
        "2026-07-26T15:45:00-07:00",
        "2026-07-26T22:45:00.000Z",
    ):
        noncanonical_archive_chain = make_manifest_policy_chain(
            assembly_root_preimage,
            archive_accepted_at=noncanonical_archive_time,
        )
        assert (
            resolve_policy_receipt_verifier(
                noncanonical_archive_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
    for field, noncanonical_key_time in (
        ("valid_from", "2026-06-30T17:00:00-07:00"),
        ("valid_from", "2026-07-01T00:00:00.000Z"),
        ("valid_until", "2026-07-31T17:00:00-07:00"),
        ("valid_until", "2026-08-01T00:00:00.000Z"),
    ):
        noncanonical_key_manifest = {
            **policy_receipt_key_manifest,
            field: noncanonical_key_time,
        }
        noncanonical_key_chain = make_manifest_policy_chain(
            assembly_root_preimage,
            receipt_key_manifest=noncanonical_key_manifest,
        )
        assert (
            resolve_policy_receipt_verifier(
                noncanonical_key_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
    mixed_revocation_manifest = {
        **policy_receipt_key_manifest,
        "revoked_key_ids": ["valid-key", ["hostile-nested-key"]],
    }
    mixed_revocation_chain = make_manifest_policy_chain(
        assembly_root_preimage,
        receipt_key_manifest=mixed_revocation_manifest,
    )
    bytes_status_chain = make_manifest_policy_chain(assembly_root_preimage)
    bytes_status_chain["receipt_verification_key_manifest"] = {
        **policy_receipt_key_manifest,
        "status": b"ACTIVE",
    }
    hostile_nested_chain = make_manifest_policy_chain(assembly_root_preimage)
    hostile_nested_chain["receipt_verification_key_manifest"] = {
        **policy_receipt_key_manifest,
        "revoked_key_ids": [HostileJsonValue()],
    }
    hostile_receipt_chains = (
        mixed_revocation_chain,
        bytes_status_chain,
        hostile_nested_chain,
    )
    for hostile_receipt_chain in hostile_receipt_chains:
        assert (
            resolve_policy_receipt_verifier(
                hostile_receipt_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
        assert assembly_head_store[initial_head_key] == initial_head
    for hostile_policy_chain in hostile_trust_policy_chains:
        assert (
            resolve_policy_receipt_verifier(
                hostile_policy_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
        assert assembly_head_store[initial_head_key] == initial_head
    assert (
        resolve_policy_receipt_verifier(
            manifest_policy_chain,
            "2026-07-26T22:45:00Z",
            verification_manifest_envelope,
            {**initial_head, "authority_id": "substituted-head-authority"},
        )
        is None
    )
    saved_initial_head = dict(assembly_head_store[initial_head_key])
    assembly_head_store[initial_head_key] = {
        **saved_initial_head,
        "accepted_at": "2026-07-26T22:45:01Z",
    }
    assert (
        resolve_policy_receipt_verifier(
            manifest_policy_chain,
            "2026-07-26T22:45:00Z",
            verification_manifest_envelope,
            initial_head,
        )
        is None
    )
    assembly_head_store[initial_head_key] = saved_initial_head
    assembly_receipt_seed = policy_receipt_signing_seed
    assembly_receipt_key_id = resolved_receipt_verifier.key_id
    burn_policy_receipt = manifest_policy_chain["decision_receipt"]
    unsigned_assembly_receipt = DecisionReceipt(
        receipt_id="assembly-receipt-1",
        request_id="assembly-request-1",
        tenant_id="questionnaire-tenant",
        actor="assembly-authority-1",
        proposed_action="questionnaire.pack.assemble",
        declared_goal="assemble verified questionnaire pack",
        execution_boundary="questionnaire-worker",
        policy_bundle_id=burn_policy_receipt["policy_bundle_id"],
        policy_version=burn_policy_receipt["policy_version"],
        policy_hash=burn_policy_receipt["policy_hash"],
        decision="allow",
        matched_rules=["questionnaire-assembly"],
        constraints={"require_receipt": True},
        transformations=[],
        approval_chain_summary={
            "validator_id": "questionnaire-policy",
            "proposer": "assembly-authority-1",
        },
        timestamp="2026-07-26T22:44:58+00:00",
        expires_at="2026-07-26T23:00:00+00:00",
        previous_audit_hash="0" * 64,
        audit_event_hash="2" * 64,
        authority="questionnaire.pack.assemble",
        validator_id="questionnaire-policy",
        validator_role="validator",
        argument_hash=assembly_argument_hash,
        signature_algorithm="ed25519",
        signing_key_id=assembly_receipt_key_id,
    )
    assembly_receipt_hash = unsigned_assembly_receipt.compute_hash()
    _, assembly_receipt_signature = _ed25519_sign(
        assembly_receipt_seed,
        assembly_receipt_hash.encode("utf-8"),
    )
    verified_assembly_receipt = replace(
        unsigned_assembly_receipt,
        receipt_hash=assembly_receipt_hash,
        signature=assembly_receipt_signature.hex(),
    )

    def verify_receipt_grant(
        receipt: DecisionReceipt,
        policy_chain: object,
    ) -> DecisionReceipt | None:
        if type(receipt) is not DecisionReceipt:
            return None
        try:
            verifier = resolve_policy_receipt_verifier(
                policy_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            if (
                verifier is None
                or receipt.decision != "allow"
                or receipt.signing_key_id != verifier.key_id
            ):
                return None
            receipt.verify(
                expected_tenant_id="questionnaire-tenant",
                expected_execution_boundary="questionnaire-worker",
                expected_audit_hash="2" * 64,
                expected_args=assembly_arguments,
                expected_action="questionnaire.pack.assemble",
                expected_policy_hash=burn_policy_receipt["policy_hash"],
                expected_policy_bundle_id=burn_policy_receipt[
                    "policy_bundle_id"
                ],
                expected_authority="questionnaire.pack.assemble",
                expected_actor="assembly-authority-1",
                verifier={verifier.key_id: verifier},
                require_signature=True,
                require_expiry=True,
                now_iso="2026-07-26T22:45:00+00:00",
                max_clock_skew_seconds=0,
            )
        except (Exception, MemoryError):
            return None
        return receipt

    class HostileReceiptProxy:
        accesses = 0

        @property
        def decision(self) -> str:
            type(self).accesses += 1
            raise AssertionError("receipt proxy property must not run")

    class HostileReceiptSubclass(DecisionReceipt):
        accesses = 0

        def __getattribute__(self, name: str) -> object:
            if name not in {"__class__", "accesses"}:
                type(self).accesses += 1
                raise AssertionError("receipt subclass attribute must not run")
            return super().__getattribute__(name)

    hostile_receipt_proxy = HostileReceiptProxy()
    hostile_receipt_subclass = object.__new__(HostileReceiptSubclass)
    receipt_gate_head_before_hostile = dict(
        assembly_head_store[initial_head_key]
    )
    assert (
        verify_receipt_grant(  # type: ignore[arg-type]
            hostile_receipt_proxy,
            manifest_policy_chain,
        )
        is None
    )
    assert (
        verify_receipt_grant(
            hostile_receipt_subclass,
            manifest_policy_chain,
        )
        is None
    )
    assert HostileReceiptProxy.accesses == 0
    assert HostileReceiptSubclass.accesses == 0
    assert assembly_head_store[initial_head_key] == receipt_gate_head_before_hostile

    verified_assembly_receipt = verify_receipt_grant(
        verified_assembly_receipt,
        manifest_policy_chain,
    )
    assert verified_assembly_receipt is not None
    assert verified_assembly_receipt.compute_hash() == assembly_receipt_hash
    assert verified_assembly_receipt.argument_hash == assembly_call.argument_hash()

    signed_non_allow_receipts: list[DecisionReceipt] = []
    for non_allow_decision in ("transform", "deny", "escalate"):
        non_allow_unsigned = replace(
            unsigned_assembly_receipt,
            receipt_id=f"assembly-receipt-{non_allow_decision}",
            request_id=f"assembly-request-{non_allow_decision}",
            decision=non_allow_decision,
            transformations=(
                [{"field": "args", "value": assembly_arguments}]
                if non_allow_decision == "transform"
                else []
            ),
        )
        non_allow_hash = non_allow_unsigned.compute_hash()
        _, non_allow_signature = _ed25519_sign(
            assembly_receipt_seed,
            non_allow_hash.encode("utf-8"),
        )
        signed_non_allow = replace(
            non_allow_unsigned,
            receipt_hash=non_allow_hash,
            signature=non_allow_signature.hex(),
        )
        assert resolved_receipt_verifier.verify(
            non_allow_hash.encode("utf-8"),
            signed_non_allow.signature,
        )
        assert (
            verify_receipt_grant(signed_non_allow, manifest_policy_chain)
            is None
        )
        signed_non_allow_receipts.append(signed_non_allow)

    receipt_anchor_preimage = {
        "schema_version": "ReceiptAnchorPreimage/v1",
        "decision_audit_event_hash": verified_assembly_receipt.audit_event_hash,
    }
    receipt_anchor_bytes = json.dumps(
        receipt_anchor_preimage,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    receipt_anchor = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-anchor/v1\0" + receipt_anchor_bytes
    ).hexdigest()
    assert set(receipt_anchor_preimage) == {
        "schema_version",
        "decision_audit_event_hash",
    }
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_anchor)
    burn_verification_manifest_hash = (
        "sha256:60364b456803f3bcfe69cc8f425e6c765"
        "333b2cc2d28c52887c28c75786bd778"
    )
    burn_store_record = {
        "schema_version": "ReceiptBurnStoreRecordPreimage/v1",
        "burn_acceptance_id": "burn-1",
        "receipt_id": "assembly-receipt-1",
        "receipt_hash": verified_assembly_receipt.receipt_hash,
        "decision_audit_event_hash": verified_assembly_receipt.audit_event_hash,
        "receipt_anchor": receipt_anchor,
        "actor": "assembly-authority-1",
        "action": "questionnaire.pack.assemble",
        "argument_hash": assembly_argument_hash,
        "transaction_id": "burn-txn-1",
        "commit_timestamp": "2026-07-26T22:45:00.000000Z",
        "burn_state": "CONSUMED",
        "burn_authority_id": "receipt-burn-authority-1",
        "burn_signing_key_id": "receipt-burn-key-1",
        "burn_verification_manifest_hash": burn_verification_manifest_hash,
    }
    assert burn_store_record["receipt_hash"] == verified_assembly_receipt.receipt_hash
    assert (
        burn_store_record["decision_audit_event_hash"]
        == verified_assembly_receipt.audit_event_hash
    )
    assert burn_store_record["argument_hash"] == assembly_call.argument_hash()
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
        str(burn_store_record["commit_timestamp"]),
    )
    trusted_commit_timestamp = str(burn_store_record["commit_timestamp"])
    trusted_commit_time = datetime.strptime(
        trusted_commit_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=UTC)
    assert trusted_commit_time == parse_rfc3339_instant(
        initial_head["accepted_at"]
    )
    assert datetime(2026, 7, 1, tzinfo=UTC) <= trusted_commit_time
    assert trusted_commit_time < datetime(2026, 8, 1, tzinfo=UTC)
    for rejected_time in (
        "2026-07-26T22:45:00Z",
        "2026-07-26T22:45:00.000Z",
        "2026-07-26T15:45:00.000000-07:00",
    ):
        assert not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
            rejected_time,
        )

    unsigned_reminted_receipt = replace(
        unsigned_assembly_receipt,
        receipt_id="assembly-receipt-reminted",
        request_id="assembly-request-reminted",
        timestamp="2026-07-26T22:44:58.500000+00:00",
        expires_at="2026-07-26T23:00:00+00:00",
    )
    reminted_receipt_hash = unsigned_reminted_receipt.compute_hash()
    _, reminted_receipt_signature = _ed25519_sign(
        assembly_receipt_seed,
        reminted_receipt_hash.encode("utf-8"),
    )
    verified_reminted_receipt = replace(
        unsigned_reminted_receipt,
        receipt_hash=reminted_receipt_hash,
        signature=reminted_receipt_signature.hex(),
    )
    verified_reminted_receipt = verify_receipt_grant(
        verified_reminted_receipt,
        manifest_policy_chain,
    )
    assert verified_reminted_receipt is not None
    assert verified_reminted_receipt.decision == "allow"
    assert verified_reminted_receipt.compute_hash() == reminted_receipt_hash
    unsigned_same_audit_receipt = replace(
        unsigned_assembly_receipt,
        receipt_id="assembly-receipt-unsigned-remint",
        request_id="assembly-request-unsigned-remint",
        timestamp="2026-07-26T22:44:58.750000+00:00",
    )
    unsigned_same_audit_hash = unsigned_same_audit_receipt.compute_hash()
    attacker_receipt_seed = b"\x0a" * 32
    attacker_receipt_public_key, _ = _ed25519_sign(attacker_receipt_seed, b"")
    attacker_receipt_key_id = "attacker-selected-receipt-key"
    unsigned_attacker_receipt = replace(
        unsigned_assembly_receipt,
        receipt_id="assembly-receipt-attacker",
        request_id="assembly-request-attacker",
        timestamp="2026-07-26T22:44:58.900000+00:00",
        signing_key_id=attacker_receipt_key_id,
    )
    attacker_receipt_hash = unsigned_attacker_receipt.compute_hash()
    _, attacker_receipt_signature = _ed25519_sign(
        attacker_receipt_seed,
        attacker_receipt_hash.encode("utf-8"),
    )
    attacker_receipt = replace(
        unsigned_attacker_receipt,
        receipt_hash=attacker_receipt_hash,
        signature=attacker_receipt_signature.hex(),
    )
    substituted_attacker_verifier = ResolvedReceiptVerifier(
        attacker_receipt_key_id,
        attacker_receipt_public_key,
    )
    attacker_receipt.verify(
        expected_tenant_id="questionnaire-tenant",
        expected_execution_boundary="questionnaire-worker",
        expected_audit_hash=verified_assembly_receipt.audit_event_hash,
        expected_args=assembly_arguments,
        expected_action="questionnaire.pack.assemble",
        expected_policy_hash=burn_policy_receipt["policy_hash"],
        expected_policy_bundle_id=burn_policy_receipt["policy_bundle_id"],
        expected_authority="questionnaire.pack.assemble",
        expected_actor="assembly-authority-1",
        verifier={attacker_receipt_key_id: substituted_attacker_verifier},
        require_signature=True,
        require_expiry=True,
        now_iso="2026-07-26T22:45:00+00:00",
        max_clock_skew_seconds=0,
    )
    assert (
        verify_receipt_grant(attacker_receipt, manifest_policy_chain)
        is None
    )
    reminted_anchor_preimage = {
        "schema_version": "ReceiptAnchorPreimage/v1",
        "decision_audit_event_hash": verified_reminted_receipt.audit_event_hash,
    }
    reminted_anchor = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-anchor/v1\0"
        + json.dumps(
            reminted_anchor_preimage,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert reminted_anchor == receipt_anchor
    mutated_anchor_preimage = {
        **receipt_anchor_preimage,
        "decision_audit_event_hash": "4" * 64,
    }
    mutated_anchor_bytes = json.dumps(
        mutated_anchor_preimage,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-anchor/v1\0" + mutated_anchor_bytes
    ).hexdigest() != receipt_anchor

    receipt_consumptions: dict[str, dict[str, object]] = {}
    burn_head_store: dict[str, object] = {}
    tool_invocations: list[str] = []
    barrier_entries: list[str] = []
    burn_results: list[bool] = []
    burn_lock = threading.Lock()
    start_barrier = threading.Barrier(2)

    receipt_fault_state = (
        {key: dict(value) for key, value in assembly_head_store.items()},
        list(barrier_entries),
        dict(receipt_consumptions),
        dict(burn_head_store),
        list(tool_invocations),
    )

    def assert_receipt_backend_failure_is_closed(
        algorithm: str,
        nth_call: int,
    ) -> None:
        original_hash = getattr(hashlib, algorithm)
        calls = 0

        def fail_nth_hash(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == nth_call:
                raise RuntimeError(
                    f"injected {algorithm} failure #{nth_call}"
                )
            return original_hash(*args, **kwargs)

        with monkeypatch.context() as patcher:
            patcher.setattr(hashlib, algorithm, fail_nth_hash)
            assert (
                verify_receipt_grant(
                    verified_assembly_receipt,
                    manifest_policy_chain,
                )
                is None
            )
        assert calls >= nth_call
        assert (
            {key: dict(value) for key, value in assembly_head_store.items()},
            list(barrier_entries),
            dict(receipt_consumptions),
            dict(burn_head_store),
            list(tool_invocations),
        ) == receipt_fault_state

    for sha256_call in (18, 19):
        assert_receipt_backend_failure_is_closed("sha256", sha256_call)
    assert_receipt_backend_failure_is_closed("sha512", 1)

    assert len(PINNED_ASSEMBLY_ROOT_P256_SPKI_DER) == 91
    assert _p256_spki(1) == PINNED_ASSEMBLY_ROOT_P256_SPKI_DER
    scalar2_root_spki = _p256_spki(2)
    assert scalar2_root_spki != PINNED_ASSEMBLY_ROOT_P256_SPKI_DER
    scalar2_root_hash = domain_hash(
        "acgs.questionnaire.p256-spki/v1",
        scalar2_root_spki,
    )
    scalar2_trust_preimage = {
        **assembly_root_preimage,
        "root_public_key_spki_der_b64u": base64.urlsafe_b64encode(
            scalar2_root_spki
        ).rstrip(b"=").decode(),
        "root_public_key_spki_sha256": scalar2_root_hash,
    }
    scalar2_policy_chain = make_manifest_policy_chain(
        scalar2_trust_preimage,
    )
    scalar2_archive = scalar2_policy_chain[
        "policy_archive_acceptance"
    ]
    scalar2_archive_hash = scalar2_archive["acceptance_hash"]
    assert isinstance(scalar2_archive_hash, str)
    scalar2_archive_signature = _p256_sign(
        b"acgs.questionnaire.policy-archive-acceptance-signature/v1\0"
        + scalar2_archive_hash.encode("ascii"),
        2,
        97,
    )
    scalar2_policy_chain["policy_archive_acceptance"] = {
        **scalar2_archive,
        "signature_b64u": base64.urlsafe_b64encode(
            scalar2_archive_signature
        ).rstrip(b"=").decode(),
    }
    scalar2_manifest_envelope = make_manifest_envelope(
        verification_manifest,
        101,
        private_scalar=2,
    )

    spki_failure_state = (
        {key: dict(value) for key, value in assembly_head_store.items()},
        {
            key: dict(value)
            for key, value in assembly_authenticated_predecessors.items()
        },
        list(barrier_entries),
        dict(receipt_consumptions),
        dict(burn_head_store),
        list(tool_invocations),
    )

    def fail_pinned_spki_constructor(private_scalar: int) -> bytes:
        raise RuntimeError(
            f"injected P-256 SPKI constructor failure for {private_scalar}"
        )

    with monkeypatch.context() as patcher:
        patcher.setitem(globals(), "_p256_spki", fail_pinned_spki_constructor)
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
        assert (
            resolve_policy_receipt_verifier(
                manifest_policy_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
    assert (
        {key: dict(value) for key, value in assembly_head_store.items()},
        {
            key: dict(value)
            for key, value in assembly_authenticated_predecessors.items()
        },
        list(barrier_entries),
        dict(receipt_consumptions),
        dict(burn_head_store),
        list(tool_invocations),
    ) == spki_failure_state

    def substitute_scalar2_spki(private_scalar: int) -> bytes:
        assert private_scalar == 1
        return scalar2_root_spki

    with monkeypatch.context() as patcher:
        patcher.setitem(globals(), "_p256_spki", substitute_scalar2_spki)
        assert (
            validate_verified_assembly_trust_chain(
                scalar2_policy_chain,
                "2026-07-26T22:45:00Z",
            )
            is None
        )
        assert not publish_assembly_manifest_head(
            scalar2_manifest_envelope,
            scalar2_policy_chain,
        )
        assert not manifest_is_accepted(
            scalar2_manifest_envelope,
            "2026-07-26T22:45:00Z",
            scalar2_policy_chain,
        )
        assert (
            resolve_policy_receipt_verifier(
                scalar2_policy_chain,
                "2026-07-26T22:45:00Z",
                scalar2_manifest_envelope,
                initial_head,
            )
            is None
        )
    assert (
        {key: dict(value) for key, value in assembly_head_store.items()},
        {
            key: dict(value)
            for key, value in assembly_authenticated_predecessors.items()
        },
        list(barrier_entries),
        dict(receipt_consumptions),
        dict(burn_head_store),
        list(tool_invocations),
    ) == spki_failure_state

    for hostile_manifest_envelope in hostile_manifest_envelopes:
        assert not manifest_is_accepted(
            hostile_manifest_envelope,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
        assert not publish_assembly_manifest_head(
            hostile_manifest_envelope,
            manifest_policy_chain,
        )
        assert (
            resolve_policy_receipt_verifier(
                manifest_policy_chain,
                "2026-07-26T22:45:00Z",
                hostile_manifest_envelope,
                initial_head,
            )
            is None
        )
    for hostile_policy_chain in hostile_trust_policy_chains:
        assert (
            validate_verified_assembly_trust_chain(
                hostile_policy_chain,
                "2026-07-26T22:45:00Z",
            )
            is None
        )
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            hostile_policy_chain,
        )
        assert (
            resolve_policy_receipt_verifier(
                hostile_policy_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
    for hostile_receipt_chain in hostile_receipt_chains:
        assert (
            resolve_policy_receipt_verifier(
                hostile_receipt_chain,
                "2026-07-26T22:45:00Z",
                verification_manifest_envelope,
                initial_head,
            )
            is None
        )
    hostile_root_carriers: tuple[object, ...] = (
        HostileManifestString("root"),
        HostileManifestList(["root"]),
        HostileManifestDict(root="value"),
    )
    for hostile_root in hostile_root_carriers:
        assert (
            validate_verified_assembly_trust_chain(
                hostile_root,
                "2026-07-26T22:45:00Z",
            )
            is None
        )
        assert not register_authenticated_assembly_predecessor(
            hostile_root,
            manifest_policy_chain,
        )
        assert not publish_assembly_manifest_head(
            hostile_root,
            manifest_policy_chain,
        )
        assert not manifest_is_accepted(
            hostile_root,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
        assert (
            resolve_policy_receipt_verifier(
                manifest_policy_chain,
                "2026-07-26T22:45:00Z",
                hostile_root,
                initial_head,
            )
            is None
        )
    hostile_head_record = HostileManifestDict(initial_head)
    assert (
        resolve_policy_receipt_verifier(
            manifest_policy_chain,
            "2026-07-26T22:45:00Z",
            verification_manifest_envelope,
            hostile_head_record,
        )
        is None
    )
    hostile_manifest_time = HostileManifestTime("2026-07-26T22:45:00Z")
    assert not manifest_is_accepted(
        verification_manifest_envelope,
        hostile_manifest_time,
        manifest_policy_chain,
    )
    assert (
        resolve_policy_receipt_verifier(
            manifest_policy_chain,
            hostile_manifest_time,
            verification_manifest_envelope,
            initial_head,
        )
        is None
    )
    assert assembly_head_store[initial_head_key] == initial_head
    assert assembly_authenticated_predecessors[initial_head_key] == saved_predecessor
    assert barrier_entries == []
    assert receipt_consumptions == {}
    assert burn_head_store == {}
    assert tool_invocations == []
    assert HostileManifestString.accesses == 0
    assert HostileManifestList.accesses == 0
    assert HostileManifestDict.accesses == 0
    assert HostileManifestTime.accesses == 0

    burn_store_fields = set(burn_store_record)
    verified_receipt_grants: dict[str, DecisionReceipt] = {
        receipt.receipt_id: receipt
        for receipt in (
            verified_assembly_receipt,
            verified_reminted_receipt,
        )
    }
    assert len(verified_receipt_grants) == 2
    assert all(
        type(receipt) is DecisionReceipt
        and receipt.decision == "allow"
        and receipt.signature
        for receipt in verified_receipt_grants.values()
    )
    assert HostileReceiptProxy.accesses == 0
    assert HostileReceiptSubclass.accesses == 0
    bare_digest_fields = {
        "receipt_hash",
        "decision_audit_event_hash",
        "argument_hash",
    }
    prefixed_digest_fields = {
        "burn_verification_manifest_hash",
        "receipt_anchor",
    }

    def atomic_burn_then_invoke(record: object) -> bool:
        if type(record) is not dict or not _is_closed_json_value(record):
            burn_results.append(False)
            return False
        expected_receipt = verified_receipt_grants.get(record.get("receipt_id"))
        if (
            set(record) != burn_store_fields
            or record.get("schema_version")
            != "ReceiptBurnStoreRecordPreimage/v1"
            or any(
                type(record.get(field)) is not str or not record[field]
                for field in burn_store_fields
            )
            or any(
                re.fullmatch(r"[0-9a-f]{64}", record[field]) is None
                for field in bare_digest_fields
            )
            or any(
                re.fullmatch(r"sha256:[0-9a-f]{64}", record[field]) is None
                for field in prefixed_digest_fields
            )
            or record["burn_state"] != "CONSUMED"
            or expected_receipt is None
            or record["receipt_hash"] != expected_receipt.receipt_hash
            or record["decision_audit_event_hash"]
            != expected_receipt.audit_event_hash
            or record["actor"] != "assembly-authority-1"
            or record["action"] != "questionnaire.pack.assemble"
            or record["argument_hash"] != assembly_argument_hash
            or record["burn_verification_manifest_hash"]
            != burn_verification_manifest_hash
        ):
            burn_results.append(False)
            return False
        try:
            timestamp = datetime.strptime(
                record["commit_timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ"
            ).replace(tzinfo=UTC)
            anchor_preimage = {
                "schema_version": "ReceiptAnchorPreimage/v1",
                "decision_audit_event_hash": record[
                    "decision_audit_event_hash"
                ],
            }
            expected_anchor = _safe_domain_hash(
                "acgs.questionnaire.receipt-anchor/v1",
                anchor_preimage,
            )
        except (Exception, MemoryError):
            burn_results.append(False)
            return False
        if (
            expected_anchor is None
            or record["receipt_anchor"] != expected_anchor
            or timestamp != trusted_commit_time
        ):
            burn_results.append(False)
            return False
        barrier_entries.append(record["receipt_id"])
        start_barrier.wait()
        key = record["receipt_anchor"]
        with burn_lock:
            if key in receipt_consumptions:
                burn_results.append(False)
                return False
            receipt_consumptions[key] = record
            tool_invocations.append(record["receipt_id"])
            burn_results.append(True)
            return True

    reminted_burn_record = {
        **burn_store_record,
        "burn_acceptance_id": "burn-reminted",
        "receipt_id": verified_reminted_receipt.receipt_id,
        "receipt_hash": verified_reminted_receipt.receipt_hash,
        "transaction_id": "burn-txn-reminted",
    }
    unsigned_remint_burn_record = {
        **burn_store_record,
        "burn_acceptance_id": "burn-unsigned-remint",
        "receipt_id": unsigned_same_audit_receipt.receipt_id,
        "receipt_hash": unsigned_same_audit_hash,
        "transaction_id": "burn-txn-unsigned-remint",
    }
    attacker_burn_record = {
        **burn_store_record,
        "burn_acceptance_id": "burn-attacker",
        "receipt_id": attacker_receipt.receipt_id,
        "receipt_hash": attacker_receipt.receipt_hash,
        "transaction_id": "burn-txn-attacker",
    }
    non_allow_burn_records = tuple(
        {
            **burn_store_record,
            "burn_acceptance_id": f"burn-{receipt.decision}",
            "receipt_id": receipt.receipt_id,
            "receipt_hash": receipt.receipt_hash,
            "transaction_id": f"burn-txn-{receipt.decision}",
        }
        for receipt in signed_non_allow_receipts
    )
    coordinated_audit_hash = "6" * 64
    coordinated_anchor_preimage = {
        "schema_version": "ReceiptAnchorPreimage/v1",
        "decision_audit_event_hash": coordinated_audit_hash,
    }
    coordinated_anchor = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-anchor/v1\0"
        + json.dumps(
            coordinated_anchor_preimage,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    class HostileBurnRecord:
        accesses = 0

        def __getitem__(self, key: object) -> object:
            self.accesses += 1
            raise AssertionError(f"hostile record accessed: {key}")

    hostile_burn_record = HostileBurnRecord()
    hostile_burn_dict = HostileManifestDict(burn_store_record)
    malformed_burn_calls = (
        None,
        [],
        "invalid",
        7,
        hostile_burn_record,
        hostile_burn_dict,
        unsigned_remint_burn_record,
        attacker_burn_record,
        *non_allow_burn_records,
        {},
        {
            field: value
            for field, value in burn_store_record.items()
            if field != "receipt_anchor"
        },
        {**burn_store_record, "unknown": True},
        {**burn_store_record, "receipt_id": 7},
        {**burn_store_record, "burn_state": "PENDING"},
        {
            **burn_store_record,
            "receipt_hash": "sha256:" + verified_assembly_receipt.receipt_hash,
        },
        {
            **burn_store_record,
            "decision_audit_event_hash": "sha256:"
            + verified_assembly_receipt.audit_event_hash,
        },
        {
            **burn_store_record,
            "argument_hash": "sha256:" + assembly_argument_hash,
        },
        {**burn_store_record, "receipt_hash": "9" * 64},
        {**burn_store_record, "receipt_id": "wrong-receipt"},
        {**burn_store_record, "actor": "wrong-actor"},
        {**burn_store_record, "action": "questionnaire.other"},
        {**burn_store_record, "argument_hash": "4" * 64},
        {
            **burn_store_record,
            "burn_verification_manifest_hash": "sha256:" + "5" * 64,
        },
        {
            **burn_store_record,
            "decision_audit_event_hash": coordinated_audit_hash,
            "receipt_anchor": coordinated_anchor,
        },
        {**burn_store_record, "receipt_anchor": "sha256:" + "7" * 64},
        {**burn_store_record, "commit_timestamp": hostile_manifest_time},
        {**burn_store_record, "commit_timestamp": "not-a-time"},
        {
            **burn_store_record,
            "commit_timestamp": "2026-07-26T22:44:59.000000Z",
        },
        {
            **burn_store_record,
            "commit_timestamp": "2026-02-30T22:45:00.000000Z",
        },
    )
    for malformed_burn_call in malformed_burn_calls:
        atomic_burn_then_invoke(malformed_burn_call)
    assert burn_results == [False] * len(malformed_burn_calls)
    assert hostile_burn_record.accesses == 0
    assert HostileManifestDict.accesses == 0
    assert HostileManifestTime.accesses == 0
    assert barrier_entries == []
    assert receipt_consumptions == {}
    assert burn_head_store == {}
    assert tool_invocations == []
    burn_results.clear()

    contenders = [
        threading.Thread(target=atomic_burn_then_invoke, args=(burn_store_record,)),
        threading.Thread(
            target=atomic_burn_then_invoke, args=(reminted_burn_record,)
        ),
    ]
    for contender in contenders:
        contender.start()
    for contender in contenders:
        contender.join()
    assert len(barrier_entries) == 2
    assert sorted(burn_results) == [False, True]
    assert len(receipt_consumptions) == 1
    assert len(tool_invocations) == 1
    winning_grant = verified_receipt_grants[tool_invocations[0]]
    assert winning_grant.decision == "allow"
    assert winning_grant.signature
    burn_store_record_bytes = json.dumps(
        burn_store_record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    burn_store_record_digest = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-burn-store-record/v1\0"
        + burn_store_record_bytes
    ).hexdigest()
    burn_preimage = {
        **burn_store_record,
        "schema_version": "ReceiptBurnAcceptancePreimage/v1",
        "store_record_digest": burn_store_record_digest,
    }
    burn_bytes = json.dumps(
        burn_preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    burn_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-burn-acceptance/v1\0" + burn_bytes
    ).hexdigest()
    assert len(burn_bytes) == 935
    assert burn_hash == (
        "sha256:b8c71745abb57be7a793c3e4ebc0f493"
        "b0d6e2eb2a658c1a357d444c7ab1cbdf"
    )
    burn_message = (
        b"acgs.questionnaire.receipt-burn-acceptance-signature/v1\0"
        + burn_hash.encode("ascii")
    )
    burn_signature_raw = _p256_sign(burn_message, 3, 7)
    burn_signature = base64.urlsafe_b64encode(burn_signature_raw).rstrip(b"=").decode()
    assert burn_signature == (
        "jlM7b6C_e0YluzBmfAH7YH75-LioD-9bMAYocDGHsqNazFfRgSirQqZIkGG9K2Ll"
        "ZfS91eJnL4o4A7e9l68s_g"
    )
    burn_envelope = {
        "schema_version": "ReceiptBurnAcceptance/v1",
        "preimage": burn_preimage,
        "burn_acceptance_hash": burn_hash,
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "signature": burn_signature,
    }
    assert set(burn_envelope) == {
        "schema_version",
        "preimage",
        "burn_acceptance_hash",
        "signature_algorithm",
        "signature_encoding",
        "signature",
    }
    assert _p256_verify(burn_message, burn_signature_raw, 3)
    assert not _p256_verify(burn_message, burn_signature_raw, 2)
    bad_burn_signature = burn_signature_raw[:-1] + bytes([burn_signature_raw[-1] ^ 1])
    assert not _p256_verify(burn_message, bad_burn_signature, 3)

    acceptance = {
        "schema_version": "AssemblyAcceptancePreimage/v1",
        "assembly_event_id": "assembly-1",
        "job_id": "job-1",
        "question_id": "q-1",
        "response_id": "resp-1",
        "response_version": 1,
        "content_manifest_hash": content_hash,
        "assembly_lineage_hash": assembly_hash,
        "authority_id": "assembly-authority-1",
        "assembly_action": "questionnaire.pack.assemble",
        "assembly_actor": "assembly-authority-1",
        "assembly_argument_hash": assembly_argument_hash,
        "assembly_receipt_id": "assembly-receipt-1",
        "assembly_receipt_hash": verified_assembly_receipt.receipt_hash,
        "assembly_audit_event_hash": verified_assembly_receipt.audit_event_hash,
        "assembly_burn_acceptance_hash": burn_hash,
        "assembly_burn_acceptance_signature": burn_signature,
        "burn_verification_manifest_hash": burn_verification_manifest_hash,
        "assembly_outcome_hash": digest("0"),
        "signature_algorithm": "ECDSA_P256_SHA256",
        "signature_encoding": "P1363_BASE64URL_NOPAD",
        "signing_key_id": "assembly-key-1",
        "verification_manifest_hash": verification_manifest_hash,
        "created_at": "2026-07-26T22:45:00Z",
    }
    assert set(acceptance) == {
        "schema_version",
        "assembly_event_id",
        "job_id",
        "question_id",
        "response_id",
        "response_version",
        "content_manifest_hash",
        "assembly_lineage_hash",
        "authority_id",
        "assembly_action",
        "assembly_actor",
        "assembly_argument_hash",
        "assembly_receipt_id",
        "assembly_receipt_hash",
        "assembly_audit_event_hash",
        "assembly_burn_acceptance_hash",
        "assembly_burn_acceptance_signature",
        "burn_verification_manifest_hash",
        "assembly_outcome_hash",
        "signature_algorithm",
        "signature_encoding",
        "signing_key_id",
        "verification_manifest_hash",
        "created_at",
    }
    acceptance_bytes = json.dumps(
        acceptance, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    acceptance_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.assembly-acceptance/v1\0" + acceptance_bytes
    ).hexdigest()
    assert len(acceptance_bytes) == 1505
    assert acceptance_hash == (
        "sha256:d64be354affc906846f099986fe59daa"
        "dc8283796dea4f7562011970165e65e2"
    )
    assert "signature" not in acceptance
    assert "assembly_acceptance_hash" not in acceptance
    acceptance_message = (
        b"acgs.questionnaire.assembly-acceptance-signature/v1\0"
        + acceptance_hash.encode("ascii")
    )
    acceptance_signature_raw = _p256_sign(acceptance_message, 2, 5)
    acceptance_signature = base64.urlsafe_b64encode(
        acceptance_signature_raw
    ).rstrip(b"=").decode()
    assert acceptance_signature == (
        "UVkLelFRQNLXhMhWCGaP3--Mgv0fW-UkIVVKDcPQM-1Rfya7b8bgYTWuQReh89b"
        "OWUBQ-4AhLNKcC-ELt_rzhg"
    )
    acceptance_envelope = {
        "schema_version": "AssemblyAcceptance/v1",
        "preimage": acceptance,
        "assembly_acceptance_hash": acceptance_hash,
        "signature": acceptance_signature,
    }
    assert set(acceptance_envelope) == {
        "schema_version",
        "preimage",
        "assembly_acceptance_hash",
        "signature",
    }
    assert _p256_verify(acceptance_message, acceptance_signature_raw, 2)
    assert not _p256_verify(acceptance_message, acceptance_signature_raw, 1)
    tampered_acceptance_signature = acceptance_signature_raw[:-1] + bytes(
        [acceptance_signature_raw[-1] ^ 1]
    )
    assert not _p256_verify(acceptance_message, tampered_acceptance_signature, 2)

    substituted_content = {
        **content,
        "ordered_payload_artifacts": content["ordered_payload_artifacts"][:1],
    }
    substituted_content_bytes = json.dumps(
        substituted_content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert (
        "sha256:"
        + hashlib.sha256(
            b"acgs.questionnaire.content-manifest/v1\0"
            + substituted_content_bytes
        ).hexdigest()
        != content_hash
    )
    for field, replacement in (
        ("trust_root_id", "attacker-root"),
        ("manifest_sequence", 6),
        ("key_purpose", "OUTCOME_SIGNING"),
        ("signature_algorithm", "ED25519"),
        ("signature_encoding", "DER_BASE64"),
        ("signing_key_id", "attacker-key"),
        ("public_key_spki_sha256", digest("5")),
        ("valid_from", "2026-07-27T00:00:00Z"),
        ("valid_until", "2026-07-26T00:00:00Z"),
        ("revoked_at", "2026-07-26T00:00:00Z"),
        ("previous_verification_manifest_hash", digest("5")),
    ):
        substituted_manifest = {**verification_manifest, field: replacement}
        assert json.dumps(
            substituted_manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") != verification_manifest_bytes

    assert root_signature + "==" != root_signature
    tampered_root_signature = root_signature_raw[:-1] + bytes(
        [root_signature_raw[-1] ^ 1]
    )
    assert not _p256_verify(manifest_signature_message, tampered_root_signature, 1)
    assert not _p256_verify(
        b"acgs.questionnaire.wrong-domain/v1\0"
        + verification_manifest_hash.encode("ascii"),
        root_signature_raw,
        1,
    )
    replayed_burn = {**burn_preimage, "transaction_id": "burn-txn-2"}
    replayed_burn_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.receipt-burn-acceptance/v1\0"
        + json.dumps(
            replayed_burn,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert replayed_burn_hash != burn_hash
    assert not _p256_verify(
        b"acgs.questionnaire.receipt-burn-acceptance-signature/v1\0"
        + replayed_burn_hash.encode("ascii"),
        burn_signature_raw,
        3,
    )

    verifier_state_before_backend_faults = (
        {key: dict(value) for key, value in assembly_head_store.items()},
        {
            key: dict(value)
            for key, value in assembly_authenticated_predecessors.items()
        },
        list(barrier_entries),
        dict(receipt_consumptions),
        dict(burn_head_store),
        list(tool_invocations),
    )

    def assert_composed_hash_failure_is_closed(
        operation: Callable[[], object],
        nth_call: int,
    ) -> None:
        original_sha256 = hashlib.sha256
        calls = 0

        def fail_nth_hash(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == nth_call:
                raise AssertionError(f"injected sha256 failure #{nth_call}")
            return original_sha256(*args, **kwargs)

        with monkeypatch.context() as patcher:
            patcher.setattr(hashlib, "sha256", fail_nth_hash)
            result = operation()
        assert result is False or result is None
        assert calls >= nth_call
        assert (
            {key: dict(value) for key, value in assembly_head_store.items()},
            {
                key: dict(value)
                for key, value in assembly_authenticated_predecessors.items()
            },
            list(barrier_entries),
            dict(receipt_consumptions),
            dict(burn_head_store),
            list(tool_invocations),
        ) == verifier_state_before_backend_faults

    composed_backend_failure_operations = (
        lambda: publish_assembly_manifest_head(
            verification_manifest_envelope,
            manifest_policy_chain,
        ),
        lambda: manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        ),
        lambda: resolve_policy_receipt_verifier(
            manifest_policy_chain,
            "2026-07-26T22:45:00Z",
            verification_manifest_envelope,
            initial_head,
        ),
    )
    for operation in composed_backend_failure_operations:
        for nth_call in (2, 4):
            assert_composed_hash_failure_is_closed(operation, nth_call)
    assert_composed_hash_failure_is_closed(
        lambda: atomic_burn_then_invoke(burn_store_record),
        1,
    )

    for field, replacement in (
        ("assembly_action", "questionnaire.pack.other"),
        ("assembly_actor", "attacker"),
        ("assembly_argument_hash", "3" * 64),
        ("assembly_receipt_id", "stale-receipt"),
        ("assembly_receipt_hash", "4" * 64),
        ("assembly_audit_event_hash", "5" * 64),
        ("assembly_burn_acceptance_hash", digest("6")),
        ("assembly_burn_acceptance_signature", root_signature),
        ("burn_verification_manifest_hash", digest("5")),
        ("assembly_outcome_hash", digest("7")),
        ("verification_manifest_hash", digest("5")),
        ("signature_algorithm", "ED25519"),
        ("signature_encoding", "DER_BASE64"),
    ):
        substituted_acceptance = {**acceptance, field: replacement}
        assert json.dumps(
            substituted_acceptance,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") != acceptance_bytes

    malformed_objects: tuple[object, ...] = (None, [], "not-an-object", 7)
    for malformed in malformed_objects:
        assert not register_authenticated_assembly_predecessor(
            malformed,
            manifest_policy_chain,
        )
        assert not register_authenticated_assembly_predecessor(
            initial_predecessor,
            malformed,
        )
        assert not publish_assembly_manifest_head(malformed, manifest_policy_chain)
        assert not publish_assembly_manifest_head(
            verification_manifest_envelope,
            malformed,
        )
        assert not manifest_is_accepted(
            malformed,
            "2026-07-26T22:45:00Z",
            manifest_policy_chain,
        )
        assert not manifest_is_accepted(
            verification_manifest_envelope,
            "2026-07-26T22:45:00Z",
            malformed,
        )

    contract_text = re.sub(r"\s+", " ", text)
    for contract_token in (
        "AssemblyManifestPredecessorPreimage/v1",
        "acgs.questionnaire.assembly-manifest-predecessor/v1\\0",
        "AssemblyManifestPredecessorEnvelope/v1",
        'authenticated_trust.predecessor_signing_domain || "\\0"',
        "caller-written raw value",
        "No global fixture key, hard-coded public scalar",
        "Before any JCS serialization or domain-separated hashing",
        "SPKI-digest, policy-version, and signature-verification backend failures",
        "No public verifier may call a raw hash backend",
        "second and fourth calls of composed verification",
        "callers must not first evaluate an unsafe JCS serializer",
        "receipt-grant boundary contains receipt-verifier resolution",
        "Ed25519 SHA-512 signature verification",
        "complete intended 91-byte scalar-1 P-256 assembly-root SPKI DER",
        "independently frozen literal",
        "compares the loaded or constructed output byte-for-byte",
        "valid scalar-2 DER",
        "coordinated scalar-2 re-signing of the trust chain",
        "never evaluate a P-256/SPKI constructor as an argument",
        'revoked_at = b"x"',
        "non-JSON member is rejected before",
        "Thus a bytes-valued",
        "`status`, custom object",
        "without canonicalization, exception, barrier entry",
        "uses bounded iterative closed validation",
        "maximum nesting depth 32",
        "maximum 4,096 visited scalar/container/key nodes",
        "maximum 1,024 containers",
        "cycles and repeated list/object identities are rejected",
        "restricted to exact built-in `dict`, `list`, `str`, `bool`, `int`, or `null`",
        "I-JSON interoperable range `[-(2^53)+1, (2^53)-1]`",
        "never materializes an unbounded `extend` from attacker input",
        "shared safe-JCS and safe-domain-hash helpers catch",
        "Mapping subclasses and hostile scalar/container subclasses are rejected",
        "registry verifier requires the manifest and every nested carrier/scalar",
        "safe domain-hash exception boundary encloses the validator call",
        "Every timestamp parser likewise requires an exact built-in string",
        "exact runtime type `DecisionReceipt`",
        "runs the bounded iterative validator over the complete candidate",
        "This gate applies before canonicalization in predecessor registration",
        "integrated `RegistryKeyAuthorityProof` verification",
    ):
        assert contract_token in contract_text


def test_site_copy_source_version_evidence_matches_current_manifest() -> None:
    deck = _read(SITE_DECK)
    row = next(line for line in deck.splitlines() if line.startswith("| C2 | **Verified**"))
    manifest = (ROOT / "packages/gove-zone/pyproject.toml").read_text(encoding="utf-8")
    package_init = (
        ROOT / "packages/gove-zone/src/gove_zone/__init__.py"
    ).read_text(encoding="utf-8")
    for token in (
        'dynamic = ["version"]',
        "Development Status :: 4 - Beta",
        '[tool.hatch.version]',
        'path = "src/gove_zone/__init__.py"',
    ):
        assert token in manifest
    assert '__version__ = "1.0.0rc1"' in package_init
    for token in (
        'dynamic = ["version"]',
        "Beta classifier",
        "[tool.hatch.version]",
        "source/editable fallback is `1.0.0rc1`",
        "published version 1.0.0rc2",
        "public pin separate from source metadata",
    ):
        assert token in row
    assert "0.1.0.dev0 Alpha" not in row


def test_qa_contradictions_have_separate_authenticated_lineage() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    evidence = text.partition("### 2.3 Evidence")[2].partition(
        "### 2.3.1 CitationQARecord"
    )[0]
    contradiction = text.partition("#### ContradictionRecord")[2].partition(
        "### 2.3.2 SemanticAdjudicationRecord"
    )[0]
    normalized = re.sub(r"\s+", " ", contradiction)
    for token in (
        "ContradictionRecordPreimage/v1",
        "ContradictionRecord/v1",
        "To avoid self-reference",
        "it excludes qa_outcome_hash",
        "source_file_path",
        "source_commit_sha",
        "source_excerpt_hash",
        "source_artifact_hash",
        "qa_receipt_id",
        "qa_outcome_hash",
        "acgs.questionnaire.contradiction/v1\\0",
        "acgs.questionnaire.excerpt/v1\\0",
        "same strict decoded excerpt bytes and line-range equality",
        "acgs.questionnaire.artifact/v1\\0",
        "source_artifact_hash is exactly the §2.3.3 Git-blob digest",
        "No alternate contradiction-specific text decoding",
        "canonical QA result envelope authenticates that complete candidate preimage",
        "outer OutcomeEvent.result_hash",
        "Only after that outcome is finalized",
        "not mining Evidence",
        "never attributed to the mining receipt or mining outcome",
        "mining outcome pointer, mining producer lineage",
        "Mutating the excerpt bytes, range, file bytes, commit",
    ):
        assert token in normalized.replace("`", "")
    assert "contradicts_locator" not in evidence
    assert "contradicts_evidence_id" not in text

    file_bytes = b"alpha\n"
    excerpt_bytes = b"alpha"
    source_artifact_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.artifact/v1\0" + file_bytes
    ).hexdigest()
    source_excerpt_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.excerpt/v1\0" + excerpt_bytes
    ).hexdigest()
    assert source_artifact_hash == (
        "sha256:1e6f051f9e613e96aa7cae9326e57c1"
        "e48eca357fc5c81728786ce493f1d4f43"
    )
    assert source_excerpt_hash == (
        "sha256:bb38581a1481f962bdb5e211141f1e62"
        "d8a76e6ba1552c9586fec56b8b563648"
    )

    preimage = {
        "schema_version": "ContradictionRecordPreimage/v1",
        "contradiction_record_id": "cr-1",
        "job_id": "job-1",
        "question_id": "q-1",
        "response_id": "resp-1",
        "response_version": 1,
        "answer_hash": "sha256:" + "b" * 64,
        "assertion_id": "as-1",
        "assertion_hash": "sha256:" + "a" * 64,
        "source_file_path": "src/a.py",
        "source_commit_sha": "0123456789abcdef0123456789abcdef01234567",
        "source_line_start": 1,
        "source_line_end": 1,
        "source_excerpt_hash": source_excerpt_hash,
        "source_artifact_hash": source_artifact_hash,
        "qa_receipt_id": "qa-rec-1",
    }
    canonical = json.dumps(
        preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.contradiction/v1\0" + canonical
    ).hexdigest()
    assert digest == (
        "sha256:ed439722855ac5c404a636edaee0ae2c"
        "cabfb0b74dd5669a228dd72f7c0949b9"
    )
    mutated_excerpt_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.excerpt/v1\0" + b"alphA"
    ).hexdigest()
    mutated_artifact_hash = "sha256:" + hashlib.sha256(
        b"acgs.questionnaire.artifact/v1\0" + b"alpha\r\n"
    ).hexdigest()
    assert mutated_excerpt_hash != source_excerpt_hash
    assert mutated_artifact_hash != source_artifact_hash

    for mutated in (
        dict(preimage, source_line_end=2),
        dict(preimage, source_excerpt_hash=mutated_excerpt_hash),
        dict(preimage, source_artifact_hash=mutated_artifact_hash),
    ):
        mutated_bytes = json.dumps(
            mutated, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        mutated_digest = "sha256:" + hashlib.sha256(
            b"acgs.questionnaire.contradiction/v1\0" + mutated_bytes
        ).hexdigest()
        assert mutated_digest != digest
