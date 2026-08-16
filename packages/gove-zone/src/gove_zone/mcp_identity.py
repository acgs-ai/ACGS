"""Identity verification boundary for the protocol-agnostic MCP gateway.

The gateway never parses or trusts bearer-token fields itself.  A configured
``MCPTokenVerifier`` authenticates the token and returns immutable claims;
this module then enforces the claims that are relevant to side-effect
authorization before constructing the existing :class:`VerifiedPrincipal`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, cast, runtime_checkable

from gove_zone.authorization import (
    StrictJSONBudgetError,
    VerifiedPrincipal,
    validate_strict_json_budget,
)


def _require_text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    return value


def _timestamp(value: object, name: str) -> str:
    text = _require_text(value, name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be a UTC timestamp")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _unique_text_tuple(value: object, name: str) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise TypeError(f"{name} must be a list or tuple")
    items = tuple(
        _require_text(item, f"{name} item") for item in cast(list[Any] | tuple[Any, ...], value)
    )
    if not items:
        raise ValueError(f"{name} must not be empty")
    if len(items) != len(set(items)):
        raise ValueError(f"{name} must not contain duplicates")
    return items


class MCPIdentityReasonCode(StrEnum):
    """Stable fail-closed identity rejection reasons."""

    TOKEN_INVALID = "mcp.identity.token_invalid"  # noqa: S105 - reason code, not a token
    TOKEN_EXPIRED = "mcp.identity.token_expired"  # noqa: S105 - reason code, not a token
    ISSUER_MISMATCH = "mcp.identity.issuer_mismatch"
    AUDIENCE_MISMATCH = "mcp.identity.audience_mismatch"
    RESOURCE_MISMATCH = "mcp.identity.resource_mismatch"
    CLIENT_NOT_ALLOWED = "mcp.identity.client_not_allowed"
    TENANT_NOT_ALLOWED = "mcp.identity.tenant_not_allowed"
    ROLE_NOT_ALLOWED = "mcp.identity.role_not_allowed"
    SESSION_MISMATCH = "mcp.identity.session_mismatch"
    AUTHORITY_MISMATCH = "mcp.identity.authority_mismatch"
    SCOPE_MISSING = "mcp.identity.scope_missing"


class MCPIdentityError(RuntimeError):
    """Structured, non-retryable rejection at the token boundary."""

    non_retryable = True

    def __init__(self, reason_code: MCPIdentityReasonCode) -> None:
        if not isinstance(reason_code, MCPIdentityReasonCode):
            raise TypeError("reason_code must be an MCPIdentityReasonCode")
        self.reason_code = reason_code
        super().__init__(reason_code.value)


@dataclass(frozen=True, slots=True)
class MCPTokenClaims:
    """Authenticated claims returned by the deployment's token verifier."""

    issuer: str
    audiences: tuple[str, ...]
    resource: str
    client_id: str
    user_id: str
    tenant_id: str
    role: str
    authority: str
    scopes: tuple[str, ...]
    session_id: str
    token_id: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for name in (
            "issuer",
            "resource",
            "client_id",
            "user_id",
            "tenant_id",
            "role",
            "authority",
            "session_id",
            "token_id",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(self, "audiences", _unique_text_tuple(self.audiences, "audiences"))
        object.__setattr__(self, "scopes", _unique_text_tuple(self.scopes, "scopes"))
        issued_at = _timestamp(self.issued_at, "issued_at")
        expires_at = _timestamp(self.expires_at, "expires_at")
        if _as_datetime(expires_at) <= _as_datetime(issued_at):
            raise ValueError("token expiry must be after issuance")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)


@runtime_checkable
class MCPTokenVerifier(Protocol):
    """Authenticate an inbound token and return trusted claims."""

    def verify(self, token: str) -> MCPTokenClaims: ...


_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_ED25519_PUBLIC_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64
_JWS_HEADER_KEYS = frozenset({"alg", "typ", "kid"})
_JWS_CLAIM_KEYS = frozenset(
    {
        "iss",
        "aud",
        "sub",
        "client_id",
        "user_id",
        "tenant_id",
        "role",
        "authority",
        "scope",
        "resource",
        "sid",
        "jti",
        "iat",
        "nbf",
        "exp",
    }
)
_JWS_ALGORITHM = "EdDSA"
_JWS_TYPE = "at+jwt"
_MAX_TOKEN_BYTES = 4096
_MAX_SEGMENT_BYTES = 2048


def _required_authorities(required_authority: str | frozenset[str]) -> frozenset[str]:
    """Normalize one authority, or an immutable set of accepted authorities.

    A caller that accepts more than one authority must say so with a frozenset:
    a mutable set would let a later holder widen what the gate accepts.
    """

    if type(required_authority) is frozenset:
        if not required_authority:
            raise ValueError("required_authority must not be an empty set")
        return frozenset(_require_text(item, "required_authority") for item in required_authority)
    return frozenset({_require_text(required_authority, "required_authority")})


class JWSVerificationError(ValueError):
    """A compact JWS failed a strict structural, cryptographic, or claim check.

    The message is a fixed operator-authored string.  No inbound token bytes,
    key material, or JSON fragment is ever interpolated into it.
    """


def _b64url_decode(segment: str, name: str) -> bytes:
    """Decode one canonical, unpadded base64url segment.

    ``base64.urlsafe_b64decode`` silently tolerates non-canonical trailing bits
    and a padded alphabet, so two distinct segment spellings can decode to the
    same bytes.  A signature covers the *encoded* segments, so an accepted
    alternate spelling is a signature-reuse primitive.  Re-encoding and
    requiring an exact round-trip is what makes the encoding injective.
    """

    if not segment:
        raise JWSVerificationError("compact JWS segment must not be empty")
    if len(segment.encode("ascii", errors="replace")) > _MAX_SEGMENT_BYTES:
        raise JWSVerificationError(f"compact JWS {name} segment exceeds the bounded size")
    if any(character not in _B64URL_ALPHABET for character in segment):
        raise JWSVerificationError(f"compact JWS {name} segment is not canonical base64url")
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError):
        raise JWSVerificationError(f"compact JWS {name} segment is not decodable") from None
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != segment:
        raise JWSVerificationError(f"compact JWS {name} segment is not canonical base64url")
    return raw


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys instead of last-one-wins.

    ``json.loads`` keeps the last duplicate.  A token carrying ``{"iss": "good",
    "iss": "evil"}`` would therefore verify under one reading and authorize under
    another, which is exactly the confusion this boundary exists to stop.
    """

    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise JWSVerificationError("JSON object contains duplicate keys")
    return dict(pairs)


def _strict_json_object(raw: bytes, name: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise JWSVerificationError(f"compact JWS {name} is not strict UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constants)
    except JWSVerificationError:
        raise
    except (ValueError, RecursionError):
        raise JWSVerificationError(f"compact JWS {name} is not a strict JSON object") from None
    if type(value) is not dict:
        raise JWSVerificationError(f"compact JWS {name} must be a JSON object")
    try:
        validate_strict_json_budget(value)
    except (StrictJSONBudgetError, RecursionError):
        raise JWSVerificationError(f"compact JWS {name} exceeds the strict JSON budget") from None
    return cast(dict[str, Any], value)


def _no_constants(_value: str) -> Any:
    raise JWSVerificationError("JSON must not contain NaN or Infinity constants")


def _claim_text(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if type(value) is not str or not value:
        raise JWSVerificationError(f"claim {name} must be a non-empty string")
    return value


def _claim_integer(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    # ``bool`` is an ``int`` subclass; a JSON ``true`` must not read as 1.
    if type(value) is not int:
        raise JWSVerificationError(f"claim {name} must be an integer")
    if not 0 <= value <= 253_402_300_799:
        raise JWSVerificationError(f"claim {name} is out of range")
    return value


class Ed25519TrustSnapshot:
    """A frozen ``kid`` -> raw Ed25519 public-key registry.

    The snapshot is taken once at construction and copied, so mutating the
    caller's source mapping, list, or key object afterwards cannot change what
    this gateway trusts.  There is no remote fetch, no refresh, and no
    negotiation: an unknown ``kid`` fails closed.
    """

    __slots__ = ("_keys",)

    _keys: Mapping[str, bytes]

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        if not isinstance(keys, Mapping):
            raise TypeError("keys must be a mapping of kid to raw Ed25519 public bytes")
        if not keys:
            raise ValueError("trust snapshot must contain at least one key")
        frozen: dict[str, bytes] = {}
        for kid, material in keys.items():
            key_id = _require_text(kid, "kid")
            if type(material) not in (bytes, bytearray, memoryview):
                raise TypeError("trust snapshot values must be raw Ed25519 public bytes")
            # ``bytes(...)`` copies, so a later mutation of the caller's
            # bytearray cannot retroactively change the trusted key.
            raw = bytes(material)
            if len(raw) != _ED25519_PUBLIC_KEY_BYTES:
                raise ValueError("trust snapshot keys must be 32 raw Ed25519 bytes")
            if key_id in frozen:
                raise ValueError("trust snapshot must not contain duplicate kids")
            frozen[key_id] = raw
        object.__setattr__(self, "_keys", MappingProxyType(frozen))

    def public_bytes(self, kid: str) -> bytes | None:
        return self._keys.get(kid)

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))


class EdDSAJWSVerifier:
    """Strict EdDSA (Ed25519) compact-JWS workload-identity verifier.

    This is deliberately the smallest verifier that satisfies the boundary, not
    a general JOSE implementation.  Everything a JOSE library would negotiate is
    frozen instead: ``alg`` is exactly ``EdDSA``, the key comes only from the
    pinned :class:`Ed25519TrustSnapshot` by exact ``kid``, and header-carried key
    material (``jwk``/``x5u``/``jku``/``x5c``) is a hard rejection rather than an
    input.  There is no HMAC path and no ``none`` path, so algorithm confusion
    has no branch to reach.  The signature is verified *before* any claim is
    read, so unauthenticated bytes never influence a decision.
    """

    def __init__(
        self,
        *,
        trust: Ed25519TrustSnapshot,
        issuer: str,
        audience: str,
        resource: str,
        max_lifetime_seconds: int = 3600,
        clock_skew_seconds: int = 60,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(trust, Ed25519TrustSnapshot):
            raise TypeError("trust must be an Ed25519TrustSnapshot")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        for name, value in (
            ("max_lifetime_seconds", max_lifetime_seconds),
            ("clock_skew_seconds", clock_skew_seconds),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if clock_skew_seconds > 300:
            raise ValueError("clock_skew_seconds must not exceed 300")
        self._trust = trust
        self._issuer = _require_text(issuer, "issuer")
        self._audience = _require_text(audience, "audience")
        self._resource = _require_text(resource, "resource")
        self._max_lifetime = max_lifetime_seconds
        self._skew = clock_skew_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(self, token: str) -> MCPTokenClaims:
        header_segment, payload_segment = self._split(token)
        # Signature first: the header's ``kid`` selects a pinned key, and nothing
        # from the payload is parsed until that key has authenticated the bytes.
        self._verify_signature(token, header_segment, payload_segment)
        claims = _strict_json_object(_b64url_decode(payload_segment, "payload"), "payload")
        return self._claims(claims)

    def _split(self, token: str) -> tuple[str, str]:
        if type(token) is not str or not token:
            raise JWSVerificationError("token must be a non-empty string")
        try:
            raw = token.encode("ascii")
        except UnicodeEncodeError:
            raise JWSVerificationError("compact JWS must be ASCII") from None
        if len(raw) > _MAX_TOKEN_BYTES:
            raise JWSVerificationError("compact JWS exceeds the bounded size")
        segments = token.split(".")
        if len(segments) != 3:
            raise JWSVerificationError("compact JWS must have exactly three segments")
        return segments[0], segments[1]

    def _verify_signature(self, token: str, header_segment: str, payload_segment: str) -> None:
        from gove_zone.signing import Ed25519Signer

        header = _strict_json_object(_b64url_decode(header_segment, "header"), "header")
        if set(header) != _JWS_HEADER_KEYS:
            # An exact key set, not a superset check: ``crit``, ``jwk``, ``jku``,
            # ``x5u``, and ``x5c`` are all rejected by their mere presence, so no
            # attacker-supplied key can ever be consulted.
            raise JWSVerificationError("compact JWS protected header schema is not exact")
        if header["alg"] != _JWS_ALGORITHM:
            raise JWSVerificationError("compact JWS alg must be EdDSA")
        if header["typ"] != _JWS_TYPE:
            raise JWSVerificationError("compact JWS typ must be at+jwt")
        kid = header["kid"]
        if type(kid) is not str or not kid:
            raise JWSVerificationError("compact JWS kid must be a non-empty string")
        public_bytes = self._trust.public_bytes(kid)
        if public_bytes is None:
            raise JWSVerificationError("compact JWS kid is not in the pinned trust snapshot")
        signature = _b64url_decode(token.rpartition(".")[2], "signature")
        if len(signature) != _ED25519_SIGNATURE_BYTES:
            raise JWSVerificationError("compact JWS signature must be 64 Ed25519 bytes")
        signed = f"{header_segment}.{payload_segment}".encode("ascii")
        verifier = Ed25519Signer.from_public_bytes(public_bytes, key_id=kid)
        if not verifier.verify(signed, signature.hex()):
            raise JWSVerificationError("compact JWS signature is invalid")

    def _claims(self, claims: Mapping[str, Any]) -> MCPTokenClaims:
        if set(claims) != _JWS_CLAIM_KEYS:
            raise JWSVerificationError("compact JWS claim schema is not exact")
        if _claim_text(claims, "iss") != self._issuer:
            raise JWSVerificationError("compact JWS issuer is not the pinned issuer")
        audience = claims["aud"]
        # A single exact audience string only.  A list would let one token be
        # replayed at every audience that appears in it.
        if type(audience) is not str or audience != self._audience:
            raise JWSVerificationError("compact JWS audience is not the pinned audience")
        if _claim_text(claims, "resource") != self._resource:
            raise JWSVerificationError("compact JWS resource is not the pinned resource")
        scope = _claim_text(claims, "scope")
        scopes = tuple(scope.split(" "))
        if any(not item for item in scopes) or len(scopes) != len(set(scopes)):
            raise JWSVerificationError("compact JWS scope must be unique space-delimited values")

        issued_at = _claim_integer(claims, "iat")
        not_before = _claim_integer(claims, "nbf")
        expires_at = _claim_integer(claims, "exp")
        if not issued_at <= not_before < expires_at:
            raise JWSVerificationError("compact JWS iat/nbf/exp are not ordered")
        if expires_at - issued_at > self._max_lifetime:
            raise JWSVerificationError("compact JWS lifetime exceeds the configured ceiling")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise JWSVerificationError("verifier clock must return an aware UTC datetime")
        seconds = int(now.timestamp())
        if seconds + self._skew < not_before:
            raise JWSVerificationError("compact JWS is not yet valid")
        if seconds - self._skew >= expires_at:
            raise JWSVerificationError("compact JWS has expired")

        subject = _claim_text(claims, "sub")
        user_id = _claim_text(claims, "user_id")
        if subject != user_id:
            # The subject is the identity the authority signed; letting a second
            # claim name a different user would split authentication from
            # authorization.
            raise JWSVerificationError("compact JWS sub and user_id must agree")
        return MCPTokenClaims(
            issuer=self._issuer,
            audiences=(self._audience,),
            resource=self._resource,
            client_id=_claim_text(claims, "client_id"),
            user_id=user_id,
            tenant_id=_claim_text(claims, "tenant_id"),
            role=_claim_text(claims, "role"),
            authority=_claim_text(claims, "authority"),
            scopes=scopes,
            session_id=_claim_text(claims, "sid"),
            token_id=_claim_text(claims, "jti"),
            issued_at=_epoch_iso(issued_at),
            expires_at=_epoch_iso(expires_at),
        )


def _epoch_iso(value: int) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class MCPIdentityPolicy:
    """Immutable administrative identity policy for one gateway."""

    trusted_issuer: str
    gateway_audience: str
    resource_audience: str
    allowed_clients: tuple[str, ...]
    allowed_tenants: tuple[str, ...]
    allowed_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("trusted_issuer", "gateway_audience", "resource_audience"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        for name in ("allowed_clients", "allowed_tenants", "allowed_roles"):
            object.__setattr__(self, name, _unique_text_tuple(getattr(self, name), name))


@dataclass(frozen=True, slots=True)
class VerifiedMCPIdentity:
    """A verified principal plus MCP client/session attributes."""

    principal: VerifiedPrincipal
    client_id: str
    user_id: str
    session_id: str
    token_id: str
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.principal, VerifiedPrincipal):
            raise TypeError("principal must be a VerifiedPrincipal")
        for name in ("client_id", "user_id", "session_id", "token_id"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        if type(self.scopes) is not frozenset or not self.scopes:
            raise ValueError("scopes must be a non-empty frozenset")
        if any(type(scope) is not str or not scope for scope in self.scopes):
            raise ValueError("scopes must contain non-empty strings")


class MCPIdentityVerifier:
    """Convert authenticated token claims into the shared principal model."""

    def __init__(
        self,
        token_verifier: MCPTokenVerifier,
        policy: MCPIdentityPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(token_verifier, MCPTokenVerifier):
            raise TypeError("token_verifier must implement MCPTokenVerifier")
        if not isinstance(policy, MCPIdentityPolicy):
            raise TypeError("policy must be an MCPIdentityPolicy")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._token_verifier = token_verifier
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        inbound_token: str,
        *,
        session_id: str,
        required_authority: str | frozenset[str],
        required_scopes: frozenset[str] = frozenset(),
    ) -> VerifiedMCPIdentity:
        try:
            token = _require_text(inbound_token, "inbound_token")
        except (TypeError, ValueError):
            raise MCPIdentityError(MCPIdentityReasonCode.TOKEN_INVALID) from None
        try:
            expected_session = _require_text(session_id, "session_id")
        except (TypeError, ValueError):
            raise MCPIdentityError(MCPIdentityReasonCode.SESSION_MISMATCH) from None
        try:
            authorities = _required_authorities(required_authority)
        except (TypeError, ValueError):
            raise MCPIdentityError(MCPIdentityReasonCode.AUTHORITY_MISMATCH) from None
        if type(required_scopes) is not frozenset:
            raise MCPIdentityError(MCPIdentityReasonCode.SCOPE_MISSING)
        try:
            claims = self._token_verifier.verify(token)
        except Exception:
            raise MCPIdentityError(MCPIdentityReasonCode.TOKEN_INVALID) from None
        if not isinstance(claims, MCPTokenClaims):
            raise MCPIdentityError(MCPIdentityReasonCode.TOKEN_INVALID)

        policy = self._policy
        if claims.issuer != policy.trusted_issuer:
            raise MCPIdentityError(MCPIdentityReasonCode.ISSUER_MISMATCH)
        if policy.gateway_audience not in claims.audiences:
            raise MCPIdentityError(MCPIdentityReasonCode.AUDIENCE_MISMATCH)
        if claims.resource != policy.resource_audience:
            raise MCPIdentityError(MCPIdentityReasonCode.RESOURCE_MISMATCH)
        if claims.client_id not in policy.allowed_clients:
            raise MCPIdentityError(MCPIdentityReasonCode.CLIENT_NOT_ALLOWED)
        if claims.tenant_id not in policy.allowed_tenants:
            raise MCPIdentityError(MCPIdentityReasonCode.TENANT_NOT_ALLOWED)
        if claims.role not in policy.allowed_roles:
            raise MCPIdentityError(MCPIdentityReasonCode.ROLE_NOT_ALLOWED)
        if claims.session_id != expected_session:
            raise MCPIdentityError(MCPIdentityReasonCode.SESSION_MISMATCH)
        if claims.authority not in authorities:
            raise MCPIdentityError(MCPIdentityReasonCode.AUTHORITY_MISMATCH)
        scopes = frozenset(claims.scopes)
        if not required_scopes.issubset(scopes):
            raise MCPIdentityError(MCPIdentityReasonCode.SCOPE_MISSING)

        now = self._clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise MCPIdentityError(MCPIdentityReasonCode.TOKEN_INVALID)
        now = now.astimezone(UTC)
        if not (_as_datetime(claims.issued_at) <= now < _as_datetime(claims.expires_at)):
            raise MCPIdentityError(MCPIdentityReasonCode.TOKEN_EXPIRED)

        principal = VerifiedPrincipal(
            tenant_id=claims.tenant_id,
            actor_id=claims.user_id,
            role=claims.role,
            authority=claims.authority,
            authentication_context={
                "authentication_method": "verified-bearer-token",
                "issuer": claims.issuer,
                "audience": policy.gateway_audience,
                "resource_audience": claims.resource,
                "client_id": claims.client_id,
                "user_id": claims.user_id,
                "session_id": claims.session_id,
                "token_id": claims.token_id,
                "token_fingerprint": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                "scopes": sorted(scopes),
            },
            verified_at=claims.issued_at,
            expires_at=claims.expires_at,
        )
        return VerifiedMCPIdentity(
            principal=principal,
            client_id=claims.client_id,
            user_id=claims.user_id,
            session_id=claims.session_id,
            token_id=claims.token_id,
            scopes=scopes,
        )


class MCPPrincipalContext:
    """Concurrency-safe principal resolver shared by gateway and kernel gates."""

    def __init__(self) -> None:
        self._current: ContextVar[VerifiedPrincipal | None] = ContextVar(
            "gove_zone_mcp_verified_principal",
            default=None,
        )

    @contextmanager
    def bind(self, principal: VerifiedPrincipal) -> Iterator[None]:
        if not isinstance(principal, VerifiedPrincipal):
            raise TypeError("principal must be a VerifiedPrincipal")
        token = self._current.set(principal)
        try:
            yield
        finally:
            self._current.reset(token)

    def resolve(self) -> VerifiedPrincipal:
        principal = self._current.get()
        if principal is None:
            raise RuntimeError("no verified MCP principal is bound to this call")
        return principal


__all__ = [
    "Ed25519TrustSnapshot",
    "EdDSAJWSVerifier",
    "JWSVerificationError",
    "MCPIdentityError",
    "MCPIdentityPolicy",
    "MCPIdentityReasonCode",
    "MCPIdentityVerifier",
    "MCPPrincipalContext",
    "MCPTokenClaims",
    "MCPTokenVerifier",
    "VerifiedMCPIdentity",
]
