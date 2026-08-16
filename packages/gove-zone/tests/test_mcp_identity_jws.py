"""Adversarial tests for the frozen EdDSA compact-JWS workload-identity verifier.

Every denial here must happen *before* the catalog is reached, so these drive
`EdDSAJWSVerifier.verify` directly: it is the only thing standing between an
inbound string and a `VerifiedPrincipal`.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from gove_zone.mcp_identity import (
    Ed25519TrustSnapshot,
    EdDSAJWSVerifier,
    JWSVerificationError,
    MCPTokenClaims,
)
from gove_zone.signing import Ed25519Signer

_ISSUER = "https://identity.fixture.invalid"
_AUDIENCE = "acgs-mcp-gateway"
_RESOURCE = "mcp://fixture-server"
_KID = "fixture-signing-key-1"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.fixture
def authority() -> Ed25519Signer:
    """The ephemeral demo authority.  Only its public key ever reaches a gateway."""

    return Ed25519Signer.generate(_KID)


@pytest.fixture
def trust(authority: Ed25519Signer) -> Ed25519TrustSnapshot:
    return Ed25519TrustSnapshot({_KID: authority.public_bytes()})


@pytest.fixture
def verifier(trust: Ed25519TrustSnapshot) -> EdDSAJWSVerifier:
    return EdDSAJWSVerifier(
        trust=trust,
        issuer=_ISSUER,
        audience=_AUDIENCE,
        resource=_RESOURCE,
    )


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(datetime.now(UTC).timestamp())
    claims: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": "fixture-agent",
        "client_id": "fixture-agent-client",
        "user_id": "fixture-agent",
        "tenant_id": "fixture-tenant",
        "role": "automation-agent",
        "authority": "mcp.tools.call",
        "scope": "tools:list fixture:read fixture:write",
        "resource": _RESOURCE,
        "sid": "fixture-session",
        "jti": "fixture-token-id",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 600,
    }
    claims.update(overrides)
    return claims


def _mint(
    authority: Ed25519Signer,
    *,
    header: dict[str, Any] | None = None,
    claims: dict[str, Any] | None = None,
    signer: Ed25519Signer | None = None,
    header_text: str | None = None,
    claims_text: str | None = None,
) -> str:
    protected = {"alg": "EdDSA", "typ": "at+jwt", "kid": _KID}
    if header is not None:
        protected.update(header)
    payload = _claims() if claims is None else claims
    header_segment = _b64(
        (header_text or json.dumps(protected, separators=(",", ":"))).encode("utf-8")
    )
    payload_segment = _b64(
        (claims_text or json.dumps(payload, separators=(",", ":"))).encode("utf-8")
    )
    signed = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = bytes.fromhex((signer or authority).sign(signed))
    return f"{header_segment}.{payload_segment}.{_b64(signature)}"


# -- happy path -------------------------------------------------------------


def test_valid_eddsa_token_verifies(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    claims = verifier.verify(_mint(authority))
    assert isinstance(claims, MCPTokenClaims)
    assert claims.issuer == _ISSUER
    assert claims.audiences == (_AUDIENCE,)
    assert claims.resource == _RESOURCE
    assert claims.client_id == "fixture-agent-client"
    assert claims.user_id == "fixture-agent"
    assert claims.tenant_id == "fixture-tenant"
    assert claims.role == "automation-agent"
    assert claims.authority == "mcp.tools.call"
    assert claims.session_id == "fixture-session"
    assert claims.token_id == "fixture-token-id"
    assert set(claims.scopes) == {"tools:list", "fixture:read", "fixture:write"}


# -- algorithm confusion ----------------------------------------------------


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "HS256", "RS256", "ES256", "EdDSA "])
def test_wrong_algorithm_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    alg: str,
) -> None:
    with pytest.raises(JWSVerificationError, match="alg must be EdDSA"):
        verifier.verify(_mint(authority, header={"alg": alg}))


def test_an_hmac_signature_over_the_public_key_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """The classic confusion: sign with HMAC keyed by the Ed25519 public key."""

    import hashlib
    import hmac

    protected = {"alg": "HS256", "typ": "at+jwt", "kid": _KID}
    header_segment = _b64(json.dumps(protected, separators=(",", ":")).encode())
    payload_segment = _b64(json.dumps(_claims(), separators=(",", ":")).encode())
    signed = f"{header_segment}.{payload_segment}".encode("ascii")
    forged = hmac.new(authority.public_bytes(), signed, hashlib.sha256).digest()
    with pytest.raises(JWSVerificationError):
        verifier.verify(f"{header_segment}.{payload_segment}.{_b64(forged)}")


def test_an_unsigned_token_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    header_segment = _b64(json.dumps({"alg": "none", "typ": "at+jwt", "kid": _KID}).encode())
    payload_segment = _b64(json.dumps(_claims(), separators=(",", ":")).encode())
    for token in (
        f"{header_segment}.{payload_segment}.",
        f"{header_segment}.{payload_segment}",
    ):
        with pytest.raises(JWSVerificationError):
            verifier.verify(token)


@pytest.mark.parametrize("key", ["jwk", "jku", "x5u", "x5c", "crit", "epk"])
def test_header_carried_key_material_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    key: str,
) -> None:
    """A header key the verifier might consult must be refused by its presence."""

    with pytest.raises(JWSVerificationError, match="header schema is not exact"):
        verifier.verify(_mint(authority, header={key: {"attacker": "controlled"}}))


def test_a_missing_header_field_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    header_text = json.dumps({"alg": "EdDSA", "typ": "at+jwt"}, separators=(",", ":"))
    with pytest.raises(JWSVerificationError, match="header schema is not exact"):
        verifier.verify(_mint(authority, header_text=header_text))


def test_a_wrong_typ_is_denied(verifier: EdDSAJWSVerifier, authority: Ed25519Signer) -> None:
    with pytest.raises(JWSVerificationError, match="typ must be at\\+jwt"):
        verifier.verify(_mint(authority, header={"typ": "JWT"}))


# -- key selection ----------------------------------------------------------


def test_an_unknown_kid_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    with pytest.raises(JWSVerificationError, match="kid is not in the pinned trust snapshot"):
        verifier.verify(_mint(authority, header={"kid": "some-other-key"}))


def test_a_valid_signature_from_an_untrusted_key_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """A perfectly valid signature under the *wrong* key must not verify."""

    rogue = Ed25519Signer.generate(_KID)
    with pytest.raises(JWSVerificationError, match="signature is invalid"):
        verifier.verify(_mint(authority, signer=rogue))


def test_a_tampered_signature_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    token = _mint(authority)
    header_segment, payload_segment, signature = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
    raw[0] ^= 0xFF
    with pytest.raises(JWSVerificationError, match="signature is invalid"):
        verifier.verify(f"{header_segment}.{payload_segment}.{_b64(bytes(raw))}")


def test_a_swapped_payload_under_a_valid_signature_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """Signature covers the encoded segments, so a payload swap must not survive."""

    token = _mint(authority)
    header_segment, _, signature = token.split(".")
    elevated = _b64(json.dumps(_claims(tenant_id="victim-tenant"), separators=(",", ":")).encode())
    with pytest.raises(JWSVerificationError, match="signature is invalid"):
        verifier.verify(f"{header_segment}.{elevated}.{signature}")


def test_a_wrong_signature_length_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    token = _mint(authority)
    header_segment, payload_segment, _ = token.split(".")
    with pytest.raises(JWSVerificationError, match="64 Ed25519 bytes"):
        verifier.verify(f"{header_segment}.{payload_segment}.{_b64(b'short')}")


# -- trust snapshot ---------------------------------------------------------


def test_the_trust_snapshot_copies_its_key_material() -> None:
    """Mutating the caller's buffer must not change what the gateway trusts."""

    material = bytearray(b"\x01" * 32)
    # A mutable buffer is passed deliberately: the case exists to prove the
    # snapshot copies key material rather than aliasing the caller's.
    trust = Ed25519TrustSnapshot({_KID: material})  # type: ignore[dict-item]
    material[0] = 0xFF
    assert trust.public_bytes(_KID) == b"\x01" * 32


def test_the_trust_snapshot_ignores_later_source_mapping_writes() -> None:
    source = {_KID: b"\x01" * 32}
    trust = Ed25519TrustSnapshot(source)
    source["injected-kid"] = b"\x02" * 32
    source[_KID] = b"\x03" * 32
    assert trust.key_ids == (_KID,)
    assert trust.public_bytes(_KID) == b"\x01" * 32
    assert trust.public_bytes("injected-kid") is None


def test_a_source_signer_rotation_cannot_change_a_live_verifier(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """Minting a new authority after the snapshot must not grant it trust."""

    rotated = Ed25519Signer.generate(_KID)
    with pytest.raises(JWSVerificationError, match="signature is invalid"):
        verifier.verify(_mint(authority, signer=rotated))
    # The originally pinned authority still works.
    assert verifier.verify(_mint(authority)).user_id == "fixture-agent"


def test_the_trust_snapshot_rejects_a_wrong_length_key() -> None:
    with pytest.raises(ValueError, match="32 raw Ed25519 bytes"):
        Ed25519TrustSnapshot({_KID: b"\x01" * 31})


def test_the_trust_snapshot_rejects_an_empty_registry() -> None:
    with pytest.raises(ValueError, match="at least one key"):
        Ed25519TrustSnapshot({})


def test_the_trust_snapshot_registry_is_read_only() -> None:
    trust = Ed25519TrustSnapshot({_KID: b"\x01" * 32})
    with pytest.raises(TypeError):
        trust._keys["injected-kid"] = b"\x02" * 32  # type: ignore[index]
    assert trust.key_ids == (_KID,)


# -- claim schema -----------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("iss", "https://evil.invalid", "issuer is not the pinned issuer"),
        ("aud", "some-other-gateway", "audience is not the pinned audience"),
        ("resource", "mcp://other-server", "resource is not the pinned resource"),
        ("sub", "someone-else", "sub and user_id must agree"),
    ],
)
def test_a_pinned_claim_mismatch_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    name: str,
    value: str,
    match: str,
) -> None:
    with pytest.raises(JWSVerificationError, match=match):
        verifier.verify(_mint(authority, claims=_claims(**{name: value})))


def test_a_list_audience_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """A multi-audience token is one token replayable at every audience in it."""

    claims = _claims(aud=[_AUDIENCE, "some-other-gateway"])
    with pytest.raises(JWSVerificationError, match="audience is not the pinned audience"):
        verifier.verify(_mint(authority, claims=claims))


@pytest.mark.parametrize(
    "name",
    ["client_id", "user_id", "tenant_id", "role", "authority", "sid", "jti", "scope"],
)
def test_an_empty_identity_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    name: str,
) -> None:
    with pytest.raises(JWSVerificationError, match=f"claim {name} must be a non-empty string"):
        verifier.verify(_mint(authority, claims=_claims(**{name: ""})))


@pytest.mark.parametrize(
    "name",
    ["client_id", "user_id", "tenant_id", "role", "authority", "sid", "jti"],
)
def test_a_non_string_identity_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    name: str,
) -> None:
    with pytest.raises(JWSVerificationError):
        verifier.verify(_mint(authority, claims=_claims(**{name: {"nested": "object"}})))


def test_an_extra_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    with pytest.raises(JWSVerificationError, match="claim schema is not exact"):
        verifier.verify(_mint(authority, claims=_claims(admin=True)))


def test_a_missing_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    claims = _claims()
    del claims["tenant_id"]
    with pytest.raises(JWSVerificationError, match="claim schema is not exact"):
        verifier.verify(_mint(authority, claims=claims))


def test_a_duplicate_json_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """`json.loads` keeps the last duplicate; two readings is one confusion."""

    claims_text = json.dumps(_claims(), separators=(",", ":"))
    poisoned = claims_text.replace(
        '"tenant_id":"fixture-tenant"',
        '"tenant_id":"fixture-tenant","tenant_id":"victim-tenant"',
    )
    with pytest.raises(JWSVerificationError, match="duplicate keys"):
        verifier.verify(_mint(authority, claims_text=poisoned))


def test_a_duplicate_json_header_field_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    header_text = '{"alg":"EdDSA","alg":"none","typ":"at+jwt","kid":"' + _KID + '"}'
    with pytest.raises(JWSVerificationError, match="duplicate keys"):
        verifier.verify(_mint(authority, header_text=header_text))


@pytest.mark.parametrize("scope", ["tools:list  fixture:read", "tools:list tools:list", " ", "  "])
def test_a_malformed_scope_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    scope: str,
) -> None:
    with pytest.raises(JWSVerificationError):
        verifier.verify(_mint(authority, claims=_claims(scope=scope)))


# -- time -------------------------------------------------------------------


def _at(trust: Ed25519TrustSnapshot, moment: datetime) -> EdDSAJWSVerifier:
    return EdDSAJWSVerifier(
        trust=trust,
        issuer=_ISSUER,
        audience=_AUDIENCE,
        resource=_RESOURCE,
        clock=lambda: moment,
    )


def test_an_expired_token_is_denied(
    trust: Ed25519TrustSnapshot,
    authority: Ed25519Signer,
) -> None:
    token = _mint(authority)
    future = datetime.now(UTC) + timedelta(hours=2)
    with pytest.raises(JWSVerificationError, match="has expired"):
        _at(trust, future).verify(token)


def test_a_not_yet_valid_token_is_denied(
    trust: Ed25519TrustSnapshot,
    authority: Ed25519Signer,
) -> None:
    now = int(datetime.now(UTC).timestamp())
    token = _mint(authority, claims=_claims(iat=now + 600, nbf=now + 600, exp=now + 1200))
    with pytest.raises(JWSVerificationError, match="not yet valid"):
        _at(trust, datetime.now(UTC)).verify(token)


def test_an_unordered_lifetime_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    now = int(datetime.now(UTC).timestamp())
    for claims in (
        _claims(iat=now, nbf=now - 60, exp=now + 600),
        _claims(iat=now, nbf=now, exp=now),
        _claims(iat=now, nbf=now, exp=now - 1),
    ):
        with pytest.raises(JWSVerificationError, match="not ordered"):
            verifier.verify(_mint(authority, claims=claims))


def test_an_overlong_lifetime_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    now = int(datetime.now(UTC).timestamp())
    claims = _claims(iat=now - 10, nbf=now - 10, exp=now + 86_400)
    with pytest.raises(JWSVerificationError, match="lifetime exceeds"):
        verifier.verify(_mint(authority, claims=claims))


@pytest.mark.parametrize("name", ["iat", "nbf", "exp"])
def test_a_non_integer_time_claim_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
    name: str,
) -> None:
    now = int(datetime.now(UTC).timestamp())
    for value in ("1700000000", 1.5, True, None):
        with pytest.raises(JWSVerificationError, match=f"claim {name} must be an integer"):
            verifier.verify(_mint(authority, claims=_claims(**{name: value})))
    del now


def test_a_skewed_clock_cannot_exceed_the_configured_ceiling(
    trust: Ed25519TrustSnapshot,
) -> None:
    with pytest.raises(ValueError, match="clock_skew_seconds must not exceed 300"):
        EdDSAJWSVerifier(
            trust=trust,
            issuer=_ISSUER,
            audience=_AUDIENCE,
            resource=_RESOURCE,
            clock_skew_seconds=86_400,
        )


def test_a_naive_clock_is_denied(
    trust: Ed25519TrustSnapshot,
    authority: Ed25519Signer,
) -> None:
    verifier = EdDSAJWSVerifier(
        trust=trust,
        issuer=_ISSUER,
        audience=_AUDIENCE,
        resource=_RESOURCE,
        clock=lambda: datetime.now(UTC).replace(tzinfo=None),
    )
    with pytest.raises(JWSVerificationError, match="aware UTC datetime"):
        verifier.verify(_mint(authority))


# -- encoding ---------------------------------------------------------------


def test_a_padded_header_segment_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """A padded segment is a second spelling of the same bytes; only one passes."""

    header_segment, payload_segment, signature = _mint(authority).split(".")
    padded = header_segment + "=" * (-len(header_segment) % 4)
    if padded == header_segment:
        padded = header_segment + "="
    with pytest.raises(JWSVerificationError, match="not canonical base64url"):
        verifier.verify(f"{padded}.{payload_segment}.{signature}")


def test_a_padded_payload_segment_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """Re-spelling the payload changes the signed input, so the signature fails.

    The signature is checked before the payload is parsed, so this is denied at
    the cryptographic step rather than the encoding step.  Either way it never
    reaches a claim.
    """

    header_segment, payload_segment, signature = _mint(authority).split(".")
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    if padded == payload_segment:
        padded = payload_segment + "="
    with pytest.raises(JWSVerificationError):
        verifier.verify(f"{header_segment}.{padded}.{signature}")


def test_a_padded_signature_segment_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    header_segment, payload_segment, signature = _mint(authority).split(".")
    padded = signature + "=" * (-len(signature) % 4)
    if padded == signature:
        padded = signature + "="
    with pytest.raises(JWSVerificationError, match="not canonical base64url"):
        verifier.verify(f"{header_segment}.{payload_segment}.{padded}")


def test_a_standard_base64_segment_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """A segment in the standard base64 alphabet is rejected, never decoded.

    The divergence is constructed rather than hoped for: 0xFB 0xFF 0xBE encodes
    to ``+/++`` under the standard alphabet and ``-_--`` under base64url, so the
    payload always carries both characters the URL-safe alphabet excludes.
    """

    raw = bytes([0xFB, 0xFF, 0xBE]) + json.dumps(_claims(), separators=(",", ":")).encode()
    standard = base64.b64encode(raw).decode("ascii").rstrip("=")
    assert "+" in standard and "/" in standard
    header_segment = _mint(authority).split(".")[0]
    # Sign over the standard-alphabet segment itself.  A merely re-encoded
    # payload would fail the signature check first, which would leave the
    # canonical-encoding gate untested; here the signature is valid, so only
    # alphabet validation can reject this token.
    signature = _b64(bytes.fromhex(authority.sign(f"{header_segment}.{standard}".encode("ascii"))))

    with pytest.raises(JWSVerificationError, match="not canonical base64url"):
        verifier.verify(f"{header_segment}.{standard}.{signature}")


@pytest.mark.parametrize(
    "token",
    [
        "",
        "only-one-segment",
        "two.segments",
        "four.segments.here.now",
        "..",
        "a..c",
    ],
)
def test_a_malformed_compact_serialization_is_denied(
    verifier: EdDSAJWSVerifier,
    token: str,
) -> None:
    with pytest.raises(JWSVerificationError):
        verifier.verify(token)


def test_an_oversized_token_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    token = _mint(authority, claims=_claims(jti="j" * 8192))
    with pytest.raises(JWSVerificationError, match="exceeds the bounded size"):
        verifier.verify(token)


def test_a_non_ascii_token_is_denied(verifier: EdDSAJWSVerifier) -> None:
    with pytest.raises(JWSVerificationError, match="must be ASCII"):
        verifier.verify("héader.payload.signature")


def test_a_non_object_payload_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    with pytest.raises(JWSVerificationError, match="payload must be a JSON object"):
        verifier.verify(_mint(authority, claims_text='["not","an","object"]'))


def test_a_deeply_nested_payload_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    nested = "[" * 400 + "]" * 400
    with pytest.raises(JWSVerificationError):
        verifier.verify(_mint(authority, claims_text=nested))


def test_a_nan_constant_is_denied(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    with pytest.raises(JWSVerificationError):
        verifier.verify(_mint(authority, claims_text='{"iat":NaN}'))


# -- no key material leaks --------------------------------------------------


def test_no_private_key_material_reaches_a_rejection_message(
    verifier: EdDSAJWSVerifier,
    authority: Ed25519Signer,
) -> None:
    """Rejections are fixed operator strings, never token or key bytes."""

    token = _mint(authority, header={"kid": "attacker-chosen-kid-value"})
    with pytest.raises(JWSVerificationError) as caught:
        verifier.verify(token)
    message = str(caught.value)
    assert "attacker-chosen-kid-value" not in message
    assert token not in message
    assert authority.public_bytes().hex() not in message
