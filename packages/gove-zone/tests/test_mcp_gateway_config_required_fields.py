"""Required-field guards for ``load_gateway_config``.

``test_mcp_gateway_config.py`` covers the policy-bundle format rules and the
validator/principal clash. What it does not cover is the plainer failure: a
config that simply omits a field the gateway needs to establish who is being
governed and where the boundary is.

Every one of these must be a load-time ``ValueError`` naming the config file.
Defaulting instead would produce a gateway that starts, looks configured, and
enforces against the wrong tenant or an empty execution boundary — a silent
authorisation hole rather than a failed start. The production key-loading path
is covered here too, since a mis-loaded verifier is the same class of problem.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gove_zone.adapters.mcp_gateway import load_gateway_config

_BUNDLE = {
    "id": "tenant-A",
    "rules": [{"id": "deny-secret", "effect": "deny", "path_prefix": ["secret"]}],
}


def _config(tmp: Path, **overrides) -> Path:
    """A valid dev config, with `governance` keys overridden or removed.

    Passing ``key=None`` removes the key; passing a value replaces it.
    """
    (tmp / "policy.json").write_text(json.dumps(_BUNDLE), encoding="utf-8")
    governance = {
        "tenant_id": "tenant-A",
        "execution_boundary": "mcp-partner-sandbox",
        "profile": "dev",
        "policy_bundle": "policy.json",
    }
    for key, value in overrides.items():
        if value is None:
            governance.pop(key, None)
        else:
            governance[key] = value
    cfg = {
        "downstream": {"transport": "stdio", "command": ["python", "-m", "srv"]},
        "governance": governance,
        "identity": {
            "validator_id": "constitutional-council",
            "validator_role": "council",
            "principals": {"claude-code": "agent:claude-code@tenant-A"},
        },
        "audit": {"sink": "evidence/audit.jsonl"},
    }
    path = tmp / "gateway.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def test_the_baseline_config_loads(tmp_path: Path):
    assert load_gateway_config(_config(tmp_path)).tenant_id == "tenant-A"


@pytest.mark.parametrize("missing", [None, ""])
def test_a_config_without_a_tenant_id_is_refused(tmp_path: Path, missing):
    path = _config(tmp_path, tenant_id=missing)

    with pytest.raises(ValueError, match="governance.tenant_id is required"):
        load_gateway_config(path)


@pytest.mark.parametrize("missing", [None, ""])
def test_a_config_without_an_execution_boundary_is_refused(tmp_path: Path, missing):
    path = _config(tmp_path, execution_boundary=missing)

    with pytest.raises(ValueError, match="governance.execution_boundary is required"):
        load_gateway_config(path)


@pytest.mark.parametrize("missing", [None, ""])
def test_a_config_without_a_policy_bundle_is_refused(tmp_path: Path, missing):
    """No bundle means no policy; starting with an implicit allow-all would be
    the worst possible default here."""
    path = _config(tmp_path, policy_bundle=missing)

    with pytest.raises(ValueError, match="governance.policy_bundle is required"):
        load_gateway_config(path)


def test_the_error_names_the_config_file_so_an_operator_can_find_it(tmp_path: Path):
    path = _config(tmp_path, tenant_id=None)

    with pytest.raises(ValueError, match=str(path)):
        load_gateway_config(path)


def test_a_policy_bundle_that_does_not_exist_is_not_silently_skipped(tmp_path: Path):
    path = _config(tmp_path, policy_bundle="nope.json")

    with pytest.raises(OSError):
        load_gateway_config(path)


# --------------------------------------------------------------------------- #
# Production profile key loading
# --------------------------------------------------------------------------- #
def test_a_production_profile_loads_the_signing_and_verifying_keys(tmp_path: Path):
    pytest.importorskip("cryptography")
    from gove_zone.signing import Ed25519Signer

    seed = hashlib.sha256(b"mcp gateway config test key").digest()
    signer = Ed25519Signer.from_private_bytes(seed)
    (tmp_path / "signer.key").write_bytes(seed)
    (tmp_path / "verifier.key").write_bytes(signer.public_bytes())

    path = _config(tmp_path, profile="production")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["signing"] = {"signer_key": "signer.key", "verifier_key": "verifier.key"}
    path.write_text(json.dumps(raw), encoding="utf-8")

    config = load_gateway_config(path)

    assert config.profile.name == "production"
    assert config.profile.signer is not None
    assert config.profile.verifier is not None
    assert config.profile.verifier.key_id == signer.key_id


def test_a_production_profile_without_keys_loads_with_no_verifier(tmp_path: Path):
    """Documented posture: a missing verifier is not a load-time error. The
    load half is asserted here; that it then fails closed is asserted below."""
    config = load_gateway_config(_config(tmp_path, profile="production"))

    assert config.profile.name == "production"
    assert config.profile.verifier is None


def test_a_keyless_production_profile_still_demands_a_signature_at_the_gate(tmp_path: Path):
    """The other half of the posture. Deferring the error to first use is only
    safe if the loaded profile still carries ``require_signature``: that pair
    (require a signature, have no verifier) is exactly what makes the gate fail
    closed loud — proven at the gate itself by
    ``test_receipt_signing.py::test_production_default_no_verifier_fails_loud``.
    A config loader that quietly relaxed ``require_signature`` when no key was
    configured would turn that loud failure into a silent unsigned accept.
    """
    config = load_gateway_config(_config(tmp_path, profile="production"))

    assert config.profile.require_signature is True
    assert config.profile.verifier is None
    assert config.profile.as_gate_kwargs()["require_signature"] is True


def test_an_unknown_profile_name_falls_back_to_production_not_dev(tmp_path: Path):
    """Fail-safe direction: a typo in the profile name must not silently drop
    the gateway into the permissive dev profile."""
    config = load_gateway_config(_config(tmp_path, profile="prod-ish"))

    assert config.profile.name == "production"


def test_the_profile_name_is_matched_case_insensitively(tmp_path: Path):
    assert load_gateway_config(_config(tmp_path, profile="DEV")).profile.name == "dev"
