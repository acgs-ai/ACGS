"""Phase 2 signed-trace test helpers.

`mint_signed_trace(...)` is the canonical builder used by every Phase 2
test that needs a properly-signed :class:`AuthorizationTrace`. It
generates an Ed25519 keypair per hop (or per call), writes a JSON
keystore, signs each hop's canonical payload with the matching key,
and returns the trace + keystore handle.

Kept out of conftest.py because keypair generation is slow and
non-deterministic; tests opt-in by importing this module.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.crypto.hop_signature import sign_hop
from governance.crypto.principal_keys import FilePrincipalKeyStore
from governance.models import HOP_SIGNATURES_VERSION, AuthorizationTrace


def _now() -> datetime:
    return datetime.now(tz=timezone.utc).replace(microsecond=0)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class HopSpec:
    """One delegation hop. ``delegator_id`` defaults follow chain order."""

    principal_id: str
    role: str = "implementation-agent"
    tenant: str = "default"
    delegator_id: str | None = None
    delegated_at: datetime | None = None
    not_after: datetime | None = None
    delegation_evidence_hash: str = "sha256:delegation-evidence"


@dataclass
class MintedTrace:
    trace: AuthorizationTrace
    keystore_path: Path
    key_store: FilePrincipalKeyStore
    private_keys: dict[str, Ed25519PrivateKey]


def default_action_binding(
    *,
    workflow_id: str,
    tenant: str = "default",
    actor_id: str | None = None,
    session_nonce: str = "AAAAAAAAAAAAAAAAAAAAAA",
) -> dict[str, str]:
    return {
        "action_type": "governance.receipt.verify",
        "tenant": tenant,
        "actor_id": actor_id or "codex:gpt-5",
        "resource": workflow_id,
        "inputs_hash": "sha256:trace-test",
        "workflow_id": workflow_id,
        "policy_version": "policy-test/v1",
        "role_version": "roles-test/v1",
        "session_nonce": session_nonce,
    }


def mint_signed_trace(
    tmp_path: Path,
    *,
    trace_id: str = "trace-r5-r6",
    workflow_id: str = "workflow-r5-r6",
    parent_workflow_id: str | None = None,
    evaluation_policy: str = "access-time",
    hops: list[HopSpec] | None = None,
    action_binding: dict[str, str] | None = None,
    tenant: str = "default",
    keystore_name: str = "principal_keys.json",
) -> MintedTrace:
    """Build a fully-signed Phase 2 trace + keystore on disk.

    The first hop's ``delegator_id`` defaults to ``orchestrator-root``;
    subsequent hops default to the prior hop's ``principal_id`` (chain
    continuity). ``delegated_at`` defaults to ``now()``, ``not_after``
    to ``now() + 1h``.
    """
    if hops is None:
        hops = [
            HopSpec(principal_id="codex:gpt-5", role="implementation-agent", tenant=tenant),
            HopSpec(principal_id="codex:gpt-5-worker", role="receipt-verifier", tenant=tenant),
        ]

    now = _now()
    if action_binding is None:
        action_binding = default_action_binding(workflow_id=workflow_id, tenant=tenant)

    # Generate one keypair per unique delegator_id.
    private_keys: dict[str, Ed25519PrivateKey] = {}
    key_records: list[dict[str, Any]] = []
    chain_records: list[dict[str, Any]] = []

    prior_principal: str | None = None
    for index, hop in enumerate(hops):
        delegator_id = hop.delegator_id or ("orchestrator-root" if prior_principal is None else prior_principal)
        delegated_at = hop.delegated_at or (now - timedelta(seconds=60 - index))
        not_after = hop.not_after or (now + timedelta(hours=1))

        if delegator_id not in private_keys:
            sk = Ed25519PrivateKey.generate()
            private_keys[delegator_id] = sk
            pk_bytes = sk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            key_records.append(
                {
                    "key_id": f"key-{delegator_id}",
                    "public_key_hex": pk_bytes.hex(),
                    "principal_id": delegator_id,
                    "tenant": hop.tenant,
                    "issuer": "acgs-root-ca",
                    "valid_from": (now - timedelta(days=1)).isoformat(),
                    "valid_to": (now + timedelta(days=30)).isoformat(),
                    "purposes": ["trace-delegation"],
                    "revoked_at": None,
                }
            )

        signing_key_id = f"key-{delegator_id}"
        hop_payload = {
            "alg": "Ed25519",
            "key_version": 1,
            "schema_version": HOP_SIGNATURES_VERSION,
            "trace_id": trace_id,
            "parent_workflow_id": parent_workflow_id,
            "workflow_id": workflow_id,
            "evaluation_policy": evaluation_policy,
            "hop_index": index,
            "delegator_id": delegator_id,
            "delegatee_id": hop.principal_id,
            "role": hop.role,
            "tenant": hop.tenant,
            "delegated_at": delegated_at.isoformat(),
            "not_after": not_after.isoformat(),
            "delegation_evidence_hash": hop.delegation_evidence_hash,
            "action_binding": dict(action_binding),
        }
        signature = sign_hop(private_keys[delegator_id], hop_payload)
        chain_records.append(
            {
                "principal_id": hop.principal_id,
                "role": hop.role,
                "tenant": hop.tenant,
                "delegated_at": delegated_at.isoformat(),
                "delegation_evidence_hash": hop.delegation_evidence_hash,
                "delegator_id": delegator_id,
                "signing_key_id": signing_key_id,
                "signature": _b64url(signature),
                "not_after": not_after.isoformat(),
            }
        )
        prior_principal = hop.principal_id

    keystore_path = tmp_path / keystore_name
    keystore_path.write_text(json.dumps(key_records), encoding="utf-8")
    key_store = FilePrincipalKeyStore(keystore_path)

    trace = AuthorizationTrace(
        trace_id=trace_id,
        workflow_id=workflow_id,
        parent_workflow_id=parent_workflow_id,
        principal_chain=tuple(chain_records),
        evaluation_policy=evaluation_policy,  # type: ignore[arg-type]
        action_binding=dict(action_binding),
    )
    return MintedTrace(trace=trace, keystore_path=keystore_path, key_store=key_store, private_keys=private_keys)


__all__ = [
    "HopSpec",
    "MintedTrace",
    "default_action_binding",
    "mint_signed_trace",
]
