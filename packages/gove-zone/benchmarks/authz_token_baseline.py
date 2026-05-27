"""JWT-style capability-token benchmark baseline."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

from gove_zone import Decision, DecisionRecord, Policy, canonical_json, new_event_id, sha256_json
from gove_zone.tool import ToolCall

SECRET = b"gove-zone-week2-token-baseline-secret"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(message: str) -> str:
    return _b64(hmac.new(SECRET, message.encode("utf-8"), hashlib.sha256).digest())


@dataclasses.dataclass(frozen=True)
class CapabilityTokenIssuer:
    """Creates compact signed capability tokens for the whole delegation path."""

    tenant: str = "tenant-alpha"
    capability: str = "filesystem:read"

    def issue(self, *, subject: str, path: str, path_chain: tuple[str, ...]) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        claims = {
            "iss": "orchestrator",
            "sub": subject,
            "tenant": self.tenant,
            "cap": self.capability,
            "path": path,
            "delegation_path": path_chain,
        }
        signing_input = ".".join(
            (
                _b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode()),
                _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()),
            )
        )
        return f"{signing_input}.{_sign(signing_input)}"

    def verify(self, token: str, *, expected_subject: str, expected_path: str) -> str:
        parts = token.split(".")
        if len(parts) != 3:
            return "malformed token"
        signing_input = ".".join(parts[:2])
        if not hmac.compare_digest(parts[2], _sign(signing_input)):
            return "bad token signature"
        try:
            claims = json.loads(_unb64(parts[1]))
        except (json.JSONDecodeError, ValueError) as exc:
            return f"bad token claims: {exc}"
        if claims.get("sub") != expected_subject:
            return "subject mismatch"
        if claims.get("tenant") != self.tenant:
            return "tenant mismatch"
        if claims.get("cap") != self.capability:
            return "capability mismatch"
        if claims.get("path") != expected_path:
            return "path caveat mismatch"
        path_chain = claims.get("delegation_path")
        if not isinstance(path_chain, list) or not path_chain or path_chain[-1] != expected_subject:
            return "delegation caveat mismatch"
        return ""


class TokenBaselinePolicy(Policy):
    def __init__(self, agent_name: str, issuer: CapabilityTokenIssuer) -> None:
        self.agent_name = agent_name
        self.issuer = issuer

    @property
    def version(self) -> str:
        return f"authz-token/{self.agent_name}/v0"

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        authz = call.args.get("authz")
        token = authz.get("token") if isinstance(authz, Mapping) else None
        payload = call.args.get("payload")
        path = payload.get("resource") if isinstance(payload, Mapping) else None
        reason = (
            self.issuer.verify(
                str(token),
                expected_subject=self.agent_name,
                expected_path=str(path),
            )
            if token and path
            else "missing capability token"
        )
        decision = Decision.DENY if reason else Decision.ALLOW
        return DecisionRecord(
            decision=decision,
            tool=call.name,
            argument_hash=sha256_json(dict(call.args)),
            policy_version=self.version,
            event_id=new_event_id(),
            matched_rules=(() if decision is Decision.ALLOW else ("AUTHZ_TOKEN_INVALID",)),
            reason=reason or "capability token verified",
        )


class TokenBaselineAuthzStrategy:
    name = "token-baseline"

    def __init__(self, *, issuer: CapabilityTokenIssuer | None = None) -> None:
        self.issuer = issuer or CapabilityTokenIssuer()

    def policy_for_agent(self, agent_name: str) -> Policy:
        return TokenBaselinePolicy(agent_name, self.issuer)

    def args_for_hop(
        self,
        *,
        agent_name: str,
        tool_name: str,
        payload: Mapping[str, Any],
        parent_authz: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        del tool_name
        previous_path = () if parent_authz is None else tuple(parent_authz["delegation_path"])
        delegation_path = (*previous_path, agent_name)
        token = self.issuer.issue(
            subject=agent_name,
            path=str(payload["resource"]),
            path_chain=delegation_path,
        )
        return {
            "payload": payload,
            "authz": {"token": token, "delegation_path": delegation_path},
        }

    def token_units_for_hop(self, args: Mapping[str, Any]) -> int:
        return max(1, len(canonical_json(args)) // 4)
