import json
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import Decision, DecisionRecord
from gove_zone.errors import PolicyError
from gove_zone.policy import Policy, RuleSetPolicy
from gove_zone.receipt import DecisionReceipt
from gove_zone.tool import ToolCall


class TransformPolicy(Policy):
    """A policy implementation that transforms arguments, supporting dump/load."""

    def __init__(
        self,
        policy_id: str = "transform-policy",
        version_str: str = "transform-policy/v1",
    ) -> None:
        self._policy_id = policy_id
        self._version = version_str

    @property
    def version(self) -> str:
        return self._version

    @property
    def policy_id(self) -> str:
        return self._policy_id

    def evaluate(self, call: ToolCall) -> DecisionRecord:
        t = dict(call.args)
        t["path"] = "transformed.txt"
        from gove_zone.policy import new_event_id

        return DecisionRecord(
            decision=Decision.TRANSFORM,
            tool=call.name,
            argument_hash=call.argument_hash(),
            policy_version=self.version,
            event_id=new_event_id(),
            transformed_args=t,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.policy_id, "version": self.version}

    def dump(self, path: Path | str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), sort_keys=True), encoding="utf-8")


class TenantPolicyStore:
    """Fixture store for active policy bundle lookups by tenant ID."""

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def store_bundle(self, tenant_id: str, policy: Policy) -> Path:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        tenant_dir = self.base_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = tenant_dir / "policy.bundle.json"
        if hasattr(policy, "dump"):
            policy.dump(bundle_path)
        else:
            # Fallback serializer
            import json

            data = {"id": getattr(policy, "policy_id", "custom"), "version": policy.version}
            bundle_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        return bundle_path

    def load_bundle(self, tenant_id: str, requester_tenant_id: str) -> Policy:
        """Load the active bundle for *tenant_id*.

        Raises PermissionError if requester_tenant_id does not match tenant_id.
        """
        if not tenant_id:
            raise PolicyError("tenant_id is missing")
        if not requester_tenant_id:
            raise PolicyError("requester_tenant_id is missing")
        if tenant_id != requester_tenant_id:
            raise PermissionError(
                f"Cross-tenant access blocked: tenant {requester_tenant_id} "
                f"cannot load bundle for tenant {tenant_id}"
            )
        bundle_path = self.base_dir / tenant_id / "policy.bundle.json"
        if not bundle_path.exists():
            raise FileNotFoundError(f"No policy bundle found for tenant {tenant_id}")

        text = bundle_path.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, dict) and "rules" in data:
            return RuleSetPolicy.from_dict(data)
        elif isinstance(data, dict) and data.get("id") == "transform-policy":
            return TransformPolicy(policy_id=data["id"], version_str=data["version"])
        else:
            # Return a simple ruleset or raise
            raise PolicyError(f"Unknown policy format in tenant store for {tenant_id}")


def evaluate_tenant_action(
    store: TenantPolicyStore,
    tenant_id: str,
    requester_tenant_id: str,
    action: str,
    args: dict[str, Any],
    *,
    goal: str = "",
    execution_boundary: str,
    request_id: str,
    actor: str,
    audit_store: ChainHashAuditStore,
    expires_at: str = "",
) -> DecisionReceipt:
    """Securely evaluate a proposed action under tenant-isolated policies.

    Fails closed immediately if tenant context is missing/mismatched or
    the active policy bundle cannot be loaded.
    """
    if not tenant_id or not requester_tenant_id:
        raise PolicyError("Tenant identification missing")

    try:
        policy = store.load_bundle(tenant_id, requester_tenant_id)
    except FileNotFoundError as exc:
        raise PolicyError(f"Tenant bundle missing for {tenant_id}") from exc
    except PermissionError as exc:
        raise PolicyError(f"Unauthorized tenant policy load: {exc}") from exc

    from gove_zone.kernel import Kernel

    kernel = Kernel(policy=policy, audit=audit_store, actor=actor)

    previous_hash = audit_store.last_hash()

    from gove_zone.tool import ToolCall, normalize_path_context

    path_val = args.get("path") or args.get("file_path") or ()
    call = ToolCall(
        name=action,
        args=args,
        goal=goal,
        actor=actor,
        path=normalize_path_context(path_val),
        state={},
    )

    try:
        record, audit_hash = kernel._evaluate_and_record(call)
    except Exception as exc:
        raise PolicyError(f"Governance evaluation raised: {exc}") from exc

    policy_id = getattr(policy, "policy_id", "custom")

    return DecisionReceipt.from_record(
        record=record,
        audit_hash=audit_hash,
        previous_audit_hash=previous_hash,
        tenant_id=tenant_id,
        execution_boundary=execution_boundary,
        policy_bundle_id=policy_id,
        policy_hash=policy.version,
        request_id=request_id,
        expires_at=expires_at,
    )
