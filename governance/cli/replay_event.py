from __future__ import annotations

import argparse
import json

from governance.audit.jsonl_chain import ChainHashAuditStore
from governance.policy_loader import load_policy_bundle, load_roles
from governance.replay import replay_event


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("event_id")
    parser.add_argument("--audit-path", default=".acgs/audit.jsonl")
    parser.add_argument("--roles-path", default="governance/roles.json")
    parser.add_argument("--policy-dir", default="governance/policies/2026-05")
    args = parser.parse_args()

    store = ChainHashAuditStore(args.audit_path)
    matches = store.query(event_id=args.event_id, limit=1)
    if not matches:
        raise SystemExit(f"event not found: {args.event_id}")

    result = replay_event(
        matches[0],
        roles_bundle=load_roles(args.roles_path),
        policy_bundle=load_policy_bundle(args.policy_dir),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
