from __future__ import annotations

import argparse
import json

from governance.audit.jsonl_chain import ChainHashAuditStore


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-path", default=".acgs/audit.jsonl")
    parser.add_argument("--rule-id")
    parser.add_argument("--gate")
    parser.add_argument("--allow", choices=["true", "false"])
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    allow = None if args.allow is None else args.allow == "true"
    store = ChainHashAuditStore(args.audit_path)
    events = store.query(rule_id=args.rule_id, gate=args.gate, allow=allow, limit=args.limit)
    print(json.dumps(events, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
