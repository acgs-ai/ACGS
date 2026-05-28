from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from governance.audit.jsonl_chain import ChainHashAuditStore
from governance.evaluation import ingest_gove_zone_evaluation_report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest a gove-zone evaluation report into the ACGS audit ledger.")
    parser.add_argument("--report", required=True, help="Path to a gove-zone eval JSON report")
    parser.add_argument("--audit-path", default=".acgs/audit.jsonl")
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--actor-id", default="gove-zone-evaluation-ingestor")
    args = parser.parse_args(argv)

    evidence = ingest_gove_zone_evaluation_report(
        args.report,
        audit_store=ChainHashAuditStore(args.audit_path),
        tenant=args.tenant,
        actor_id=args.actor_id,
    )
    print(json.dumps(evidence.to_dict(), indent=2, ensure_ascii=False))
    return 0 if evidence.status == "passed" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
