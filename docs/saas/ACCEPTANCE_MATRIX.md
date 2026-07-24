# SaaS Beta Acceptance Matrix

This is the conservative capability view of the canonical
[`DELIVERY_DAG.yaml`](DELIVERY_DAG.yaml). It freezes observations at origin/master
commit `ee83e189ec62eddea4a73be79e9bf492a2f6b371` as observed on
2026-07-24; G006 must survey current code, tests, GitHub, CI, releases, and
deployment state before any capability is promoted.
`Built` means current accepted implementation evidence—not deployment, customer use,
independent review, certification, or production readiness.

| Matrix ID | Acceptance criterion | State | Evidence state | DAG IDs | Accepted artifact |
|---|---|---|---|---|---|
| AM-001 | Canonical resumable program record | built | independently_reviewed | G005 | Independently reviewed DELIVERY_DAG.yaml, ACCEPTANCE_MATRIX.md, and test_saas_delivery_dag.py with passing documentation gates. |
| AM-002 | Frozen current-state and product-contract reconciliation | partial | current_local | G006, G007, G008 | G006 `CURRENT_STATE_SURVEY.md` plus G007/G008 target contracts are independently reviewed; owner-only provider, legal, licensing, spend, and deployment decisions remain proposed, so this is not an accepted product-contract decision or managed implementation evidence. |
| AM-003 | Authoritative current-baseline gate proof | partial | current_local | G004, G030B, G031 | G030B records current origin/master `ee83e189ec62eddea4a73be79e9bf492a2f6b371`, PR #308 closed unmerged, and PR #353 open draft as the current G004 rebuild path. G004 is built/local-verified in draft PR #353 but remains blocked by unmerged review and EXT-GITHUB-BILLING hosted check-start failures, so this is not completed accepted gate proof. |
| AM-004 | Open local fail-closed execution plane in the canonical SaaS journey | missing | none | G004, G204 | No accepted journey evidence until G006 survey and G004 rebuild complete. |
| AM-005 | Tenant-scoped managed control-plane foundation | partial | current_local | G101, G102, G103, G104, G105, G106 | Current-local G101 evidence covers the full control-plane package at 214 passed/32 skipped, real disposable PostgreSQL migration recovery at 8 passed, and focused migration, CLI, startup, rolling-upgrade, and recovery-tool-provenance tests wired through `.github/workflows/python-acgs-control-plane.yml`. Recovery uses `ACP_TEST_RECOVERY_SOURCE_URL`, `ACP_TEST_RECOVERY_TARGET_URL`, and explicit absolute `pg_dump`/`pg_restore` wrapper paths. It remains blocked by the unmerged #353/#354/#355 draft stack and EXT-GITHUB-BILLING hosted PostgreSQL/codex-review check-start failures; G102 is not unlocked, G103 tenant isolation remains planned, and G603 production DR/PITR/object/witness recovery remains separate. |
| AM-006 | Enrolled gates, signed policy lifecycle, degraded sync, and proven-wired fleet | missing | none | G201, G202, G203, G204, G205 | No accepted Phase-2 evidence. |
| AM-007 | Provenance-preserving native, federated, and observed assurance | missing | none | G206, G301, G404 | No accepted assurance-class integration evidence. |
| AM-008 | Durable retained evidence, independent witness, offline proof, alerts, and outbound delivery | missing | none | G301, G302, G303, G304, G306 | No accepted managed evidence-plane artifact. |
| AM-009 | Separated approval and exactly-once resume | missing | none | G305, G405 | No accepted approval race or forbidden-side-effect proof. |
| AM-010 | One real role-aware console and fifteen-minute quickstart | missing | none | G401, G402, G403, G404, G405, G406, G407 | No accepted canonical browser journey or timing artifact. |
| AM-011 | Identity, entitlements, evidence-derived usage, and billing test integration | missing | none | G501, G502, G503 | No accepted identity or commercial integration artifact; live charges remain unauthorized. |
| AM-012 | Supply chain, observability, recovery, capacity, and application security | missing | none | G601, G602, G603, G604, G605 | No accepted Phase-6 technical readiness packet. |
| AM-013 | Beta operations readiness | missing | none | G606 | No accepted onboarding, incident, privacy, support, or live-operations evidence. |
| AM-014 | Independent proof-pack and security assessment | missing | none | G701, G703 | No independent assessor evidence exists. |
| AM-015 | Three paid design partners and owner launch decision | missing | none | G702, G704 | No customer, revenue, pricing, legal, deployment, or launch evidence exists. |

## State rules

- **built** requires a referenced built node with accepted current evidence.
- **partial** requires a referenced partial or built node and names the remaining evidence gap.
- **missing** has no accepted evidence for the complete criterion.
- **conflicting** retains incompatible history only; `historical_only` can never support `built`.

No row declares beta code-complete or production-ready. The DAG controls dependencies,
blockers, and evidence gates. Production launch remains a separate human-authorized decision.
