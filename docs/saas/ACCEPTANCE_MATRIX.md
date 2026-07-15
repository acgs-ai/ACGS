# SaaS Beta Acceptance Matrix

This is the conservative capability view of the canonical
[`DELIVERY_DAG.yaml`](DELIVERY_DAG.yaml). It freezes observations at commit
`1d9c9b21372ebdbd20aefc3ca454a47a3d5d1f96`; G006 must survey current code,
tests, GitHub, CI, releases, and deployment state before any capability is promoted.
`Built` means current accepted implementation evidence—not deployment, customer use,
independent review, certification, or production readiness.

| Matrix ID | Acceptance criterion | State | Evidence state | DAG IDs | Accepted artifact |
|---|---|---|---|---|---|
| AM-001 | Canonical resumable program record | built | independently_reviewed | G005 | Independently reviewed DELIVERY_DAG.yaml, ACCEPTANCE_MATRIX.md, and test_saas_delivery_dag.py with passing documentation gates. |
| AM-002 | Frozen current-state and product-contract reconciliation | partial | current_local | G006, G007, G008 | G006 `CURRENT_STATE_SURVEY.md` plus G007/G008 target contracts are independently reviewed; owner-only provider, legal, licensing, spend, and deployment decisions remain proposed, so this is not an accepted product-contract decision or managed implementation evidence. |
| AM-003 | Authoritative current-baseline gate proof | partial | current_local | G004, G030B | PR #308 exact head `53ca32d` is independently reviewed and locally acceptance-ready with 40 package tests passing; the minimum-version HEAD concern was disproved and all seven current head checks completed SUCCESS. Repository acceptance remains blocked because #308 is open and unaccepted with an unresolved review thread and no repository acceptance. PR #267 remains closed-unmerged superseded history and is never promoted. |
| AM-004 | Open local fail-closed execution plane in the canonical SaaS journey | missing | none | G004, G031, G204 | The reviewed G031 corpus alone is not journey evidence; no accepted journey evidence exists until the G004 rebuild completes. |
| AM-005 | Tenant-scoped managed control-plane foundation | partial | current_local | G101, G102, G103, G104, G105, G106 | PR #324 remains the open-draft G101 anchor. PR #330 exact head `31badd9` is independently approved and current-local only: five repairs provide atomic private `.pgpass` handling and exact mode enforcement, portable directory fsync, fixed retained canonical fingerprint limits, aggregate-only PostgreSQL logical-row preflight with batch-one streaming, manifest-v1 digest compatibility, and read-only `REPEATABLE READ` captures. Evidence includes 48 targeted and 116 package passes; wrapper-free disposable PostgreSQL 17 proof of canonical upgrade, transaction state, seeded capture, oversized JSONB refusal, and 4-of-4 migration tests; and a unique disposable PostgreSQL 17 private same-path `:Z` rerun where pg_dump/pg_restore smoke and `test_postgresql_migration_recovery.py` passed 4 of 4 in 4.38 seconds, covering round-trip, nonempty-target no mutation, restore-lock contention no mutation, and injected late-failure rollback, with container/temp artifacts absent. Live bytea remains unit-only. PR #331 exact head `4116778995d17755e9f3328698f6519145404336` is independently approved and current-local only after four repairs for portable queue-based pipe reading, continuous bounded stdout/stderr collection, incremental overlong-line drain with forced thread cleanup, and rolling secret detection after overflow and across chunk boundaries. Its default no-PostgreSQL suite passed 83 with 7 skipped, focused suite passed 15 with 7 deselected, and exact disposable PostgreSQL 17 suite passed 21 with one Windows-only skip; cleanup found zero tables, connections, workers, or containers. Configured source mypy passed; changed-test-file mypy debt is not an authoritative configured gate. CI run `29418915375`, job `87364038830`, failed before steps because of billing, so `ci_backed` remains false and the draft PR remains unmerged. This does not prove production backup/PITR/object retention, production recovery objectives, a total-process memory bound, multi-host/network-partition/failover operations, Windows execution, #308 startup integration, or completed Phase-1 acceptance. PRs #329 and #332 retain separate records. Do not start G102. |
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
