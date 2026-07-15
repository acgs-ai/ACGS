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
| AM-003 | Authoritative current-baseline gate proof | partial | unverified | G004, G030B, G031 | PR #308 exact head `53ca32d` is independently reviewed and locally acceptance-ready with 40 package tests passing; the minimum-version HEAD concern was disproved. Repository acceptance remains blocked because #308 is open and unaccepted with an unresolved thread and stale or queued checks. PR #267 remains closed-unmerged superseded history and is never promoted. |
| AM-004 | Open local fail-closed execution plane in the canonical SaaS journey | missing | none | G004, G204 | No accepted journey evidence until G006 survey and G004 rebuild complete. |
| AM-005 | Tenant-scoped managed control-plane foundation | partial | current_local | G101, G102, G103, G104, G105, G106 | PR #324 remains the open-draft G101 anchor. PR #330 exact head `31badd9` is independently approved and current-local only: five repairs provide atomic private `.pgpass` handling and exact mode enforcement, portable directory fsync, fixed retained canonical fingerprint limits, aggregate-only PostgreSQL logical-row preflight with batch-one streaming, manifest-v1 digest compatibility, and read-only `REPEATABLE READ` before/after captures. Final local evidence is 48 targeted and 116 package tests passing with 2 credential-gated PostgreSQL skips. CI run `29414888896`, job `87350442086`, failed before steps because of the billing lock, so `ci_backed` remains false and the PR remains unmerged. PRs #329, #331, and #332 retain their separate current-local review records. This does not prove live PostgreSQL runtime execution of the new preflight, production backup/PITR, a total-process memory bound, multi-host/failover/rolling-upgrade operations, #308 startup integration, or completed Phase-1 acceptance. Do not start G102. |
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
