# SaaS Beta Acceptance Matrix

This is the conservative capability view of the canonical
[`DELIVERY_DAG.yaml`](DELIVERY_DAG.yaml). The original program baseline is frozen at
commit `1d9c9b21372ebdbd20aefc3ca454a47a3d5d1f96`; completed G006 preserves its
independently reviewed survey snapshot, while later rows separately label newer
current-local evidence. `Built` means current accepted implementation evidence—not
deployment, customer use, independent review, certification, or production readiness.

| Matrix ID | Acceptance criterion | State | Evidence state | DAG IDs | Accepted artifact |
|---|---|---|---|---|---|
| AM-001 | Canonical resumable program record | built | independently_reviewed | G005 | Independently reviewed DELIVERY_DAG.yaml, ACCEPTANCE_MATRIX.md, and test_saas_delivery_dag.py with passing documentation gates. |
| AM-002 | Frozen current-state and product-contract reconciliation | partial | current_local | G006, G007, G008 | G006 `CURRENT_STATE_SURVEY.md` plus G007/G008 target contracts are independently reviewed; owner-only provider, legal, licensing, spend, and deployment decisions remain proposed, so this is not an accepted product-contract decision or managed implementation evidence. |
| AM-003 | Authoritative current-baseline gate proof | partial | current_local | G004, G030B | PR #308 head `53ca32d116398057c882bfaa852fb305a9fd0fca` has its sole review thread resolved, but independent review then found raw `ACP_RUNTIME_POSTURE` disclosure through chained exception traceback; #308 remains open, repository-unaccepted, and superseded. Rebased repair successor draft PR #337 exact head `4f0c685b5d2ffac0e6a71810b77c6357b8d56a94` is independently APPROVED/PASS locally. Self-hosted constitutional-hash verify passes, and the self-hosted Python 3.11 and 3.12 jobs each report 40 package tests passing. Codex review, GitHub-hosted advisory hash, GitGuardian, and Socket each failed with zero steps because of the billing lock. #337 remains open, draft, and unmerged, so no repository-accepted baseline exists. PR #267 remains closed-unmerged superseded history and is never promoted. |
| AM-004 | Open local fail-closed execution plane in the canonical SaaS journey | missing | none | G004, G031, G204 | The reviewed G031 corpus alone is not journey evidence; no accepted journey evidence exists until the G004 rebuild completes. |
| AM-005 | Tenant-scoped managed control-plane foundation | partial | current_local | G101, G102, G103, G104, G105, G106 | Integrated draft PR #338 exact head `1e7aa033bb5a2b8ee0984e98b148e0c14b94622d`, stacked on repaired draft baseline PR #337, supersedes the separate G101 increment topology without promoting either draft to accepted evidence. Independent review and verification report APPROVE/PASS. Local evidence reports 191 package passes with 19 skips, 31 documentation passes, 53 main PostgreSQL passes with one Windows-only skip, 8 recovery passes, 3 bytea passes, and 7 rolling-upgrade passes. A transient cleanup symptom in the aggregate bytea run was diagnosed; the isolated exact bytea module passed 3 of 3. The self-hosted remote Python 3.11 and 3.12 checks pass. Required `postgresql-migrations` and `codex-review` jobs failed with zero steps because of the GitHub billing lock, and Windows remains unavailable. Security review rejected predecessor commit `952186c5039504c7be4d086c5d2eb806beecb3b8`. It was never published as a standalone accepted PR/head; it is present in remote history only as the immediate ancestor of repair `1e7aa033bb5a2b8ee0984e98b148e0c14b94622d` in draft PR #338, is superseded/repaired by that head, and is not accepted evidence. Repair head `1e7aa033bb5a2b8ee0984e98b148e0c14b94622d` canonically binds recovery clients to the authenticated database and `public` schema, qualifies `pg_catalog` functions, adds live shadow-search-path/function-hijack/nonempty-public zero-subprocess and zero-mutation tests, and replaces the unpinned client trust root with digest-pinned PostgreSQL 17.10 wrappers. PRs #337 and #338 remain open drafts and unmerged; required PostgreSQL/Codex CI and Windows are unverified. G101 therefore remains `in_progress`/`partial`/`local_verified`, G102 remains blocked, and G105 remains planned and deferred behind G103, G104, and G004. |
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
