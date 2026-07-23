# Platform Reconstruction Blueprint (doc 4 of 6)

> **Status: PROPOSAL — not an executed plan, not a production claim.**
> Platform-reconstruction program, document 4 of 6. Basis: `01-internal-audit.md`
> (current estate, §2 layer map, §4 duplication register, §7 gap register) and
> `02-external-research.md` (§4 whitespace: standard-aligned portable receipts,
> risk-tiered enforcement, MCP boundary). This document formalizes the de-facto
> architecture and proposes a phased, non-big-bang migration. It changes no code
> and seals nothing; every decision below is a recommendation for the maintainer,
> not a merged fact. Present-tense capability language describes the *target*,
> not today's state. Doc 05 owns productionization; doc 00 owns synthesis.

---

## 1. Target architecture — organized layers

The audit's finding (§8.1) is that a layered platform already exists de facto; the
work is to **formalize and consolidate**, not rebuild. The kernel (`gove-zone`) is
the strongest asset and a dependency-graph leaf — nothing imports from siblings —
so layering can be imposed without unwinding a tangle.

```
                          ┌───────────────────────────────────────────────┐
   L4  EXPERIENCE         │  acgi-ai console (GCP Cloud Run/WIF) +          │
                          │  acgi-ai marketing (CF Pages) + gove-zone CLI  │
                          └───────────────────────────────────────────────┘
                                          │ calls (verify / present receipts)
                          ┌───────────────────────────────────────────────┐
   L3  INTEGRATIONS RING  │  MCP gateway · framework adapters (LangGraph/  │
                          │  AutoGen/A2A) · cft-pack · hermes-as-adapter   │
                          └───────────────────────────────────────────────┘
                                          │ wrap host tool-call boundary
                          ┌───────────────────────────────────────────────┐
   L2  CONTROL PLANE      │  policy mgmt · receipt verification API ·      │
      (services)          │  tenant · revocation/consumption ledger        │
                          └───────────────────────────────────────────────┘
                                          │ depend on kernel contracts
                          ┌───────────────────────────────────────────────┐
   L1  KERNEL (gove-zone) │  policy · decision · executor gate · audit     │
                          │  chain · replay · signing · CLI                │
                          └───────────────────────────────────────────────┘
                                          │ build on evidence primitives
                          ┌───────────────────────────────────────────────┐
   L0  EVIDENCE/RECEIPT   │  shared evidence-chain + receipt primitives    │
      PRIMITIVES          │  (Ed25519 / W3C-VC · IETF AER/SCITT-aligned)   │
                          └───────────────────────────────────────────────┘

   L5  OBSERVABILITY/EVAL  (spans L1–L4): agent-bus-analyzer · eval-mvp
   Cross-cutting OPS      : automation/ · CI templates · scripts · IaC (doc 05)
```

| Layer | Owns | Depends on | Gate | Deploy unit |
|---|---|---|---|---|
| **L0 Evidence/receipt primitives** | Chain-hashed JSONL writer, Merkle/receipt-hash core, canonical serialization, signing envelope; the format compatibility contract | stdlib + optional crypto extra only | ruff + mypy `--strict` + pytest, ≥90% cov (adopt kernel's bar) | Published Python package (new: `packages/acgs-evidence/`) |
| **L1 Kernel (`gove-zone`)** | Policy eval, decision, executor gate, audit chain, replay, signing, CLI (`packages/gove-zone/src/gove_zone/`) | L0 only | ruff + format + mypy `--strict` + pytest `--cov-fail-under=90`, 3.11/3.12 | PyPI package (currently `0.1.0.dev0`) |
| **L2 Control plane services** | Policy management, receipt verification API, tenant lookup, revocation/consumption ledger (`consumption.py`, `tenant.py` promoted to services) | L1, L0 | service CI (lint+type+test) + deploy smoke | Cloud Run service(s) (new) |
| **L3 Integrations ring** | MCP gateway (`adapters/mcp_gateway.py`), framework adapters (`adapters/autogen`, `langgraph`, `a2a.py`), `acgs-cft-governance-pack/`, `hermes_acgs_bundle/` folded in as adapter | L1 contracts (never internals) | per-adapter lint+test; normalized template (§2c) | Library extras / plugin packages |
| **L4 Experience** | `acgi-ai/` console + marketing, `gove-zone` CLI | L2 APIs (console), L1 CLI | `test:all` (~55 gates); console + marketing deploy pipelines | CF Pages (marketing) + Cloud Run/WIF (console) |
| **L5 Observability/eval** | `packages/agent-bus-analyzer/`, `acgs_governance_eval_mvp/` | consumes L0 evidence shape, L1 receipts | mypy-strict (analyzer) + doubly-gated eval CI | Cloud Run (analyzer, deploy pipeline TBD — doc 05) |
| **Cross-cutting OPS** | `automation/`, CI templates, `scripts/`, IaC | all | tests-root + template lint | n/a (control artifacts) |

**Research ring** (`packages/research-engine/`, `packages/ai-governance-research/`) stays
off the critical path as a plugin ring per audit §4.5; it is not a platform layer.

**Layer-boundary contracts (the rule that keeps layers from re-tangling):**

- **L0 → L1:** L1 imports only L0's public evidence/receipt primitives, never reaches into
  L0 internals. L0 knows nothing of policy, executors, or hosts.
- **L1 → L2:** control-plane services consume the kernel through its documented gate surfaces
  (`execute_with_receipt`, `GovernedExecutor`, `ReceiptVerifier`) and the receipt schema —
  never by importing kernel internals across a service boundary.
- **L2/L1 → L3:** adapters bind hosts to the kernel through contracts only (audit §4.1's
  "thin adapters" rule). An adapter that reimplements a gate is a layering violation to be
  reviewed out. This is the anti-pattern the duplication register (§4) exists to kill.
- **L3/L2 → L4:** the console/CLI call verification and policy APIs; they never embed
  kernel or evidence internals in a privileged origin (constraint §4, console CSP).
- **L5** reads evidence and receipts by their public shape only; it is a consumer, never a
  writer into the enforcement path — observability must not be able to alter what it observes.

---

## 2. Key decisions

**(a) Two-lineage question — kernel of record vs published SDK spine.**
Recommend: **`gove-zone` is the enforcement kernel of record** (the fail-closed
executor gate and receipt issuer), and **`acgs-lite` remains the published SDK/spine**
(PyPI v2.10.1, the base of `Acgs-Swarm`/`clinicalguard`). Do **not** merge the nested
repos — they are independent git repos under `.gitmodules` (hard constraint; parent
`CLAUDE.md` §2) and `acgs-lite` carries a `>=3.10` published floor that must not break
(constraint §3). Bind them with an explicit **receipt-format compatibility contract**:
a versioned schema (owned by L0) that both lineages serialize to and validate against,
tested by a cross-lineage conformance fixture. This resolves the audit's "two governance
lineages with no code-level link" (§3) without a risky repo merge. *Evidence:* audit §3,
§8.2; `DECISION_RECEIPT_SPEC.md` schema is already vendor-neutral and a natural contract anchor.

**(b) Extract shared evidence-chain library (L0) vs keep 4 impls.**
Recommend: **extract one library.** The audit finds chain-hashed JSONL evidence writers
duplicated ~4× (eval-mvp, hermes, cft-pack, plus the kernel's own `audit.py`), all
consumed in the same shape by `agent-bus-analyzer` (§4.2). Extract `packages/acgs-evidence/`
as L0; the kernel's `audit.py` and each host become thin consumers. This is also the
**standards attachment point** (§8.3): align the extracted format to Agent Receipts
(Ed25519 + W3C-VC) and the IETF AER/SCITT direction (research §2, §4.2) once, in one place,
rather than 4×. Guard the extraction with a refactor-safety gate: baseline the kernel's
634 tests, extract, re-run; revert if failures exceed baseline.

**(c) Hermes → adapter in eval-mvp.**
Recommend: **fold `hermes_acgs_bundle/` into `acgs_governance_eval_mvp/` as a host adapter**
(audit §2, §4.1). Hermes is 4 `.py` / 1.2k LOC with test-only CI (no lint/mypy), no README —
it is a host binding, not a package. eval-mvp's `governed_mcp_v0` is the canonical pre/post-tool
gate; hermes and cft-pack should be thin adapters over it, not parallel gate implementations.

**(d) Archive orphan Vue app.**
Recommend: **archive `acgs-enterprise-ai-manager/`** (audit §2 verdict: Archive). It is a
Vue 3 skeleton with no backend, no tests, and no CI gate at all, yet it is a live pnpm
workspace member (§5). Move to `docs/archive/` or a dormant branch and remove from
`pnpm-workspace.yaml` so Turbo/installs stop discovering it. The real console is `acgi-ai/`.

**(e) Defaults hardening — signing + single-use ON by default, explicit dev-mode.**
Recommend: make the **production profile the default** — `require_signature=True` and a
`ReceiptConsumptionLedger` wired by default at the gate surfaces (`execute_with_receipt`,
`GovernedExecutor`, `ReceiptVerifier`), with a **loud, explicit `GovernanceProfile.dev`
opt-out**. Today signing/single-use are implemented but opt-in, and bare
`DecisionReceipt.verify()` defaults `require_signature=False` (audit §7 gap #4) — so the
core invariant only binds if the integrator wires it. Flipping the default is the single
highest-leverage integrity change. Keep the bare primitive's signature intact for
compatibility but route docs/examples exclusively through the gate surfaces.

**(f) Risk-tiered policy enforcement surface.**
Recommend: add a **risk-tier dimension** to policy evaluation (`policy.py` /
`yaml_policy.py`) so enforcement depth scales per action class (e.g. low-risk read →
receipt-logged; high-risk delete/exfil/deploy → signed + single-use + human-in-loop).
This directly answers the Gartner objection that *uniform* governance across all agents
causes failure (research §3, §4.5) and matches Microsoft Entra's high-risk-action gating
(research §1 Camp C) without conceding the portable-receipt edge. Tiers are policy
metadata, not new enforcement code paths — the executor stays one gate.

**Alternatives considered and rejected.** (i) *Merge the two lineages into one repo* —
rejected: violates the nested-repo hard constraint (§2), breaks `acgs-lite`'s published
`>=3.10` floor risk surface (§3), and forces a high-blast-radius change for a problem a
format contract solves. (ii) *Keep the 4 evidence implementations and add a shared test
suite* — rejected: leaves the standards-alignment work to be done 4× and the drift risk
permanent; one library is strictly cheaper to align to SCITT/W3C-VC. (iii) *Leave defaults
permissive and document the hardening path* — rejected: the invariant is the product, and
a default that silently doesn't bind is the single most dangerous gap in the estate (§7 #4).

---

## 3. Migration path from current state

Non-big-bang, phased, respecting nested-repo boundaries and sealed files. Each phase has
entry/exit criteria; sizes are rough order-of-magnitude, not commitments.

### Phase A — Hygiene (low risk, no runtime change)
- **Entry:** blueprint accepted.
- **Work:** collapse plan/roadmap sprawl (3 root roadmaps + `docs/ROADMAP.md` + 3 PLAN
  docs) into one roadmap of record + `docs/archive/`; fix stale pointers (root `PLAN.md`
  cited but absent; parent `CLAUDE.md` layout table omits gove-zone + 3 packages — audit
  §7 gaps #5/#6); archive orphan Vue app (2d); normalize per-package CI templates so hermes
  et al. run mypy-strict like peers (§4.4); fix `gove-zone` version-string skew
  (`0.1.0a1` vs `0.1.0.dev0`, gap #10); fold `ai-governance-research/` into `docs/`.
- **Affected paths:** `docs/**`, `.github/workflows/*.yml` (templates), `pnpm-workspace.yaml`,
  `packages/gove-zone/pyproject.toml`, parent `CLAUDE.md`, `MONOREPO.md`.
- **Exit:** one roadmap of record; no dangling pointers; every Python package runs the same
  gate template; orphan archived; docs/code parity improved.
- **Risk:** green. **Size:** S–M (docs + CI YAML only).

### Phase B — Consolidation (medium risk, refactor)
- **Entry:** Phase A merged; kernel test baseline (634) captured.
- **Work:** extract L0 `packages/acgs-evidence/` (2b) and reroute `audit.py` + 3 hosts to it;
  fold hermes into eval-mvp (2c); flip defaults to signed + single-use with `dev` opt-out (2e);
  populate or remove the empty parent constitutional-hash inventory so the CI gate stops being
  a no-op (audit §6, §7 gap #3); un-ignore the 5 readiness/evidence tests currently in no CI
  (audit §6); fix clinicalguard CI soft-fail (gap #9).
- **Affected paths:** new `packages/acgs-evidence/`; `packages/gove-zone/src/gove_zone/audit.py`;
  `acgs_governance_eval_mvp/**`; `hermes_acgs_bundle/` (removed/folded); `acgs-cft-governance-pack/**`;
  `docs/constitutional-hashes.lock` + gate; root `tests/`. **Nested-repo caveat:** clinicalguard
  CI fix and any acgs-lite conformance work happen *inside* those submodules, committed there
  first, parent pointer bumped separately (constraint §2).
- **Exit:** one evidence lib, kernel tests ≥ baseline; production profile default; constitutional
  gate guards a real inventory or is removed; readiness tests run in CI.
- **Risk:** yellow (touches kernel `audit.py` + published-adjacent defaults). **Size:** L.

### Phase C — Platformization (higher risk, new surface)
- **Entry:** Phase B merged; L0 stable.
- **Work:** stand up L2 control-plane service(s) — receipt verification API, policy management,
  tenant, revocation/consumption ledger promoted from kernel modules to a service; align L0
  receipt format to Agent Receipts (Ed25519/W3C-VC) + IETF AER/SCITT with a conformance suite
  (research §2, §4.2); add the risk-tier surface (2f); wire acgs-lite ↔ gove-zone receipt-format
  contract test (2a).
- **Affected paths:** new L2 service dir(s); L0 format modules; `policy.py`/`yaml_policy.py`;
  cross-lineage conformance fixtures.
- **Exit:** offline-verifiable receipt API; standard-aligned format with passing conformance;
  risk-tiered policy demonstrable. **Risk:** yellow–red (new services, standards surface).
  **Size:** XL.

### Phase D — Productionization
- Handoff to **doc 05** (staging env, IaC for CF Pages + GCP WIF, ≥1 more CI runner to kill the
  single-runner SPOF, armed `production` environment reviewers, agent-bus-analyzer deploy pipeline,
  Python publish automation — audit §5, §8.4). Not detailed here.

---

## 4. What does NOT change (invariants preserved)

1. **Fail-closed everywhere.** Policy exception, audit-append failure, missing/malformed/
   tampered/expired/mismatched receipt, unsigned-when-required → deny, no side effect
   (`ARCHITECTURE.md` failure modes). No refactor may add a silent-allow path.
2. **No valid Decision Receipt, no side effect.** The core invariant is untouched; Phase B
   *strengthens* it by making the binding default rather than opt-in.
3. **Zero-runtime-deps kernel policy.** `gove-zone` (and the new L0 lib) stay stdlib-only with
   crypto/schema/yaml as lazy optional extras (audit §3). L0 inherits this rule.
4. **Python floors.** `acgs-lite` published `>=3.10`; workspace local `3.11`. Intentionally
   different (constraint §3) — neither moves.
5. **Console CSP posture.** `acgi-ai/src/routes/console/**` keeps enforced CSP `script-src 'self'`,
   fail-closed `AUTH_UPSTREAM`, no CDN/third-party/anonymous-endpoint leakage (constraint §4).
6. **Sealed-file discipline.** `# Constitutional Hash:` markers and `docs/constitutional-hashes.lock`
   are not hand-edited; changes recompute the hash via the generator and pass the CI gate.
7. **Nested-repo boundaries.** `acgs-lite`, `Acgs-Swarm`, `clinicalguard` stay independent repos;
   commits from inside, parent pointer bumped as a separate step (constraint §2).

---

## 5. Open questions for the maintainer

1. **Two-lineage contract ownership:** who owns the L0 receipt-format schema of record —
   `gove-zone`, `acgs-lite`, or the new `acgs-evidence` package — and which lineage's current
   serialization becomes the canonical one when they diverge? (Settling needs an `acgs-lite`
   source checkout, per audit §3.)
2. **Standards target commitment:** align L0 to Agent Receipts (Ed25519/W3C-VC) *and* IETF
   AER/SCITT now (ride the emerging standard, research §4.2), or ship a stable internal format
   first and adapt later? The window is 12–18 months (research §5).
3. **Defaults-flip blast radius:** flipping signing + single-use ON by default (2e) may break
   existing integrators relying on the permissive default. Ship as a major version with a
   migration note, or gate behind an env/profile for one release cycle first?
4. **L2 as service vs library:** should policy management / receipt verification / revocation
   ledger be a deployed control-plane *service* (new Cloud Run, new SPOF-sensitive surface) or
   stay an in-process library that hosts embed? Affects doc 05 scope materially.
5. **Constitutional-hash gate:** populate the empty parent hash inventory (making it a real
   control) or remove it (audit §7 gap #3)? Keeping a no-op gate that *reads* as an active
   control is the worse of the two.
