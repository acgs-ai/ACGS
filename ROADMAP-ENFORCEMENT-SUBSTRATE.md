# ACGS — The Right Roadmap: Enforcement-Substrate Frame

> **Status:** Draft for review. Companion to root `ROADMAP.md` (the *draft* 12-week
> kernel plan — itself self-labeled "not yet committed", synthesized 2026-05-22). This
> document widens the aperture; it does not replace that plan. The existing Phase 1–4
> execution is kept verbatim as the near-term track and is mapped into Gate G1 below.
>
> **Thesis:** ACGS is a *verifiable reference monitor for autonomous side effects*. The
> language model is one untrusted proposer, not the center of the system. This document
> re-derives the architecture from that frame and sequences a roadmap whose hard problems
> are systems, cryptography, and formal methods — not transformers.
>
> **Claim discipline:** Everything here is roadmap, not present-state. Nothing in this
> document may be claimed publicly until its named gate passes. The per-track
> claim-discipline notes map to the **`Status` + `Safe public wording`** ledger in
> `docs/CLAIMS.md` (status values: `implemented / tested / partial / roadmap / not
> claimed`). Current honest claims (beta, `gove-zone` `1.0.0rc1`, tamper-*evident* not
> trustless, tested not verified) stand unchanged until superseded by a passed gate.

---

## Provenance legend (read before trusting any present-tense sentence)

This document distinguishes what already exists on `master` from what it proposes. Every
load-bearing factual claim is tagged:

- **[on-master]** — verified present in the repository at `origin/master` (file cited).
- **[proposed]** — introduced or argued *by this document*; not yet in the repo.
- **[drift]** — exists in the repo but with a documented code/doc inconsistency; the code
  is treated as authoritative.

Two namespace cautions, because earlier drafts of this document tripped both:

1. The **adversary set in Part III is `[proposed]` and uses the `ADV1–ADV8` prefix.** The
   repo has **no** enumerated adversary model today. Do **not** confuse it with
   `COMPARISON.md`'s `A1–A8`, which are *capability-comparison axes* (A1 = pre-side-effect
   interception, … A8 = maturity), a different and unrelated namespace. The closest
   existing artifact is the **18-named-threat table in `docs/SECURITY_MODEL.md`** (Missing
   receipt, Tampered receipt, Replay attempt, **Executor bypass**, …); Part III must be
   reconciled *into* that table, not presented as already living there. The
   `Executor bypass` row — a caller invoking the raw tool instead of the governed executor
   — is the **complete-mediation keystone** and must map to an adversary (ADV9 below); an
   earlier draft of this document miscounted the table at 14 and dropped it.
2. The **G1/G2/G3 three-gate ladder in Part II is `[proposed]`.** `ROADMAP.md` has a
   "Final goal (end of week 12)" section, but it is a flat six-bullet capability list, not
   a kernel→evidence→production ladder. The ladder is this document's framing.

---

## Part I — What ACGS actually is (paradigm-agnostic)

The current README positions gove-zone as a "vendor-neutral, receipt-gated governance
layer for AI-agent side effects." **[on-master]** Correct, but the "AI-agent" qualifier is
too narrow and hides the real category. Strip it and the system is a classical construct
with fifty years of literature behind it.

### 1. It is a reference monitor (Anderson 1972)

A reference monitor is the validation mechanism that mediates every access of a subject to
an object. To be sound it must satisfy three properties — and *only* three:

| Reference-monitor property | gove-zone instantiation | Primary threat to it | Closed by |
|---|---|---|---|
| **Complete mediation** (always invoked) | Executor gate below every framework; *no valid receipt, no side effect* **[on-master]** (`executor.py`, fails closed without a receipt + `expected_actor`) | **Out-of-gate executor bypass** (a caller invokes the raw tool, skipping the gate — `SECURITY_MODEL.md` "Executor bypass", ADV9); TOCTOU (secondary, ADV8); "is the live host actually enforcing the gate?" (an explicit non-claim today) | Track F (adapter/gateway completeness) + Track D (attestation) |
| **Tamper-proof** (cannot be bypassed or altered) | Chain-hash audit **[on-master]** (`audit.py`, single linear `previous_hash`/`event_hash` JSONL chain, serialized by `fcntl.flock`/`msvcrt` in `_locking.py`) + Ed25519 signing **[drift]** (`signing.py`; **required by default** in the production profile — see note) | Concurrent writes on NFS-without-lockd break the linear chain; compromised host/operator | Track B (audit structure) + Track D (TEE) |
| **Verifiable** (small enough to be analyzed) | The kernel core **[on-master]** (`kernel.py`, `policy.py`, `receipt.py`, `executor.py`) | "Verifiable" is currently asserted by tests, not proof; the running binary ≠ the audited source | Track A (formal core + reproducible builds) |

None of these three properties references a model. This is the entire argument for "don't
limit to transformers": the soundness of the monitor is independent of what produced the
proposal.

> **[drift] Signing default.** Earlier drafts called Ed25519 signing "opt-in." The **code
> is authoritative and says otherwise**: `profile.py` — *"production (default) — signed
> Decision Receipts are required (`require_signature=True`)"*; `executor.py` defaults
> `require_signature=True` and a production gate with no verifier fails closed. Unsigned
> `dev` mode is the explicit opt-*out*. (`docs/SECURITY_MODEL.md` still lists "signing on
> by default" as a *roadmap* item — that doc lags the code; the code wins.) Honest current
> wording: **"Ed25519 receipt signing, required by default in the production profile."**

### 2. It implements the Clark-Wilson integrity model (1987)

MACI is Clark-Wilson separation of duty applied to agent actions. The mapping gives the
design a formal target and a vocabulary auditors already trust:

| Clark-Wilson element | ACGS element |
|---|---|
| Constrained Data Items (CDIs) | The real-world side-effect targets: files, DBs, money, infra, MCP tools |
| Transformation Procedures (TPs) | Approved actions — the only sanctioned way to mutate a CDI |
| Integrity Verification Procedures (IVPs) | Replay + audit-chain verification **[on-master]** (`replay.py`, `replay_store.py`, `test_audit_chain.py`) |
| Certification rules (policy authoring) | The constitution / policy bundles **[on-master]** (`policy.py`, constitutional-hash lock) |
| Enforcement rule E2/E3 (actor↔TP binding, authenticated) | Actor/action/argument/policy binding **[on-master]** (`test_argument_binding.py`, `tenant.py`) |
| Separation of duty (certifier ≠ executor) | MACI four-role architecture **[on-master, partial]** — see note below |
| The authenticated transaction record | **The Decision Receipt** — made cryptographic |

> **[on-master, partial] MACI roles.** The four-role architecture
> **Proposer → Validator → Executor → Observer** is real and documented in
> `docs/adr/0002-maci-four-role-architecture.md` and `MACI-ROADMAP.md`. **What is actually
> enforced and test-pinned is the two-role guarantee `validator ≠ proposer`** (issuance
> *and* verification: `escalation.py` — *"self-validation forbidden: validator must differ
> from proposer"*; `test_maci_role_separation.py`). Executor is the gate; Observer is a
> passive logging policy (`_ObserverPolicy`). So: cite the four-role architecture, but
> claim only **Proposer ≠ Validator** as an *enforced* separation of duty. Promoting
> Executor/Observer to enforced-distinct principals is itself roadmap work (Track F).
>
> **Caveat on the Clark-Wilson cut.** Proposer ≠ Validator is a *request ≠ approve*
> separation. It is **not** the Clark-Wilson SoD the §2 table row literally names — CW
> separation of duty is *certifier ≠ executor*, where the **certifier is the policy
> author**. That cut (the policy-author/certifier separated from the executor as a distinct
> principal) is **not yet enforced** — it is ADV12 / Track F+A roadmap work. Map
> Proposer ≠ Validator to CW's enforcement rules (E-series, actor↔TP binding), not to the
> certification SoD, to avoid overclaiming the integrity model.

Implication: the Decision Receipt is a *Clark-Wilson transaction certificate*. Its
correctness criteria are integrity-model criteria — testable and (Track A) provable — not
behavioral judgments about model output.

### 3. The Decision Receipt is *ocap-adjacent*, the token fallback *macaroon-adjacent* — design targets, not current characterizations

A signed Decision Receipt is an unforgeable token designating *this exact actor may run
this exact action with these exact arguments under this exact policy evidence*. It is close
to an object-capability — but **not** a classic one: a classic ocap grants authority by
*unforgeable possession*, identity-free and transferable, whereas the receipt is
**actor-bound**, which is precisely what makes it non-transferable. So today it is more
accurately an *authenticated authorization token* (and, per §2, a Clark-Wilson transaction
certificate). **[proposed] design target:** reaching true ocap semantics requires
supplementing or relaxing actor-binding with attenuable bearer authority — net-new, not a
property Ed25519 signing alone confers.

The AUTHZ fallback in `ROADMAP.md` **[on-master]** — *"token-based fallback (JWT-style
capability tokens signed by the Orchestrator with localized path + capability caveats;
verification in PreToolUse hooks)"* — is **macaroon-*adjacent***: it has caveats but, as
specified, a single Orchestrator signer and **no holder-side attenuation** (the defining
macaroon property — anyone holding one can mint a more-restricted one via HMAC
caveat-chaining; Birgisson et al., 2014). **[proposed]** *"macaroon" is this document's
analytic *design target*, not a current characterization; the term does not appear in the
repo, `AUTHZ-ROADMAP.md` proposes a different mechanism (a `capabilities.toml` registry),
and the delegation the citation promises does not yet exist.* The framing still clarifies
the Week-2 gate: that benchmark chooses between *graph propagation* and *caveated capability
tokens* — both are capability systems; the question is propagation cost, not paradigm.

### 4. Where the model actually sits: advisory, never authoritative

The decision function is deterministic:

```
D(actor, action, args, context, policy) -> {ALLOW + Receipt | DENY}
```

`D` is the authority. An optional advisory signal — which *may* be an LLM risk classifier —
is one input to `D`, never the output of `D`. Three consequences the roadmap exploits:

- **Swappable.** The advisory model can be downgraded or removed without changing any
  security property.
- **Falsifiable.** "The model is non-authoritative" is testable: remove the advisory plugin
  and the proof pack must still pass (Track F exit gate).
- **Paradigm-agnostic proposer.** Because `D` does not depend on how `action` was produced,
  the proposer can be an LLM agent, an RPA script, a CI job, a human operator, a classical
  planner, an RL policy, or an industrial controller.

### 5. The positioning sentence

> ACGS is a verifiable reference monitor for autonomous action. Its addressable surface is
> *any system that takes consequential action without a human approving each one* — of which
> agentic AI is the first and loudest instance, not the boundary.

---

## Part II — North star and the three gates

The north star is unchanged: **trustless third-party verifiability**.

> **Trustless** = a verifier who trusts *neither the proposer, nor the operator, nor the
> auditor* can confirm that policy was enforced on every executed side effect, and can detect
> any omission, reordering, or rewrite — without access to the operator's infrastructure.

That definition rules out an LLM-centric roadmap. Distrusting the proposer is the easy half
(deny-by-default). Distrusting the operator and the auditor is the hard half, satisfied only
by cryptographic transparency, hardware attestation, and formal proof.

**[proposed] — the three-gate ladder below is this document's framing.** `ROADMAP.md`'s
"Final goal (end of week 12)" is a flat capability list (replayable receipts; identity
end-to-end; boundary fail-closed; governed recovery evidence; MACI-aware aggregation;
constitutional-hash CI). The ladder *organizes* those into acceptance gates; it does not
already exist in the repo.

| Gate | Name | Plain-language bar | Horizon |
|---|---|---|---|
| **G1a** | Adoptable kernel (wk-12) | The reference monitor is correct, complete-mediation, fail-closed; a third party can run the proof and get the same result; threat table canonicalized; ≥1 non-LLM proposer governed | Now → wk 12 (`ROADMAP.md` Phases 1–4, hardened) |
| **G1b** | Formally-twinned kernel | The fail-closed invariant is model-checked and the kernel build is bit-reproducible (the multi-month formal half — see Part V "Honest note") | Post-wk-12 |
| **G2** | Trustless evidence | A third party verifies enforcement without trusting the logger or the operator | Post-wk-12 |
| **G3** | Production proof | The substrate governs a real adversarial regulated workload and survives an external audit conducted with G2 artifacts only | After G2 |

---

## Part III — The threat model is the spine

**[proposed] — this adversary set does not yet exist in the repo and must be reconciled
into `docs/SECURITY_MODEL.md`.** That file today enumerates **18 named threats** (Missing
receipt, Malformed receipt, Expired receipt, Tampered receipt, Mismatched actor, Mismatched
action, Argument substitution, Self-validation, Replay attempt, Audit-chain tampering,
Consumption-ledger tampering, Unsigned dev mode misuse, Policy-bundle substitution,
MCP/tool-gateway misuse, **Executor bypass**, **Policy evaluation failure**, **Policy
timeout/hang**, **Audit append failure**) — **not** an A-prefixed adversary model. The
`ADV*` prefix below is deliberate to avoid colliding with `COMPARISON.md`'s `A1–A8`
*capability axes*. Reconciling this 14-adversary view with the 18-threat table (which
adversary subsumes which threats) is itself a G1 deliverable, not a citation of existing
work — and the reconciliation must not silently drop `Executor bypass`, the
complete-mediation keystone, which is ADV9.

| # | Adversary | What they attempt | Closing mechanism | Gate / track | Evidence (maps to SECURITY_MODEL threats) |
|---|---|---|---|---|---|
| ADV1 | **Malicious / jailbroken proposer** (incl. the LLM) | Emit a dangerous action | Complete mediation + deny-by-default; proposer holds no authority | G1 | `test_fail_closed.py`; "Missing receipt" |
| ADV2 | **Insider / malicious operator** | Execute unreceipted side effects; rewrite history | Tamper-evidence + transparency (rewrite detectable without trusting them) | G2 / Track C | "Audit-chain tampering"; inclusion + consistency proofs **[proposed]** |
| ADV3 | **Compromised host** | Subvert the running kernel | TEE remote attestation; minimized + measured TCB | G2 / Track D | attestation quote bound to receipt **[proposed]** |
| ADV4 | **Network adversary** | Drop / delay / replay / MITM the authz lookup | Fail-closed on timeout; signed receipts; receipt expiry | G1 | `test_receipt_expiry.py`; "Expired receipt"; ROADMAP Week-2 network-resilience gate |
| ADV5 | **Colluding / cross-tenant** | Use another tenant's authority or read its evidence | Tenant isolation + proven non-interference | G1 / Track A | `test_tenant_safety.py`; "Policy-bundle substitution" + model-check **[proposed]** |
| ADV6 | **Supply-chain attacker** | Poison a dependency, the build, or the constitution | Reproducible builds + binary transparency + constitutional-hash CI | G2 / Track A | constitutional-hash CI **[on-master, but see caveat]** + bit-reproducible build check **[proposed]** |
| ADV7 | **Dishonest auditor / verifier** | The logging party itself cheats or colludes | Trustless verification — third party needs no trust in the logger | G2 / Track C | split-view defense via ≥2 witnesses **[proposed]** |
| ADV8 | **TOCTOU / time-of-use** | Change state between check and execute | Pre-execution re-validation hook + exact-argument binding | G1 | `test_argument_binding.py`; executor re-verifies receipt before `tool_fn` (burn-before-execute) **[on-master]** |
| ADV9 | **Out-of-gate executor bypass** | Invoke the raw tool/side-effect path, never reaching the governed executor | Adapter/gateway completeness + a static "is the gate wired" check (Track F's real security payload, not just the LLM-decentering demo) | G1 / Track F | `SECURITY_MODEL.md` "Executor bypass"; `INTEGRATION_MATRIX.md` tiers + `test_integration_gaps.py` **[on-master, partial]** |
| ADV10 | **Profile / signature downgrade** | Force a signed gate to accept unsigned, or downgrade `production-strict`→`production`→`dev` | Pin the profile to the verifier; never let the artifact decide whether its own signature is checked | G1 | repo fixtures `tests/fixtures/proofpacks/sig-downgrade-with-verifier/`, `receipts/sig-missing-verifier/` (a downgrade fail-open was found+fixed) **[on-master]** |
| ADV11 | **Signing-key compromise / key lifecycle** | Steal or misuse the Ed25519 key; exploit absent rotation/revocation | Key custody + rotation + a revocation registry (none exist yet) | G2 / Track D | `signing.py` key handling; `SECURITY_MODEL.md` "no global revocation list" **[proposed]** |
| ADV12 | **Malicious policy-author / insider certifier** | Author a permissive policy bundle that defeats deny-by-default *within the rules* (the Clark-Wilson certifier role) | Policy→SMT property checks (deny-by-default holds) + signed, reviewed, versioned bundles; certifier ≠ executor as principals | G1 / Track A + Track F | `policy.py`; "Policy-bundle substitution" — author separation is **[proposed]** |
| ADV13 | **Availability / denial-of-service** | Kill the verifier, audit sink, or network so a fail-closed gate halts all side effects (fail-closed inverts every integrity attack into an availability attack) | SLO/error-budget + degraded-mode policy; price the DoS surface explicitly | G3 | "Policy timeout/hang", "Audit append failure" (fail-closed today); availability budget **[proposed]** |
| ADV14 | **Clock / time manipulation** | Skew the host clock to extend or void receipt expiry | Trusted time source / signed timestamps; expiry not solely host-clock-bound | G2 | `test_receipt_expiry.py` (host-clock today); trusted-time binding **[proposed]** |

> **ADV2 vs ADV3 boundary.** ADV2 (insider operator) is *privileged-but-policy-bound* —
> they run the deployment but are still subject to the gate and the transparency log; ADV3
> (compromised host) is *below the TCB* — the kernel binary or its environment is subverted.
> In many deployments an insider operator also has host access; the table treats them as
> distinct *defense surfaces* (transparency/witnessing for ADV2, attestation for ADV3), not
> as disjoint actors.

> **[caveat] constitutional-hash CI.** `.github/workflows/constitutional-hash.yml` exists and
> runs on every PR/push **[on-master]**, but its own header states *"Today the inventory is
> empty (no markers in the parent-tracked tree)"* — so it presently guards an **empty
> inventory**. ADV6's supply-chain defense is real plumbing over a currently no-op gate;
> populating the inventory is part of the work, not a finished control.

The point this table makes at a glance: **thirteen of fourteen adversaries are
systems-and-crypto problems.** ADV1 is the only one the model touches, and even there the
defense is structural, not model-quality. That is the refutation of the LLM framing, in one
(proposed) artifact. (ADV9–ADV14 were added after an adversarial review found the original
eight set missing the complete-mediation keystone (bypass), the repo-acknowledged downgrade
attack, key-lifecycle, the insider certifier, availability, and clock adversaries.)

---

## Part IV — Workstreams (the non-LLM agenda)

Each track: the problem, the approach, where it lands, a falsifiable exit gate, and the
claim it unlocks. Adversary references use the `ADV*` prefix from Part III.

### Track A — Reference-monitor correctness & formal methods → G1/G2

**Problem.** "Verifiable" is currently carried by tests. Anderson requires the monitor be
*analyzable*.

> **[drift correction] "already uses Z3" — it does not.** Earlier drafts said the project
> "already uses Z3 SMT elsewhere — elevate it to the kernel." Ground truth: the only Z3
> reference on `master` is an **unwired stub**, `FormalPolicyHooks.prove_z3()` in
> `acgs_governance_eval_mvp/governance/hooks/formal.py` — a *different package* from the
> gove-zone kernel — whose own docstring reads *"This scaffold does not require OPA/Z3 at
> runtime."* There is **no solver, no `z3-solver` dependency, and no call site that proves
> anything**; with no adapter it either passes through or fail-closes with *"adapter is
> required but not configured."* Track A is therefore **net-new construction**, not
> elevation: implement a real Z3 adapter, add the `z3-solver` dep, build the policy→SMT
> compiler, and *separately* specify the gate loop in TLA+ (a different tool for a different
> target — state-interleaving safety vs. policy satisfiability).

**Approach.**
1. **State-machine spec + model-checking (TLA+ or equivalent).** **[proposed]** Specify the
   gate loop `propose → validate(policy) → receipt → execute → audit-append` and
   machine-check the invariant *no side effect occurs without a valid, current receipt*
   under **all interleavings** (audit-append failure, policy crash, watchdog timeout). This
   is the formal twin of the Week-1 scenarios A/B/C **[on-master]** and the natural place to
   discharge the concurrent-write hazard (Track B) and the TOCTOU gap (ADV8).
2. **Policy → SMT.** **[proposed]** Wire the reserved (currently-stub) Z3 seam into a real
   adapter; compile policy bundles (and the YAML-driven risk tiers from `MACI-ROADMAP.md`
   change-order item 2 **[on-master]**) to SMT and prove: deny-by-default holds; no policy
   admits an unreceipted side effect; tenant non-interference (ADV5). Gate it in CI so a
   violating policy is *rejected*.
3. **Reproducible builds + binary transparency.** **[proposed]** Make the kernel build
   bit-reproducible so "small enough to verify" extends from source to the *running binary*.

**Lands in.** `packages/gove-zone/` spec dir (new), `policy.py`, CI (`make verify`,
`constitutional-hash.yml` sibling).

**Exit gate.** Invariant model-checked with no counterexample; SMT property suite passes for
the shipped policy schema and gates CI; kernel build verified bit-reproducible in CI.

**Claim unlocked.** From "fail-closed is tested against A/B/C" → "the fail-closed invariant is
model-checked over the specified state machine." **DO-NOT-SAY "formally verified"** until the
machine-checked proof is reproducible by a third party.

### Track B — Distributed audit integrity → G1/G2

**Problem.** A single linear hash chain serialized by one `fcntl.flock` lock file
**[on-master]** (`_locking.py`) cannot hold a total order across uncoordinated writers; on
NFS without `lockd`, duplicate parentage breaks the cryptographic history. `ROADMAP.md`
flags exactly this and proposes a startup probe **[on-master]** (*"add a startup probe that
fails if `audit.jsonl` lives on NFS"*) — necessary as a guardrail, insufficient as a fix.
Audit persistence is also in-memory-only in `acgs-lite` (`MACI-ROADMAP.md` Observer gap
**[on-master]**).

**Approach (laddered).**
1. *Single-writer broker.* A dedicated append service owns the chain; replicate via Raft.
2. *Per-actor chains + periodic Merkle cross-checkpoint.* **Recommended** — this structure
   *is* the transparency log Track C needs, so G2 is not a rewrite.
3. *Merkle-DAG.* Concurrent parents first-class; weaker ordering semantics.

**Lands in.** `audit.py`, `_locking.py`, `acgs-lite` audit + public-API export
(`MACI-ROADMAP.md` change-order item 5: `AuditRegistry.merge` **[on-master, proposed export]**),
startup NFS probe.

**Exit gate.** Append-only and no-duplicate-parent proven under concurrent multi-writer +
crash injection (property test, cross-checked by the Track A model); persistence first-class
with crash-consistency (atomic rename + fsync barrier).

**Claim unlocked.** "tamper-evident audit chain safe under concurrent writers." Keep
**SAY-WITH-CAVEAT** on distributed deployments until option 2 lands.

### Track C — Trustless verifiability substrate → G2 (the heart of the reframe)

**Problem.** Tamper-*evidence* lets *you* detect changes if you hold the log. Trustlessness
(ADV2, ADV7) requires a *third party* to verify append-only-ness and inclusion **without
trusting the operator**. **[proposed] — all of Track C is net-new.**

**Approach (laddered, ship the cheap rungs first).**
1. **Transparency log** (RFC 9162 Merkle-log structures / verifiable-log): signed tree heads,
   **inclusion** and **consistency** proofs, checkable with no operator infrastructure. Built
   on the Track B option-2 structure. *Note: the existing `verify_proof_pack` / `verify-proofpack`
   offline verifier* **[on-master]** *is the seed — extend it to emit/verify inclusion +
   consistency proofs.*
2. **Witnessing / gossip for split-view defense (ADV7).** Publish signed tree heads to ≥2
   independent witnesses that gossip heads. Only *roots* leave — no sensitive payload.
3. **Verifiable policy evaluation (research spike, gated, kill-criterion).** Prove
   `decision = D(policy, inputs)` **without revealing inputs** (zk-SNARK/STARK over a
   constrained policy fragment). Treat exactly like the Week-2 paper gate: prove it for a
   bounded fragment within a stated proving-cost budget, or defer. No commitment until the
   spike passes.

**Lands in.** New transparency-log component; `signing.py`; `cli.py` (`verify-proofpack`
extended); a standalone **external verifier** binary depending on *none* of the operator's
services.

**Exit gate.** An independent third party, given only public tree heads + receipts +
inclusion/consistency proofs (+ optional ZK proofs), can (a) confirm every executed side
effect carried a valid policy decision, (b) detect any omission/reorder/rewrite, (c) without
operator infrastructure — and split-view is defeated by ≥2 witnesses.

**Claim unlocked.** This is the gate that earns the words **"trustless"** and **"third-party
verifiable."** **DO-NOT-SAY either** before this exit gate. ZK items are **DO-NOT-SAY** until
the spike passes.

### Track D — Hardware root of trust / confidential computing → G2/G3 (the GPU bridge)

**Problem.** ADV2/ADV3: a third party verifying receipts still has to trust that the *kernel
binary that ran* is the audited one, on a host the operator didn't tamper with. **[proposed].**

**Approach.**
1. **CPU TEE remote attestation** (SEV-SNP / TDX / SGX): attest the measured kernel binary +
   boot state. Combined with Track A reproducible builds, the verifier independently rebuilds,
   gets the same measurement, and confirms the attested code.
2. **GPU confidential computing.** Where the proposer is itself model inference, evaluate
   binding receipts to an attested GPU TEE (NVIDIA CC mode on Hopper/Blackwell-class
   accelerators). **Evaluate-and-gate** current GPU-CC attestation maturity; do not assume it.

**Lands in.** Deployment/attestation module (new); receipt schema gains an optional attested
binding; verifier checks the quote.

**Exit gate.** Remote attestation binds a receipt to "this exact kernel binary on this attested
host (and, where used, this attested GPU)," third-party checkable.

**Claim unlocked.** "attested enforcement / confidential governance." **DO-NOT-SAY "attested"
or "confidential"** until the quote is wired and externally verifiable.

### Track E — Threat-model-driven scope (cross-cutting)

**Problem.** Scope creep and "which adversary does this defend against?" ambiguity.

**Approach.** **[proposed]** Promote the Part III table to a canonical
`docs/SECURITY_MODEL.md` section (reconciled with the existing 14-threat table); every
roadmap item must name the adversary it closes and ship a falsifiable test; an item closing
no enumerated adversary is out of scope until the model is extended deliberately.

**Lands in.** `docs/SECURITY_MODEL.md` (add the ADV table + threat-to-adversary mapping),
proof-pack manifest.

**Exit gate.** Every adversary ADV1–ADV8 maps to a closing mechanism *and* a passing
proof-pack test; CI fails if an adversary has no covering test.

### Track F — Proposer-agnostic adapter surface → G1 (decenters the LLM, concretely)

**Problem.** The cleanest demonstration that this is not an LLM tool is to govern a non-LLM
proposer with the *same* receipt path, and show the security properties survive the model's
removal.

**Approach.**
1. Generalize `integration.py` **[on-master]** (already supports hook / MCP JSON-RPC /
   function-call shapes). Add non-LLM reference proposers: a pure-automation / scheduled-job
   gate; a **human-operator** proposer; and one flagship "no transformer" example (classical
   planner or RL-policy action gate), reusing the existing `ci_deploy_gate` pattern. *Existing
   root `examples/` gates to extend:* `python_tool_gate`, `mcp_tool_gate`,
   `agent_framework_gate`, `ci_deploy_gate` **[on-master]**.
2. Formalize **advisory vs authoritative** in code: `D` deterministic and authoritative; the
   advisory signal a pluggable, removable input. Also promote Executor/Observer toward
   enforced-distinct principals (closing the Part I §2 gap).

**Lands in.** `integration.py`, root `examples/` (new non-LLM gates).

**Exit gate (the killer demo).** The same proof pack passes (a) governing a non-LLM proposer
end-to-end, **and** (b) with the LLM advisory plugin removed entirely — proving no security
property depends on the model.

**Claim unlocked.** "paradigm-agnostic / model-independent enforcement," demonstrated.

---

## Part V — Sequencing: overlay on the existing 12-week plan

`ROADMAP.md` Phases 1–4 (the *draft* plan) are **kept verbatim** as the execution of **G1**.
The tracks overlay with minimal disruption. **Honest note:** Tracks C, D, and the formal-methods
half of A are genuine multi-month efforts — this is an *overlay of new work onto* the kernel
plan, not a relabeling of work already done.

| Existing phase (kept) | Overlay added | Why it slots here |
|---|---|---|
| **Phase 1** (wk 1-3) kernel hardening + paper gate **[on-master plan]** | **Track E spine [proposed]** canonicalize the Part III adversary table into `SECURITY_MODEL.md` (the cheap part — must land *first*, since it scopes every later item); **Track A seed [proposed]** TLA+ spec as the formal twin of Week-1 scenarios A/B/C; stand up reproducible-build CI | The threat model is the spine — it cannot admit Tracks A/B/F if it ships after them; the fail-closed audit *is* the invariant to formalize |
| **Phase 2** (wk 4-6) R5/R6 trace receipts | **Track B [proposed]**: upgrade the NFS risk from "probe + document" to per-actor chains + Merkle checkpoint (**option 2 is a hard prerequisite for Track C**, not just a recommendation) | Phase 2 already touches audit-chain events; seed G2 now |
| **Phase 3** (wk 7-9) R1/R2 identity + R3 boundary | **Track F [proposed]** first non-LLM adapter + the ADV9 "is the gate wired" check; **Track A** policy→SMT alongside R3 risk tiers | Identity/boundary work is paradigm-independent |
| **Phase 4** (wk 10-12) R7/R4 + hash CI | **Track E enforcement [proposed]** per-item test coverage (CI fails if an adversary has no covering test); **Track A** binary transparency joins hash CI | Aggregation + hash CI are the natural home for supply-chain (ADV6) defense |
| **Post-wk-12 (G2)** | **Track C** transparency log + witnessing; **Track D** attestation; **Track C** ZK spike (gated) — all **[proposed]** | Built on the Phase-2 structure, so G2 is extension, not rewrite |
| **After G2 (G3)** | Regulated production proof (`clinicalguard` PHIPA/PIPEDA; or iGaming AGCO/iGO) under external audit | The commercial proof; uses only G2 trustless artifacts |

### Gate acceptance (in the existing "exit 0 = done" style)

G1 is split so the week-12 milestone is **not** gated on the multi-month formal-methods
work the "Honest note" above flags (a single bundled gate would force G1 to slip):

**G1a acceptance (wk 12 — the [on-master plan] + cheap additions):**
```
# (existing) make verify && acgs-lite lint/typecheck/test && Acgs-Swarm tests
#            && eval-mvp tests && propagation-gate artifact && ADR present
# (added — proposed, but week-12-feasible)
&& <Part III adversary table canonicalized into docs/SECURITY_MODEL.md, ADV→threat map>
&& <proof pack governs >=1 non-LLM proposer>
&& <"remove advisory model, properties unchanged" demo passes>
```

**G1b acceptance (post-12 — the multi-month formal half of Track A):**
```
&& test -f packages/gove-zone/spec/fail_closed.tla   # formal twin exists
&& <model-check fail_closed invariant: no counterexample>
&& <verify kernel build is bit-reproducible>
```
Track A itself is three independent specialties — formal-spec (TLA+), SMT-policy, and
reproducible-build — and should carry three independent exit gates, not one.

**G2 acceptance** — an independent verifier, with public tree heads + receipts +
inclusion/consistency proofs (+ optional ZK + attestation quotes) and **no operator
infrastructure**, confirms every executed side effect carried a valid decision, detects any
omission/rewrite, and split-view is defeated by ≥2 independent witnesses.

**G3 acceptance** — the substrate governs a real regulated adversarial workload for a defined
period, an external auditor verifies enforcement using only G2 artifacts, and the audit passes.

---

## Part VI — Claim-discipline guardrails (mapped to `docs/CLAIMS.md`)

`docs/CLAIMS.md` uses a `Claim | Status | Evidence source | Test or demo | Limitation |
Safe public wording` ledger with status values `implemented / tested / partial / roadmap /
not claimed`. The **DO-NOT-SAY column below is this document's overlay** on that ledger (a
publication gate keyed to a passed roadmap gate); it is not a separate label scheme already
in the repo. Each row's safe wording should land in the CLAIMS.md `Safe public wording`
column with status `roadmap` until its gate passes.

| Capability | DO-NOT-SAY until… | Honest interim wording (CLAIMS.md `Safe public wording`) |
|---|---|---|
| Formal verification | Track A invariant is machine-checked **and** third-party reproducible | "fail-closed is tested against scenarios A/B/C"; later "the fail-closed invariant is model-checked over the specified state machine" |
| Trustless / third-party verifiable | G2 exit gate passes | "tamper-evident audit chain with replay" (current, status `tested`) |
| Concurrent-safe audit | Track B option-2 lands | SAY-WITH-CAVEAT: safe on local SSD single-writer; distributed via the new structure |
| Attested / confidential | Track D quote is wired and externally checkable | "Ed25519 receipt signing required by default in the production profile; receipt binds actor/action/args/policy" (current) |
| Zero-knowledge policy proofs | the gated spike passes its kill criterion | Frame as exploration only; no public claim |
| Paradigm-agnostic | Track F killer demo passes | "vendor-neutral; sits below any framework" (current) — upgrade to "model-independent, demonstrated" after the demo |

The constitutional-hash sealing discipline is the right enforcement *pattern* for this
ledger — a claim "sealed" to regenerated evidence — **with the standing caveat that the hash
inventory is currently empty** (the gate runs but guards nothing yet; populating it is part
of the work).

---

## One-paragraph summary for the top of the repo

*This blurb is written to pass its own Part VI publication gates — present tense only for
what is on `master`; roadmap aspirations are explicitly future-tense.*

> ACGS is a **fail-closed reference monitor** for autonomous side effects: a
> deterministic authority boundary that emits a cryptographic Decision Receipt and makes
> executors fail closed without one. (The Anderson *verifiable* property is a roadmap target
> via the formal track — currently tested, not proven.) It applies the Clark-Wilson integrity
> model with **Proposer ≠ Validator enforced today** and the full four-role architecture
> documented in ADR 0002, using authenticated authorization receipts (true object-capability
> semantics are a design target, not a current claim). It is **vendor-neutral and sits below
> any framework**; model-independence across non-LLM proposers is *demonstrated only after the
> Track F gate*, and until then the language model is treated, by design, as a removable
> advisory input rather than an authority. The roadmap then drives toward trustless
> third-party verifiability: a transparency log and external verifier (no trust in operator or
> auditor), a model-checked fail-closed kernel, reproducible builds with hardware attestation,
> and a regulated production proof. The hard problems are systems, cryptography, and formal
> methods. The model is a guest.
