# Stage 3 — Landing-Page Thesis (gove-zone / ACGS)

> **Status:** launch artifact, built against verified anchor `f9a8f37` (gove-zone
> `0.1.0.dev0`). Every claim below traces to the claims map (§6 of the launch
> handoff) and to source: `packages/gove-zone/SECURITY.md`, `ARCHITECTURE.md`, and
> the live proof-pack at `dist-govern-zone-proofpack/`. Caveats are part of the
> copy, not footnotes to be stripped.
>
> **Naming:** ACGS = project/brand (leads externally). gove-zone = the package you
> install and run. One repo, two names.

---

## 0. The one line

> **gove-zone is an alpha runtime governance plane for receipt-gated agent
> execution — no valid Decision Receipt, no side effect.**

Everything on the page is in service of that sentence.

---

## 1. Hero

**Headline:**
> Your agents can reason freely. They cannot execute freely.

**Subhead:**
> gove-zone is a fail-closed governance gate that sits between an agent's decision
> and its side effect. No valid Decision Receipt, no side effect — enforced by one
> verifier, with a tamper-evident audit trail you can replay.

**Primary CTA:** `Reproduce the proof →` (anchors to §5)
**Secondary CTA:** `Read the security boundary →` (links to `SECURITY.md`)

---

## 2. The problem

An agent that can *decide* to call a tool can, today, *call* it. The gap between
"the model chose to write this file / hit this endpoint / move this money" and the
side effect actually firing is, in most stacks, unguarded. You either trust the
model or you turn it off.

That is the wrong choice to have to make. The architect who has to let agents
touch real infrastructure needs a third option: let them propose anything, and
let a separate authority decide — verifiably — whether the specific action with
the specific arguments is allowed to run.

---

## 3. The thesis

**Fail-closed constitutional governance, before the side effect.**

gove-zone enforces a single invariant — *no valid Decision Receipt, no side
effect* — through one enforcement gate (`DecisionReceipt.verify`, wrapped by
`execute_with_receipt` / `GovernedExecutor` / `ReceiptVerifier`). There is no
second, weaker path. A policy that raises or times out becomes a `DENY`; an
audit-append failure raises rather than proceeds. No exception path resolves to
"allow." *(Source: `SECURITY.md` §"Fail-closed by construction".)*

> Agents can reason freely, but they cannot execute freely.

---

## 4. How it works (what we can say, plainly)

Each item below is a verified capability (§6 SAY). The canonical proof path is
`decision.py → receipt.py → audit.py → replay.py`.

- **Deny before the side effect.** Unsafe tool calls are refused *before* anything
  runs — fail-closed on no/malformed/tampered receipt, on `DENY`/`ESCALATE`, on
  tenant / boundary / action / policy-hash / expiry mismatch.
- **Argument binding — not a blank cheque.** A receipt authorizes a specific tool
  *with specific arguments*, not the tool in general. A valid receipt for
  `write_file(path="/tmp/safe")` cannot authorize `write_file(path="/etc/shadow")`.
  *(Source: `SECURITY.md` §"Argument binding".)*
- **Tamper-evident, replayable audit.** The audit log is an append-only hash
  chain; any edit, reorder, or truncation fails `verify_chain()`. Recorded
  decisions are replayable against policy via receipt + audit-chain verification.
- **Role separation (MACI), at the kernel.** A receipt binds two distinct
  principals — the **proposer** (the agent that asked) and the **validator** (the
  authority that approved). The kernel refuses to mint a self-validated receipt:
  *an agent can propose an action but can never validate its own authority to
  execute it.* ⚠️ This is the kernel MACI invariant; broader MACI phases are
  roadmap (`MACI-ROADMAP.md`).
- **Speaks your agents' tool formats.** Normalizers bridge Claude/Codex, MCP,
  OpenAI, and LangChain tool-call formats (`integration.py`).
- **Deterministic policy bundles.** Decisions are driven by rule-set *policy
  bundles*, tenant- and boundary-bound.

---

## 5. Proof, not adjectives

This is the differentiator. The claims above are not marketing — they are the
output of a command you can run.

**`gove-zone proofpack` → `status: pass`** on all six checks
(`dist-govern-zone-proofpack/conformance-results.json`):

| Check | Result |
|---|---|
| `allowed_action_executed` | ✅ true |
| `denied_action_blocked` | ✅ true |
| `transformed_action_executed` | ✅ true |
| `missing_receipt_blocked` | ✅ true |
| `tampered_receipt_blocked` | ✅ true |
| `audit_chain_verified` | ✅ true |

Audit chain: `verification.json` → `valid: true`, `failures: []`. The proof pack
writes receipts (unsigned `unsigned_local` by default — see the signing caveat in
§6), the `audit.jsonl` chain, and a `limitations.md` — real artifacts, attachable
as release evidence.

**Tests:** 250+ gove-zone tests green, **0 failing** (kernel, receipt, audit-chain
corruption, replay, MACI role separation). The Ed25519 signing tests are active
only when the optional `cryptography` dependency is installed — consistent with
signing being opt-in (see caveat below). The CaLegal companion
(`ca-legal-agent-skills`) ships the same fail-closed / audit-hash / replay
governance contract with its own governance core green.

**Run it yourself** (from the monorepo root):

```bash
uv sync --all-extras
uv run --package gove-zone gove-zone proofpack    # → {"status":"pass", ...}
uv run --package gove-zone python -m pytest packages/gove-zone/tests \
  --import-mode=importlib -q
```

> Don't take the headline on trust. The whole pitch is that you don't have to.

---

## 6. What gove-zone deliberately does **not** do

The honesty is the positioning. These are stated up front, not buried.

- **Alpha** (`0.1.0.dev0`) — a production-shaped foundation, **not** production-,
  compliance-, or regulator-certified.
- **Ed25519 signing is opt-in.** It is real and closes the recomputed-receipt
  residual — but default deployments are **unsigned**; integrity then rests on
  `receipt_hash` + the audit chain. It is never on by default.
- **No PKI, CA, trust chain, key custody, or revocation.** Signing is
  point-to-point; key management is the operator's responsibility.
- **No side-effect sandboxing.** gove-zone decides *whether* and *with which
  arguments* an action runs; it does not contain the blast radius of the tool you
  register. **Run tools in your own sandbox.**
- **No durable off-host audit sink** (WORM / SIEM) by default; the chain is local
  JSONL. Audit locking is **Unix-only** (`fcntl`); Windows deferred.
- **Not a guarantee against full host compromise** — an attacker controlling host
  + issuer + audit file can forge a *locally* consistent chain. The chain proves
  tamper-evidence for readers, not unforgeability under host compromise.
- **Not yet on PyPI** — install is from source today.

---

## 7. Who this is for

The architect who must let agents act on real infrastructure without surrendering
control. If "the model decided to" is currently your only authorization layer,
gove-zone gives you a verifiable second one — without taking the agent's autonomy
away from the part where autonomy is valuable (reasoning), and adding it back
exactly where it isn't (execution).

---

## 8. CTA

- **Reproduce the proof pack** (§5) — `status: pass` in one command.
- **Read the boundary** — `packages/gove-zone/SECURITY.md` states, honestly, what
  is enforced and what is out of scope.
- **Star / follow** `github.com/dislovelhl/ACGS`.

---

## Appendix A — Claims traceability (every public line maps here)

| Page claim | §6 bucket | Source of truth |
|---|---|---|
| "no valid Decision Receipt, no side effect" | SAY | `SECURITY.md` §"The security property" |
| Deny before side effect / fail-closed | SAY | `SECURITY.md` §"Fail-closed by construction"; `test_fail_closed` |
| Tamper-evident hash-chained audit | SAY | `SECURITY.md` §"Tamper-evidence"; proofpack `audit_chain_verified` |
| Replayable decisions | SAY | `replay.py`; `verification.json valid:true` |
| Argument binding (`/tmp/safe` ≠ `/etc/shadow`) | SAY | `SECURITY.md` §"Argument binding" |
| Tool-format normalizers | SAY | `integration.py` |
| Proposer ≠ validator role separation | SAY (kernel) | `SECURITY.md` §"Role separation (MACI)" |
| Ed25519 signing | **CAVEAT** — opt-in, unsigned default | `SECURITY.md` §"Opt-in Ed25519 receipt signing" |
| Broader MACI phases | **CAVEAT** — roadmap | `MACI-ROADMAP.md` |
| "policy bundles" (not "compile-time policies") | **CAVEAT** — wording | §6 |
| proofpack 6/6 + chain verified | SAY (evidence) | `dist-govern-zone-proofpack/` |
| 250+ tests green, 0 failing | SAY (measured) | local pytest run on `f9a8f37` |

## Appendix B — Do **not** say (guard rail for downstream copy)

- ❌ "the default governance layer for AI agents" as a *present* fact (north-star
  destination only).
- ❌ "production-certified" / "compliance-proven" / "regulator-approved".
- ❌ "cryptographically complete" / "verifier-complete" (no PKI, custody, revocation).
- ❌ "sandboxes side effects" / "strict network proxy" (it decides whether/with which
  args an action runs; the tool runs in the operator's sandbox).
- ❌ "enterprise standard" — too early for alpha; use "production-shaped foundation
  / credible default candidate".
- ❌ a precise "256 tests" / "165 tests" headline — use "250+ green, 0 failing" and
  "governance core green"; exact counts shift with optional deps.
