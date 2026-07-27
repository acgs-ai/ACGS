> **Internal engineering document.** Not part of the public release artifact.

# Security Whitepaper Outline — ACGS / gove-zone

> Working title: **"No Valid Decision Receipt, No Side Effect: A Reference-Monitor
> Architecture for AI-Agent Actions"**

Status: outline for a public whitepaper. Ground rules for the eventual draft:
every claim must trace to [`docs/CLAIMS.md`](../../CLAIMS.md); residual gaps are
stated in the body, not a footnote; no certification, regulator-approval, or
production-readiness language anywhere.

---

## 1. Executive summary (1 page)

- The shift: agents that *act* (pay, write, deploy) vs agents that chat; the
  unanswered question "was this action authorized, and can you prove it?"
- The answer in one artifact: the Decision Receipt — verifiable, vendor-neutral
  proof-of-decision, enforced fail-closed at the executor boundary.
- Scope honesty: what this paper claims (tested local invariants) and what it
  does not (certification, formal verification, managed-service guarantees).

## 2. Problem statement

- Side-effect authorization today: prompt-level guardrails, scattered `if`
  checks, after-the-fact log archaeology.
- Why audit-centric governance is insufficient: logs record what happened;
  receipts gate whether it happens (receipt-centric vs audit-centric framing,
  cf. `docs/COMPARISON.md`).
- Why a neutral layer: the governor and the governed should not be the same
  vendor (`docs/POSITIONING.md`).

## 3. Architecture: a reference monitor for agent side effects

- Anderson-1972 frame: complete mediation, tamper-evidence, verifiability —
  and where each property lives in the design.
- Component walk: policy engine → receipt issuance → executor gate →
  hash-chained audit → replay/proof packs (mirror of `docs/ARCHITECTURE.md`).
- Role separation (MACI): proposer ≠ validator ≠ executor; self-validation is
  refused at mint and at the gate.
- The fail-closed catalogue: the 13 enumerated failure modes that block
  execution (from `docs/ARCHITECTURE.md` §Failure modes).

## 4. The Decision Receipt

- Schema and binding roles (28 fields; from `docs/DECISION_RECEIPT_SPEC.md`).
- Hash construction and anti-downgrade: algorithm + key id inside the hash.
- The 20-step validation order; why order matters (reject before compare).
- Signed vs unsigned modes; why the default profile requires signatures and
  fails closed without a trusted verifier rather than auto-signing.

## 5. Threat model

- Per-mechanism threat table (18 threats: missing/malformed/expired/tampered
  receipt, actor/action/argument substitution, self-validation, replay,
  audit-chain and consumption-ledger tampering, policy substitution, MCP
  misuse, executor bypass, policy failure/timeout, audit append failure) —
  each with current protection, test evidence, and remaining limitation.
- Per-actor adversary model ADV1–ADV14, with status tags
  ([on-master] / [on-master, partial] / [proposed]) — reproduced faithfully,
  including the proposed rows (compromised host, dishonest auditor, clock
  manipulation).
- The keystone: ADV9 out-of-gate bypass — the kernel cannot govern paths it is
  not wired into; how the shipped static wiring check (`test_gate_wiring_matrix`)
  and dispatcher-level test discipline address it.
- The headline finding: 13 of 14 adversaries are systems-and-cryptography
  problems, not model-quality problems.

## 6. Evidence integrity

- Hash-chained JSONL audit: edit/reorder/truncation/malformed-tail detection.
- Single-use receipts: consumption ledger, burn-before-effect, high-water-mark
  sidecar for tail truncation, prune watermark vs clock rollback.
- Replay verification and the raw-argument side-store.
- Offline proof packs: auditor verification with zero trust in the operator's
  running system (`gove-zone verify-proofpack`).
- Stated limits: tamper-evident ≠ tamper-proof; local JSONL is not WORM;
  detection-not-prevention for host-level insiders.

## 7. Deployment hardening

- The secure-by-default posture and the one dev-permissive default
  (anti-replay opt-in) — stated as an accepted alpha limitation.
- Hardened checklist: signing + verifier, consumption ledger with checkpoint,
  short expiries, policy timeout, WORM placement of chain + sidecars.
- Governed-MCP gateway trust boundary (alpha): local-transport trust
  assumption, session-principal identity, denied sampling channel.
- Availability trade-off (ADV13): fail-closed inverts integrity attacks into
  availability attacks; operator SLO guidance.

## 8. What ACGS is not (explicit non-claims)

- Not IAM/RBAC/PKI; not sandboxing; not content moderation; not formal
  verification; not certified or regulator-approved — each with the
  complements-not-replaces framing from `docs/CLAIMS.md` rows 28–34.

## 9. Compliance mapping (self-assessment)

- Method and disclaimer: evidence *toward* outcomes, not compliance by adoption.
- Control inventory → NIST AI RMF 1.0, NIST CSF 2.0, MITRE ATLAS, OWASP
  LLM/Agentic (from `docs/COMPLIANCE_CROSSWALK.md`).

## 10. Verification and reproducibility

- Test evidence index (the per-claim test map from `docs/CLAIMS.md`).
- The 15-minute reproduction path: smoke run, tamper demo, proof pack — every
  claim in the paper reproducible on a laptop without network access.

## 11. Roadmap (labeled as such)

- Trustless evidence: transparency/witnessing (ADV7), TEE attestation (ADV3),
  trusted time (ADV14).
- Key lifecycle: custody, automated rotation (revocation registry exists).
- Default-on single-use profile; global revocation registry.
- Cross-host receipt portability validators.

## Appendices

- A. Full receipt JSON example (valid + invalid pairs).
- B. Adversary ↔ threat reconciliation table.
- C. Glossary (`docs/GLOSSARY.md`).

---

**Production notes for the drafting team:** target 18–25 pages; §5 is the
centerpiece; every table imports from the governing doc rather than forking it
(the docs invariant tests, e.g. `tests/docs/test_adversary_model.py`, already
fail closed if the adversary model drifts — keep the whitepaper generated or
cross-checked the same way).
