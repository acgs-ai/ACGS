# External Auditor Brief — ACGS / gove-zone Proof Pack

> **Status: ALPHA (`gove-zone 0.1.0a1`). Not production-certified. Not compliance-certified. Not regulator-approved.**
>
> Prepared: 2026-07-03. Evidence generated from repository commit `12a150b` (`origin/master`).
> Companion document: [REVIEW-CHECKLIST.md](REVIEW-CHECKLIST.md) — step-by-step verification walkthrough.

## 1. Purpose of this brief

We are asking one question of a professional GRC / audit reviewer:

> **Is a pre-execution Decision Receipt — a hash-bound (optionally Ed25519-signed) record that a specific agent action was evaluated against a specific policy *before* it executed, verifiable offline by a third party — acceptable control evidence, where a post-hoc application log would not be?**

Everything in this packet exists so you can answer that question from artifacts, not from our claims. This is a request for assessment, not a sales document. Negative findings are as valuable to us as positive ones and we intend to publish your assessment claim-safely (with your consent, attributed or anonymized as you prefer).

## 2. What ACGS / gove-zone is

gove-zone is an open-source (Apache-2.0) Python governance kernel for AI-agent side effects. It sits at the executor boundary, below any agent framework:

1. Before a governed tool call executes, a policy evaluates the proposed action (actor, action, arguments, tenant).
2. The verdict (ALLOW / DENY / ESCALATE / TRANSFORM) is bound into a **Decision Receipt**: a JSON artifact carrying the actor, proposed action, argument hash, policy bundle id + hash, tenant, timestamp, audit-chain anchor, and a receipt hash (optionally an Ed25519 signature).
3. The governed executor **fails closed**: no receipt, a tampered receipt, a DENY receipt, or arguments that differ from those the receipt bound → no side effect.
4. Every decision (including denials) is appended to a hash-chained audit log (JSONL).
5. A **proof pack** bundles receipts + audit chain + verification results into a directory a third party can verify **offline** with a standalone verifier — without running or trusting the enforcement runtime.

The core invariant: **No valid Decision Receipt, no side effect.**

## 3. What is claimed — and what is explicitly not claimed

The project maintains a claim ledger (`docs/CLAIMS.md` in the repository) mapping every public claim to code and tests. Condensed:

### Claimed (each backed by tests we ran; see Appendix A)

| Claim (safe wording) | Evidence |
|---|---|
| The governed executor fails closed without a valid receipt. | `test_executor_guard.py`; demo checks [3], [4] in Appendix A.2 |
| Kernel dispatch evaluates policy before the registered tool runs. | smoke proof (Appendix A.1): DENY leaves no side effect, audit event precedes execution |
| Receipts bind actor, action, and exact arguments checked by the executor. | `test_argument_binding.py`; tamper demo: argument substitution blocked (Appendix A.4) |
| Receipt field tampering is hash-detected; signed mode closes recomputed-forgery when engaged. | offline verifier returns `RECEIPT_HASH_MISMATCH`, exit 1 (Appendix A.6) |
| Local audit events are hash-chained and tamper-evident. | editing one audit line → `AUDIT_CHAIN_BROKEN`, exit 1 (Appendix A.7) |
| The CLI can generate a local proof pack with receipts, audit, verification, and limitations. | Appendix A.3 |
| A proof pack can be verified offline, without importing the kernel. | `gove-zone verify-proofpack`, Appendix A.5 |
| Opt-in Ed25519 receipt signing is implemented for local trusted-key verification. | demo checks [8], [9] (Appendix A.2); signed pack without a trust anchor fails closed (`SIGNED_RECEIPT_NO_VERIFIER`, Appendix A.8) |

### Explicitly NOT claimed

- **Not production-certified, not compliance-certified, not regulator-approved.** No external audit has occurred — that is why you are reading this.
- **Signing is opt-in; verification is unsigned by default.** The conformance proof pack you will generate is a *dev-mode, unsigned* pack: only the SHA-256 receipt hash is checked, which an attacker with host control could recompute. Production posture requires `require_signature=True` plus an out-of-band trust anchor. The offline verifier reports `"signature_verified": null` for unsigned packs rather than pretending.
- **No anti-replay nonce.** A valid ALLOW receipt is stateless-reusable until `expires_at`. Mitigations (short expiry, consumption ledger, side store) exist but are not the default.
- **Enforcement covers only paths wired through the governed executor.** A raw tool call the integrator exposes outside the gate is not governed. This is an integration property, not something the kernel can prove about your deployment.
- **Local JSONL is not WORM storage.** The audit chain is tamper-*evident*, not tamper-*proof*; durable retention is the operator's (or a future managed service's) job.
- **Not** content moderation, sandboxing, IAM/PKI, or formal verification. See `docs/CLAIMS.md` rows 27–33.

## 4. What the proof pack contains

`gove-zone proofpack` writes `dist-govern-zone-proofpack/` (`manifest.json` schema `gove-zone/proof-pack/v1`):

| File | Content |
|---|---|
| `manifest.json` | schema version + file inventory |
| `receipts/allowed_receipt.json` | ALLOW receipt for an executed action |
| `receipts/denied_receipt.json` | DENY receipt — the denial itself is evidence |
| `receipts/transformed_receipt.json` | TRANSFORM receipt — action constrained to approved output |
| `audit.jsonl` | hash-chained audit events anchoring each receipt |
| `verification.json` | in-runtime chain verification result |
| `conformance-results.json` | pass/fail per invariant (allow executes, deny blocks, missing/tampered receipt blocks, transform constrained, chain verifies) |
| `limitations.md` | the alpha / non-certification disclaimer, inside the artifact itself |

Receipt binding fields you can inspect directly in each receipt JSON: `actor`, `proposed_action`, `argument_hash`, `decision`, `policy_bundle_id`, `policy_hash`, `tenant_id`, `timestamp`, `expires_at`, `audit_event_hash`, `previous_audit_hash`, `receipt_hash`, `signature`, `signature_algorithm`, `signing_key_id`, `authority`, `validator_id`.

## 5. How to verify offline

Full commands with expected outcomes are in [REVIEW-CHECKLIST.md](REVIEW-CHECKLIST.md). In short, from a clone of the repository at `master` (requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/)):

```bash
# generate a pack
uv run --package gove-zone gove-zone proofpack

# verify it offline — exit 0 iff valid; prints a JSON verdict with machine-readable reasons
uv run --package gove-zone gove-zone verify-proofpack dist-govern-zone-proofpack
```

Properties of the verifier relevant to an audit posture:

- It reads only the pack directory; it does not execute the kernel or trust the runtime that produced the pack.
- Trust anchors are supplied **out-of-band**, never taken from the pack: `--verifier-key` (raw 32-byte Ed25519 public key) and `--revoked-keys` (JSON revocation list). A signed pack verified without a key **fails closed** (`SIGNED_RECEIPT_NO_VERIFIER`); a malformed revocation list fails closed (exit 2) rather than degrading to "no revocation".
- Failure reasons are enumerated codes (`RECEIPT_HASH_MISMATCH`, `AUDIT_CHAIN_BROKEN`, `RECEIPT_NOT_ANCHORED`, `SIGNING_KEY_REVOKED`, …), not prose.
- We encourage you to tamper with a copy of the pack and confirm the verifier catches it — the checklist includes two such destructive tests we ran ourselves (Appendix A.6, A.7).

## 6. Feedback requested

1. **The core question (§1):** would a Decision Receipt of this shape be acceptable evidence that a control ("agent actions are authorized before execution") operated — in contexts where you would reject a post-hoc application log? If not, what is missing?
2. **Binding sufficiency:** are the bound fields (§4) the right set? What would you additionally require bound (e.g., model/version identity, human approver identity, environment attestation)?
3. **Trust anchor posture:** is out-of-band public key + revocation list a workable custody model for your verification workflows, or do you require PKI/transparency-log integration before this is usable evidence?
4. **The unsigned default:** the honest default is dev-mode unsigned verification. Does the existence of an unsigned mode undermine the evidence class, or is "signed-mode required in production" an acceptable deployment precondition to attest against?
5. **Framework mapping:** which control framework(s) would you map this to (e.g., change-authorization, privileged-action approval, ITGC-style controls), and does the proof pack contain what you would need for a walkthrough + reperformance in that mapping?
6. **Gaps that would block reliance:** anti-replay, WORM retention, coverage proof (that *all* executor paths are gated), key custody — which of these is a hard blocker vs. a compensating-control conversation?

Written responses in any form are welcome; a marked-up copy of [REVIEW-CHECKLIST.md](REVIEW-CHECKLIST.md) is ideal.

## 7. Reference documents (in the repository)

- `docs/PROOF_PATH.md` — canonical proof narrative (the checklist follows it)
- `docs/CLAIMS.md` — full claim ledger with per-claim evidence and limitations
- `docs/DECISION_RECEIPT_SPEC.md` — receipt format specification
- `docs/SECURITY_MODEL.md` — threat model and hardening guidance
- `docs/REVIEW_CHECKLIST.md` — the project's internal review checklist (broader than this packet)
- `packages/gove-zone/SECURITY.md`, `packages/gove-zone/ARCHITECTURE.md`

---

## Appendix A — Literal command transcript (trimmed)

Environment: Linux (Fedora), `uv`-managed Python, repository worktree at commit `12a150b` (detached `origin/master`, fetched 2026-07-03). `gove-zone --version` → `gove-zone 0.1.0a1`. Output trimmed to the decision-relevant lines; nothing was altered inside the retained lines.

### A.1 Step 1 — denied action (smoke proof)

```console
$ uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
{"allow": {..., "decision": "allow", "tool": "write_file"},
 "audit": {"checked": 2, "failures": [], "valid": true},
 "checks": [
   {"id": "allow-before-side-effect", "status": "pass",
    "evidence": "ALLOW receipt emitted and safe write executed after audit append"},
   {"id": "deny-before-side-effect", "status": "pass",
    "evidence": "DENY receipt emitted and blocked path write left no side effect"},
   {"id": "audit-chain-verifies", "status": "pass",
    "evidence": "two smoke decisions are linked by a valid hash chain"}],
 "claimBoundary": "Local gove-zone smoke proof only; not production deployment proof, ...",
 "deny": {..., "decision": "deny", "matchedRules": ["SMOKE_SECRET_BOUNDARY:keyword:id_rsa"]},
 "status": "pass"}
# exit=0
```

### A.2 Step 2 — receipt-gated execution demo

```console
$ uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
[1] Allowed action executes            ✓ verified + executed with valid receipt
[2] Denied action is blocked           ✓ blocked: Denied receipt cannot authorize execution
[3] Missing receipt is blocked         ✓ blocked: No receipt provided for governed execution
[4] Tampered receipt is blocked        ✓ blocked: Altered field or invalid hash: receipt_hash mismatch. ...
[5] Cross-tenant receipt is blocked    ✓ blocked: Tenant mismatch: expected tenant-B, got tenant-A
[6] Transformed action is constrained  ✓ original args refused; approved transformed args executed
[7] Audit evidence for every decision  ✓ audit chain verified: 5 tamper-evident events
[8] Signed receipt verified            ✓ signed receipt verified with public key + executed
[9] Forged/recomputed receipt rejected ✓ invalid signature — no private key
All invariants held. No valid Decision Receipt, no side effect.
# exit=0
```

### A.3 Step 3 — proof pack generation

```console
$ python -m gove_zone.cli proofpack        # run inside a temp dir, via uv
{"output_directory": "dist-govern-zone-proofpack",
 "results": {"allowed_action_executed": true, "audit_chain_verified": true,
             "denied_action_blocked": true, "missing_receipt_blocked": true,
             "tampered_receipt_blocked": true, "transformed_action_executed": true},
 "status": "pass"}
# exit=0; files: manifest.json, receipts/{allowed,denied,transformed}_receipt.json,
#          audit.jsonl, verification.json, conformance-results.json, limitations.md
```

### A.4 Step 5 — in-runtime tamper demo

```console
$ uv run --package gove-zone python examples/tamper_demo/demo.py
{"valid_receipt_executed": true, "tampered_receipt_blocked": true,
 "argument_mismatch_blocked": true, "side_effect_count": 1,
 "audit_chain_valid_before_tamper": true, "audit_chain_valid_after_tamper": false,
 "invariant": "No valid Decision Receipt, no side effect.", "status": "pass"}
# exit=0
```

### A.5 Step 7 — offline verification of the pristine pack

```console
$ uv run --package gove-zone gove-zone verify-proofpack dist-govern-zone-proofpack
{"valid": true, "schema_version": "gove-zone/proof-pack/v1",
 "events_total": 3, "events_matched": 3,
 "signature_verified": null,            ← unsigned dev-mode pack; honest null, not "true"
 "audit_chain_verified": true, "argument_hash_verified": true,
 "authority_verified": true, "anti_replay_status": "not_present",
 "receipts": [allowed/denied/transformed — all matches_declared: true, anchored_in_audit_chain: true],
 "reasons": []}
# exit=0
```

### A.6 Destructive test — tampered receipt field in a copy of the pack

```console
$ # one string field mutated in receipts/allowed_receipt.json (no hash recomputation)
$ uv run --package gove-zone gove-zone verify-proofpack tampered-proofpack
{"valid": false, ...
 "receipts": [{"name": "allowed", "argument_hash_verified": false, "authority_verified": false,
               "reasons": ["RECEIPT_UNEXPECTED_REJECT", "RECEIPT_HASH_MISMATCH"]}, ...],
 "reasons": ["RECEIPT_UNEXPECTED_REJECT", "RECEIPT_HASH_MISMATCH"]}
# exit=1
```

### A.7 Destructive test — edited audit chain line in a copy of the pack

```console
$ # first line of audit.jsonl edited ("allow" → "deny")
$ uv run --package gove-zone gove-zone verify-proofpack tampered-audit-proofpack
{"valid": false, ... "reasons": [..., "AUDIT_CHAIN_BROKEN", ...]}
# exit=1
```

### A.8 Signed fixture pack without a trust anchor fails closed

```console
$ uv run --package gove-zone gove-zone verify-proofpack packages/gove-zone/tests/fixtures/proofpacks/valid-allow
valid: False  reasons: ['RECEIPT_UNEXPECTED_REJECT', 'SIGNED_RECEIPT_NO_VERIFIER']   # exit=1
$ uv run --package gove-zone gove-zone verify-proofpack packages/gove-zone/tests/fixtures/proofpacks/chain-break
valid: False  reasons: ['AUDIT_CHAIN_BROKEN', 'RECEIPT_UNEXPECTED_REJECT',
                        'SIGNED_RECEIPT_NO_VERIFIER', 'RECEIPT_NOT_ANCHORED']        # exit=1
$ uv run --package gove-zone gove-zone verify-proofpack packages/gove-zone/tests/fixtures/proofpacks/tampered-receipt
valid: False  reasons: ['RECEIPT_UNEXPECTED_REJECT', 'RECEIPT_HASH_MISMATCH']        # exit=1
```

(These fixtures are signed packs; verifying them *with* the trusted key is exercised by the package's test suite. We did not run the with-key CLI path here because the fixture keys are generated inside the tests.)

## Appendix B — Discrepancies observed while generating this evidence (disclosed, not fixed here)

1. **Version-string drift inside the pack.** The generated `limitations.md` says "Alpha (`0.1.0.dev0`)" while the CLI and `manifest.json` report `0.1.0a1`. Cosmetic, but an auditor would notice; it should be generated from `__version__`.
2. **`audit.jsonl.lock`** appears in the pack directory but is not listed in `manifest.json` (it is a runtime lock artifact, ignored by the verifier).
3. **Unsigned conformance pack.** The default `proofpack` output is dev-mode unsigned (`signature_verified: null`). The signed path is demonstrated by demo checks [8]/[9] and by the fixture corpus failing closed without a key — but the flagship generated artifact is not itself signed. If your assessment hinges on signed evidence, say so; that directly informs whether signed packs must become the default.
4. **Provenance of this transcript.** Commands were run on the maintainer's machine from a clean detached worktree of `origin/master` (commit `12a150b`), not on the feature branch under development at the time. Raw untrimmed outputs were retained by the generating session.
