# Auditor Review Checklist — ACGS / gove-zone Proof Pack

> **Status: ALPHA (`gove-zone 0.1.0a1`). Not production-certified, not compliance-certified.**
> Companion: [BRIEF.md](BRIEF.md) (context, claims, feedback questions, full transcript).
> Every step below states the exact command, the expected outcome, and whether the maintainer executed it on 2026-07-03 at commit `12a150b` (`origin/master`). Steps marked *documented, not executed here* are covered by the package test suite but were not part of this transcript — treat them accordingly.

## Prerequisites

- Linux or macOS shell, Python ≥ 3.11, [uv](https://docs.astral.sh/uv/) installed.
- Repository clone at `master`: `git clone https://github.com/dislovelhl/ACGS && cd ACGS`
  (your contact will give you the canonical URL; all commands run from the repository root).
- No network access is needed after `uv` resolves the environment once. The offline-verification steps (5–8) need only the pack directory and the verifier.

Suggested working convention: `export TMP=$(mktemp -d)` and keep all generated evidence under `$TMP`.

Record for your workpapers before starting:

```bash
git rev-parse HEAD
uv run --package gove-zone gove-zone --version    # expected: gove-zone 0.1.0a1 (or later)
```

---

## Step 1 — Fail-closed denial (policy decides before execution)

**Command**

```bash
uv run --package gove-zone gove-zone smoke --audit "$TMP/smoke-audit.jsonl"
```

**Expected outcome** — exit 0; JSON report with:

- `"status": "pass"` and three checks all `"pass"`: `allow-before-side-effect`, `deny-before-side-effect`, `audit-chain-verifies`;
- a `deny` object with `"matchedRules": ["SMOKE_SECRET_BOUNDARY:keyword:id_rsa"]` — the denied write (path contains `id_rsa`) produced **no file**;
- a `claimBoundary` string that itself disclaims production/deployment proof.

**What it demonstrates**: denial happens pre-execution and leaves audit evidence; the denied side effect does not occur.
**Executed by maintainer 2026-07-03**: yes (exit 0).

☐ Pass ☐ Fail ☐ Notes: ______________________

---

## Step 2 — Receipt gating (allow / deny / missing / tampered / cross-tenant / transform / signed)

**Command**

```bash
uv run --extra crypto --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py
```

**Expected outcome** — exit 0; nine checks all ✓, specifically:

| # | Check | Expected |
|---|---|---|
| 1 | Valid ALLOW receipt | executes |
| 2 | DENY receipt | blocked — a receipt is not a bearer token; the verdict travels with it |
| 3 | Missing receipt | blocked (fail closed) |
| 4 | Tampered receipt field | blocked with explicit `receipt_hash mismatch` |
| 5 | Cross-tenant receipt | blocked (`Tenant mismatch`) |
| 6 | TRANSFORM receipt | original args refused; only the approved transformed args execute |
| 7 | Audit chain | verified, one tamper-evident event per decision |
| 8 | Ed25519-signed receipt | verified with public key, executes |
| 9 | Forged/recomputed receipt | rejected — invalid signature without the private key |

**What it demonstrates**: the receipt binds actor + action + arguments + tenant + verdict; every unsafe path fails closed.
**Executed by maintainer 2026-07-03**: yes (exit 0, all 9 ✓).

☐ Pass ☐ Fail ☐ Notes: ______________________

---

## Step 3 — Generate the proof pack

**Command**

```bash
cd "$TMP" && uv run --project <repo-root> --package gove-zone python -m gove_zone.cli proofpack
# or from the repo root: uv run --package gove-zone gove-zone proofpack
find "$TMP/dist-govern-zone-proofpack" -maxdepth 2 -type f | sort
```

**Expected outcome** — exit 0; `"status": "pass"` with all six `results` true (`allowed_action_executed`, `denied_action_blocked`, `missing_receipt_blocked`, `tampered_receipt_blocked`, `transformed_action_executed`, `audit_chain_verified`); directory contains `manifest.json`, `receipts/allowed_receipt.json`, `receipts/denied_receipt.json`, `receipts/transformed_receipt.json`, `audit.jsonl`, `verification.json`, `conformance-results.json`, `limitations.md`.

Known cosmetic issues (disclosed in BRIEF.md Appendix B): `limitations.md` carries a stale version string (`0.1.0.dev0`); a transient `audit.jsonl.lock` may appear and is not part of the manifest.

**Executed by maintainer 2026-07-03**: yes (exit 0, all results true).

☐ Pass ☐ Fail ☐ Notes: ______________________

---

## Step 4 — Inspect receipt binding fields

**Command**

```bash
python3 -m json.tool "$TMP/dist-govern-zone-proofpack/receipts/allowed_receipt.json"
python3 -m json.tool "$TMP/dist-govern-zone-proofpack/receipts/denied_receipt.json"
```

**Expected outcome** — each receipt carries at minimum:

- identity/binding: `actor`, `proposed_action`, `argument_hash`, `tenant_id`, `authority`, `validator_id`;
- policy binding: `policy_bundle_id`, `policy_hash`, `policy_version`, `matched_rules`;
- decision: `decision` (`allow` / `deny` / `transform`), `transformations` (for transform);
- time: `timestamp`, `expires_at` (empty = no expiry — note for your assessment);
- evidence chain: `audit_event_hash`, `previous_audit_hash`, `receipt_hash`;
- signing: `signature`, `signature_algorithm`, `signing_key_id` — in the dev-mode pack these read `unsigned_local` / `none` / empty. **This is the honest unsigned default, not a signed artifact.**

The denied receipt is a first-class artifact: the denial itself is evidence, with the same binding fields.

**What to assess**: are these bindings sufficient for the control you would map this to? (BRIEF.md §6, question 2.)
**Executed by maintainer 2026-07-03**: yes (fields listed above are verbatim from a generated receipt).

☐ Sufficient ☐ Insufficient — missing: ______________________

---

## Step 5 — Offline verification of the pristine pack

**Command**

```bash
uv run --package gove-zone gove-zone verify-proofpack "$TMP/dist-govern-zone-proofpack"
echo "exit=$?"
```

**Expected outcome** — exit 0; JSON verdict with `"valid": true`, `"schema_version": "gove-zone/proof-pack/v1"`, `"audit_chain_verified": true`, `"argument_hash_verified": true`, `"authority_verified": true`, empty `"reasons"`, every receipt `"matches_declared": true` and `"anchored_in_audit_chain": true`. For this unsigned dev pack, `"signature_verified": null` (reported honestly as *not checked*, never as *passed*). `"anti_replay_status": "not_present"` — no consumption ledger in the conformance pack.

**What it demonstrates**: a relying party can validate the evidence bundle without executing or trusting the runtime that produced it.
**Executed by maintainer 2026-07-03**: yes (exit 0, valid true).

☐ Pass ☐ Fail ☐ Notes: ______________________

---

## Step 6 — Destructive test: tamper with a receipt, expect detection

**Command**

```bash
cp -r "$TMP/dist-govern-zone-proofpack" "$TMP/tampered-pack"
# change any single character of any field value in the receipt JSON, e.g. the actor:
sed -i 's/"actor": "/"actor": "X/' "$TMP/tampered-pack/receipts/allowed_receipt.json"
uv run --package gove-zone gove-zone verify-proofpack "$TMP/tampered-pack"; echo "exit=$?"
```

**Expected outcome** — exit 1; `"valid": false`; the tampered receipt reports `"reasons"` including `RECEIPT_HASH_MISMATCH`; untouched receipts still verify individually. Any single-field edit must be caught — try several.

**Executed by maintainer 2026-07-03**: yes (string-field mutation → exit 1, `RECEIPT_UNEXPECTED_REJECT` + `RECEIPT_HASH_MISMATCH`).

☐ Detected ☐ NOT detected (report immediately) ☐ Notes: ______________________

---

## Step 7 — Destructive test: tamper with the audit chain, expect detection

**Command**

```bash
cp -r "$TMP/dist-govern-zone-proofpack" "$TMP/tampered-audit-pack"
# edit any byte of any line in audit.jsonl, e.g.:
sed -i '1s/allow/deny/' "$TMP/tampered-audit-pack/audit.jsonl"
uv run --package gove-zone gove-zone verify-proofpack "$TMP/tampered-audit-pack"; echo "exit=$?"
```

**Expected outcome** — exit 1; `"valid": false`; `"reasons"` includes `AUDIT_CHAIN_BROKEN` (hash chain recomputation fails at the edited event).

**Executed by maintainer 2026-07-03**: yes (exit 1, `AUDIT_CHAIN_BROKEN`).

☐ Detected ☐ NOT detected (report immediately) ☐ Notes: ______________________

---

## Step 8 — Signed-pack posture: no trust anchor → fail closed

**Command** (uses the committed signed fixture corpus)

```bash
uv run --package gove-zone gove-zone verify-proofpack \
  packages/gove-zone/tests/fixtures/proofpacks/valid-allow; echo "exit=$?"
```

**Expected outcome** — exit 1 with `SIGNED_RECEIPT_NO_VERIFIER`: a **signed** pack verified without an out-of-band public key fails closed rather than silently downgrading to hash-only verification. Trust anchors are never read from the pack itself.

To verify a signed pack positively you would supply the anchor out-of-band:

```bash
gove-zone verify-proofpack <pack> --verifier-key trusted.pub --key-id <signing_key_id> \
  [--revoked-keys revoked.json]   # revoked key → SIGNING_KEY_REVOKED; malformed list → exit 2 (fail closed)
```

**Executed by maintainer 2026-07-03**: the no-anchor fail-closed path, yes (exit 1). The with-key positive path and revocation path: *documented, not executed here* — they are exercised by the package test suite (`packages/gove-zone/tests/`, fixture corpus + `test_cli.py`), and the fixture signing keys live inside the test generator. You can reperform via `uv run --package gove-zone pytest packages/gove-zone/tests -k verifier` if desired (not run in this transcript).

☐ Fail-closed confirmed ☐ Notes: ______________________

---

## Step 9 — In-runtime tamper demo (end-to-end narrative)

**Command**

```bash
uv run --package gove-zone python examples/tamper_demo/demo.py
```

**Expected outcome** — exit 0; JSON with `valid_receipt_executed: true`, `tampered_receipt_blocked: true`, `argument_mismatch_blocked: true`, `side_effect_count: 1` (exactly one side effect across all attempts), `audit_chain_valid_before_tamper: true`, `audit_chain_valid_after_tamper: false`.

**What it demonstrates**: the whole proof path in one script — including that receipt *reuse with different arguments* is blocked. Note the limitation disclosed in BRIEF.md §3: reuse with *identical* arguments before expiry is not prevented (no anti-replay nonce by default).

**Executed by maintainer 2026-07-03**: yes (exit 0).

☐ Pass ☐ Fail ☐ Notes: ______________________

---

## Step 10 — Limitations acknowledgment (read, do not skip)

Read, inside the pack you generated: `limitations.md`. Read, in the repo: `docs/CLAIMS.md` (especially the "not claimed" rows), `docs/SECURITY_MODEL.md`.

Confirm the packet never claims: production certification, compliance certification, regulator approval, anti-replay by default, WORM storage, coverage of ungated executor paths, or signed verification by default.

☐ Limitations are clearly disclosed ☐ Found an overclaim (quote it): ______________________

---

## Verdict block (please fill in)

| Question | Your answer |
|---|---|
| Tamper detection works as claimed (Steps 6–7)? | |
| Fail-closed behavior works as claimed (Steps 1, 2, 8)? | |
| Receipt binding fields sufficient for a control mapping (Step 4)? | |
| Offline verification workflow usable in your practice (Step 5)? | |
| **Core question: is a Decision Receipt acceptable control evidence where a post-hoc log is not?** | |
| Hard blockers before reliance | |
| Compensating-control conversations | |

Reviewer: ______________  Firm/role: ______________  Date: ______________
