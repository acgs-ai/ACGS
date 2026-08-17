# REAL_AUTHORITY_EVIDENCE_ONBOARDING_V1 — Migration Plan

How production moves from today's empty registry to real authority coverage.
Every step is fail-closed; no step may be skipped or simulated.

## Current state (verified)

- registry: empty (0 bytes) — by design
- lifecycle distribution: all zeros
- `READY_TO_SEND 0` / `ROUTING_REQUIRED 340` (306 counsel + 34 controller)
- verdict: `AUTHORITY_LAYER_READY`

## Step 0 — preconditions (already met, re-check before any onboarding)

```bash
python3 verify_substrate_identity.py    # must exit 0 (IDENTITY_CONFIRMED)
python3 verify_authority_state.py       # must print AUTHORITY_LAYER_READY
python3 -m pytest attack_suite/ -q      # must pass
```

## Step 1 — DATA_CONTROLLER track (unblocks ≤ 34 requests)

1. **Acquire the real artifact.** A signed controller appointment for the AGEC
   asset family — the fact the substrate records as
   `PRIVACY_OWNERSHIP.json: data_controller = "UNASSIGNED"`. Human/legal task;
   nothing in this repo can produce it.
2. **Draft the evidence record** per `AUTHORITY_EVIDENCE_SCHEMA.json`
   (`authority_type: DATA_CONTROLLER`, `issuer_or_appointing_party` from the
   artifact, scope limited to what the appointment actually covers).
3. **Compute the binding:**
   `python3 onboard_authority_evidence.py --record R.json --document DEED --emit-binding`
4. **Human validation.** The legal validator reviews the artifact and writes
   the `validation` block (their identity, method, instant, the binding). The
   software never writes this block.
5. **Onboard:**
   `python3 onboard_authority_evidence.py --record R.json --document DEED --instant <now>Z`
   Expect `lifecycle_state = ACTIVE`.
6. **Verify:** `python3 verify_authority_state.py` — expect
   `AUTHORITY_PARTIALLY_ACTIVATED`, `ready_to_send` = number of controller
   requests actually inside the evidenced scope (≤ 34; **re-derived, never
   assumed to be 34**), counsel requests unchanged at 306.

## Step 2 — COUNSEL_OR_RIGHTS_AUTHORITY track (unblocks ≤ 306, scope-bounded)

Same flow, with the class contract enforced by the pipeline: `jurisdiction`,
`appointment_authority`, `verification_metadata` must come from a real
engagement/appointment artifact. Do **not** assume one counsel covers all 306 —
scope each record to the assets/requirements the engagement actually names;
multiple records may be needed. Each onboarding transitions only the requests
its evidenced scope covers.

## Step 3 — steady state

- **Supersession:** onboard the successor with `supersedes: <old id>`; the old
  record derives `SUPERSEDED` and stops routing — never edit or delete records.
- **Revocation/expiry:** set `revoked_at` (append a superseding record carrying
  it) or let `effective_until` pass; affected requests fall back to
  `ROUTING_REQUIRED` on the next derivation. Historical receipts remain valid
  history; current sendability is recomputed (baseline §15 separation).
- **Substrate re-baseline:** if the substrate legitimately changes (a new
  verified build), rebind explicitly with `build_substrate_identity.py` — a
  deliberate operation, never an automatic response to `SUBSTRATE_DRIFT`.

## Rollback

Everything this phase writes lives in the package (registry JSONL, keystore,
receipts in-memory per run). Rolling back = removing the appended registry
lines (append-only file; each line is one record). The substrate and the
baseline code are untouched by onboarding, so no code rollback is ever implied.

## Hard rules carried through migration

- No placeholder identities; `[FIXTURE]` markers exist only in `attack_suite/`.
- Production registry stays empty until a real validated artifact exists.
- Counts are re-derived at every step — the plan's "34"/"306" are today's
  derived values, not constants to force.
- `rights_assertion` stays null throughout: routing authority ≠ rights.
