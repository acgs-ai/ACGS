# gove-zone — 15-Minute Live Demo Runbook

Audience: a security-engineering team evaluating a design-partner pilot. Goal: show the invariant **"No valid Decision Receipt, no side effect"** end-to-end — **allow, deny, receipt, tamper** — against the real gove-zone API, on a governed pentest agent (VulnClaw).

**Every command below was run on this repo at `0.1.0.dev0` (Python 3.13).** Verified exit codes: `smoke`, `doctor`, `governed_vulnclaw_demo.py`, `undeniable-demo/demo.py` → **0**; `proofpack` → `"status":"pass"`. Keep the honest-scope note visible: alpha, not production/compliance certified; the VulnClaw tool is a mock (proves gate behavior, does not attack real hosts); dev demos are unsigned, the signed profile is Step 4.

---

## 0. Before the call (2 min, do this offline first)

Pre-warm the environment so nothing installs live on screen:

```bash
cd /path/to/ACGS
uv sync
uv run --package gove-zone gove-zone --version   # expect: gove-zone 0.1.0.dev0
uv run --package gove-zone gove-zone doctor       # expect JSON with "ok": true
```

If `doctor` prints `"ok": true`, you are ready. Have two terminals open: one for commands, one showing the demo source (`packages/gove-zone/examples/governed_vulnclaw_demo.py`) so you can point at the policy while it runs.

---

## Minute 0–2 — Frame the problem

Say: *"This is VulnClaw — an autonomous pentest agent that can port-scan, exploit, run arbitrary Python on the runner, and write reports. Ungoverned, nothing stops it scanning the wrong subnet or executing `os.system` on your host. Watch what happens when every one of those tool calls has to pass a gate first."*

Point at the policy bundle in the source (lines ~41–79): four rules — deny unauthorized targets, restrict exploitation to admins, block local Python for non-admins, lock report directories.

## Minute 2–8 — The governed pentest run (ALLOW + DENY)

```bash
uv run --package gove-zone python \
    packages/gove-zone/examples/governed_vulnclaw_demo.py
```

Walk the 8 scenarios as they print. The four beats to call out:

| Scenario | What to say |
|---|---|
| **1. Recon scan, authorized target → ALLOW** | *"`[REAL SCAN]` printed — the tool actually ran, because policy allowed it. The gate is not just blocking everything."* |
| **2. Recon scan, unauthorized target → DENY** | *"`Blocked as expected by execution gate: Denied receipt cannot authorize execution`. No `[REAL SCAN]` line — the side effect provably never ran."* |
| **3. Exploit by standard agent → DENY / 4. Exploit by admin → ALLOW** | *"Same tool, same payload. The only thing that changed is the actor. Authorization is bound to who is asking, not just what."* |
| **5. `python_execute` by non-admin → DENY** | *"Arbitrary local code execution on the runner — blocked before a single byte ran. This is the RCE-on-your-pentest-box scenario."* |

Close: *"Eight decisions, and the last line — `Audit chain successfully verified with 8 tamper-evident events` — means all eight are hash-linked and tamper-evident."*

## Minute 8–13 — Receipt + tamper (the undeniable path)

This is the money shot. Switch to the production **signed** profile:

```bash
uv run --package gove-zone python \
    packages/gove-zone/examples/undeniable-demo/demo.py
```

Point at these printed lines as they appear (ends with `=== ALL 5 STEPS PROVEN ===`):

- **RECEIPT** — *"The denial produced a signed Decision Receipt: `signature_algorithm = ed25519`, a `receipt_hash`, a `signing_key_id`. This is the artifact you hand your auditor instead of a log grep."*
- **EVIDENCE BUNDLE** — *"A portable folder: the receipts, a copy of the append-only audit chain, a manifest. It leaves with the auditor."*
- **OFFLINE REPLAY** — *"`valid=True` re-verified with a fresh verifier over the copied chain — no access to our systems needed."*
- **TAMPER FAILS (the point)** — *"Two attacks. (a) Mutate one audit event → `event_hash_mismatch`, chain rejects it. (b) Forge the DENY into an ALLOW and recompute its hash → `invalid signature`, because the attacker has no private key. You cannot rewrite history and you cannot forge an authorization."*

## Minute 13–15 — The ask

*"That is the whole invariant: allow, deny, a signed receipt, and tampering that fails two ways. It runs in your process, zero runtime deps, Apache-2.0. The pilot is: wire ONE of your real pipelines through this gate, fail-closed, and target first governed call under an hour. We'll help author the policy and package the proof pack. Everything you saw is yours to keep."*

Hand over `ONBOARDING.md`.

---

## Fallback if something breaks

Degrade gracefully — you always have a runnable proof at a lower cost:

1. **`uv sync` fails / slow network:** you pre-warmed in Step 0; if not, fall back to `pip install -e packages/gove-zone` (the `crypto` extra is only needed for the signed `undeniable-demo`; the VulnClaw demo and `smoke` run without it).
2. **The VulnClaw demo errors or a scenario asserts:** drop to the 30-second proof — `uv run --package gove-zone gove-zone smoke` — which prints the allow/deny/audit-chain JSON verdict in one shot and exits non-zero on any failure. It proves the same invariant with no moving parts.
3. **The signed `undeniable-demo` fails (missing `crypto` extra):** run `uv run --package gove-zone gove-zone proofpack` instead — it emits a conformance result object (`allowed_action_executed`, `denied_action_blocked`, `missing_receipt_blocked`, `tampered_receipt_blocked`, `audit_chain_verified`, all `true`) and writes a proof-pack folder.
4. **Total environment failure (no Python, screen-share dies):** show the recorded terminal output captured during Step 0 and walk the policy source by eye. The claim-safe posture means you never have to overstate — say "here is the output from my last run" and point at exit codes.
5. **They ask "is this certified?":** answer honestly — *"No. Alpha, `0.1.0.dev0`, not certified. This is the evidence mechanism; the pilot is how we find out if your auditor accepts receipts. That's the experiment we're proposing to run together."*

## Command reference (all verified, exit 0)

```bash
uv run --package gove-zone gove-zone --version                                  # 0.1.0.dev0
uv run --package gove-zone gove-zone doctor                                      # {"ok": true, ...}
uv run --package gove-zone gove-zone smoke                                       # allow/deny/audit JSON, "status":"pass"
uv run --package gove-zone python packages/gove-zone/examples/governed_vulnclaw_demo.py   # 8 scenarios + chain verify
uv run --package gove-zone python packages/gove-zone/examples/undeniable-demo/demo.py     # signed receipt + tamper, ALL 5 STEPS PROVEN
uv run --package gove-zone gove-zone proofpack                                   # conformance proof pack, "status":"pass"
```
