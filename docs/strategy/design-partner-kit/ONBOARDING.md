# gove-zone — Design Partner Onboarding

**Goal: time-to-first-governed-call under 1 hour.** This is the design-partner path from zero to a fail-closed governed pipeline, with a metric wired at the end.

**Status: Alpha (`0.1.0a1`). Not production-certified, not compliance-certified.** Every command below was run on this repo (Python 3.13.11, re-verified 2026-07-03 at `0.1.0a1`) and produced the stated output. Verified exit codes: `smoke`, `doctor`, `governed_vulnclaw_demo.py`, `undeniable-demo/demo.py`, `replay` → **0**; `gate --policy-bundle` on a matching deny → **1** (non-zero *by design* — that is how a hook host blocks; requires the dev-profile acknowledgment, see Step 4). `proofpack` → `"status":"pass"`.

> **Behavior change at `0.1.0a1` (fail-closed by default):** the gate now defaults to **enforce** mode, and under enforcement the unsigned CLI auditor refuses to run at all (exit 2 with an explanatory error) unless you explicitly acknowledge unsigned receipts with `GOVE_ZONE_PROFILE=dev` or opt into observe mode with `GOVE_ZONE_GATE_MODE=observe`. Nothing silently observes and nothing unsigned silently enforces. Steps 2 and 4 below show the explicit opt-ins. The one exception, called out inline, is `enable --enforce/--observe`, which mutates shared project state and was **not** run here (documented from `--help` + README). Commands that change local state (gate mode, audit files) are flagged.

---

## 0. Prerequisites (5 min)

- **Python 3.11+** (kernel floor is `>=3.11`; verified here on 3.13).
- **git** to clone the repo, and one of:
  - **[uv](https://docs.astral.sh/uv/)** (recommended — every command in this kit uses `uv run`), or
  - **pip** with a virtualenv.
- No production credentials, no network egress, no external service is required for any step below. The decision runs in-process.

## 1. Install (10 min)

Clone and sync from the monorepo root:

```bash
git clone https://github.com/dislovelhl/ACGS.git
cd ACGS
uv sync
```

Verify the install (verified output shown):

```bash
uv run --package gove-zone gove-zone --version
# → gove-zone 0.1.0a1

uv run --package gove-zone gove-zone doctor
# → JSON with "ok": true; checks gove_zone_importable, integration_adapter_present,
#   audit_path_writable all true; reports gate_mode, python_version, uv_installed.
```

**pip alternative** (no uv): `python -m venv .venv && . .venv/bin/activate && pip install -e packages/gove-zone`. For the signed-receipt demo add the crypto extra: `pip install -e "packages/gove-zone[crypto]"`. (These are the documented install shapes; the `uv` path above is the one this kit verifies command-by-command.)

## 2. First governed call (10 min)

The fastest honest first call routes a tool-call payload through the gate adapter and gets a Decision Receipt back:

```bash
printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/home/you/notes.txt","content":"hi"}}' \
  | GOVE_ZONE_GATE_MODE=observe uv run --package gove-zone gove-zone gate
```

Verified: returns a JSON envelope with `"decision": "allow"`, `"blocked": false`, `"gate_mode": "observe"`, and a full `receipt` object (`event_id`, `argument_hash`, `audit_hash`, `decision_request_hash`, `matched_rules`, `path`). **That receipt is your first governed call** — a bound, hash-chained record emitted before the side effect.

The `GOVE_ZONE_GATE_MODE=observe` opt-in is required: since `0.1.0a1` the gate **defaults to enforce** (fail-closed), and without it the bare command refuses with exit 2 (unsigned receipts may not silently enforce — verified). Observe mode is fail-open (records, does not block) and is intentional for the first call only. The next step runs the gate fail-closed.

## 3. Fail-closed proof (10 min)

You need to see a real DENY that blocks a side effect. The one-command proof does exactly this — allow, deny, and audit chain in a single verified run:

```bash
uv run --package gove-zone gove-zone smoke
```

Verified output (`"status": "pass"`): a safe `write_file` was **allowed** and executed; an `id_rsa` path write was **denied before any side effect** (`matchedRules: ["SMOKE_SECRET_BOUNDARY:keyword:id_rsa"]`); and the two decisions verify as a hash-linked chain (`"audit": {"valid": true, "checked": 2}`). It exits non-zero if any check fails — there is no fake green.

For the **signed, tamper-evident** version (production profile, needs the `crypto` extra), run the flagship:

```bash
uv run --package gove-zone python packages/gove-zone/examples/undeniable-demo/demo.py
```

Verified: ends with `=== ALL 5 STEPS PROVEN ===` — signed Ed25519 denial receipt, portable evidence bundle, offline replay `valid=True`, and two tamper attacks both rejected (`event_hash_mismatch` on chain mutation, `invalid signature` on receipt forgery).

## 4. Block a real side effect (10 min)

Fail-closed blocking comes from a **policy bundle that denies** — and this holds regardless of the project gate mode. Verified at `0.1.0a1`: piping a matching tool call into `gate --policy-bundle` returned `"decision":"deny"`, `"blocked":true`, and **exit code 1**. One prerequisite under the new enforce-by-default behavior: the unsigned CLI auditor must be explicitly acknowledged with `GOVE_ZONE_PROFILE=dev`, otherwise the gate refuses outright (exit 2) before evaluating any policy — that refusal is itself fail-closed behavior, not a bug. The production alternative is a configured signer (`crypto` extra).

Author a minimal deny bundle (`RuleSetPolicy`: deny / escalate rules over tool + canonical path + org state + actor trust tier), then gate against it:

```bash
cat > deny.bundle.json <<'JSON'
{"id":"my-guard/v1","rules":[{"id":"DENY_SECRETS_WRITE","effect":"deny",
  "tools":["runtime.Write"],"path_prefix":"home/you/secrets",
  "reason":"writes under secrets are denied"}]}
JSON

printf '%s' '{"tool_name":"Write","tool_input":{"file_path":"/home/you/secrets/id_rsa","content":"x"}}' \
  | GOVE_ZONE_PROFILE=dev uv run --package gove-zone gove-zone gate --policy-bundle deny.bundle.json
echo "exit: $?"   # verified: 1 — non-zero, so your hook host blocks the side effect
```

Wire the gate into your real pipeline at the tool-dispatch boundary. Two shapes:

- **As a hook / subprocess (verified CLI):** pipe each proposed tool call (normalized hook payload, incl. OpenAI Responses `output[]`, OpenAI Chat `tool_calls`, LangChain `tool_calls`) into `gove-zone gate --policy-bundle your-policy.bundle.json`. It **exits non-zero on any deny/escalate**, so your host blocks before the side effect runs. Start from the VulnClaw bundle (`packages/gove-zone/examples/governed_vulnclaw_demo.py`, lines ~41–79) and swap in your tool names.
- **In-process:** call `execute_with_receipt(...)` around your real tool function (same demo shows the exact call shape governing eight pentest tools; `packages/gove-zone/README.md` documents the API surface).

### Optional: set the project default gate mode

`enable` writes `.gove-zone/gate.mode`, the **default** for the no-bundle observer path (observe = fail-open record-only; enforce = fail-closed). It does **not** change the policy-bundle behavior above, which already blocks on deny:

```bash
uv run --package gove-zone gove-zone enable --enforce    # default fail-closed for this project
uv run --package gove-zone gove-zone enable --observe    # revert to observe-only
```

> State change + not run here: these flip `.gove-zone/gate.mode` for the whole project. This kit did not execute them (they mutate shared project state); the flags are from `gove-zone enable --help` and the package README. In a shared checkout, confirm you own that state before flipping it.

## 5. Instrument the OMTM — fail-closed external pipelines (5 min)

Our One Metric That Matters is **the number of external teams running the receipt gate fail-closed in a real pipeline** (not stars, not downloads). "Fail-closed" here means: a policy bundle is loaded and denies/escalates actually block (non-zero exit / `blocked:true`) in a pipeline processing real traffic. Instrument it in yours:

1. **Confirm the gate is blocking, not just observing:** run one known-deny payload through `gate --policy-bundle your-policy.bundle.json` and confirm exit is non-zero and `"blocked": true` (Step 4). A pipeline whose gate never blocks a known-deny is not fail-closed. Optionally check `doctor`'s `"gate_mode"` if you also set a project default with `enable`.
2. **Confirm real denials are firing:** grep your audit chain for deny/escalate decisions. Note the on-disk `audit.jsonl` is **compact** JSON — `"decision":"deny"` with **no space** after the colon (the CLI stdout envelope has a space; the file does not). Verified against a live chain (running the Step 4 deny appended one `"decision":"deny"` line):
   ```bash
   grep -c '"decision":"deny"' .gove-zone/audit.jsonl
   grep -c '"decision":"escalate"' .gove-zone/audit.jsonl
   ```
   A non-zero enforced-deny count in a pipeline that actually processes traffic is the OMTM signal: your pipeline is fail-closed and the gate is doing work. (`grep -c` exits 1 when the count is 0 — that itself tells you no denials have fired yet.)
3. **Confirm the chain still verifies** (evidence integrity):
   ```bash
   uv run --package gove-zone gove-zone replay --event <event_id> --audit .gove-zone/audit.jsonl
   ```
   `replay` takes an `--event` id (from any receipt's `event_id`) plus `--audit` pointing at the chain your pipeline produced; it re-verifies that governed action against the hash chain.
4. **Package proof for review:** `uv run --package gove-zone gove-zone proofpack` emits a conformance proof-pack folder (allowed/denied/missing-receipt/tampered/chain-verified all `true`) you can hand to your risk/compliance function.

Report back to us: (a) which pipeline, (b) `gate_mode: enforce` confirmed, (c) enforced deny/escalate count over the pilot window. That tuple is one unit of the OMTM.

---

## Time budget

| Step | Target |
|---|---|
| 0. Prerequisites | 5 min |
| 1. Install + doctor | 10 min |
| 2. First governed call (receipt) | 10 min |
| 3. Fail-closed proof (smoke / signed) | 10 min |
| 4. Enforce mode + wire one pipeline | 10 min |
| 5. Instrument OMTM | 5 min |
| **Total** | **~50 min** |

## Honest boundaries

- Alpha, `0.1.0a1`. Not production/compliance certified. The proof-pack and receipts are evidence artifacts, not a certification stamp.
- Two distinct enforcement paths exist; do not conflate them. (1) The **policy-bundle path** (`gate --policy-bundle`) blocks on deny with exit 1 regardless of project gate mode — verified in Step 4. (2) The **no-bundle observer path** uses the project gate mode: observe = fail-open record-only, `enable --enforce` = fail-closed. A pipeline counts toward the OMTM only if its actual execution path is fail-closed — either it consumes `blocked:true`/exit 1 from a deny-bearing policy bundle, or it runs with `gate_mode: enforce`. Do not claim fail-closed for a no-bundle pipeline still in observe mode.
- The demos govern mock tools with (except the signed `undeniable-demo`) unsigned receipts. Real key custody is out of scope for the demo; production signing needs the `crypto` extra and real key management.
- See `packages/gove-zone/SECURITY.md` for the enforced-vs-out-of-scope boundary and `docs/CLAIMS.md` for the claim discipline every statement here follows.
