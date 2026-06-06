# CI / deployment-action gate

Use gove-zone as a **CI/CD gate that fails the pipeline** (non-zero exit) when a
deployment action is denied or escalated, and lets it proceed (exit 0) when the
action is allowed. The decision is recorded as a **signed Decision Receipt** that
a CI log can keep as verifiable evidence of *why* a deploy was allowed or blocked.

## What it shows

A "deploy" payload — e.g.

```json
{"action":"deploy","environment":"prod","image":"checkout-svc@sha256:...",
 "proposer":"ci-bot","approver":"release-manager"}
```

is governed by the real gove-zone API under the **production profile** (signed
receipts required at the gate). Two **independent** guards run:

- **Environment gate (the WHAT)** — a `RuleSetPolicy` on the deploy action. It
  denies `deploy` to the protected `prod` environment and escalates `deploy` to
  the `restricted` environment (matched by path `env/<environment>`). Staging is
  allowed. A prod deploy yields a **signed DENY receipt**, a restricted deploy a
  **signed ESCALATE receipt**; the gate refuses execution either way and the demo
  exits non-zero. This guard does not look at who proposes or approves.
- **Approver separation / MACI (the WHO)** — independent of the environment gate.
  The receipt is issued with the *approver* as the distinct validating principal
  and the *proposer* as the actor (`proposer != validator`). A self-approving
  deploy (`approver == proposer`) **cannot mint a receipt at all** — issuance
  fails closed before any receipt exists.

The demo proves **both** outcomes:

- **ALLOW** — staging deploy with a distinct approver → side effect runs →
  exit 0, signed receipt + verified audit chain printed.
- **DENY** — prod deploy → policy denies → signed deny receipt printed, the
  deploy stub is asserted **not** to have run → exit non-zero.
- **DENY (self-approval)** — issuance refused, no receipt → exit non-zero.
- **Misconfig** — production profile with no verifier fails closed *loud*
  (`ProductionProfileError`), never a silent downgrade.

## How to run

From the package root (`packages/gove-zone`):

```bash
# Self-test: runs ALLOW + DENY cases and asserts the exit-code contract.
# Exits 0 iff the gate behaved correctly (allow -> 0, deny -> non-zero).
uv run --package gove-zone python examples/ci-deployment-gate/demo.py

# Single-payload mode (what a CI step calls): exit code is the gate's verdict.
uv run --package gove-zone python examples/ci-deployment-gate/demo.py \
  --payload '{"action":"deploy","environment":"prod","image":"svc@sha256:abc","proposer":"ci-bot","approver":"release-manager"}'
echo "exit=$?"   # -> non-zero: prod deploy denied, pipeline fails closed

# A staging deploy with a distinct approver is allowed (exit 0):
uv run --package gove-zone python examples/ci-deployment-gate/demo.py \
  --payload '{"action":"deploy","environment":"staging","image":"svc@sha256:abc","proposer":"ci-bot","approver":"release-manager"}'
echo "exit=$?"   # -> 0: staging deploy allowed

# The payload may also come from $DEPLOY_PAYLOAD (see the GitHub Actions step).
```

## What to look for

- The DENY case prints a **signed receipt** (`signature=ed25519`,
  `matched_rules=['PROD_DEPLOY_GATE']`) *and then* the gate refusal — proof the
  block is recorded, not just logged. The deploy stub never runs.
- `approval_chain` shows the distinct proposer/validator (the MACI separation).
- The ALLOW case verifies the tamper-evident audit chain and prints the event
  hash that anchors the decision.
- Exit code is the contract: **0 = pipeline proceeds, non-zero = pipeline fails
  closed**.

## GitHub Actions step (copy-pasteable)

Run the gate as a job step. A denied/escalated deploy makes the step exit
non-zero, which fails the job and blocks the deploy. The full step log — signed
receipt included — is your audit evidence.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install gove-zone
        # The gate needs ONLY gove-zone installed, WITH the crypto extra — the
        # production profile signs receipts (Ed25519), which lives in [crypto].
        # This example file ships in the repo you just checked out:
        run: pip install './packages/gove-zone[crypto]'

      - name: Governance gate (fail closed on denied deploy)
        env:
          # Build the deploy payload from trusted CI context, NOT from PR input.
          # 'proposer' / 'approver' must come from authenticated CI identity in
          # real use (e.g. the OIDC subject and an approval gate), not free text.
          DEPLOY_PAYLOAD: >-
            {"action":"deploy",
             "environment":"${{ inputs.environment }}",
             "image":"${{ steps.build.outputs.image }}",
             "proposer":"${{ github.actor }}",
             "approver":"${{ inputs.approver }}"}
        run: |
          # Pass the payload EXPLICITLY with --payload. If DEPLOY_PAYLOAD is unset
          # or malformed the gate fails closed (non-zero) instead of no-op'ing —
          # never run the bare `demo.py` here, which would self-test and exit 0.
          python examples/ci-deployment-gate/demo.py --payload "$DEPLOY_PAYLOAD"
          # ^ exits non-zero on DENY/ESCALATE/bad-payload -> this step (and the
          #   job) fail, blocking the deploy. The step log holds the signed receipt.

      - name: Deploy
        run: ./deploy.sh   # only reached if the gate above passed
```

> **Fail-closed entry point.** Always pass the payload explicitly
> (`--payload "$DEPLOY_PAYLOAD"`). A bare `python demo.py` runs the self-test and
> exits 0 — useful locally, wrong for a gate. With `--payload`, an unset/empty/
> malformed payload exits non-zero, so a CI misconfiguration fails the pipeline
> rather than silently letting an ungated deploy through.

> The example file lives in this repo; in your own pipeline, point the gate at
> your installed entry point and feed it your real deploy payload. The key
> contract is the exit code, not the file path.

## Honest scope

Status: foundational / Alpha (gove-zone `0.1.0.dev0`). This is **local proof** of
the receipt-gate invariant ("No valid Decision Receipt, no side effect") applied
to a deploy decision. It is **not** a production-, compliance-, or
regulator-ready CI security control.

This example models the integration **pattern** — it does not vendor a CI SDK and
touches no real registry or cluster (the deploy is a local stub; everything
writes to a tempdir). The Ed25519 keypair is generated in-process for a
self-contained run; a real gate injects a **trusted** signer at issuance and a
trusted public-key verifier at the gate from KMS / secret storage, and derives
`proposer` / `approver` from authenticated identity — never from the payload.
