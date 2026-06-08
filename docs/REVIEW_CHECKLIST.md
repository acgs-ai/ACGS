# Human and agent review checklist

> **Core invariant: No valid Decision Receipt, no side effect.**


Use this to evaluate the repo cold.

## Can I run it?

- [ ] `tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"`
- [ ] `uv run --package gove-zone python packages/gove-zone/examples/receipt-gated-execution/demo.py`
- [ ] `uv run python -m pytest tests/docs --import-mode=importlib -q`

## Can I see a denial?

- [ ] Smoke output shows a denied `id_rsa` path write.
- [ ] Demo output shows denied receipt blocked.
- [ ] Example outputs include failure cases.

## Can I inspect a receipt?

- [ ] `gove-zone proofpack` generates receipt JSON files.
- [ ] Receipt fields include actor, action, args hash, policy, validator, authority, audit hash, and receipt hash.

## Can I tamper with it?

- [ ] `examples/tamper_demo/demo.py` tampers a receipt and audit evidence.

## Does tampering fail?

- [ ] Tampered receipt fails before the side effect.
- [ ] Argument mismatch fails before the side effect.
- [ ] Audit chain verification fails after evidence tampering.

## Can I replay audit evidence?

- [ ] `test_replay.py` covers replay and side-store re-derivation.
- [ ] Docs distinguish audit-only replay from raw-argument side-store replay.

## Are claims backed by code/tests?

- [ ] Each major claim appears in `docs/CLAIMS.md`.
- [ ] Each claim lists source and tests/demos.
- [ ] Non-claims are explicit.

## Are alpha limitations clear?

- [ ] README says alpha/local proof, not production/compliance certified.
- [ ] `docs/SECURITY_MODEL.md` includes remaining limitations.
- [ ] `docs/ROADMAP.md` separates planned work from implemented work.

## Is integration obvious?

- [ ] `docs/INTEGRATION_GUIDE.md` shows where to put the gate.
- [ ] `examples/**` show Python, MCP, agent-framework, CI deploy, and tamper patterns.
- [ ] Docs state that the executor, not the model, enforces the gate.

## Are unsafe assumptions avoided?

- [ ] No claim of production readiness without release/deployment evidence.
- [ ] No claim of compliance certification or regulator approval.
- [ ] No claim that ACGS replaces sandboxing, IAM, guardrails, or MCP.
- [ ] No claim that unsigned dev mode is production signing.
