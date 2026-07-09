# PR-4 — ESCALATE → Approve → Resume (executable plan)

> Keystone of the agent-native audit (`docs/design/agent-native-architecture-audit.md`, finding R2/R6).
> Subproject: `packages/gove-zone` (Python ≥3.11, uv workspace). **Dangerous edit zone** per `AGENTS.md` — touches receipts/executor/kernel/fail-closed.
> Local instructions: no package `CLAUDE.md`/`AGENTS.md`; conventions from `packages/gove-zone/README.md` + root `AGENTS.md`.

---

## 1. Goal & the one-sentence insight

Turn ESCALATE from a terminal exception into a **resumable, human-gated, fully-governed** path — *without adding any new gate logic.*

**Insight from reading the code:** the two halves already exist and already enforce every fail-closed property. PR-4 is a **bridge**, not new security code:

- **Minting half** — `DecisionReceipt.from_record(...)` (`receipt.py:247`) already mints a receipt and already **forbids `validator == proposer`** at issuance (`receipt.py:283-287`).
- **Execution half** — `execute_with_receipt` / `GovernedExecutor` (`executor.py`) already verify-and-run, passing `expected_actor`/`expected_args`/tenant/boundary/policy to `DecisionReceipt.verify` (`receipt.py:340`).

The only reason they were never connected: the kernel's ESCALATE produces a `DecisionRecord` whose `decision == ESCALATE`, and `verify()` check 4 (`receipt.py:491-495`) **rejects any ESCALATE/DENY receipt for execution**. So you cannot sign-and-replay the escalated record. The bridge must derive a fresh **ALLOW** record representing the *post-approval* decision, minted with the **human** as the distinct MACI `Validator`.

---

## 2. Design — three phases

### Phase 1 — Capture (kernel, ESCALATE)
Today `kernel.dispatch` raises `EscalateError(record, audit_hash)` (`kernel.py:138`). The `record` already carries everything a receipt needs **except the raw args** (it has `argument_hash`, `decision_request_hash`, `actor`, `tool`, `goal`, `matched_rules`, `policy_version`, `event_id`, `timestamp_iso` — confirmed `decision.py:51-92`). The kernel *has* the args at dispatch time (`call.args`) but never surfaces them.

**Change:** surface the args so an approver can later mint a receipt that binds them. Capture them in a small immutable artifact.

```python
# gove_zone/escalation.py  (NEW)
@dataclass(frozen=True)
class PendingApproval:
    """Everything needed to later mint an approval receipt for an escalated call.
    Deployment config (tenant/boundary/policy_hash/bundle_id) is NOT captured here —
    it is supplied by the approver, who holds the same config as the resuming executor."""
    record: DecisionRecord      # decision is ESCALATE
    audit_hash: str             # audit anchor of the escalation event
    args: dict[str, Any]        # the exact proposed args (bound on approval)
```

`EscalateError` gains one backward-compatible attribute (`pending: PendingApproval`); existing `.record`/`.audit_hash` stay. No decision logic changes.

### Phase 2 — Approve (human, offline) — the bridge
A new pure-ish function. It (a) derives an ALLOW record, (b) **re-stamps `argument_hash`** to bind the exact args, (c) appends the approval as its **own audit event** (the approval is itself a governed decision), (d) mints via the existing `from_record`.

```python
def approve_escalation(
    pending: PendingApproval,
    *,
    validator: Validator,          # the HUMAN approver — must differ from proposer
    authority: str,
    tenant_id: str,
    execution_boundary: str,
    policy_bundle_id: str,
    policy_hash: str,
    audit: ChainHashAuditStore,    # approval is appended to the chain
    request_id: str | None = None, # defaults to original decision_request_hash
    signer: ReceiptSigner | None = None,
    expires_at: str = "",          # RECOMMENDED: bound the approval window
    constraints: dict[str, Any] | None = None,
) -> DecisionReceipt:
    if pending.record.decision is not Decision.ESCALATE:
        raise ReceiptValidationError("approve_escalation only approves ESCALATE records (fail-closed)")

    approved = dataclasses.replace(
        pending.record,
        decision=Decision.ALLOW,
        argument_hash=sha256_json(dict(pending.args)),  # binds verify check 10b
        matched_rules=(*pending.record.matched_rules, f"HUMAN_APPROVED:{validator.validator_id}"),
        reason=((pending.record.reason + "; ") if pending.record.reason else "")
               + f"approved by {validator.validator_id}",
        event_id=pending.record.event_id + ":approved",   # distinct audit identity
        # decision_request_hash UNCHANGED -> binds approval to the same original request
    )
    previous = _chain_head(audit)                  # head before append
    approval_audit_hash = str(audit.append(approved)["event_hash"])
    return DecisionReceipt.from_record(
        approved, audit_hash=approval_audit_hash, previous_audit_hash=previous,
        tenant_id=tenant_id, execution_boundary=execution_boundary,
        policy_bundle_id=policy_bundle_id, policy_hash=policy_hash,
        request_id=request_id or pending.record.decision_request_hash,
        validator=validator, authority=authority, signer=signer,
        expires_at=expires_at, constraints=constraints,
    )  # from_record re-enforces validator != proposer (receipt.py:283)
```

### Phase 3 — Resume (execute through the **existing** gate)
No new execution path. Thin convenience wrapper over the existing executor:

```python
def resume_with_receipt(executor: GovernedExecutor, pending: PendingApproval,
                        receipt: DecisionReceipt, **gate_kwargs) -> Any:
    return executor.execute(
        action=pending.record.tool, args=pending.args, receipt=receipt,
        expected_actor=pending.record.actor, **gate_kwargs,   # require_signature, verifier, policy hashes
    )
```
This routes to `execute_with_receipt` → `receipt.verify(...)` → `tool_fn(**args)`. **The same code that gates every other execution gates the resume.**

---

## 3. Why every fail-closed invariant already holds

| Invariant | Enforced by (existing) | PR-4 obligation |
|---|---|---|
| Resume ≠ re-run | Execution only via `execute_with_receipt` + valid **ALLOW** receipt | Wrapper must not call `tool_fn`/`dispatch` directly |
| Human ≠ agent | `from_record` (`receipt.py:283`) **and** `verify` check 2b (`receipt.py:443-452`) | Pass the human as `Validator`; pass proposer as `expected_actor` |
| Exact args bound | `verify` check 10b (`receipt.py:567-584`) | **Re-stamp** `argument_hash = sha256_json(args)` on the derived record |
| Escalated/denied receipt can never execute | `verify` check 4 (`receipt.py:491-495`) | Derive ALLOW; never sign the raw ESCALATE record |
| Approval is itself in the audit chain | `ChainHashAuditStore.append` | Append the derived ALLOW record before minting |
| Same-request binding | `decision_request_hash` carried unchanged | Do not mutate it in `dataclasses.replace` |
| Optional crypto closure / expiry | `from_record(signer=)`, `verify` 2a + check 13 | Forward `signer`/`expires_at`; recommend short expiry |

**No allow/deny/escalate verdict moves into a model** (the AGENTS.md red line): the *post-approval* decision is made by a human and recorded deterministically; the gate logic is untouched. This is additive to fail-closed.

---

## 4. File-by-file change set

| File | Change | Risk |
|---|---|---|
| `gove_zone/escalation.py` **(new)** | `PendingApproval`, `approve_escalation`, `resume_with_receipt`, `_chain_head` helper | new surface, no edits to gate |
| `gove_zone/errors.py` | `EscalateError` gains optional `pending: PendingApproval` attr (back-compat: keep `record`/`audit_hash`) | low |
| `gove_zone/kernel.py` | At `dispatch` ESCALATE branch (l.138): build `PendingApproval(record, audit_hash, dict(call.args))`, attach to `EscalateError` | low — no decision-path change |
| `gove_zone/__init__.py` | Export `PendingApproval`, `approve_escalation`, `resume_with_receipt` | trivial |
| `packages/gove-zone/README.md` | Document the escalate→approve→resume flow (public behavior change) | docs |

No change to `receipt.py`, `executor.py`, `policy.py`, `audit.py`, `signing.py`, `contracts.py`. **No constitutional-hash-marked file is touched** (verify with `git diff --check` + hash lock check).

---

## 5. Test plan (outcome-based, dispatcher-level)

New `packages/gove-zone/tests/test_escalation_resume.py`, plus assertions co-located with existing suites:

1. **Happy path, executes exactly once.** Policy → ESCALATE; `approve_escalation` with human `Validator`; `resume_with_receipt` → tool runs once, returns result. Assert a spy tool-fn call count == 1.
2. **Resume without approval is impossible.** Attempt `execute_with_receipt` with the *original* escalated record minted naively → rejected by verify check 4. (Belongs near `test_executor_guard.py`.)
3. **Self-approval forbidden (MACI).** `validator.validator_id == proposer` → `from_record` raises at issuance; and a hand-built receipt with `validator_id == expected_actor` → `verify` 2b rejects at the gate. (Extend `test_maci_role_separation.py`.)
4. **Arg tampering after approval rejected.** Approve args `{path:/tmp/safe}`, resume with `{path:/etc/shadow}` → verify check 10b rejects. (Extend `test_argument_binding.py`.)
5. **Approval is audited.** After `approve_escalation`, the chain has a new ALLOW event linked to the escalation's `audit_hash`; chain still verifies. (Near `test_audit_chain.py`.)
6. **Wrong tenant/boundary/policy on resume rejected.** Approver config ≠ executor config → verify checks 5/6/11/12 reject. (Near `test_tenant_safety.py`.)
7. **Signed approval round-trips; `require_signature=True` rejects unsigned approval.** (Extend `test_receipt_signing.py`.)
8. **Expired approval rejected.** `expires_at` in the past → verify check 13 rejects. (Near `test_receipt_expiry.py`.)
9. **Non-ESCALATE input refused.** `approve_escalation` on an ALLOW/DENY pending → fail-closed.

---

## 6. Verification & rollback

```bash
# Baseline first (capture pass count BEFORE editing — Refactor Safety Gate)
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
# After implementation
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
uv run --package gove-zone mypy packages/gove-zone/src   # typed surface
git diff --check                                          # no whitespace/hash drift
make lint-docs                                            # README/doc invariants
```
All three gates (lint/type, tests, docs) must pass at exit 0. Constitutional hashes unchanged. Rollback = revert the (small, additive) change set; nothing in existing gate code was modified, so revert is clean.

---

## 7. Known limitations (named, not hidden)

- **Single-use is not enforced.** A valid ALLOW approval receipt can be presented to `execute_with_receipt` more than once (verify is stateless → executes N times). For true "approve once, run once," a nonce / consumption ledger (e.g. via `ReplaySideStore` or an audit-chain consumed-set) is needed. **v1 mitigation:** issue approvals with a short `expires_at`; **follow-up PR-4b:** one-shot consumption tracking.
- **Approver/executor share deployment config** (tenant/boundary/policy_hash/bundle_id). If they diverge, resume fails closed (correct, but an integration foot-gun) — document the contract in README.
- **No arg mutation on approval in v1.** Approving with modified args is a TRANSFORM-shaped approval; deferred to keep the argument-binding story (check 10b) simple. v1 approves the proposed args verbatim.
- **`policy_hash`/`policy_bundle_id` at escalation time** are supplied by the approver, not computed by the kernel (the kernel surface doesn't own that vocabulary). Same posture as `GovernedExecutor` today.

---

## 8. Out of scope (separate PRs)

PR-1 (structured rejection), PR-2 (`simulate`), PR-3 (enforce-by-default at the adapter), PR-5 (kernel-backed production MCP binding). PR-4 depends on none of them and unblocks the HITL story independently. PR-5, which crosses the `gove_zone ↔ acgs_governance_eval_mvp` boundary, should run under the `subproject-orchestrate` four-lane flow; PR-4 is single-subproject and does not.
