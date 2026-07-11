# PR-1 — Structured Rejection Payload (executable plan)

> Audit finding **R3** (`docs/design/agent-native-architecture-audit.md`). First in the post-PR-4 sequence **PR-1 → PR-2 → PR-3 → PR-5**.
> Subproject: `packages/gove-zone` (Python ≥3.11, uv workspace). **Additive / output-enrichment only** — no allow/deny/escalate verdict logic touched (the audit tags R3 "None triggered (output enrichment only)").
> **Base: fresh worktree off `origin/master`** (HEAD `2640b4d`, includes PR-4). The `docs/campaign-launch-drafts` branch is 77 commits behind master and lacks PR-4 (`escalation.py` absent) — do **not** build here. Worktree already created at `/home/martin/Documents/ACGS-wt/pr1-structured-rejection` on branch `feat/gove-zone-structured-rejection`.

---

## 1. Goal & the one-sentence insight

Give a calling agent a **machine-readable, self-correctable** rejection when the gate returns DENY or ESCALATE — instead of *only* a raised exception — **without moving any decision logic out of code.**

**Insight from the master ground-truth:** the gate already raises typed errors carrying a full `DecisionRecord` (`DeniedError.record` / `EscalateError.record` + `.audit_hash`, and post-PR-4 `EscalateError.pending`). Everything an agent needs to self-correct is *already computed* — PR-1 only **projects** it into a stable envelope. This is the agent-facing twin of `frontend_contract.record_to_governed_action` (which projects the *same* record into the **human/console** shape). Two consumers, two shapes; PR-1 adds the missing **agent** shape.

**Post-PR-4 sharpening (do not ship the stale design):** `EscalateError` now carries `pending: PendingApproval`. So the ESCALATE envelope is **not a dead-end** — it advertises "resumable via human approval" (`approve_escalation` → `resume_with_receipt`). PR-1 thereby wires **R3 → R2**: a denied agent learns *why*; an escalated agent learns *how to get unblocked*.

---

## 2. Design

### 2a. Canonical envelope — new `gove_zone/rejection.py`

One source of truth, tested once. Pure projection, dependency-free (matches `frontend_contract.py` posture):

```python
# gove_zone/rejection.py  (NEW)
from gove_zone.decision import Decision, DecisionRecord

_OUTCOME = {Decision.DENY: "denied", Decision.ESCALATE: "escalated"}

def rejection_dict(
    record: DecisionRecord, audit_hash: str, *,
    resumable: bool, resolution: str, approval: dict | None = None,
) -> dict:
    payload = {
        "status": record.decision.value,            # "deny" | "escalate"
        "outcome": _OUTCOME[record.decision],        # reuse frontend_contract vocabulary
        "tool": record.tool,
        "actor": record.actor,
        "reason": record.reason,
        "matched_rules": list(record.matched_rules),
        "policy_version": record.policy_version,
        "decision_request_hash": record.decision_request_hash,
        "audit_hash": audit_hash,
        "resumable": resumable,                      # False=deny, True=escalate
        "resolution": resolution,                    # "revise_and_retry" | "human_approval"
        "allowed_alternatives": [],                  # provisional: [] == "not yet computed"; PR-2 `simulate` populates it
    }
    if approval is not None:
        payload["approval"] = approval               # {"via": "approve_escalation", "pending": bool}
    return payload
```

### 2b. Thin methods on the error classes (`gove_zone/errors.py`)

```python
# DeniedError
def to_rejection_dict(self) -> dict:
    return rejection_dict(self.record, self.audit_hash,
                          resumable=False, resolution="revise_and_retry")

# EscalateError  — surfaces the PR-4 resume affordance (R3 -> R2)
def to_rejection_dict(self) -> dict:
    return rejection_dict(
        self.record, self.audit_hash,
        resumable=True, resolution="human_approval",
        approval={"via": "approve_escalation", "pending": self.pending is not None},
    )
```

### 2c. Consumer & wiring — this is a library API, not a handler

`to_rejection_dict()` is **output enrichment on a library exception**, not a handler that traffic must route through. The audit tagged R3 *"None triggered (output enrichment only)"* — so the handler-wiring rule does **not** apply. The caller is whoever catches `DeniedError` / `EscalateError`:

- **External integrators are the primary callers** (acgs-lite/gove-zone is a published library). They catch the gate's typed errors and call `to_rejection_dict()` to drive self-correction. The method is **not** orphan code — its caller is the downstream integrator, outside this repo.
- **Internally, the only existing catchers are `api.py` and `smoke.py`.** `api.py.build_demo_actions()` is a demo-data generator served to the React **console** (a human UI — no agent reads `/api/v1/actions`), and its escalate branch is `except Exception` + `hasattr(exc, "record")` (l.140), not `except EscalateError`. `smoke.py` is a test. **Neither is a production agent gateway.** The real internal consumer is built by **PR-5** (kernel-backed production MCP binding), which is where `to_rejection_dict()` gets called on the production deny/escalate boundary.

So PR-1 deliberately **does not wire a consumer** and does **not** touch `api.py`. It ships the projection and proves it works off the **real** `kernel.dispatch` raise path (tests §5 #1–#3). A console *display* of rejections, if ever wanted, is a separate frontend PR with a different goal — not smuggled into PR-1. This keeps PR-1 entirely **green** and single-purpose.

---

## 3. Why every fail-closed invariant already holds (output enrichment only)

| Invariant | Status under PR-1 |
|---|---|
| No allow/deny/escalate verdict moves into a model | Untouched — `rejection_dict` only *reads* an already-decided `DecisionRecord` |
| No new information exposure | The only free-text field is the policy-authored `reason`. The envelope carries `argument_hash` (never raw args), and **no** `state_hash` / `transformed_args` / raw `state`. Test asserts **absence of sensitive values** (not merely key names); the README "keep `reason` non-sensitive" note is the actual control. Same fields `frontend_contract` already surfaces. |
| ESCALATE still not executable | Envelope is purely descriptive; execution still requires a valid ALLOW receipt through the gate (PR-4). The `approval` hint points at `approve_escalation`, which re-runs the full verify path. |
| Deny still denies | Method is read-only; the raising path in `kernel.dispatch` is unchanged. |

No `AGENTS.md` "forbidden change" is triggered: the gate logic, receipt verification, audit ordering, and `expected_actor` anchoring are all untouched.

---

## 4. File-by-file change set

| File | Change | Risk |
|---|---|---|
| `gove_zone/rejection.py` **(new)** | `rejection_dict()` projection | green — pure, dependency-free |
| `gove_zone/errors.py` | `to_rejection_dict()` on `DeniedError` + `EscalateError` | green |
| `gove_zone/__init__.py` | export `rejection_dict` (and re-confirm error exports) | green |
| `packages/gove-zone/tests/test_structured_rejection.py` **(new)** | dispatcher-level + envelope + value-leak + self-correction tests | — |
| `packages/gove-zone/README.md` | document the agent rejection envelope + "keep `reason` non-sensitive" note | docs |

**Entirely green — no `api.py` change.** No change to `receipt.py`, `executor.py`, `policy.py`, `audit.py`, `signing.py`, `api.py`, the `kernel.dispatch` decision path, or any constitutional-hash-marked file. Verify with `git diff --check` + hash-lock check.

---

## 5. Test plan (outcome-based, dispatcher-level — per `~/.claude/rules/review-handler-wiring.md`)

New `packages/gove-zone/tests/test_structured_rejection.py`:

1. **Deny envelope off the real raise path.** `kernel.dispatch` with a denying `BoundaryPolicy` → catch the **real** `DeniedError` → `to_rejection_dict()`; assert `status=="deny"`, `resumable is False`, `resolution=="revise_and_retry"`, `matched_rules` equals the policy's rule, `decision_request_hash`/`audit_hash` present.
2. **Escalate envelope advertises resume.** `EscalatePolicy` → catch the **real** `EscalateError` → assert `status=="escalate"`, `resumable is True`, `resolution=="human_approval"`, `approval == {"via":"approve_escalation","pending":True}`.
3. **Self-correction loop (success-criterion #3).** dispatch denied args → read `matched_rules` from the envelope → dispatch revised args → **ALLOW executes**. Proves the envelope is *actionable*, not decorative.
4. **No value leak (not just key names).** Dispatch with a sentinel-bearing arg (e.g. `{"secret": "SENTINEL-XYZ"}`); assert the serialized envelope contains **no** raw argument value, **no** `state_hash`, **no** `transformed_args` — the positive absence of sensitive *values*, not merely a key-subset check. The key-subset (`set(envelope) ⊆ set(record.to_dict()) ∪ {control keys}`) is kept as a secondary guard.
5. **Regression floor.** The full existing `packages/gove-zone/tests` suite stays green — the new module perturbs nothing (no shared-state import, no monkeypatch).

---

## 6. Verification & rollback

```bash
WT=/home/martin/Documents/ACGS-wt/pr1-structured-rejection
# Baseline BEFORE editing (Refactor Safety Gate — capture pass count)
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
# After implementation
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
uv run --package gove-zone mypy packages/gove-zone/src
git -C "$WT" diff --check          # no whitespace / hash drift
make lint-docs                     # README/doc invariants
```
All three gates (lint/type, tests, docs) at exit 0; constitutional hashes unchanged. Rollback = revert the additive change set; no existing gate code was modified → clean revert.

---

## 7. Known limitations (named, not hidden)

- **`allowed_alternatives` is empty in v1.** gove-zone has no capability-discovery surface yet. **PR-2 (`simulate`) is its source:** a denied agent calls `simulate` on candidate variants to populate the allowed set. PR-1 ships the *envelope*; PR-2 fills the *field*. Dependency noted, not blocking — PR-1 stands alone.
- **The envelope surfaces policy `reason` / `matched_rules`.** A policy author who places secrets in `reason` would leak them — but that is already true of the audit chain and the console projection; **not a PR-1 regression.** README note: keep `reason` non-sensitive.
- **No production consumer ships in PR-1.** There is no production agent gateway in the repo today — `api.py` is a demo/console adapter (human UI) and `smoke.py` is a test. PR-1 ships the library projection only; the production consumer that calls `to_rejection_dict()` on the deny/escalate boundary lands with **PR-5**. The method is exercised end-to-end against the real `kernel.dispatch` raise path in tests, and is callable today by any external integrator.

---

## 8. Out of scope / sequencing

- **PR-2** (`simulate` read-only primitive) — fills `allowed_alternatives`; `api.py.test_action` (l.156) is the existing demo-only seed to generalize.
- **PR-3** (enforce-by-default at the adapter) — `current_gate_mode()` still defaults `OBSERVE` on master (verified); PR-3 flips it. **PR-1 first is a real dependency, not just risk-laddering:** PR-3 produces *more* denials, and PR-1's structured rejections make those denials self-correctable.
- **PR-5** (kernel-backed production MCP binding) — consumes `to_rejection_dict()` at the production boundary; crosses `gove_zone ↔ acgs_governance_eval_mvp`, runs under the four-lane flow.

One PR per branch, sequential. PR-1 is single-subproject and additive; it does **not** need the four-lane orchestration.
