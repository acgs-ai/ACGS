# Game-Day Runbook — Governed Incident-Evidence Drill

A **game-day** (tabletop) exercise that rehearses how gove-zone contains a
misbehaving governed agent and, in the same pass, produces a durable, auditor-ready
incident-evidence bundle. The exercise is executable: the **drill** script drives
the real kernel, `GovernedExecutor`, and hash-chained audit store — not mocks —
through a fail-closed `DENY` and a fail-closed `ESCALATE`, then persists a
sha256-manifested evidence bundle.

- **Drill:** [`examples/gameday_incident_evidence.py`](../examples/gameday_incident_evidence.py)
- **Test:** [`tests/test_gameday_incident_evidence.py`](../tests/test_gameday_incident_evidence.py)
- **Playbook it maps to:**
  [`ai-governance-research/solution-catalog/incident-response.md`](../../ai-governance-research/solution-catalog/incident-response.md)

> Scope: this rehearses the **mechanism** (fail-closed gate + evidence capture)
> against a synthetic pentest agent. Production / organic attestation of a real
> incident stays **human-gated** and is out of scope for the drill.

## Why run it

Incidents are the worst time to discover that your evidence trail has holes. This
game-day proves, on demand, that:

1. A denied action (`DENY`) **cannot** execute — the DENY `DecisionReceipt` is
   rejected at the execution gate and no side effect fires.
2. An action that needs human authority (`ESCALATE`) **dead-ends** — the ESCALATE
   receipt can never authorize execution; the only way forward is a *named human*
   approval that routes back through the same gate (MACI: approver ≠ proposer).
3. Every decision lands in a **tamper-evident** hash chain, and the whole incident
   is captured as a **durable, hash-manifested** bundle that an auditor can
   re-verify offline.

## Roles

| Role | Responsibility in the drill |
|---|---|
| **Incident commander** | Runs the drill, owns the bundle, decides reactivation. |
| **Governed agent (proposer)** | The synthetic pentest agent (`recon-agent-1`) whose calls are gated. |
| **Human approver (validator)** | `human-on-call-approver` — a principal *distinct* from the proposer who approves the ESCALATE. |
| **Policy authority** | The constitutional council that owns the policy bundle. |
| **Security-ops on-call** | Notification owner; owns remediation follow-up. |

## Scenario setup

Two fail-closed events are staged against a governed pentest agent:

1. **Out-of-scope scan (DENY).** `recon-agent-1` tries `vulnclaw.port_scan` against
   an unauthorized target (`10.0.0.1`). The scope-boundary policy returns `DENY`.
2. **Privileged exploit (ESCALATE).** The agent tries `vulnclaw.exploit`; policy
   returns `ESCALATE` because the action requires named human authority.

## Expected fail-closed outcomes

| Event | Decision | Invariant that must hold |
|---|---|---|
| Out-of-scope scan | `DENY` | `execute_with_receipt` raises `ReceiptValidationError`; the tool never runs. |
| Privileged exploit | `ESCALATE` | Dispatch dead-ends (`EscalateError`); a receipt minted from the ESCALATE record is rejected at the gate ("cannot authorize execution"); the tool never runs. |
| Exploit after approval | `ALLOW` | Only after a *distinct human* approves does `resume_with_receipt` execute — and only through the `GovernedExecutor` gate. |

If any invariant fails, the drill raises and exits non-zero. Green means fail-closed
held.

## How to run the drill

From the monorepo root:

```bash
uv run --package gove-zone python \
    packages/gove-zone/examples/gameday_incident_evidence.py ./incident-bundle
```

Omit the output-directory argument to write to a temp directory. On success the
drill prints a single-line JSON status summary (`"status": "pass"`) and exits 0 —
CI-friendly.

Run it as a test (asserts the bundle is persisted and hash-consistent):

```bash
cd packages/gove-zone && \
  uv run --extra dev --extra crypto --extra schema --with pyyaml \
    python -m pytest tests/test_gameday_incident_evidence.py --import-mode=importlib -q
```

## Where the evidence bundle lands

The bundle is written to the output directory you pass (or a temp dir). Members,
mapped to the incident-response playbook's **required inputs** and **expected
outputs**:

| File | Contents | Playbook mapping |
|---|---|---|
| `incident-summary.json` | Description, affected systems, severity/risk tier, containment status, notification owners; classification, containment action, evidence-preservation plan, remediation owner/timeline, re-test/reactivation criteria. | Required inputs + expected outputs |
| `decision-receipts.json` | The `DENY`, `ESCALATE`, and human-approval `ALLOW` receipts (hash-bound). | Logs and receipts; model/tool/policy versions |
| `audit-chain.json` | The full tamper-evident audit chain + its verification result. | Access/action logs; incident timeline |
| `verification-summary.md` | Human-readable auditor summary of the fail-closed outcomes and lessons learned. | Remediation verification; lessons-learned record |
| `manifest.json` | sha256 digest + byte length of **each** member above. | Evidence integrity (tamper-evidence) |

`manifest.json` binds every member by sha256 (it does not, and cannot, carry its
own digest). To verify integrity, recompute each member's sha256 and compare to the
manifest; re-walk `audit-chain.json` via `ChainHashAuditStore.verify_chain`.

## Reactivation criteria

Do not reactivate the agent until:

- The drill runs green (chain verifies; DENY non-executable; ESCALATE is
  resume-only after a distinct human approval).
- The target scope list has been corrected and re-reviewed by the policy authority.
- The incident bundle is archived where the audit writer cannot rewrite it.

## Lessons learned (template)

Capture these after each game-day and feed them back into policy + tests:

- **Control point:** the **gate**, not the agent, is what enforces safety — "no
  valid `ALLOW` receipt, no side effect."
- **Human-in-the-loop:** ESCALATE requires a *named* human whose identity differs
  from the proposing agent; the original ESCALATE decision can never authorize
  execution.
- **Evidence first:** containment and evidence preservation precede root-cause —
  the drill captures both atomically.
- **Feedback:** any invariant that was *close* to failing becomes a new adversary
  test and, if needed, a tightened policy rule.
