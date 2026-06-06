# Auditability and Receipts

## When to use

Use when an agent must support, replay, challenge, or verify a governance decision, safety claim, compliance mapping, tool action, or model output.

## When not to use

Do not treat a receipt as proof that the decision was good. A receipt proves what was recorded; it still needs review, validation, and sometimes external evidence.

## Required inputs

- Request and context.
- Risk tier.
- Policy/control applied.
- Evidence used.
- Decision outcome.
- Actor or owner.
- Timestamp and expiry/re-check trigger.

## Expected outputs

- Decision record.
- Evidence links.
- Replay data where safe.
- Hash or immutable reference where appropriate.
- Human-readable summary.

## Evidence required

- Source documents and versions.
- Logs or command output.
- Evaluation results.
- Approval records.
- Incident references if relevant.

## Failure modes

- Logs that omit denied actions.
- Receipts that cannot be tied to the exact model/tool/policy version.
- Sensitive data leaked into audit records.
- Claims recorded without evidence.
- Records with no retention or deletion plan.

## Agent instruction block

```text
Before acting, classify the request, select the control, gather evidence, and produce an allow/deny/escalate decision. If required evidence is missing for the risk tier, do not proceed silently. Escalate or ask for the missing authority.
```
