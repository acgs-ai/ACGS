# Human Oversight

## When to use

Use when AI influences consequential decisions, affects people, creates legal/security/privacy exposure, or takes actions that are hard to reverse.

## When not to use

Do not use human oversight as theater. If the human lacks authority, context, time, or evidence to reject the AI output, it is not meaningful oversight.

## Required inputs

- Decision impact.
- Human reviewer role and authority.
- Evidence packet.
- Criteria for approval/denial.
- Appeal, override, and rollback process.
- Time sensitivity.

## Expected outputs

- Approval, denial, or requested change.
- Reviewer identity or role.
- Reason and evidence reviewed.
- Conditions or expiry.
- Escalation path.

## Evidence required

- Review packet.
- Model/system limitations.
- Known risks and mitigations.
- Instructions for use.
- Record of human action and rationale.

## Failure modes

- Automation bias.
- Reviewer rubber-stamping.
- No way to override the AI.
- Review after irreversible action.
- Ambiguous responsibility between provider, deployer, and user.

## Agent instruction block

```text
Before acting, classify the request, select the control, gather evidence, and produce an allow/deny/escalate decision. If required evidence is missing for the risk tier, do not proceed silently. Escalate or ask for the missing authority.
```
