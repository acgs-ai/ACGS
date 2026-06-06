# Policy-as-Code

## When to use

Use when governance rules must be repeatable, testable, inspectable, and enforceable across agents, tools, environments, or teams.

## When not to use

Do not encode vague legal judgment as brittle rules without a review path. Policy-as-code should support human judgment, not hide it.

## Required inputs

- Policy source and owner.
- Rule scope and exceptions.
- Required evidence fields.
- Enforcement point.
- Test cases and negative cases.
- Versioning and change process.

## Expected outputs

- Machine-checkable policy rules.
- Decision reasons.
- Test suite for allowed, denied, and escalated cases.
- Change log.
- Mapping to human-readable policy.

## Evidence required

- Policy document or standard reference.
- Rule version.
- Test results.
- Exception approvals.
- Runtime decision logs.

## Failure modes

- Rules drift from human policy.
- Exceptions become invisible.
- No negative-path tests.
- Policy checks happen after the action.
- Overfitting to examples instead of risk logic.

## Agent instruction block

```text
Before acting, classify the request, select the control, gather evidence, and produce an allow/deny/escalate decision. If required evidence is missing for the risk tier, do not proceed silently. Escalate or ask for the missing authority.
```
