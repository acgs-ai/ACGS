# Incident Response

## When to use

Use when an AI system causes or nearly causes harm, exposes data, bypasses a policy, generates dangerous output, fails in a consequential workflow, or behaves outside expected boundaries.

## When not to use

Do not wait for perfect root-cause analysis before containment. Initial incident response should prioritize safety, containment, evidence preservation, and accountability.

## Required inputs

- Incident description.
- Affected people/systems/data.
- Severity and risk tier.
- Logs and receipts.
- Current containment status.
- Required notification owners.

## Expected outputs

- Severity classification.
- Containment action.
- Evidence preservation plan.
- Remediation owner and timeline.
- Re-test and reactivation criteria.
- Lessons-learned record.

## Evidence required

- Incident timeline.
- Model/tool/policy versions.
- Inputs/outputs where safe to retain.
- Access and action logs.
- User reports or monitoring alerts.
- Remediation verification.

## Failure modes

- Continuing to run an unsafe system during analysis.
- Losing logs or prompts needed for replay.
- Treating user harm reports as anecdotal noise.
- No criteria for deactivation or reactivation.
- No feedback into risk classification and tests.

## Agent instruction block

```text
Before acting, classify the request, select the control, gather evidence, and produce an allow/deny/escalate decision. If required evidence is missing for the risk tier, do not proceed silently. Escalate or ask for the missing authority.
```
