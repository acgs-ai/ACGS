# Risk Classification

## When to use

Use when an agent needs to decide how much governance is required before acting, advising, deploying, or making a claim.

## When not to use

Do not use risk classification as a substitute for controls. A label such as G2 only tells you which controls are needed.

## Required inputs

- Intended use and user population.
- Data classes used or produced.
- Autonomy level and tool permissions.
- Decision impact and reversibility.
- Jurisdictions and sector rules.
- Model/provider/version and integration context.

## Expected outputs

- Risk tier: G0, G1, G2, or G3.
- Required overlays: security, privacy, legal, procurement, sector, human oversight.
- Re-check triggers.
- Evidence gaps.

## Evidence required

- User/task description.
- Data classification evidence.
- Tool permission list.
- Applicable standards/law/policy links.
- Any prior evaluation, incident, or approval records.

## Failure modes

- Treating “internal use” as automatically low risk.
- Ignoring affected non-users.
- Missing jurisdiction or sector overlays.
- Keeping an old risk tier after model/data/tool changes.
- Allowing high-impact work without an accountable owner.

## Agent instruction block

```text
Before acting, classify the request, select the control, gather evidence, and produce an allow/deny/escalate decision. If required evidence is missing for the risk tier, do not proceed silently. Escalate or ask for the missing authority.
```
