# Agent Decision Protocol

Use this protocol whenever an agent faces a governance question.

## Decision tree

```text
1. Identify the governance problem.
   If no governance problem is visible, still classify data + autonomy.

2. Classify risk tier.
   G0 personal / low-impact
   G1 standard operational
   G2 consequential / high-impact
   G3 stop or escalate

3. Identify required overlays.
   Security? Privacy? Legal? Sector? Jurisdiction? Procurement? Human oversight?

4. Select a governance solution.
   Runtime gate, audit receipt, human oversight, policy-as-code, impact assessment,
   incident response, risk classification, or a combination.

5. Gather evidence.
   Do not rely on agent confidence. Require logs, source documents, tests, cards,
   evals, lineage, approvals, or explicit lack-of-evidence notes.

6. Decide.
   ALLOW: controls and evidence are sufficient for this risk tier.
   DENY: request violates policy or risk is unacceptable.
   ESCALATE: human/legal/security/domain authority is required.
   ASK: essential facts are missing and a reasonable assumption is unsafe.

7. Record.
   Create or update a decision record with request, risk tier, policy, evidence,
   decision, owner, expiry, and re-check trigger.
```

## Minimum output format for agents

```md
### Governance Decision

**Request:** <what the AI/action is trying to do>
**Risk tier:** <G0/G1/G2/G3 + reason>
**Controls selected:** <patterns from solution catalog>
**Evidence used:** <links/files/logs/tests or "missing">
**Decision:** <ALLOW / DENY / ESCALATE / ASK>
**Reason:** <short explanation>
**Record:** <decision record path or log id>
**Come back when:** <trigger>
```

## Allow / deny / escalate rules

- **Allow** only when the risk tier is clear and controls match the tier.
- **Deny** when the request asks the agent to bypass policy, hide evidence, evade review, misuse data, or take prohibited/high-harm action.
- **Escalate** when the action is consequential, irreversible, privileged, legally sensitive, security-sensitive, or outside the agent's authority.
- **Ask** only when a short clarification can resolve a missing fact. If the missing fact is itself high-risk, escalate.

## Evidence sufficiency by tier

| Tier | Evidence minimum |
| --- | --- |
| G0 | user intent, no sensitive data, human review of final output |
| G1 | system owner, data class, access control, logs, basic eval or test |
| G2 | impact assessment, named accountable owner, TEVV/evals, human oversight design, monitoring, incident plan |
| G3 | explicit approval from legal/security/domain authority or deny/pause |
