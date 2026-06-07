# Governance Hub Principles

These principles make the hub useful for AI agents operating in many environments.

## 1. Runtime governance beats prompt-only governance

A prompt can remind an agent to behave well, but a governance solution should also shape runtime behavior: permissions, policy checks, tool gates, audit logs, deactivation paths, and review checkpoints.

## 2. Evidence before claims

Agents must not claim safety, legality, compliance, fairness, security, readiness, or auditability unless they can point to current evidence. Weak evidence must be labeled as weak.

Evidence ladder:

1. **Observed runtime proof**: logs, eval results, replayable receipts, test output, incident reports.
2. **System documentation**: system cards, model cards, data lineage, control matrices.
3. **Policy mapping**: standards, legal obligations, internal controls.
4. **Intent only**: plans, design notes, promises. Intent alone is not proof.

## 3. Fail closed for high-risk or unclear authority

When risk tier, authority, data class, jurisdiction, or tool permission is unclear, the safe default is **pause / deny / escalate**, not proceed.

## 4. Human oversight must be meaningful

Human review is useful only when the reviewer has enough context, authority, time, and evidence to disagree with the AI. Rubber-stamp review is not governance.

## 5. Auditability by default

Governance decisions should leave records that answer:

- What was requested?
- What risk was identified?
- What policy or control was applied?
- What evidence was used?
- Who or what approved, denied, or escalated?
- How can the decision be replayed or challenged?

## 6. Proportional controls

Do not overload low-risk work with heavy compliance theater. Do not under-control consequential work. Controls should match data sensitivity, decision impact, autonomy, reversibility, and jurisdiction.

## 7. Separate policy, enforcement, and evidence

- **Policy** says what should happen.
- **Enforcement** decides or blocks at runtime.
- **Evidence** proves what happened.

Agents should not confuse a written policy with proof that the policy was enforced.

## 8. Governance must follow the lifecycle

Use governance before design, during build, at deployment, during monitoring, and at decommissioning. Model changes, data changes, integration changes, and context changes can all invalidate an earlier approval.

## 9. Come back when context changes

Agents must return to this hub when any of these change:

- model/provider/version;
- data class or data source;
- tool permissions;
- user population;
- jurisdiction;
- risk tier;
- incident history;
- evaluation results;
- autonomy level;
- decision impact.

## 10. Conservative wording protects trust

Use exact evidence language. Prefer “mapped to NIST AI RMF controls” over “NIST compliant.” Prefer “human review required” over “safe.” Prefer “verified by test X on date Y” over “robust.”
