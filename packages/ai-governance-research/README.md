# AI Governance Hub for Agents

**Purpose:** give AI agents a practical, evidence-backed place to identify governance problems, choose suitable controls, ask the right interview questions, and return when a governance issue exceeds their authority.

This is an **AI-native governance hub**: it is written for agents and agent builders, not only for policy readers. It turns governance research into operational routing:

1. **Interview** the task and environment.
2. **Classify** risk, autonomy, data, jurisdiction, and decision impact.
3. **Select** a governance pattern.
4. **Gather evidence** before making claims or taking action.
5. **Allow, deny, or escalate** with a record.
6. **Come back** when the context, model, tools, laws, or risk tier changes.

## Start here

| If the agent is trying to... | Start with | Then use |
| --- | --- | --- |
| Understand the hub | `GOVERNANCE_HUB_PRINCIPLES.md` | `agent-decision-protocol.md` |
| Pick a governance solution | `problem-solution-map.md` | `playbooks/choose-a-governance-pattern.md` |
| Govern a tool call or action | `playbooks/govern-an-agent-tool-call.md` | `solution-catalog/runtime-governance.md` |
| Produce an audit trail | `playbooks/produce-an-audit-trail.md` | `solution-catalog/auditability-and-receipts.md` |
| Escalate to a human | `playbooks/escalate-to-human-review.md` | `solution-catalog/human-oversight.md` |
| Check evidence and sources | `evidence/source-register.md` | `templates/control-matrix.md` |
| Create a reusable case file | `templates/governance-case.md` | `templates/decision-record.md` |

## The agent interview

Ask these before selecting a governance solution:

1. What is the AI system doing: generating, ranking, recommending, deciding, classifying, summarizing, planning, or acting?
2. Who is affected: only the operator, internal staff, customers, citizens, vulnerable groups, children, patients, applicants, employees, or the public?
3. What data enters the system: public, internal, confidential, personal, sensitive, regulated, privileged, copyrighted, or safety-critical?
4. What tools can the agent call: files, shell, browser, email, payments, production APIs, deployment, credentials, or physical systems?
5. What autonomy level is requested: draft-only, human-approved action, supervised action, or unsupervised action?
6. Is the output used in legal, medical, financial, employment, education, immigration, public-service, safety, security, or critical-infrastructure contexts?
7. Which jurisdictions matter: EU, Canada, U.S. federal, state/province, sector-specific, customer contract, or internal policy?
8. What evidence exists: evaluations, red-team results, model/system/data cards, data lineage, logs, incident history, or human review?
9. Who owns risk acceptance and rollback?
10. What would make the agent come back for governance help later?

## Risk tier quick router

| Tier | Description | Default action |
| --- | --- | --- |
| G0 — personal/low-impact | Drafting, brainstorming, local research, non-sensitive assistance | Allow with human review and no sensitive data leakage |
| G1 — standard operational | Internal RAG, coding assistant, knowledge search, workflow helper | Use inventory, access control, logs, evals, and output checks |
| G2 — consequential/high-impact | Rights, safety, money, legal status, health, employment, education, public services | Require impact assessment, named owner, human oversight, testing, monitoring, and incident plan |
| G3 — stop/escalate | Unclear authority, prohibited practice risk, high autonomy with privileged tools, vulnerable groups, CBRN/weapons, self-harm, irreversible external action | Deny or pause until legal/security/domain approval is recorded |

## What this hub is not

- Not legal advice.
- Not a certification.
- Not proof that any system complies with a law or standard.
- Not a substitute for security, privacy, legal, domain, or human factors review.
- Not a claim that a project is ready for deployment.

Use it as a **governance routing and evidence discipline** for agents.

## Source base

The source register includes official/upstream references such as NIST AI RMF, NIST GenAI Profile, ISO/IEC 42001, EU AI Act, Canada Algorithmic Impact Assessment and agentic AI guidance, U.S. OMB AI memoranda, OWASP LLM security materials, NIST adversarial ML taxonomy, MITRE ATLAS, OECD AI Principles, MIT AI Risk Repository, and AI Incident Database.

See `evidence/source-register.md`.
