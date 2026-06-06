# Problem → Governance Solution Map

Use this map to route agent governance problems to controls.

| Governance problem | Risk signal | Suitable governance solution | Minimum evidence required | Recommended playbook |
| --- | --- | --- | --- | --- |
| Agent wants to call a tool | External side effect, file write, credential, API, payment, deployment, shell | Runtime governance gate | Requested tool, arguments, caller, policy result, logs | `playbooks/govern-an-agent-tool-call.md` |
| Agent makes a safety, legal, or compliance claim | Claim could influence trust or risk acceptance | Auditability + source evidence | Source URL/file, date, scope, uncertainty | `playbooks/produce-an-audit-trail.md` |
| Agent handles personal or sensitive data | PII, health, financial, biometric, children, privileged, confidential | Risk classification + policy-as-code + audit trail | Data class, purpose, minimization, retention, access control | `playbooks/choose-a-governance-pattern.md` |
| Agent affects rights, money, health, job, education, legal status, or public service | Consequential decision or recommendation | Human oversight + impact assessment | Decision impact, human authority, appeal path, testing | `playbooks/escalate-to-human-review.md` |
| Agent uses RAG or external knowledge | Retrieval can be stale, poisoned, private, or irrelevant | Policy-as-code + auditability | Source provenance, retrieval logs, freshness, citation checks | `solution-catalog/policy-as-code.md` |
| Agent can act autonomously | Multi-step action, tool chaining, weak human review | Runtime governance + human oversight | Autonomy level, allowed actions, stop button, rollback plan | `solution-catalog/runtime-governance.md` |
| Model or prompt changes | Prior approval may no longer apply | Risk reclassification + eval rerun | Model/version diff, eval results, risk owner approval | `solution-catalog/risk-classification.md` |
| Incident or near miss occurs | Harm, data exposure, wrong decision, unsafe output, policy bypass | Incident response | Incident log, severity, containment, remediation, notification owner | `solution-catalog/incident-response.md` |
| Vendor model is introduced | Unknown data, IP, security, or lock-in risk | Vendor evidence + control matrix | Model/system/data cards, acceptable use policy, data processing terms | `templates/control-matrix.md` |
| User asks to skip audit or review | Evidence suppression or policy bypass | Deny or escalate | Request text, policy reason, owner approval if exception allowed | `agent-decision-protocol.md` |

## First solution to try

1. If the agent can take action: start with **runtime governance**.
2. If the agent makes claims: start with **auditability and receipts**.
3. If humans are affected: start with **risk classification** and **human oversight**.
4. If the system must enforce repeatable rules: start with **policy-as-code**.
5. If something went wrong: start with **incident response**.
