# Playbook: Choose a Governance Pattern

## Steps

1. Write the user/task request in one sentence.
2. Classify data: public, internal, confidential, personal, sensitive, regulated, privileged.
3. Classify action: observe, draft, recommend, decide, act, deploy, spend, notify, delete.
4. Classify autonomy: none, human-approved, supervised, unsupervised.
5. Classify impact: low, operational, consequential, high-harm.
6. Identify jurisdictions and sector overlays.
7. Select one or more patterns:
   - risk classification;
   - runtime governance;
   - auditability and receipts;
   - human oversight;
   - policy-as-code;
   - incident response.
8. Fill `templates/governance-case.md`.
9. If G2/G3, create a `templates/decision-record.md` before action.

## Output

```md
Pattern selected: <pattern list>
Reason: <risk signals>
Evidence needed: <minimum evidence>
Decision: <allow / deny / escalate / ask>
```
