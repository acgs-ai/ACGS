# Playbook: Escalate to Human Review

## Escalate when

- Risk tier is G2 or G3.
- The task affects legal rights, money, health, employment, education, public services, safety, or security.
- The agent uses privileged credentials or irreversible external actions.
- Data is sensitive, regulated, privileged, or about vulnerable people.
- The user requests bypassing controls or hiding evidence.
- Required evidence is missing.

## Steps

1. Pause the action.
2. Summarize the request and risk signals.
3. Prepare an evidence packet.
4. Identify the reviewer type: legal, security, privacy, domain expert, product owner, executive risk owner.
5. Ask for a decision: approve, deny, request changes, or request more evidence.
6. Record the decision and conditions.
7. Resume only within the approved scope.

## Escalation packet

```md
Request: <summary>
Risk signals: <why agent cannot self-approve>
Evidence attached: <links/files/logs>
Decision needed: <specific question>
Deadline: <if any>
Safe default if no answer: <deny/pause>
```
