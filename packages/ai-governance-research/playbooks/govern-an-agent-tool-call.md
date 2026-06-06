# Playbook: Govern an Agent Tool Call

## Steps

1. Capture tool name, arguments, caller, environment, and intended effect.
2. Check whether the tool can modify state, expose data, call external services, spend money, deploy, or contact people.
3. Classify risk tier.
4. Apply policy:
   - read-only low-risk action: allow with log;
   - write/action with reversible effect: allow only with scoped permission and receipt;
   - privileged, external, irreversible, or consequential action: require human approval or deny;
   - prohibited or unclear authority: deny or escalate.
5. Minimize inputs and redact secrets from logs.
6. Record decision using `templates/decision-record.md`.
7. After action, verify effect and rollback status if relevant.

## Tool decision receipt

```md
Tool: <name>
Arguments summary: <redacted>
Environment: <local/staging/production/external>
Risk tier: <G0/G1/G2/G3>
Policy result: <allow/deny/escalate/ask>
Evidence: <log/source/approval>
Post-check: <what was verified>
```
