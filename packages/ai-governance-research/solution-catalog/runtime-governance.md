# Runtime Governance

## When to use

Use when an AI agent can take actions, call tools, use credentials, modify files, invoke APIs, write to databases, deploy software, send messages, or trigger workflows.

## When not to use

Do not use runtime governance alone for legal, medical, financial, employment, public-service, or safety decisions. Pair it with human oversight, impact assessment, and auditability.

## Required inputs

- Tool/action name and arguments.
- Caller identity and role.
- Environment: local, staging, production, customer, public.
- Resource sensitivity.
- Policy rules and risk tier.
- Approval and rollback requirements.

## Expected outputs

- ALLOW, DENY, ESCALATE, or ASK.
- Reason code.
- Evidence record.
- Optional transformed safer action.
- Deactivation or rollback instruction when risk is high.

## Evidence required

- Tool invocation record.
- Policy version used for decision.
- Authorization check.
- Human approval record when required.
- Logs sufficient for replay.

## Failure modes

- Prompt-only safety instructions with no enforcement gate.
- Allowing tool chaining without per-step checks.
- Missing rollback path.
- Hidden credentials in prompts or logs.
- No record of denied actions.

## Agentic AI control emphasis

For agentic systems, make autonomy bounded and recoverable: label permission level, constrain data/tools/actions, keep an external pause/disable mechanism, log actions in a place the agent cannot alter, and treat untrusted content as data rather than instructions.

## Agent instruction block

```text
Before acting, classify the request, select the control, gather evidence, and produce an allow/deny/escalate decision. If required evidence is missing for the risk tier, do not proceed silently. Escalate or ask for the missing authority.
```
