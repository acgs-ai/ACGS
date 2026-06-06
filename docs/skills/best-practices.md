# Skill best practices

## Keep authority separate from instruction

A skill may instruct an agent to perform a task. It should not imply that the agent is authorized to perform every side effect needed for that task.

## Make side effects explicit

List expected side effects and route them through the governance gate. Avoid vague language such as "do what is necessary" for high-risk tools.

## Include negative paths

Document what happens when governance denies, escalates, or cannot write evidence. A skill that only describes success behavior is incomplete for governed workflows.

## Preserve evidence

A governed skill should end with receipt paths, audit paths, exact commands run, and what was not verified.

## Avoid overclaims

Do not describe a skill pack as compliance-certified or production-safe unless external evidence supports that exact claim.
