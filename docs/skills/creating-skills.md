# Creating skills for governed actions

When a skill may trigger side effects, design it so the runtime can govern those effects.

## Checklist

- Declare which tools the skill may call.
- Identify high-risk tools and irreversible operations.
- Require pre-execution authorization for side effects.
- Preserve decision receipts in the task handoff.
- Include deny-path behavior, not only success behavior.
- Avoid asking the agent to bypass hooks, policy gates, or audit writes.

## Skill text pattern

Use language such as:

> Before any side-effectful tool call, route the normalized action through the configured ACGS gate. If the gate denies, escalates, fails to parse, or cannot write required evidence in enforce mode, stop before the side effect and report the receipt or error.

## Review pattern

Reviewers should verify that the skill does not confuse an instruction to act with proof of authority to act.
