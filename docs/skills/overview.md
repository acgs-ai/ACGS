# Skills overview

Skills are reusable agent workflows, prompts, and operating procedures. They help agents behave consistently, but they should not be treated as the same thing as runtime authority.

## ACGS relationship to skills

ACGS can govern actions proposed by a skill-driven agent, but it does not depend on a particular skill framework. The skill decides how the agent plans. ACGS decides whether a proposed side effect is authorized.

## What to record

Skill-driven actions should preserve:

- skill name and version when available;
- actor identity;
- proposed tool call;
- policy context;
- decision receipt;
- audit event path.

## Design goal

The governance plane should remain useful even when the agent uses a different skill system, no skill system, or a custom workflow engine.
