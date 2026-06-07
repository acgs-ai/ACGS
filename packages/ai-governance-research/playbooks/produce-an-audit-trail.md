# Playbook: Produce an Audit Trail

## Steps

1. Identify what must be proven: action, claim, decision, review, test, or incident.
2. Capture request, context, model/tool/policy versions, and risk tier.
3. Attach evidence:
   - source URL or file;
   - command output or test result;
   - eval/red-team result;
   - human approval;
   - data lineage;
   - incident log.
4. Record decision with `templates/decision-record.md`.
5. Add expiry/re-check trigger.
6. Store sensitive data separately or redact it.
7. Verify the record can answer who/what/when/why/how.

## Audit quality check

An audit record is weak if it says “approved” but does not show who approved, what evidence was reviewed, what version was evaluated, or when it must be rechecked.
