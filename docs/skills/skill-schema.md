# Skill schema

This page describes recommended metadata for skills that operate in governed environments. It is a documentation contract, not a claim that every field is currently enforced by all hosts.

## Recommended fields

```yaml
name: governed-release-check
description: Verify release evidence before publishing.
version: 0.1.0
allowed_tools:
  - shell
  - file_read
  - file_write
risk_level: high
requires_governance_gate: true
evidence_outputs:
  - decision_receipt
  - audit_event
  - command_output
deny_behavior: stop_before_side_effect
owner: platform-governance
```

## Field guidance

- `allowed_tools`: keep narrow and explicit.
- `risk_level`: use the highest plausible impact class.
- `requires_governance_gate`: set true for side-effectful workflows.
- `evidence_outputs`: list the artifacts a reviewer must receive.
- `deny_behavior`: specify stop, escalate, or require human approval.

## Host integration

A host can use this metadata to decide which skills require pre-tool authorization and which evidence artifacts must be attached to the final handoff.
