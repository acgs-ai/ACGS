# Hook or runtime reference

## Decision outcomes

| Outcome | Host behavior |
| --- | --- |
| `allow` | Execute only the action covered by the receipt. |
| `transform` | Execute only the transformed action covered by the receipt. |
| `deny` | Stop before the side effect. |
| `escalate` | Stop before the side effect and require review. |
| malformed input | Stop before the side effect. |
| gate or audit failure in enforce mode | Stop before the side effect. |

## Required host responsibilities

- Send normalized action data to the gate.
- Treat failed parsing as a blocking condition.
- Preserve receipt and audit output.
- Ensure the executed action matches the authorized action.
- Surface the exact failure mode to the operator.

## Minimum evidence for a wiring claim

A wiring claim should include:

- inbound host event path;
- adapter or hook command;
- dispatcher or settings registration;
- allow-path test;
- deny-path or malformed-path test;
- audit evidence path.
