# Hooks or runtime overview

Hook systems are useful places to intercept tool calls. ACGS uses those surfaces as adapters, but its product boundary is broader: governed runtime enforcement with decision receipts and replayable audit evidence.

## Comparison

| Hook surface | ACGS boundary |
| --- | --- |
| Scriptable pre/post tool control | Governed runtime enforcement |
| Can allow or deny tool use | Must fail closed before side effects |
| Useful for local policy | Built for verifiable authority and evidence |
| JSON stdin/stdout hook model | Decision receipt plus replayable audit evidence |
| Developer productivity guardrail | Governance and security evidence boundary |

## Integration principle

Copy the useful integration shape from hook systems: simple payloads, clear exit behavior, and host-native ergonomics. Do not copy branding or weaken the governance requirement that evidence be replayable.
