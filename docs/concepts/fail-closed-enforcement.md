# Fail-closed enforcement

Fail-closed enforcement means an action does not proceed when governance cannot prove that it is authorized.

## Fail-closed triggers

A host should block before side effects when:

- the policy bundle cannot be loaded;
- the tool-call payload is malformed;
- a recognized batch contains an unparseable child call;
- receipt issuance or audit writing fails in enforce mode;
- the decision is deny or escalate;
- the receipt does not verify against the expected action;
- required identity or boundary context is missing.

## Why hooks alone are not enough

Hook systems are useful integration points, but they are often developer-productivity guardrails. ACGS uses hook surfaces as adapters while preserving a stricter governance contract: the authority decision must happen before execution, produce evidence, and be replayable.

## Safe rollout pattern

1. Start in report mode.
2. Confirm receipts are emitted for allow and deny paths.
3. Test malformed input and audit-write failure behavior.
4. Enable enforcement.
5. Keep the bypass story explicit in documentation and tests.
