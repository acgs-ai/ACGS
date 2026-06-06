# Receipt schema reference

A decision receipt binds a governance decision to a specific action.

## Conceptual fields

Receipt implementations should include or derive:

- receipt identifier or hash;
- actor;
- validator;
- action/tool name;
- normalized arguments or argument hash;
- decision outcome;
- policy identifier or policy hash;
- timestamp;
- expiry or review constraints when applicable;
- signature or canonical hash metadata.

## Verification checks

A verifier should reject receipts when:

- the receipt is malformed;
- actor, action, arguments, or policy context do not match;
- the receipt is expired;
- the hash or signature does not verify;
- the decision outcome is not sufficient for the requested side effect.

## Current implementation pointer

See `packages/gove-zone/src/gove_zone/receipt.py` and `packages/gove-zone/tests/test_decision_receipt.py` for the authoritative local schema behavior.
