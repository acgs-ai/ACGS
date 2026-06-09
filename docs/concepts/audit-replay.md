# Audit replay

Audit replay checks whether recorded decisions can be independently validated after the original run.

## Replay inputs

Replay needs:

- the recorded receipt;
- normalized action arguments;
- policy material or policy hash reference;
- expected actor and boundary context;
- audit-chain metadata where applicable.

## Replay outcomes

Replay should make mismatch classes visible:

- receipt hash mismatch;
- actor mismatch;
- argument mismatch;
- policy mismatch;
- expired or malformed receipt;
- audit-chain break;
- missing evidence.

## Operational use

Use replay during release evidence review, incident review, and regression testing for governance adapters. Replay is not a substitute for live deployment checks; it verifies recorded governance evidence.
