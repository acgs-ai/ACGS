# Decision receipts

A decision receipt is the durable proof that a governance decision was made for a specific proposed action.

## Purpose

Decision receipts let reviewers answer:

- who proposed the action;
- what action and arguments were evaluated;
- which policy context was used;
- whether the result allowed, denied, transformed, or escalated the action;
- how to verify the receipt later.

## Receipt properties

A useful receipt is:

- **bound** to actor, action, arguments, and policy context;
- **tamper-evident** through canonical hashing or signature metadata;
- **replayable** against captured policy material;
- **narrow** enough that it cannot authorize a different action;
- **explicit** about expiry or review obligations where applicable.

## What receipts do not prove

A valid receipt does not by itself prove that production deployment happened, that a regulator approved the system, or that every downstream side effect was safe. It proves the recorded governance decision for the recorded action.
