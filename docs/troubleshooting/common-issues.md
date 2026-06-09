# Common issues

## The hook emitted a receipt but the tool still ran after deny

The host is not enforcing the decision. Confirm the hook is configured as a pre-tool blocking hook and that deny, escalate, malformed input, and gate failures produce non-zero/blocking behavior.

## The gate cannot parse the payload

Capture the exact host event JSON and add a normalization test. In enforce mode, malformed recognized payloads should fail closed.

## The audit file is missing

Check the configured audit path, filesystem permissions, and whether the host is running in report or enforce mode. In enforce mode, required audit-write failure should block the side effect.

## The receipt verifies locally but not in review

Compare actor, action name, normalized arguments, policy hash, timestamp/expiry, and expected boundary. A receipt for one action must not authorize a different action.

## A production-readiness claim is disputed

Separate local test output from live workflow evidence. If post-deploy checks were not run against a real deployment, call it readiness evidence rather than production proof.
