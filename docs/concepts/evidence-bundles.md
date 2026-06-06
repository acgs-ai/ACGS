# Evidence bundles

Evidence bundles package the material needed to review or replay governed decisions.

## Contents

An evidence bundle may include:

- decision receipts;
- audit JSONL events;
- policy bundles or policy hashes;
- verifier output;
- command output from local gates;
- deployment or post-deploy evidence when available;
- notes about unverified external dependencies.

## Review questions

A reviewer should be able to determine:

1. Was the action evaluated before the side effect?
2. Which policy was applied?
3. Was the decision receipt valid for the exact action?
4. Is the audit chain intact?
5. Are production or compliance claims backed by direct evidence?

## Claim discipline

Evidence bundles should distinguish local readiness from live deployment proof. If a required workflow, credentialed deploy, browser check, or external audit was not run, state that explicitly.
