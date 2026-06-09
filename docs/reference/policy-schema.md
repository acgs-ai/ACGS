# Policy schema reference

ACGS policy schemas describe what actions are allowed, denied, transformed, or escalated for a given authority context.

## Minimum policy concepts

A useful policy schema captures:

- actor or principal constraints;
- tool/action name constraints;
- argument constraints;
- path, tenant, or environment boundaries;
- decision outcome;
- review or escalation requirements;
- policy version or hash.

## Operational requirements

Policies used for enforcement should be:

- reviewed before use;
- loadable by the gate without network-only dependencies;
- hashable or versioned for receipt binding;
- tested for allow and deny paths;
- treated as blocking when missing or malformed in enforce mode.

## Current implementation pointer

Use `packages/gove-zone` policy and setup tests for current executable behavior. Do not treat this page as a substitute for the package-local schema and tests.
