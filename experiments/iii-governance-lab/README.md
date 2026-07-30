# iii Governance Lab

Experimental only. This lab exercises iii as a local orchestration layer for
governance-style workers. It is not production deployment proof and does not
change the production console, Cloud Run, Vercel, or package release paths.

## Shape

The lab has one external worker:

- `governance-worker`: Python worker that registers `governance::evaluate_policy`.

The worker connects to the local iii engine at `ws://localhost:49134`. The
engine's built-in HTTP worker serves endpoints from `http://localhost:3111`.

A TypeScript `caller-worker` previously registered `governance::evaluate_request`
and an HTTP trigger at `/governance/evaluate`, demonstrating the cross-language
path. It was removed because its only dependency, `iii-sdk`, pulls
`@opentelemetry/core` and `@opentelemetry/propagator-jaeger` at `1.30.1`, which
carry CVE-2026-54285 and CVE-2026-59892. Both are fixed only on the 2.x majors,
and every published `iii-sdk` pins `^1.30.0`, so no upgrade path exists. Restore
the worker once `iii-sdk` ships on OpenTelemetry 2.x.

## Setup

Install iii from the official docs before running this lab:

- https://iii.dev/docs/0-11-0/install.md
- https://iii.dev/docs/0-11-0/quickstart.md
- https://iii.dev/docs/0-11-0/how-to/define-request-response-formats.md

Start the engine from this directory. The checked-in config starts only the
engine's built-in worker manager and HTTP worker; the local SDK workers are
added separately.

```bash
iii --config config.yaml
```

In a separate terminal, add the worker:

```bash
iii worker add ./workers/governance-worker
```

Trigger the policy worker directly:

```bash
iii trigger governance::evaluate_policy subject=demo action=read resource=policy/P-1207
```

Expected decision:

```json
{
  "decision": "allow",
  "reason": "read access to policy resources is allowed in the local lab",
  "mode": "experimental"
}
```

## Teardown

Stop workers with the iii console or terminate the local worker processes. Stop
the engine process that is running `iii --config config.yaml`.

## Guardrails

This lab uses placeholder local policy logic. Do not wire it to production auth,
production bus traffic, or release evidence until a later design covers security,
RBAC, deploy topology, and operations ownership.
