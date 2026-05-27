# iii Governance Lab

Experimental only. This lab exercises iii as a local orchestration layer for
governance-style workers. It is not production deployment proof and does not
change the production console, Cloud Run, Vercel, or package release paths.

## Shape

The lab has two external workers:

- `governance-worker`: Python worker that registers `governance::evaluate_policy`.
- `caller-worker`: TypeScript worker that registers `governance::evaluate_request`
  and an optional HTTP trigger at `/governance/evaluate`.

The workers connect to the local iii engine at `ws://localhost:49134`. The HTTP
worker, when installed with iii, serves endpoints from `http://localhost:3111`.

## Setup

Install iii from the official docs before running this lab:

- https://iii.dev/docs/0-11-0/install.md
- https://iii.dev/docs/0-11-0/quickstart.md
- https://iii.dev/docs/0-11-0/how-to/define-request-response-formats.md

Start the engine from this directory:

```bash
iii --config config.yaml
```

In separate terminals, add the workers:

```bash
iii worker add ./workers/governance-worker
iii worker add ./workers/caller-worker
iii worker add iii-http
```

Trigger the cross-language path:

```bash
iii trigger governance::evaluate_request subject=demo action=read resource=policy/P-1207
```

Call the HTTP endpoint:

```bash
curl -X POST http://localhost:3111/governance/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"subject":"demo","action":"read","resource":"policy/P-1207"}'
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
