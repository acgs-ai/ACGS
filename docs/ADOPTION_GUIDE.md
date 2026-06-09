# Adoption guide

> **Core invariant: No valid Decision Receipt, no side effect.**


## Who should use this now

Good early adopters:

- agent-tool developers who need pre-execution authorization;
- teams building MCP gateways for sensitive tools;
- CI/CD teams experimenting with governed deploy gates;
- security reviewers evaluating side-effect evidence;
- researchers comparing governance layers vs. orchestration frameworks;
- buyers/funders looking for claim-safe local proof.

## Who should not use this yet

Do not use this as-is for unattended production-critical enforcement if you need:

- compliance certification;
- regulator approval;
- WORM/off-host audit durability;
- complete IAM/RBAC/PKI/key lifecycle;
- audited production deployment profile;
- third-party security review;
- full formal verification.

Use it as a local kernel, reference implementation, or production-adjacent pilot with explicit risk acceptance and external controls.

## Integration wedges

Start with one narrow side effect:

1. filesystem write in an internal tool;
2. outbound HTTP/API mutation;
3. database write;
4. CI deploy/publish step;
5. MCP `tools/call` gateway;
6. email/send action;
7. payment or billing operation only after stronger signing/identity controls.

## First production-adjacent pilots

A credible pilot should include:

- authenticated actor identity from existing IAM;
- signed receipts required at the executor;
- policy bundle hash pinned in config;
- audit evidence shipped off-host;
- deny/missing/tampered receipt tests in CI;
- incident/runbook docs;
- claim wording reviewed against `docs/CLAIMS.md`.

## How to evaluate success

A pilot is working when reviewers can answer:

- Which side effects are behind the gate?
- Which direct raw-tool paths are impossible or monitored?
- Can a missing receipt run the side effect? It should not.
- Can a tampered receipt run the side effect? It should not.
- Can argument substitution run the side effect? It should not.
- Can receipt/audit evidence be exported and replayed?
- Are limitations documented honestly?

## How to contribute safely

- Start with docs/examples/tests unless changing runtime behavior is necessary.
- Add negative-path tests for any security behavior change.
- Update `docs/CLAIMS.md` when claims change.
- Keep examples local-only and dependency-light.
- Do not touch nested submodule files from the parent repo.
- Do not stage generated, sealed, or hash-marked files without the proper regeneration path.
