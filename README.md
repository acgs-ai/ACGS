# govern-zone

`govern-zone` is a receipt-first governance plane for AI agents and agentic
workflows. It is not another agent framework: it sits before high-risk
execution, decides whether a proposed action is allowed, denied, transformed,
or escalated, and emits verifiable Decision Receipts plus audit evidence before
side effects can run.

The first execution-ready foundation lives in `packages/gove-zone/`. It proves
this local path:

```text
agent/workflow request
-> pre-execution governance check
-> ALLOW / DENY / TRANSFORM / ESCALATE Decision Receipt
-> receipt-gated executor
-> hash-chained audit evidence
```

The current implementation is an alpha foundation, not a production-ready,
compliance-proven, or regulator-approved system. Use `MONOREPO.md` as the
package registry, `docs/governance-stack-index.md` as the policy/evidence
ownership map, and `AGENTS.md` / package-local `AGENTS.md` or `CLAUDE.md` files
as the agent operating contract.

## Quick start

Prerequisites:

- Python 3.11+
- `uv`
- Node 24.x
- `pnpm` 9.x

```bash
make install      # pnpm install + uv sync --all-extras
make verify       # lint + typecheck + test
make verify-js-node24  # acgi-ai readiness under exact Node 24 via fnm
make build        # JS and Python build artifacts
make platform-readiness  # local deploy/platform readiness audit
make release-evidence    # local release-readiness evidence bundle
```

For a bounded local smoke check that avoids full dependency fan-out:

```bash
bash scripts/vibe-kanban-verify.sh
uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q
PYTHONPATH=packages/gove-zone/src python3 packages/gove-zone/examples/receipt_first_demo.py
```

## Docker

The root Docker setup is for local workspace and CI-style commands. The
privileged console production image remains
`acgi-ai/infra/Dockerfile.console`, matching the Cloud Run contract in
`acgi-ai/DEPLOY.md`.

```bash
docker compose --profile dev build workspace
docker compose --profile dev run --rm workspace make install
docker compose --profile dev run --rm workspace make verify

docker compose --profile console build console
docker compose --profile console up console
```

Set `CONSOLE_PORT` to publish the console on a different host port:

```bash
CONSOLE_PORT=8081 docker compose --profile console up console
```

## Primary package surfaces

| Path | Purpose | Main gate |
|---|---|---|
| `packages/gove-zone/` | Minimal governed runtime kernel, CLI, runtime-hook adapter, receipts, replay, audit chain | `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q` |
| `acgi-ai/` | React/Vite console and marketing surfaces | `pnpm -F acgi-ai lint && pnpm -F acgi-ai build` |
| `packages/agent-bus-analyzer/` | FastAPI observer API and OpenAPI export | package pytest + mypy via `make verify` |
| `acgs_governance_eval_mvp/` | Governance evaluation MVP and replay checks | package pytest via `make verify` |

## External desktop clients

| Path | Purpose | Description |
|---|---|---|
| `external/hermes-desktop/` | Electron desktop GUI companion (ACGS Agent) | Graphical desktop assistant interface for conversations and task execution with the ACGS Agent, protected by runtime governance. |

Nested repos under `packages/acgs-lite`, `packages/Acgs-Swarm`, and
`packages/clinicalguard` keep their own git boundaries. Do not stage or commit
inside them from the parent repo.

## Agent/runtime integration smoke path

`gove-zone` exposes a small receipt-gated CLI surface that is implemented in
`packages/gove-zone/src/gove_zone/cli.py`:

```bash
uv run --package gove-zone gove-zone doctor
uv run --package gove-zone gove-zone smoke
printf '{"tool":"message.send","args":{"body":"hello"},"tenant_id":"tenant-alpha","policy_bundle_id":"local-boundary"}' \
  | uv run --package gove-zone gove-zone gate
uv run --package gove-zone gove-zone proofpack
```

`gove-zone smoke` is the fastest local proof that the runtime can allow a safe
tool call, deny a blocked one before side effects, block missing receipts, and
verify the audit chain. Pass `--audit <path>` when that smoke audit JSONL should
be retained as evidence.

`gove-zone gate` normalizes one JSON tool-call envelope, performs a deterministic
pre-execution governance check, emits a canonical Decision Receipt, appends the
audit event, and exits non-zero for `DENY` or `ESCALATE`. The current gate uses
a local static boundary policy for alpha proof; it is not a remote policy-engine
integration.

`gove-zone proofpack` writes `dist-govern-zone-proofpack/` with receipts,
`audit.jsonl`, verification output, conformance results, and limitations. It is
the local buyer/security-review artifact for the claim: no valid Decision
Receipt, no side effect.

The adapter module exposes `normalize_governance_request` for MCP-style
`tools/call`, OpenAI/Responses-style function calls, LangChain-style tool calls,
generic JSON tool calls, CI/CD executor actions, and workflow-engine steps.
Unsupported envelopes fail closed with a clear adapter error.

`setup` and `enable` are not advertised commands in this alpha surface. Add them
later only when they perform real, tested work.

## Deployment readiness

- Frontend deployment details live in `acgi-ai/DEPLOY.md`; `acgi-ai/package.json`
  requires Node `>=24 <25`.
- `make verify-js-node24` uses the local `fnm` installation and
  `acgi-ai/.node-version` to activate Node 24, verify pnpm `9.15.4`, and run
  `pnpm -F acgi-ai run test:all` without accepting the shell-default Node.
- `docs/governance-stack-index.md` maps each package to its policy/evidence
  contract, local gate, and live/deploy proof caveat; `make lint-docs`
  guards the required rows and concepts.
- Ignored adjacent legal-domain checkouts are listed in `MONOREPO.md`; their
  package-local gates are not covered by root CI unless explicitly run.
- Root CI/package fan-out is documented in `MONOREPO.md` and the root
  `Makefile`.
- `make release-evidence` writes `dist-release-evidence/manifest.json`,
  `platform-readiness.json`, and a human README that package local readiness,
  buyer-evidence artifact metadata, verification commands, and explicit
  external blockers for deploy handoff.
- Local Vibe Kanban orchestration setup lives in
  `docs/vibe-kanban-govern-zone.md`; scripts under `scripts/vibe-kanban-*.sh`
  are safe, bounded setup/verify/dev/cleanup hooks.
- `pnpm -F acgi-ai run evidence:build` creates the dependency-free local buyer-evidence
  gallery, and `pnpm -F acgi-ai run test:buyer-evidence` verifies
  its receipt-proof, bus-source, visual workbench guided path, claim-safety, and
  deploy-boundary story cards.
  Console CI now uploads that gallery as the `buyer-evidence-gallery` artifact
  before any credentialed deploy step.
- `pnpm -F acgi-ai run test:storybook-publication` verifies the gated
  Storybook-named publication scaffold for `storybook.acgs.ai`; it remains a
  claim-safe buyer-evidence artifact path, not official Storybook runtime or
  live browser/axe/visual proof.
- Console Cloud Run deploy also requires `CONSOLE_AUTH_UPSTREAM`, rendered into
  Caddy as `AUTH_UPSTREAM`, so `/console*` deep links fail closed behind
  `forward_auth` instead of falling through to the SPA fallback while OIDC or
  server-cookie proof remains external.

Do not claim production deployment is complete unless the relevant deploy
workflow has actually run and post-deploy checks have live evidence. Local
build/test success is deployment readiness, not independent production proof.
Use `make platform-readiness` to summarize the local proof surface and the
remaining external blockers before making platform-readiness claims.

## Known limitations

- `packages/gove-zone` is alpha (`0.1.0.dev0`) and not yet published to PyPI.
- `packages/gove-zone` audit locking uses Unix `fcntl`; Windows support is not
  implemented.
- Private submodule checkout for `packages/clinicalguard` may require
  `SUBMODULE_TOKEN` in CI.
- The root `make typecheck` target is currently an informational fan-out for
  legacy packages with outstanding mypy noise; `packages/gove-zone` is strict
  clean with `(cd packages/gove-zone && uv run mypy .)`.
