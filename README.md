# govern-zone

`govern-zone` is the ACGS workspace for governed agent/runtime experiments,
frontend console work, and integration-ready governance packages. The current
repo is a monorepo: root files coordinate setup and verification; individual
packages own their runtime contracts.

Use `MONOREPO.md` as the package registry,
`docs/governance-stack-index.md` as the policy/evidence ownership map, and
`AGENTS.md` / package-local `AGENTS.md` or `CLAUDE.md` files as the agent
operating contract.

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
```

## Primary package surfaces

| Path | Purpose | Main gate |
|---|---|---|
| `packages/gove-zone/` | Minimal governed runtime kernel, CLI, runtime-hook adapter, receipts, replay, audit chain | `uv run --package gove-zone python -m pytest packages/gove-zone/tests --import-mode=importlib -q` |
| `acgi-ai/` | React/Vite console and marketing surfaces | `pnpm -F acgi-ai lint && pnpm -F acgi-ai build` |
| `packages/agent-bus-analyzer/` | FastAPI observer API and OpenAPI export | package pytest + mypy via `make verify` |
| `acgs_governance_eval_mvp/` | Governance evaluation MVP and replay checks | package pytest via `make verify` |

Nested repos under `packages/acgs-lite`, `packages/Acgs-Swarm`, and
`packages/clinicalguard` keep their own git boundaries. Do not stage or commit
inside them from the parent repo.

## Agent/runtime integration smoke path

`gove-zone` exposes a single hook adapter for runtimes that emit tool events:

```bash
uv run --package gove-zone gove-zone setup --format json
uv run --package gove-zone gove-zone doctor
uv run --package gove-zone gove-zone smoke
printf '{"tool_name":"Edit","tool_input":{"file_path":"README.md","new_string":"demo"}}' \
  | uv run --package gove-zone gove-zone gate --actor smoke
```

`gove-zone smoke` is the fastest local proof that the runtime can allow a safe
tool call, deny a blocked one before side effects, and verify the audit chain.
Pass `--audit <path>` when that smoke audit JSONL should be retained as release
evidence.

The adapter also exposes `tool_call_from_hook_payload` and
`tool_calls_from_hook_payload` for dependency-free
Claude/Codex-style, MCP-style `tools/call`, function-call-style, OpenAI Chat
`tool_calls`, OpenAI Responses, LangChain-style `tool_calls`, generic
agent-framework bridge payload normalization, and batched tool-call expansion
before receipts are emitted.
For enforceable hook hosts, run `gove-zone gate --policy-bundle
policy.bundle.json < event.json`; the gate writes receipts and exits non-zero
when any normalized child call returns `deny` / `escalate` before the side
effect runs. Recognized multi-call containers that include unparseable child
calls fail closed as a `runtime.malformed_batch` deny receipt instead of
falling back to `runtime.unknown`.

The parent `.claude/settings.json` wires `.claude/hooks/acgs-emit-receipt.py` to
Claude Code `PreToolUse` events for `Edit|Write|MultiEdit` and selected `Bash`
workflow commands. The hook writes a tamper-evident audit chain to
`.gove-zone/audit.jsonl` by default. Use `gove-zone enable --enforce` to make
receipt-emission failures block the tool call.

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
  its receipt-proof, bus-source, visual workbench, claim-safety, and
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
