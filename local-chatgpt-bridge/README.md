# Local ChatGPT Bridge

Private developer-mode bridge for local workspace context.

It has two surfaces:

- `chatgpt-local`: a local CLI that packages selected files, search results, and git status into a ChatGPT-ready prompt bundle.
- `/mcp`: a read-only MCP endpoint for ChatGPT.com developer mode.

V1 intentionally has no widget, no public app submission, no write tools, and no arbitrary shell command exposed to ChatGPT.

## Setup

```bash
cp config.example.json config.json
npm test
npm run check
npm start
```

Edit `config.json` before starting. The server refuses to start without a config file and at least one allowed root.

## CLI

```bash
node bin/chatgpt-local roots --config config.json
node bin/chatgpt-local doctor --config config.json
node bin/chatgpt-local context --config config.json --root govern-zone --file PLAN.md
node bin/chatgpt-local ask --config config.json --root govern-zone --search "MCP" --prompt "Summarize the relevant local context"
```

`ask` calls the OpenAI Responses API only when `OPENAI_API_KEY` is set. Without that key it prints a paste-ready prompt bundle.

## Browser automation via kernel.sh pools

`browser-ask` acquires a pre-warmed stealth Chrome from a [kernel.sh browser pool](https://kernel.sh/docs/browsers/pools/overview), navigates to ChatGPT, submits the prompt, waits for the full response, releases the browser back to the pool, and prints the reply.

**Prerequisites:**

1. Set `KERNEL_API_KEY` in your environment.
2. Create a pool (once): `npx @onkernel/sdk browser-pools create --name chatgpt-pool --size 2 --stealth`
3. Log in to ChatGPT in the acquired browser — or use a pool configured with a persisted session.
4. Add the pool name to `config.json`:

```json
{
  "kernel": {
    "poolName": "chatgpt-pool",
    "acquireTimeoutSeconds": 30,
    "responseTimeoutMs": 120000
  }
}
```

**Commands:**

```bash
# List your kernel.sh pools
KERNEL_API_KEY=... node bin/chatgpt-local pools --config config.json

# Ask ChatGPT with full local context
KERNEL_API_KEY=... node bin/chatgpt-local browser-ask \
  --config config.json \
  --root govern-zone \
  --file acgi-ai/PLAN.md \
  --prompt "What is the next Phase 0 item to implement?"

# Override the pool at runtime
KERNEL_API_KEY=... node bin/chatgpt-local browser-ask \
  --config config.json \
  --pool my-other-pool \
  --prompt "Review this codebase"

# Release without reuse (destroys the browser instance)
KERNEL_API_KEY=... node bin/chatgpt-local browser-ask \
  --config config.json \
  --reuse false \
  --prompt "..."
```

`browser-ask` accepts the same `--root`, `--file`, `--search`, `--no-git` flags as `context` and `ask` to compose the local context injected before the user prompt.

## ChatGPT Developer Mode

ChatGPT requires an HTTPS endpoint. For local development, run this server locally and expose it with a tunnel such as ngrok or Cloudflare Tunnel.

Tunnel mode must use a high-entropy endpoint token:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8788,
    "basePath": "/mcp",
    "tunnelMode": true,
    "endpointToken": "replace_with_at_least_32_url_safe_random_chars",
    "allowedOrigins": ["https://chatgpt.com"]
  }
}
```

Connect ChatGPT to:

```text
https://your-tunnel.example/mcp/<token>
```

Direct untokened `/mcp` is only for loopback-only local testing and is not tunnel-safe.

## MCP Tools

All tools are read-only and idempotent:

- `list_allowed_roots`
- `list_dir`
- `read_file`
- `search_files`
- `get_file_metadata`
- `git_status`

`git_status` only runs:

```bash
git status --short --branch
```

It does not expose arbitrary command execution.

## Threat Model

Read-only local files can still leak sensitive data. The bridge uses:

- explicit root aliases
- fail-closed config loading
- tunnel endpoint token
- origin validation
- realpath containment
- traversal and absolute-path refusal
- symlink refusal by default
- secret-path denial
- ignored heavy/sensitive dirs
- binary and oversized file refusal
- output caps
- content-free audit logs

The audit log records tool names, aliases, relative paths or queries, counts, refusal reasons, and timing. It does not record file contents or endpoint tokens.

## Non-Goals

- No ChatGPT-facing writes.
- No ChatGPT-facing shell.
- No OAuth in v1.
- No public app directory submission.
- No widget resources.
- No MCP resources, prompts, sampling, SSE, or server-initiated roots negotiation.
