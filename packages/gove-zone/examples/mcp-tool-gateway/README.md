# MCP tool gateway — gove-zone

Govern an MCP server's `tools/call` with gove-zone. A standard MCP JSON-RPC
request is routed through gove-zone's real governance API: a write to a
protected path (`/etc`) is **denied** with no side effect, and a write to a
tempdir is **allowed** and executed behind a signed receipt gate.

## What it shows

- **MCP integration PATTERN, not a vendored SDK.** There is no real `mcp` /
  `fastmcp` import — the demo runs with only `gove-zone` installed. It models the
  MCP `tools/call` request shape
  (`{"method":"tools/call","params":{"name","arguments"}}`) and governs it.
- **`handle_mcp_call(request, ...)`** is copy-pasteable into a real FastMCP
  `@server.tool()` handler.
- **Two governance layers (defense in depth):**
  1. *In-band audited policy decision* — `emit_receipt_for_hook` parses the MCP
     request, lifts `arguments.path` into the governed `ToolCall.path`, runs a
     `PathBoundaryPolicy`, and appends a tamper-evident audit receipt.
  2. *Cryptographic signed execution gate* — on ALLOW, the real side effect runs
     only behind `execute_with_receipt` configured from the **production**
     `GovernanceProfile` (`require_signature=True`, the secure default). An
     Ed25519 keypair is generated in-demo.
- **The deny path is the point:** the protected-path write is asserted to leave
  no side effect, and the production-with-no-verifier case is asserted to fail
  closed loud.

### Hook-adapter gotcha (why `PathBoundaryPolicy`)

Through the hook adapter, raw tool *arguments* are replaced by a hash before the
policy sees them. A policy keyed on raw argument keywords would silently never
fire. This demo matches on `call.path` (`PathBoundaryPolicy`), which the adapter
preserves by lifting `arguments["path"]`.

## How to run

```bash
# from the monorepo root
uv run --package gove-zone python \
    packages/gove-zone/examples/mcp-tool-gateway/demo.py

# or with the package venv
.venv-ci/bin/python examples/mcp-tool-gateway/demo.py
```

`python demo.py` exits 0, writes only to a tempdir, and prints step-by-step
evidence. A test can call `main() -> int` directly.

## What to look for

- Step 1: an MCP `isError: true` response for the `/etc/passwd` write, an
  `audit_hash`, and `ASSERT OK: denied, no file written`.
- Step 2: an MCP `isError: false` response, the file actually written in the
  tempdir, and `ASSERT OK: executed behind signed gate`.
- Step 3: `ProductionProfileError` raised when the production gate has no
  verifier.
- Step 4: `"valid": true` over the full audit chain.

## Honest scope

Foundational / local-alpha proof. It proves the local invariant — no allowed
path executes without a verified receipt, and a denied path leaves no side
effect — against the real evaluator, hook adapter, signer, executor, and audit
chain. It is **not** a production, compliance, or regulator-ready certification.
Generating the keypair in-process is a self-contained-demo convenience; real
deployments must manage key custody, distribution, and revocation externally.
See `../../SECURITY.md`.
