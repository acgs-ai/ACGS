# MCP Action Gateway local quickstart

This quickstart runs the current P1 reference implementation: an official MCP
client talks only to the ACGS gateway, every governed `tools/call` passes through
the shared Side-Effect Authorization Kernel, and the fixture adapter executes
only after final receipt verification.

The walkthrough is local and deterministic. It uses synthetic credentials,
ephemeral Ed25519 keys, temporary fixture state, and no production system. From
an existing checkout it normally takes less than 15 minutes, excluding tool and
dependency downloads.

## Safety topology

```text
Agent / MCP client
        |
        | stdio or loopback Streamable HTTP
        v
ACGS MCP Action Gateway
        |
        | private child-process transport and synthetic downstream credential
        v
Local fixture MCP server
```

Configure the Agent to connect only to the ACGS entrypoint. Do not publish or
configure the fixture server's private endpoint or downstream credential in the
Agent. The reference runtime creates and owns that downstream process; neither
value is emitted in the public response or proof artifacts. The token below is
only the synthetic *inbound gateway* token for this local demonstration.

This topology is part of the security boundary. If an Agent can connect to the
downstream server directly, the gateway cannot prevent that bypass.

## 1. Install the package-local MCP dependencies

Run from the monorepo root with Python 3.11 or newer and `uv` installed:

```bash
uv sync --package gove-zone --extra mcp
```

Create owner-only local fixture material. The value is deliberately inert and
must never be replaced with a production credential for this demo:

```bash
export ACGS_MCP_WORK="$(mktemp -d)"
install -m 700 -d "$ACGS_MCP_WORK/private"
printf '%s\n' 'local-fixture-inbound-token' > "$ACGS_MCP_WORK/private/token"
chmod 600 "$ACGS_MCP_WORK/private/token"
```

## 2. Choose a reference transport

Both commands expose the same receipt-gated local fixture, but their lifecycles
differ. A stdio child normally exits with its MCP client or parent process. The
loopback HTTP Uvicorn process persists after a client disconnects and must be
stopped explicitly with `Ctrl-C` or process-manager termination.

### Local stdio wrapper

Use this executable and argument list as the MCP server command in a local MCP
client. The token value itself is never placed in argv:

```bash
uv run --package gove-zone gove-zone mcp serve-stdio \
  --state-dir "$ACGS_MCP_WORK/stdio-state" \
  --token-file "$ACGS_MCP_WORK/private/token" \
  --session-id local-stdio-session
```

### Loopback Streamable HTTP

This reference listener refuses non-loopback binds. Run it in a second terminal:

```bash
uv run --package gove-zone gove-zone mcp serve-http \
  --state-dir "$ACGS_MCP_WORK/http-state" \
  --token-file "$ACGS_MCP_WORK/private/token" \
  --session-id local-demo-session \
  --host 127.0.0.1 \
  --port 8765 \
  --allowed-origin http://127.0.0.1:8765
```

Point the reference MCP client at `http://127.0.0.1:8765/mcp`. Every HTTP MCP
request must include both headers below; obtain the bearer value from the
owner-only token file without printing or logging it:

```text
Authorization: Bearer <contents of the owner-only token file>
X-ACGS-Session-ID: local-demo-session
```

The session header must exactly match the `--session-id` supplied to
`serve-http`. A missing or mismatched bearer token or session ID fails closed;
the gateway does not fall back to the downstream fixture. This loopback server
is for local evaluation only; it is not a production remote gateway. Stop the
Uvicorn process explicitly with `Ctrl-C` when the HTTP exercise is complete.

## 3. Capture a genuine local proof pack

The demo drives the official outer MCP client against the governed fixture. It
captures one allowed write and one poisoned-catalog denial, then verifies the
result before returning success.

```bash
export ACGS_MCP_EXPORT="$ACGS_MCP_WORK/export"
uv run --package gove-zone gove-zone mcp demo \
  --output "$ACGS_MCP_EXPORT" > "$ACGS_MCP_WORK/demo.json"
cat "$ACGS_MCP_WORK/demo.json"
```

The command exits `0` only after semantic verification and replay succeed. Its
JSON includes `pack`, `verification`, `pack_digest`, and the external
`envelope_digest`. Preserve the latter outside the proof-pack and verification
directories before independently checking either artifact:

```bash
export ACGS_MCP_ENVELOPE_DIGEST="$({
  uv run --package gove-zone python -c \
    'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["envelope_digest"])' \
    "$ACGS_MCP_WORK/demo.json"
})"
printf '%s\n' "$ACGS_MCP_ENVELOPE_DIGEST"
```

The export contains a fixed 16-member proof pack and a separate 3-member
verification envelope. The digest is not an authorization capability; it is an
out-of-band integrity expectation for these offline checks.

## 4. Verify and replay independently

Both commands require the externally captured envelope digest. Omitting it is a
configuration error rather than a permissive fallback.

```bash
uv run --package gove-zone gove-zone mcp verify-proof-pack \
  --pack "$ACGS_MCP_EXPORT/proof-pack" \
  --verification "$ACGS_MCP_EXPORT/verification-envelope" \
  --expected-envelope-digest "$ACGS_MCP_ENVELOPE_DIGEST"

uv run --package gove-zone gove-zone mcp replay-proof-pack \
  --pack "$ACGS_MCP_EXPORT/proof-pack" \
  --verification "$ACGS_MCP_EXPORT/verification-envelope" \
  --expected-envelope-digest "$ACGS_MCP_ENVELOPE_DIGEST"
```

Successful JSON reports `semantic_verified: true` and
`replay_complete: true`. These are local evidence statements, not reusable
Decision Receipts.

## 5. Prove deterministic tamper rejection

Keep the valid export intact, copy it, and change one byte-equivalent region of
the copied manifest. The verifier must exit `1` with structured invalid-proof
JSON:

```bash
cp -R "$ACGS_MCP_EXPORT" "$ACGS_MCP_WORK/tampered"
printf ' ' >> "$ACGS_MCP_WORK/tampered/proof-pack/manifest.json"
set +e
uv run --package gove-zone gove-zone mcp verify-proof-pack \
  --pack "$ACGS_MCP_WORK/tampered/proof-pack" \
  --verification "$ACGS_MCP_WORK/tampered/verification-envelope" \
  --expected-envelope-digest "$ACGS_MCP_ENVELOPE_DIGEST"
ACGS_MCP_TAMPER_STATUS=$?
set -e
test "$ACGS_MCP_TAMPER_STATUS" -eq 1
```

## Client-visible governance metadata

Every governed `tools/call` returns structured governance metadata the official
MCP client can read (in `_governance_meta`). It distinguishes an **authorization
denial** from an **execution refusal**, and it never asks the client to guess:

- **Authorization denial** — the request was refused at the gate. `decision` is a
  deny verdict and `refusalEvidence` / `auditEventId` answer *"was this request
  authorized?"* The downstream fixture is never reached.
- **Execution refusal** — authorization issued an executable receipt, but the
  receipted attempt did not complete cleanly. `status` is `"failed_closed"` and
  the separate `executionRefusalEvidence` / `executionRefusalAuditEventId` /
  `executionRefusalAudited` / `executionRefusalSigned` fields answer *"did this
  receipted attempt run?"* The two audit ids belong to different records and are
  never conflated.

`status: "failed_closed"` means the side effect was refused **before it ran** —
safe to treat as no-op. A `true` `outcomeUnknown` (with `retryable: false`) means
the downstream result is **ambiguous**: do **not** blindly retry an ambiguous
`tools/call`, because the write may or may not have landed. The gateway does not
resolve that state for the client and never silently falls back to the downstream
fixture. Raw-server isolation remains the operator's residual responsibility: if
an Agent can reach the fixture server directly, none of this metadata applies to
that bypass path.

## 6. Measure local overhead

This bounded benchmark compares the governed gateway with the same durable
fixture operation through a separate direct local stdio arm:

```bash
uv run --package gove-zone python \
  packages/gove-zone/benchmarks/mcp_action_gateway.py \
  --samples 25 --warmup 5 \
  --output "$ACGS_MCP_WORK/benchmark.json"
cat "$ACGS_MCP_WORK/benchmark.json"
```

The report records the Python, platform, CPU, memory, serial concurrency
condition, sample counts, raw latency samples, and summary statistics. Treat it
only as single-machine local engineering evidence, never as a production SLA or
capacity claim.

## Thin Python entrypoint

The adjacent `demo.py` intentionally delegates to the same CLI handler instead
of implementing a second policy, receipt, audit, or proof path:

```bash
uv run --package gove-zone python \
  packages/gove-zone/examples/mcp-tool-gateway/demo.py \
  "$ACGS_MCP_WORK/python-entrypoint-export"
```

Its JSON supplies the proof-pack path, verification-envelope path, and external
digest for the same independent commands above.

## Remote TLS listener (P1 remote mode)

`gove-zone mcp serve-http --remote` runs the same governed gateway behind a
directly TLS-terminated listener instead of loopback plaintext HTTP. It uses
the same fixed stdio fixture downstream as the stdio and loopback-HTTP paths
above (`create_reference_runtime`) — remote mode changes the inbound
transport and identity model, not the downstream fixture. There is no
plaintext fallback and no proxy-header trust: TLS terminates directly in
Uvicorn against a process-private snapshot of already-validated certificate
and key bytes, the raw `Host` header must match an exact configured
authority, `Origin` is allowlisted (or explicitly opted out of, for
non-browser workload clients only), and every `Forwarded`/`X-Forwarded-*`
header is rejected outright. Concurrency, request body, header count/bytes,
keep-alive, and graceful-shutdown are all bounded (`RemoteMCPBudgets`); a
saturated listener refuses new work with `503` rather than queuing it in
front of the downstream.

Inbound identity for remote mode is a pinned Ed25519/EdDSA compact-JWS
verifier (`EdDSAJWSVerifier`): a fixed `alg: EdDSA`/`typ: at+jwt`, no
`none`/HMAC path, no header-carried or remotely fetched key, and an exact
claim schema binding issuer, audience, resource, authority, tenant, client,
user, session, scope, and a bounded time window. This is a local/reference
trust profile — a fixed public-key snapshot read once from an operator file —
not a managed PKI, key-rotation service, or full enterprise IAM system. A
normal actor token carries `mcp.tools.call` authority. The optional `/readyz`
probe (`--readyz --health-token-file ...`) runs under a **separate**
`mcp.tools.list`-only identity: that identity can see `fixture.read`'s
catalog metadata (`fixture:catalog` scope) but its signed authority is
rejected by `tools/call` before policy, kernel, or adapter dispatch, so it
can never become a caller. `/readyz` itself answers only the operator's own
loopback peer; a public caller gets a plain `404`, not even a ready/unready
signal.

Minimal flags (see `gove-zone mcp serve-http --remote --help` for the full
budget/identity flag set):

```bash
uv run --package gove-zone gove-zone mcp serve-http --remote \
  --state-dir "$ACGS_MCP_WORK/remote-state" \
  --token-file "$ACGS_MCP_WORK/private/token" \
  --session-id local-remote-session \
  --port 8443 \
  --cert-file /path/to/fixture/server.crt \
  --key-file /path/to/fixture/server.key \
  --expected-host localhost:8443 \
  --allowed-origin https://client.fixture.invalid \
  --identity-trust-file /path/to/fixture/trust.json \
  --identity-issuer https://identity.fixture.invalid \
  --identity-audience acgs-mcp-gateway \
  --identity-resource mcp://fixture-server
```

The certificate, key, and identity trust file above must be fixture/test
material only; this quickstart mints no production TLS or JWS keys.

The actual `mcp serve-http --remote` subprocess is exercised end-to-end by an
official Streamable HTTP MCP client over a real TLS socket — `initialize`,
`tools/list`, one allowed `tools/call` (receipt-backed, single ledger effect),
one denied call, and a clean `SIGTERM` shutdown — by a focused test you can
run directly:

```bash
uv run --package gove-zone python -m pytest \
  packages/gove-zone/tests/test_mcp_runtime_e2e.py \
  -k test_actual_cli_remote_governs_the_streamable_http_tool_and_exits_cleanly \
  --import-mode=importlib -q
```

The full runtime E2E file this test lives in currently passes end to end:

```bash
uv run --package gove-zone python -m pytest \
  packages/gove-zone/tests/test_mcp_runtime_e2e.py --import-mode=importlib -q
```

The graceful-shutdown assertion in that test expects a POSIX `-SIGTERM`
return code (Uvicorn's `Server.capture_signals()` completes its bounded
graceful shutdown, then re-raises the captured signal against the restored
default handler). If a future Uvicorn release changes that re-raise to a
plain `0` exit, the assertion would need updating to match — but it cannot
hide an actual hung shutdown, which still falls through to the test's own
kill-after-timeout and surfaces as `-SIGKILL`, not a false pass.

## Container-isolated Remote HTTP reference

The [`reference-topology`](reference-topology/README.md) example runs an Agent-facing
probe, the ACGS gateway, and a fixture downstream service in separate containers:

```bash
packages/gove-zone/examples/mcp-tool-gateway/reference-topology/run-demo.sh
```

The topology publishes no host ports. The probe and downstream fixture occupy separate
internal networks, while the gateway is the only dual-homed service. The demo uses a
high-entropy, fixture-only credential injected through the service environment; it is
not exposed to the probe. This demonstrates agent-container isolation only: the Docker
daemon and host operator can inspect service environments. It is not a managed secret
store or a production secret-injection pattern.

## Exact limitations

- Local fixture and alpha reference only; no production deployment is claimed.
- Production or public remote configuration requires HTTPS. Plain HTTP is
  limited to the exact container reference fixture capability and loopback test
  mode; neither is a production deployment pattern or production evidence.
- Stdio process isolation here is not proof of OS-level credential isolation
  against an Agent running with the same user privileges.
- The reference protects only calls routed through it. Direct downstream reach
  is an explicit bypass and must be prevented by deployment controls.
- The artifacts demonstrate local cryptographic and replay checks; they do not
  establish compliance certification, regulator approval, or universal MCP
  server safety.
- No real credential, payment, deployment, external message, or production side
  effect is used by this quickstart.
- Remote mode's TLS terminates in this process, not behind an operator load
  balancer or service mesh, and its Ed25519/EdDSA JWS trust is a fixed,
  in-process public-key snapshot from a fixture/test file, not a managed PKI,
  key-rotation service, or full enterprise IAM system.
- Remote mode does not prove external load balancing, high availability, or a
  durable cross-process session store; a saturated or down listener refuses
  work rather than degrading, and the raw stdio-fixture downstream must stay
  unreachable except through the gateway by deployment policy — this reference
  does not enforce that isolation on its own.
