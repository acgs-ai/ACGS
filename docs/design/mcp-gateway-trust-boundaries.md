# MCP Gateway — Trust Boundaries

Status: **alpha / design-partner pilot**. Describes the actual trust boundaries of
`packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py` as built today. Nothing
here claims production readiness, certification, compliance approval, or
regulator-ready behaviour (see `docs/CLAIMS.md`).

## Scope

The gateway is a transparent stdio proxy: an MCP *server* to the host, an MCP
*client* to one downstream server, gating `tools/call` through the sealed
gove-zone kernel. Full architecture is `docs/design/mcp-gateway-design.md`; this
doc answers one question the design doc and `docs/SECURITY_MODEL.md` leave
implicit — **who is trusted to do what, and on what basis** — across the two
places the gateway crosses a trust line: the MCP transport itself, and the
out-of-band human-approval surface layered on top of it.

## Boundary 1 — host → gateway (MCP transport)

This restates and cross-links what the module docstring and
`docs/SECURITY_MODEL.md` § "Governed-MCP gateway trust boundary (alpha)" already
say; it is not new ground, only consolidated here alongside boundary 2.

- **The host↔gateway hop is assumed trusted-local.** In the alpha runtime
  (`run_stdio_gateway`), the gateway is a stdio subprocess the operator launched
  — same trust domain as the host. The gateway does **not** authenticate the
  host at the transport level.
- **The session principal is only as strong as that transport.** `_resolve_principal`
  derives the principal from the MCP `clientInfo.name` presented at `initialize`,
  mapped through `GatewayConfig.principals` — never from a `tools/call` request
  body (`_governed_tools_call` builds `ToolCall` with `actor=ctx.principal`, not
  from `arguments`). A forged `actor` field in the call payload is inert.
- **Session isolation is real, not just documented.** `_sessions` is a
  `WeakKeyDictionary[ServerSession, SessionContext]` — keyed by the session
  object's identity, not `id()`. This closes the cross-session actor-bleed fix
  landed in PR #244 (an `id()`-keyed cache lets CPython recycle a closed
  session's address into a later session, leaking the earlier principal). The
  weak-key mapping auto-evicts when a session is garbage collected and never
  collides across concurrent live sessions — each governed `Kernel` instance in
  `SessionContext.kernel` carries its own bound `actor`, so two interleaved
  sessions never share state.
- **Enforcement point is first `tools/call`, not `initialize`.** The low-level
  MCP `Server` owns the handshake; an unmapped principal is fail-closed with a
  DENY `CallToolResult` (`_unmapped_principal_result`) at the first governed
  call rather than by rejecting `initialize`.
- **Non-goal this pass: authenticated host→principal binding under
  streamable-HTTP.** The stdio trust assumption does not survive a transport
  swap to a remote/multi-tenant listener without an explicit authentication
  step binding the transport identity to the principal map. That work is
  roadmap (see `docs/SECURITY_MODEL.md`'s Governed-MCP gateway section and the
  Follow-ups below), not shipped.

## Boundary 2 — the out-of-band operator surface (the gap this doc closes)

`build_server()` registers only `tools/list` (pass-through) and `tools/call`
(the governed gate); every other method is left unregistered so the MCP SDK
answers *method-not-found*. `approve()`, `resume()`, and `pending_descriptor()`
are **not MCP-reachable at all** — they are plain Python methods on
`GovernedGateway`, called out-of-band by an operator/CLI process (the
`gove-zone approve-escalation` verb referenced in the ESCALATE response's
`how_to_approve` field). This was previously true but undocumented; it is the
residual this doc exists to make explicit.

**These three methods carry no caller-identity check of their own.** Nothing in
`approve()` or `resume()` asks "who is calling me?" — there is no session,
principal, or request context at this layer. That is not an oversight to patch
inside the method; it is a statement about where the actual boundary lives.

**The real gate is possession, not code.** Two things must be in the caller's
process to produce a resume the gate will accept:

1. **A distinct `Validator` identity.** `GatewayConfig.__post_init__` refuses at
   config load if `validator.validator_id` collides with any mapped principal
   (self-validation forbidden up front). `approve_escalation` (via
   `DecisionReceipt.from_record`) enforces the same MACI separation again at
   mint time — `validator == proposer` raises. Whoever calls `approve()` must
   construct (or be handed) a `Validator` object whose id was never assigned to
   an agent principal in this deployment's config.
2. **The config signer key.** When the profile is `production` (the default),
   `approve_escalation` mints the approval receipt via `self._config.profile.signer`
   — an `Ed25519Signer` loaded from the raw private-key file named in the
   config's `[signing]` block (`_load_signer`). Without that key on the
   approving process, `resume()`'s downstream gate (which requires the matching
   verifier when `require_signature=True`) refuses the receipt.

So the practical boundary is **the process / CLI trust domain**: whoever can run
code with access to (a) a validator identity distinct from every agent
principal and (b) the signer's private key file can approve and resume any
parked escalation. This is deliberately the same posture `docs/SECURITY_MODEL.md`
names ADV2 (insider/operator) — privileged-but-policy-bound, not authenticated
at this API layer.

**`pending_descriptor()` is operator-sensitive.** `pending_to_dict` serializes
the *full* parked record — the escalated tool, the exact proposed args, and the
audit anchor — into a portable descriptor for the out-of-band approve verb.
Anyone holding a descriptor plus the validator identity and signer key can
approve that exact call. Custody requirement: hold descriptors, validator
identity material, and the signer key with the same care as the audit chain
itself (file permissions / secrets storage outside the gateway process's own
authority — the gateway does not protect them for you). This is an operational
control, not a code-enforced ACL; there is no in-process rate limit or audit
trail on *who* ran `approve()`, only on the decision it produced (the approval
is itself appended to the audit chain as its own governed event).

**Bounded-capacity back-pressure changes the availability posture, not the
authn posture.** This hardening pass adds `max_pending` and
`max_pending_per_principal` to `GatewayConfig`: once either cap is reached, a
new ESCALATE is rejected as a fail-closed DENY (with its own audit record)
*before* it is parked, rather than growing `_pending`/`_approvals` without
bound. This converts the previously unbounded per-instance memory-DoS (anyone
who can reach `tools/call` could grow both maps forever) into a bounded,
**audited** escalation-availability trade-off: a noisy principal can exhaust
its own sub-limit and starve its own future escalations, but every rejection is
visible in the audit chain rather than a silent resource leak. It does not
change who can call `approve()`/`resume()` — that remains boundary 2's
process/CLI trust domain, unchanged by this pass.

## Non-goals / roadmap (explicit)

- Authenticated host→principal binding under a streamable-HTTP transport
  (boundary 1's stdio assumption does not carry over automatically).
- Operator authentication in front of the CLI `approve()`/`resume()` surface —
  today, process/CLI access to validator identity + signer key *is* the
  authorization.
- Telemetry on capacity-rejection rates to help an operator tune `max_pending`
  / `max_pending_per_principal` for their deployment.

None of these are silently assumed solved elsewhere in the codebase; each is
named here so a reviewer does not have to infer it from the source.

## Cross-references

- `docs/design/mcp-gateway-design.md` — full gateway design (G1–G6).
- `docs/SECURITY_MODEL.md` — threat table and adversary model; see "Governed-MCP
  gateway trust boundary (alpha)" (boundary 1) and ADV2 / ADV5 / ADV9 (the
  insider-operator, cross-tenant, and executor-bypass adversaries this doc's
  boundary 2 maps onto).
- `docs/CLAIMS.md` — claim-safe wording ledger; nothing in this doc should be
  read as an authentication or authorization guarantee beyond what is described
  above.
- `packages/gove-zone/src/gove_zone/adapters/mcp_gateway.py` — source of record;
  see its module docstring for the boundary-1 restatement and `GovernedGateway.approve`
  / `.resume` / `.pending_descriptor` for the boundary-2 mechanics.
