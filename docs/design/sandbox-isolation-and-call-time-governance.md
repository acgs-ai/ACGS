# Sandbox Isolation and Call-Time Governance: Two Layers, One Boundary

Status: Note
Supplements: `docs/design/acgs-governed-hermes-in-context-runtime-governance.md`
Drivers: clarify how an externally provisioned agent sandbox (network-isolated
container, egress policy tiers, managed tool gateways) composes with ACGS
call-time governance, without implying ACGS provisions or network-tiers anything.

## Context

The companion design doc,
`acgs-governed-hermes-in-context-runtime-governance.md`, specifies how ACGS
intercepts a Hermes-style agent's **proposed side effects at call time**: a tool
call is normalized into a governance request, evaluated against a versioned
constitution bundle, allowed or denied before execution, and recorded in
hash-linked audit evidence. That doc is the authoritative interception story.

It does not describe the layer *underneath* the agent: the sandbox the agent
runs inside. Modern agent runtimes are increasingly deployed as isolated
containers with their own provisioning-time controls — for example, a
NemoClaw/OpenShell-style flow that stands up a per-agent sandbox, applies a
network policy tier, pins an inference egress route, and optionally exposes
managed tool gateways (web search, browser automation, code execution). This
note clarifies how that layer relates to the ACGS boundary.

ACGS ships none of this provisioning tooling. The sandbox, its network tier, and
its inference route are external infrastructure. Product and command names below
are illustrative of that external layer, not features of this repository.

## The two layers are complementary, not the same control

It is tempting to map "sandbox network tier" onto the constitution bundle's
network allowlist and call them the same rule. They are not. They are different
enforcement layers, enforced at different times, by different enforcers:

| | Provisioning-time isolation | Call-time governance |
|---|---|---|
| Enforcer | External sandbox/container infra | ACGS gate |
| When | Before the agent runs, at sandbox build | When a tool call proposes a side effect |
| What it constrains | What the *container* can reach (egress, mounted paths, exposed ports) | Whether a *proposed action* is authorized, and the evidence for it |
| Failure mode it covers | Compromised process exfiltrating over an un-tiered network | An authorized process proposing an unsafe but reachable action |
| Output | A confined runtime | A decision receipt + audit event, replayable |

Neither subsumes the other. A network tier can stop a host from being reachable
at all; it cannot decide that a *reachable* host is policy-permitted for *this
actor and intent*, nor produce a replayable receipt for the call. The ACGS gate
does the latter and cannot confine the container. Run both: defense in depth.

## Where the boundary sits

The boundary ACGS owns begins when the sandboxed agent **proposes a
side-effectful tool call** and ends when a valid `ALLOW`/`TRANSFORM` receipt
authorizes execution (see `concepts/tool-boundaries.md` and
`concepts/fail-closed-enforcement.md`). Everything before that — image build,
egress tiering, dashboard/API auth, inference routing — is the provisioning
layer's responsibility and is out of ACGS scope.

The one honest touchpoint between the layers today is the
`ExecutionBoundary` label on the tool-call contract
(`packages/gove-zone/src/gove_zone/contracts.py`): an opaque string such as
`"tenant-A/prod-egress"`. A host integrating a sandbox can record the sandbox's
identity as that label so a receipt carries *where* the approved action was
meant to run. This is audit/replay metadata, not enforcement — gove-zone does
not act on the string today.

## What this means for an integrator

To govern a sandboxed agent, the sandbox's proposed side effects must still be
normalized into the `gove-zone gate` JSON contract and gated before execution —
exactly the adapter work described in the companion design doc. The sandbox
layer does not remove that requirement; it only narrows what the agent's
container can physically reach.

Concretely, regardless of how the sandbox is provisioned:

- Side-effectful calls (shell, file write, network, MCP tool, deploy) cross the
  ACGS gate, or the boundary is advisory rather than authoritative.
- Managed tool gateways exposed inside the sandbox (web search, browser, code
  execution) are themselves tool boundaries; each is a call ACGS should gate,
  not a pre-blessed capability.
- A confined network tier is not a substitute for a call-time `ALLOW` decision
  with a receipt.

## Verify before claiming

Do not state or imply that gove-zone provisions sandboxes, enforces network
tiers, or routes inference. It does none of these. Its surface is the gate,
policy, receipt, and audit path documented in `docs/quickstart.md` and the
companion design doc. Keep this note's provisioning references illustrative.
