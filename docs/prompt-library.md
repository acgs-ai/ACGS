# Prompt library

Copy-paste prompts to give your agent — Claude Code or any harness — when you
are working **with** the ACGS governance boundary in this checkout. Use them to
explore the governance plane, wire it into a host, test deny paths, verify
receipts, and make readiness claims you can defend.

These are starting points, not scripts. They are written for the local
`gove-zone` runtime surface as documented in [Common workflows](common-workflows.md),
the [concept pages](README.md#concepts), and the [CLI reference](reference/cli.md).
Open **Why this works** under any prompt to see the pattern, then adapt it to your
own host.

Fields in `{braces}` are placeholders — fill them in before sending. Run
`uv run --package gove-zone gove-zone --help` for the authoritative command list
in your checkout.

> **Claim discipline.** Every prompt here produces *local proof* at most — command
> output and receipts from this repository. None of it is deployment proof or
> compliance certification. See [Make readiness claims safely](common-workflows.md#5-make-readiness-claims-safely)
> and the [claim boundary](#claim-boundary).

---

## Understand the boundary

### Get oriented in the governance plane

```text
give me an overview of how ACGS decides whether an action is authorized: where
the gate sits relative to the agent and the tool, what a decision receipt
contains, and how a host blocks a denied call. read docs/introduction.md and the
concept pages first, and don't change anything
```

**Why this works** — Describe what you want to understand, not which files to read.
The boundary is the point of the system; ask the agent to locate it before it
touches anything. See [Introduction](introduction.md) and [Authority model](concepts/authority-model.md).

### Explain a concept against the code

```text
explain {concept} as it is actually implemented in packages/gove-zone, and show
me the exact line where a side effect is blocked when the decision denies
```

`{concept}` → `fail-closed enforcement`

**Why this works** — Pin the explanation to the implementation, not the prose. The
answer should point at the block path, which is where the concept either holds or
fails. See [Fail-closed enforcement](concepts/fail-closed-enforcement.md).

### Find where a decision is made

```text
where in packages/gove-zone is a proposed tool call evaluated before execution,
and where is the decision receipt emitted?
```

**Why this works** — Search by behavior, not filename. "Evaluated before execution"
and "receipt emitted" are the two load-bearing events; finding them is the fastest
way into the codebase. See [Decision receipts](concepts/decision-receipts.md).

### Trace authority for one action

```text
walk me through what happens when a {host} proposes {action}, from the proposed
tool-call payload down to the retained audit event
```

`{host}` → `MCP bridge` · `{action}` → `a file write`

**Why this works** — One concrete action traced end to end reveals every stage the
boundary owns: normalize, evaluate, decide, receipt, audit. See [Tool boundaries](concepts/tool-boundaries.md).

---

## Integrate a host

*For: integrators, platform owners.*

### Generate host setup guidance

```text
run gove-zone setup --format json and gove-zone doctor, then tell me exactly
which pre-tool event in {host} I should install the gate in, and what report
mode looks like before I turn on enforcement
```

`{host}` → `my hook host`

**Why this works** — Let the CLI produce the integration guidance instead of guessing
the wiring. Starting in report mode means you see receipts before any call is
blocked. See [CLI reference](reference/cli.md) and [Hooks or runtime overview](hooks-or-runtime/overview.md).

### Wire the gate into a pre-tool hook

```text
wire the gove-zone gate into the pre-tool event of {host} so that a denied
decision blocks the side effect. start in report mode. then add a test that
sends a denied call through the host's real dispatch path and confirms it does
not execute — not a unit test that imports the handler and calls it directly
```

`{host}` → `my runtime`

**Why this works** — A handler that compiles and passes a unit test can still be
unwired — never registered in the path that receives traffic. Demand a test that
exercises the dispatch path, so "wired" is proven, not assumed. See [Common workflows §2](common-workflows.md#2-wire-a-hook-capable-host).

### Normalize an MCP tool call

```text
normalize an MCP {tool} call into the ACGS tool-call contract and evaluate it
through the gate. treat it as a proposed side effect: emit a receipt, and block
it if it is unverifiable
```

`{tool}` → `filesystem write`

**Why this works** — MCP standardizes how agents call external capabilities, which
makes every MCP call a trust-boundary crossing. Routing it through the same
normalize → evaluate → receipt → block contract keeps one governance path. See
[MCP overview](mcp/overview.md).

### Add a new agent-framework adapter

```text
the {framework} emits tool calls in its own payload shape. normalize that into
the ACGS tool-call contract, and prove the adapter is reached on the real host
path with tests for allow, deny, malformed, and batch inputs
```

`{framework}` → `LangGraph`

**Why this works** — Adapters are where governance silently leaks: the normalizer
exists but nothing routes through it. The four input classes plus a wiring proof
are the minimum that shows the adapter is live. See [Common workflows §4](common-workflows.md#4-add-a-new-agent-framework-adapter).

---

## Enforce and test deny paths

*For: integrators, security, on-call.*

### Test the deny path before enforcing

```text
run gove-zone smoke and show me the allow, deny, and audit-chain output. then
construct an event that must be denied, run it through the gate, and confirm the
decision blocks it
```

**Why this works** — The allow path is easy; the deny path is the product. Prove a
denial blocks before you trust the boundary in enforce mode. See [Quickstart](quickstart.md).

### Construct a must-deny event

```text
write a proposed tool-call event for {action} that crosses a trust boundary and
must be denied. load the policy bundle that defines that denial, pipe the event
into `gove-zone gate --actor {actor}`, and confirm the decision is a deny or
escalate — then show me the receipt
```

`{action}` → `deleting a protected path` · `{actor}` → `test`

**Why this works** — A concrete denial event is a reusable regression fixture. The
denial comes from policy, not from the gate alone: with no policy bundle loaded
the gate may return an allow or a plain decision payload, so point it at the
bundle that defines the denial (see the CLI's `--policy-bundle`). The receipt is
the evidence that the denial was recorded, not just returned. See
[Decision receipts](concepts/decision-receipts.md).

### Move from report mode to enforce mode

```text
we are running the gate in report mode. list every deny and escalate path that
currently has a test, then tell me what is still missing before it is safe to
switch {host} to enforce mode
```

`{host}` → `the host`

**Why this works** — Enforce mode is a one-way trust decision. Inventory the tested
deny paths first so the switch is gated on evidence, not optimism. See
[Common workflows §2](common-workflows.md#2-wire-a-hook-capable-host).

### Prove fail-closed, not fail-open

```text
show me what happens when policy evaluation cannot complete or the decision is
unverifiable. confirm the host blocks the action (fail-closed) rather than
letting it through, and point me at the test that proves it
```

**Why this works** — A guardrail that silently fails open is worse than none, because
it looks safe. The behavior under failure — not under success — is what makes the
boundary trustworthy. See [Fail-closed enforcement](concepts/fail-closed-enforcement.md).

---

## Verify and audit

*For: auditors, security.*

### Verify a decision receipt

```text
verify the decision receipt for {action} against the expected actor, action,
arguments, and policy context. tell me precisely what does not match if anything
```

`{action}` → `the last denied call`

**Why this works** — A receipt is only evidence if it is checked against what was
expected. Naming the four fields makes the verification reviewable instead of a
glance. See [Decision receipts](concepts/decision-receipts.md).

### Replay an audit trail

```text
read the audit JSONL at {path}, confirm each event is chained to the previous
one, and tell me if the chain has any gaps or breaks
```

`{path}` → `.gove-zone/quickstart-audit.jsonl`

**Why this works** — Audit replay turns a log into evidence: a chained sequence you
can re-verify offline. A gap is the signal that something was dropped or altered.
See [Audit replay](concepts/audit-replay.md).

### Attempt a tamper and confirm it is caught

```text
take the audit trail at {path}, mutate one recorded event, re-verify the chain,
and confirm the tamper is detected. then restore the original file
```

`{path}` → `.gove-zone/quickstart-audit.jsonl`

**Why this works** — Tamper-evidence is a claim until you try to tamper. A deliberate
mutation that the chain verification rejects is the proof. See [Audit replay](concepts/audit-replay.md).

### Assemble an evidence bundle

```text
assemble a review evidence bundle for {scope}: the decision receipts, the audit
trail path, and the exact command output that produced them. label it as local
proof — do not present it as deployment proof
```

`{scope}` → `this checkout`

**Why this works** — An evidence bundle is reviewable only if it carries the receipts,
the audit path, and the literal command output together. The honest label keeps it
from being read as more than it is. See [Evidence bundles](concepts/evidence-bundles.md).

---

## Operate and claim safely

*For: on-call, security, platform owners.*

### Debug a suspected fail-open

```text
a {action} happened that should have been denied. check the gate wiring, the
policy context, and the audit trail, and tell me whether the gate was bypassed,
never wired, or the policy actually allowed it
```

`{action}` → `protected file write`

**Why this works** — "Should have been denied but wasn't" has three distinct causes —
unwired, bypassed, or permitted by policy — and they need different fixes. Make the
agent distinguish them before changing anything. See [Tool boundaries](concepts/tool-boundaries.md).

### Write a claim-safe readiness statement

```text
summarize what we can honestly claim from this checkout. separate local proof,
release readiness, deployment proof, and compliance proof — and do not collapse
them into a single "production-ready" claim
```

**Why this works** — The most common governance overclaim is collapsing four distinct
evidence classes into one. Keeping them separate is the difference between a
defensible statement and marketing. See [Common workflows §5](common-workflows.md#5-make-readiness-claims-safely).

### Triage an action that escaped the boundary

```text
{symptom}. correlate the audit trail, the recent policy changes, and the host
wiring, then tell me the most likely cause and the smallest change that closes
the gap
```

`{symptom}` → `an unsigned tool call reached a protected resource`

**Why this works** — List the evidence sources to correlate, not the steps to take.
The audit trail, policy history, and wiring together narrow an escape to its cause.
See [Troubleshooting](troubleshooting/common-issues.md).

### Turn a correction into a governance rule

```text
you keep {mistake}. add a rule to the nearest CLAUDE.md or AGENTS.md so this
stops happening in future sessions
```

`{mistake}` → `proving a handler with a unit test instead of a wired integration test`

**Why this works** — A correction in chat is forgotten next session; a rule in the
repo's instruction file is read at the start of every one. Governance conventions
belong where the next agent will see them.

---

## What makes a good governance prompt

The prompts above share a few patterns. Recognizing them lets you adapt any of
them — or write your own — without losing claim discipline.

**Name the trust boundary, not the file.** Say which crossing you care about and
let the agent locate the gate.

```text
where do we authorize a tool call before it touches the filesystem?
```

**Ask for the receipt and the audit event, not just the change.** The artifact is
the evidence; a change with no receipt is not governed.

```text
make this call go through the gate and show me the receipt it produced
```

**Make it prove the deny path, not only the allow path.** Denials are the product;
test them explicitly.

```text
construct a call that must be denied and confirm the host blocks it
```

**Prove the handler is wired, not just imported.** A passing unit test does not
prove the gate is in the path that receives traffic.

```text
add a test that sends a denied call through the real dispatch path, not one that
calls the handler directly
```

**State the claim class.** Tell the agent which evidence class the output belongs to
so it does not overclaim.

```text
label this as local proof, not deployment proof
```

**Give it the artifact.** Paste the event JSON, the audit JSONL, or the policy
context, or `@`-mention the file, instead of describing it.

```text
why was this call allowed? @.gove-zone/quickstart-audit.jsonl
```

---

## Where these come from

These prompts are grounded in this repository's own documentation and runnable
surfaces. Each section links to its source:

- [Common workflows](common-workflows.md) — the evaluate / wire / review / adapt / claim flows
- [Concept pages](README.md#concepts) — authority model, decision receipts, evidence bundles, fail-closed enforcement, audit replay, tool boundaries
- [CLI reference](reference/cli.md) — `setup`, `doctor`, `smoke`, `gate` (run `--help` for the full list)
- In-repo runnable examples under `packages/gove-zone/examples/` — `receipt-gated-execution/demo.py`, `plan-level-governance/demo.py`, `workflow-receipt-chain/demo.py`, `runtime_hook_demo.py`, `write_file_guard.py`

## Claim boundary

Local receipts, smoke tests, and lint output are readiness evidence. They are not
production deployment proof or compliance certification unless the matching
live or external evidence is present. The prompts on this page help you produce
and verify that local evidence — they do not, by themselves, establish deployment
or compliance.
