# GOVE_ZONE_MUTATION_AUTHORITY_WIRING_V1 — Mutation Surface Map

Read-only trace of every gove-zone path capable of producing repository state
mutation. Traced from actual callable paths (grep of mutation primitives +
executor read), not inferred from names. Nothing in gove-zone was modified.

## Method

Grep across `packages/gove-zone/src/gove_zone/` for `subprocess`, `Popen`,
`os.system`, `os.replace`, `os.rename`, `os.remove`, `shutil.*`, `write_text`,
`write_bytes`, `open(...,'w'|'a'|'x')`, `mkdir`, `unlink`, and `git`
invocations; then traced the executor path (`executor.py`, `execution.py`,
`gateway.py`) to the irreversible-effect boundary.

## The dominating choke point (governed, in-process)

**`execute_with_receipt` — `executor.py`, effect at `executor.py:236`
(`return tool_fn(**args)`).**

- Everything above line 236 is verification (receipt.verify at :208, ledger
  burn at :234); line 236 is where the side effect runs; nothing reaches it
  without passing verification (fail-closed).
- `GovernedExecutor.execute` (`executor.py:338`) is a thin delegate — not a
  second boundary.
- `UniversalGateway.invoke` (`gateway.py:458`) performs effects by calling the
  same `execute_with_receipt` (`gateway.py:570`).
- All performing callers funnel here: `cli.py` (570/601/643/657/677/696),
  `a2a.py:166`, `adapters/mcp_gateway.py:540`, `escalation.py`/`workflow.py`
  via `GovernedExecutor`.

**Important:** `executor.py` performs effects only by invoking a host-supplied
callable `tool_fn`; it contains no filesystem/subprocess/git primitive of its
own, and it does not know the mutation's `(resource_path, pre_hash, post_hash)`.
That binding information lives in the classifier (`execution.py`), which is
foreign/in-flight — see §"Collision".

## Mutation-capable executors NOT dominated by the receipt gate

| Path | File:line | Note |
|---|---|---|
| `LocalProcessSandbox.run_tool` → `subprocess.run` | `sandbox.py:235` | bwrap-wrapped when available; cleared-env child otherwise, **can still mutate the FS**. `sandbox.py:62` docstring: "this class does NOT silently pretend to isolate". |
| `E2BSandbox.run_tool` | `sandbox.py:284` | remote microVM exec |
| MCP downstream-server spawn | `adapters/mcp_gateway.py` (stdio_client) | spawns subprocess; its tool calls route back through `execute_with_receipt:540`, but the spawn itself is a separate carrier |

## Governance-infrastructure writes (not repository-content mutation)

Append-only / atomic-replace persistence of the governance layer itself — audit
chains, ledgers, receipts, captures, proofpacks. Listed for completeness; these
are not the agent-driven source mutation the invariant targets.

`consumption.py` (547/551/553, 629/633/635, 757/762/767, 976/981/985,
192/275/333/685/958), `audit.py` (91/107/123/155/176), `capture.py`
(221/226/265/268), `replay_store.py` (56/100), `metrics.py` (91/92),
`proofpack.py` (188/389/410/425/1018/1026/1041/1060), `cli.py`
(415-416/501-505/569/599/636/714/719/734/741/790), `policy.py` (680/935),
`yaml_policy.py` (70/122), `tenant.py` (51/59/65/74), `gateway.py` (356/374),
`integration.py:716`, `agent.py:55`, `setup.py` (117/119/120), `smoke.py:50`.

## Per-path disposition table

| Entry point | Executor/function | Mutation capability | Current auth | MutationGateway mediates? | Disposition |
|---|---|---|---|---|---|
| governed tool call | `execute_with_receipt` (executor.py:236) | host `tool_fn` effect | gove-zone `DecisionReceipt` verify + ledger burn | **No** | dominating choke point; wiring blocked (collision) |
| hook decide leg | `UniversalGateway.decide_hook_event` (gateway.py:1022) | none (decide-only; host executes) | Policy→Receipt | No | decide-only; host is executor leg |
| exec classification | `execution.py` `classify_command` / `make_execution_call_factory` | none (classifier) | routes to `execution_boundary` | No | **foreign/in-flight**; opt-in, not auto-wired |
| local sandbox | `sandbox.py:235` `subprocess.run` | arbitrary FS via child | bwrap (best-effort) | No | separate carrier; self-declared non-isolating |
| remote sandbox | `sandbox.py:284` E2B | remote exec | microVM | No | separate carrier |
| MCP gateway | `adapters/mcp_gateway.py` | subprocess spawn | routes calls to :540 | No | spawn is separate carrier |

## Wiring status of `execution.py`

Exported from `__init__.py` but **inert-by-default**: no internal caller invokes
`make_execution_call_factory` / `execution_tool_calls_from_hook_payload` /
`build_execution_gateway` — they appear only at their definitions and as export
strings. The live hook path defaults to the plain `tool_calls_from_hook_payload`
(`gateway.py:1059`); the execution classifier enters only if an external caller
passes `call_factory=make_execution_call_factory(...)`. Even when wired,
`execution.py` carries zero mutation primitives — it only classifies/names a
proposed call for the non-executing decide leg.

## Unenforceable-by-design residuals (the foreign layer's own admissions)

These bound the achievable claim **independent of the collision** — they are
ceilings, not gaps to be closed by this wiring:

- **Shell-operator effects are undecidable.** `execution.py:40-45`: "`>`, `|`,
  `cp`, `mv` and `$(...)` mutate tracked source without naming a governed
  binary … `classify_command` marks the event `decidable=False` and does not
  route it to a risk-bearing surface." (impl: `execution.py:402-411`, 437-448)
- **Lifecycle scripts are not mediated at execution** (`execution.py:46-49`).
- **Interactive-terminal invocation is unobserved — the ADV9 residual**
  (`execution.py:50-52`): "A manager invoked from an interactive terminal is
  not observed at all."
- **The local sandbox subprocess can carry real mutations when bwrap is
  absent** (`sandbox.py:62`, 91-96).

Consequence: even on a stable baseline and fully wired, "no valid receipt → no
governed repository state change" would hold for **classified, hook-observed,
in-process** mutation — not for all repository mutation.

## Collision (why wiring is not attempted here)

The choke-point surface needed to make MutationGateway non-bypassable and to
supply per-mutation `(resource, hashX→hashY)` binding is foreign, uncommitted,
and mid-flight:

| File | sha256 (first 16) | git state | mtime |
|---|---|---|---|
| `gateway.py` | `e5663ff555516eb3` | modified (+14: `call_factory` seam) | Aug 9 13:24 |
| `integration.py` | `04c10592a80d7c4e` | modified (+26: classifier helpers) | Aug 9 13:23 |
| `__init__.py` | `414fea99153e6147` | modified (+20: execution exports) | Aug 9 13:32 |
| `execution.py` | `8686ca854488089c` | **untracked** (ADR-0010/P11 layer) | Aug 9 13:48 |

Plus untracked P12 suites: `tests/test_execution_bypass_adversarial.py`,
`tests/test_execution_governance.py`, `tests/test_p12_boundary_validation.py`,
and ADRs `docs/adr/0010-execution-governance-layer.md`,
`0011-p12-execution-trust-boundary.md`.

Per the task's Collision rule, this in-flight competing execution-governance
design is not overwritten, not merged, and not built upon. See ARCHITECTURE.md
for the composition design the wiring would follow once that baseline lands, and
REPORT.md for the verdict.
