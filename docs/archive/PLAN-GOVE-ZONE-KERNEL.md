# Gove Zone — Kernel Extraction Plan

> Scope: turn this monorepo's sprawl into a minimal **Governed Agent Runtime**
> shipped as a single library — `gove-zone` — under 2,500 LOC. Existing packages
> (`acgs-lite`, `Acgs-Swarm`, `clinicalguard`, …) become consumers or
> domain-extensions of the kernel, not the kernel itself.
>
> Companion to:
> - `docs/PLAN-MONOREPO.md` — workspace unification (mostly landed)
> - `PLAN.md` — frontend (`acgi-ai/`) completion, unrelated
> - `MONOREPO.md` — workspace registry

---

## §1 Premises (challenge first)

1. **Current state is not a kernel.** Across packages there is ~134k LOC of
   Python. The "governance" surface is a 681-LOC `GovernedAgent` that wraps
   `agent.run(text)` and validates strings against rules. The kernel target is
   one layer below: intercept *individual tool calls* before any side effect.
2. **The audit primitive is solid.** Two implementations exist
   (`acgs-lite/src/acgs_lite/audit.py`, `acgs_governance_eval_mvp/governance/audit/jsonl_chain.py`).
   `jsonl_chain.py` is the cleaner seed (process-safe `fcntl.flock`, structured
   `verify_chain()` result, ~150 usable LOC).
3. **The boundary primitive is partial.** `acgs-lite/src/acgs_lite/constitution/boundaries.py`
   blocks free-text actions, not structured tool-call arguments. Needs reshaping.
4. **The tool-interception core does not exist.** It must be written.
5. **`acgs-lite` is published on PyPI** and has downstream consumers.
   It cannot be deleted or restructured destructively. The kernel ships as a
   *new* package that `acgs-lite` may later depend on, not the other way around.
6. **Constitutional hashes are sealed.** Files with `# Constitutional Hash:`
   markers must not silently change. CI verifies on every PR.

If any premise is wrong, halt before executing.

---

## §2 Definition of done (MVP)

Per the goal statement — the kernel succeeds when:

> A developer can understand the core in one afternoon, use it in one day, and
> trust it to block unsafe agent actions before they happen.

Concretely, MVP acceptance:

| Acceptance criterion | Bar |
|---|---|
| **Governed tool calls** | Every `write_file`, `http_post`, `db_exec`, `shell`, etc. is intercepted before execution via a single typed `Decision`. Unit + integration tests prove the dispatcher path, not just the function. |
| **Fail-closed behavior** | If policy eval, receipt generation, audit append, or storage fails, the action is *denied*. No exceptions swallow into "allow". |
| **Replayable receipts** | Every decision records: goal, action, tool, argument hash, policy version, matched rules, decision, reason, timestamp, audit hash. Receipts are reconstructable from the audit log. |
| **Tiny core** | `gove_zone/` source ≤ 2,500 LOC, line length 100, full type hints (`mypy --strict` clean), single dependency on stdlib + pydantic. |
| **One-afternoon onboarding** | A `README.md` with one runnable example end-to-end ≤ 50 lines of user code. |

A passing unit test does NOT prove handler wiring — see
`~/.claude/rules/review-handler-wiring.md`. Every tool registration ships
with a dispatcher-level test.

---

## §3 Target shape

```
packages/gove-zone/                 (new uv-workspace package)
├── pyproject.toml                  # name = gove-zone, python ≥ 3.11, deps: pydantic only
├── README.md                       # one-afternoon onboarding
├── src/gove_zone/
│   ├── __init__.py                 # public surface (≤ 30 names)
│   ├── kernel.py                   # the loop: action → decision → execute/deny → receipt
│   ├── decision.py                 # Decision enum + DecisionRecord dataclass
│   ├── tool.py                     # Tool registry + ToolCall typed schema
│   ├── policy.py                   # Policy ABC + concrete BoundaryPolicy (reshaped from boundaries.py)
│   ├── receipt.py                  # Receipt dataclass + canonical serialization
│   ├── audit.py                    # ChainHashAuditStore (port of jsonl_chain.py)
│   ├── replay.py                   # Reconstruct decisions from audit log
│   ├── errors.py                   # Typed errors (DeniedError, PolicyError, AuditError)
│   └── trace.py                    # Lightweight span emission (no OTEL hard dep)
└── tests/
    ├── test_kernel_dispatch.py     # proves tool-call interception path
    ├── test_fail_closed.py         # every failure mode → DENY
    ├── test_audit_chain.py         # tamper-evident chain integrity under concurrency
    ├── test_receipt_replay.py      # receipts round-trip
    └── test_policy.py
```

### LOC budget (target 2,500, hard ceiling 2,750)

| Module | Target LOC | Source |
|---|---|---|
| `kernel.py` | 400 | greenfield |
| `decision.py` | 100 | greenfield |
| `tool.py` | 200 | greenfield |
| `policy.py` | 250 | reshaped from `boundaries.py` |
| `receipt.py` | 200 | greenfield |
| `audit.py` | 400 | ported from `jsonl_chain.py` + minimal from `audit.py` |
| `replay.py` | 200 | greenfield |
| `errors.py` | 80 | greenfield |
| `trace.py` | 150 | greenfield |
| `__init__.py` | 50 | re-exports |
| **Subtotal source** | **2,030** | |
| Headroom | 470 | for docstrings, type aliases |

### What's explicitly NOT in the kernel

- Constitutional rule loading from YAML (Constitution + rules engine)
- LangGraph / Phoenix / CrewAI integrations
- MACI separation-of-powers enforcement
- Circuit breaker (Article 14)
- EU AI Act compliance framework
- CDP record assembly
- Swarm coordination, debate resolution
- Provider capability registry
- Constrained-output adapter (provider response_format injection)

These are *extensions*, shipped in separate packages or deferred. The kernel
does not import them.

---

## §4 Decision model (the central abstraction)

```python
# decision.py
from enum import Enum
from dataclasses import dataclass

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"  # execute with modified arguments
    ESCALATE = "escalate"    # block + require external approval

@dataclass(frozen=True)
class DecisionRecord:
    decision: Decision
    tool: str
    argument_hash: str          # sha256(canonical_json(args))
    policy_version: str         # hash of policy bundle
    matched_rules: tuple[str, ...]
    reason: str
    timestamp_iso: str
    receipt_id: str             # ulid
    audit_hash: str             # chain hash returned by audit append
    transformed_args: dict | None = None  # only set when Decision.TRANSFORM
```

Every external action emits exactly one `DecisionRecord`. Replay is
`recompute_decision(record, current_policy)` — succeeds if and only if the
audit chain verifies AND the policy produces the same decision.

---

## §5 Phased execution

### Phase 0 — Plan record (ZERO blast radius) — THIS FILE

- [x] Write `docs/PLAN-GOVE-ZONE-KERNEL.md`
- [ ] User confirms scope, naming (`gove-zone`), kernel boundary

### Phase 1 — Skeleton + audit port (LOW blast radius)

Single new submodule under `packages/gove-zone/` — does not touch any existing
package. Reversible by deleting the directory.

1. `git submodule add` or plain dir (decide alongside §6.1)
2. `pyproject.toml` declaring the package, `requires-python = ">=3.11"`, deps:
   `["pydantic>=2.0"]`. No optional integrations.
3. Port `acgs_governance_eval_mvp/governance/audit/jsonl_chain.py` →
   `gove_zone/audit.py`. Strip the `governance.models` import; define
   `DecisionRecord` locally. Keep `fcntl.flock`, `fsync`, `verify_chain()`.
4. Property-test the audit chain: concurrent appends from N processes; verify
   chain integrity holds.
5. Add the package to the uv workspace in root `pyproject.toml`.

**Stop gate after Phase 1.** Show the user the kernel skeleton +
`pytest packages/gove-zone -q` output.

### Phase 2 — Kernel loop (MEDIUM)

Greenfield code. The central loop:

```python
def kernel.dispatch(tool_call: ToolCall, *, policy: Policy, audit: AuditStore) -> Any:
    record = policy.evaluate(tool_call)         # → DecisionRecord (without audit_hash)
    audit_hash = audit.append(record)            # tamper-evident anchor
    record = record.with_audit_hash(audit_hash)
    if record.decision is Decision.DENY:        raise DeniedError(record)
    if record.decision is Decision.ESCALATE:    raise EscalateError(record)
    if record.decision is Decision.TRANSFORM:   tool_call = tool_call.with_args(record.transformed_args)
    try:
        result = tool.run(tool_call.args)        # only path that produces side effects
    except Exception:
        audit.append(failure_record(tool_call, exc=...))   # fail-closed: record the failure
        raise
    return result
```

Key invariants enforced by tests:

- No code path executes a tool before the audit append commits.
- Any exception in `policy.evaluate` or `audit.append` → `DeniedError`, never silent allow.
- `TRANSFORM` re-canonicalizes args + re-hashes before execution.

### Phase 3 — Policy reshape (LOW)

Port `acgs-lite/src/acgs_lite/constitution/boundaries.py` into `gove_zone/policy.py`:

- Generalize `forbidden_keywords` / `forbidden_patterns` to operate on the
  *canonical JSON* of `ToolCall.args` (not free-text actions).
- Add `Policy` ABC with `evaluate(call: ToolCall) -> DecisionRecord`.
- Concrete `BoundaryPolicy` returns `DENY` on match, `ALLOW` otherwise.
- Concrete `CompositePolicy` runs N policies; first non-allow wins; ties broken
  by severity.

### Phase 4 — Receipt + replay (LOW)

- `Receipt = DecisionRecord + tool result digest + actor identity`
- `replay.verify(record, policy)` → re-runs policy with the recorded args and
  asserts same decision. Diverges only if policy changed; surfaces the diff.

### Phase 5 — One example, end-to-end (LOW)

```python
# examples/write_file_guard.py
from gove_zone import Kernel, Tool, BoundaryPolicy, JSONLAuditStore

kernel = Kernel(
    policy=BoundaryPolicy(forbidden_keywords=["~/.ssh", "/etc/shadow"]),
    audit=JSONLAuditStore("/var/log/gove-zone/audit.jsonl"),
)

@kernel.tool("write_file")
def write_file(path: str, content: str) -> None:
    with open(path, "w") as f: f.write(content)

kernel.dispatch("write_file", {"path": "/tmp/safe", "content": "hi"})   # allowed
kernel.dispatch("write_file", {"path": "~/.ssh/id_rsa", "content": "..."})  # raises DeniedError
```

This is the "one afternoon" onboarding artifact. Ships in `README.md`.

### Phase 6 — Cut the heavy stuff (MEDIUM)

Re-classify existing packages relative to the kernel:

| Package | Verdict | Action |
|---|---|---|
| `packages/acgs-lite/` | Legacy validator, keeps PyPI lifecycle | No code change. Optionally: future `acgs-lite>=3.0` depends on `gove-zone`. |
| `packages/Acgs-Swarm/` | Domain extension (multi-agent coord) | No code change for kernel; future swarm policies plug into `gove-zone` as `Policy` impls. |
| `packages/clinicalguard/` | Domain extension (clinical rules) | Same — becomes a `Policy` consumer. |
| `acgs_governance_eval_mvp/` | Test/eval harness | Keep `jsonl_chain.py` as the source-of-truth audit reference; kernel ports cleanly. |
| `hermes_acgs_bundle/` | Integration glue | Re-target onto kernel API; ~100 LOC. |
| `acgs-cft-governance-pack/` | Cloud policy evaluator | Out of kernel scope; could ship as a `Policy` impl. |

Phase 6 is **classification only**, not deletion. The kernel proves itself
first; pruning waits for the next plan revision.

---

## §6 Open questions (require user input or follow-up)

1. **Submodule or plain dir?** `packages/gove-zone` could be a new GitHub repo
   (submodule) or a plain monorepo-tracked directory. Plain dir is faster to
   iterate; submodule matches the existing pattern (`acgs-lite`, `Acgs-Swarm`,
   `clinicalguard`). Recommend: plain dir for now, promote to submodule when
   we publish to PyPI.
2. **Package name on PyPI.** `gove-zone` is the working name. Confirm before
   reserving the name on PyPI.
3. **License.** Apache-2.0 (matches `acgs-lite`)?
4. **Dependency policy.** Stdlib + pydantic only, or stdlib only? pydantic
   buys schema validation for free; stdlib-only forces hand-rolled validators.
   Recommend: pydantic-only soft dep; stdlib fallback.
5. **Async story.** Kernel is sync-first by default; add `await dispatch_async`
   as a thin shim. Confirm.

---

## §7 Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Scope creep — kernel grows past 2,500 LOC | High | Hard CI gate: `wc -l src/gove_zone/*.py` ≤ 2,500. PR that breaches must justify or refactor. |
| Premature integration with `acgs-lite` | Medium | Phase 6 (cut the heavy stuff) is the *last* phase, not the first. Kernel stands alone first. |
| Constitutional-hash drift on ported files | Medium | Files copied into `gove-zone` lose their old hash markers (they're new files at new paths). Recompute via existing `scripts/verify_constitutional_hashes.py`. |
| Tool-call interception spec disagreement | Medium | Lock the `ToolCall` schema in Phase 2 PR before any consumer ports. Public API freeze gate at v0.1.0. |
| `jsonl_chain.py` port introduces subtle hash semantics change | Low | Property test: append-then-replay-then-verify chain matches byte-for-byte on a 10k-event corpus. |

---

## §8 Verification gates

After each phase:

```bash
# In packages/gove-zone/
make lint typecheck test
wc -l src/gove_zone/*.py | tail -1  # must be ≤ 2,500
```

Phase 1 PASS = audit port + property test pass; LOC ≤ 600.
Phase 2 PASS = kernel dispatch path test + fail-closed test pass; LOC ≤ 1,400.
Phase 3 PASS = policy reshape; LOC ≤ 1,800.
Phase 4 PASS = receipt + replay; LOC ≤ 2,200.
Phase 5 PASS = example runs end-to-end; LOC ≤ 2,500.

A single CI workflow `python-gove-zone.yml` mirrors the per-package fan-out
pattern from `MONOREPO.md`.

---

## §9 Out of scope (explicitly deferred)

- Deleting or restructuring `acgs-lite`. Its PyPI consumers stay supported.
- Replacing `Constitution` rule loading. The kernel does not load YAML rules;
  it accepts `Policy` objects. Rule-to-policy compilers can ship later.
- Multi-agent debate / consensus. Those are *consumers* of the kernel.
- Frontend changes. `acgi-ai/` is unrelated.
- Cross-repo refactors in `Acgs-Swarm` / `clinicalguard`. Domain extensions
  port on their own timeline.

---

## §10 Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-13 | Greenfield kernel, not extraction | `GovernedAgent` is text-level, not call-level. The interception core doesn't exist in the codebase. |
| 2026-05-13 | `jsonl_chain.py` (eval_mvp) as audit seed, not `audit.py` (acgs-lite) | Smaller, process-safe via `fcntl.flock`, fewer dependencies (no PQC, no legitimacy receipts). |
| 2026-05-13 | LOC ceiling 2,500 enforced in CI | Goal mandates "tiny core." Drift without a CI gate is inevitable. |
| 2026-05-13 | Domain packages stay; reclassify, don't delete | `acgs-lite` is on PyPI; destructive changes break consumers. |
