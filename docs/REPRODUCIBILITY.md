# Reproducibility (Phase 6)

> Goal: an anonymous reviewer can clone, install, and verify the core invariant
> **without private tokens, private submodules, or unavailable repositories.**
> Every command below was executed on a clean `origin/master` worktree with **no
> submodules initialized** and produced the stated result.

## TL;DR

- **The core enforcement kernel needs no submodules.** `packages/gove-zone/`
  lives directly in this repo. The invariant demos run on a bare clone.
- **Two reviewer traps exist** — the documented package test command omits
  required extras, and the constitutional-hash check needs submodules. Both are
  documented below with the correct commands.

## Prerequisites

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/)
- A POSIX shell (bash)

Node/pnpm only needed for the frontend (`acgi-ai/`), not for the kernel invariant.

## One command — `make review` (canonical reviewer path) — VERIFIED

```bash
git clone https://github.com/dislovelhl/ACGS.git
cd ACGS
make review     # docs smoke + gove-zone kernel suite + invariant smoke → "review OK"
```

`make review` is bare-clone-safe: no submodules, no private tokens, no extra
flags. The full multi-package CI gate is `make verify` (needs submodules + all
stacks). Verified: `make review` → exit 0 (docs 82 passed; kernel suite 1101
passed; smoke `status: pass`).

## Minimal anonymous path, step by step (no submodules, no token) — VERIFIED

```bash
git clone https://github.com/dislovelhl/ACGS.git
cd ACGS

# 1) Core invariant smoke — exit 0, "status": "pass"
tmp="$(mktemp -d)"
uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"

# 2) Receipt-gated execution demo — needs the `crypto` extra
uv run --extra crypto --package gove-zone \
  python packages/gove-zone/examples/receipt-gated-execution/demo.py
#   → "All invariants held. No valid Decision Receipt, no side effect."

# 3) Tamper demo — exit 0, tampered_receipt_blocked: true
uv run --package gove-zone python examples/tamper_demo/demo.py

# 4) Documentation + examples smoke suite — 77 passed, 5 skipped
uv run python -m pytest tests/docs --import-mode=importlib -q
```

The 5 skips in step 4 are examples that require the `acgs-lite` submodule; they
skip cleanly with a message, they do not fail.

## Full kernel test suite — invocation form matters (reviewer trap #1)

```bash
# CORRECT (in-package) — 1101 passed, 0 failed, 2 skipped. What `make review` runs:
cd packages/gove-zone && uv run python -m pytest --import-mode=importlib -q

# CORRECT (from root) — needs the extras spelled out:
uv run --package gove-zone --extra crypto --extra yaml --extra mcp \
  python -m pytest packages/gove-zone/tests --import-mode=importlib -q

# WRONG — root `--package` form WITHOUT extras → 15 FAILURES (missing optional deps):
uv run --package gove-zone \
  python -m pytest packages/gove-zone/tests --import-mode=importlib -q
```

Run **from inside the package** (`cd packages/gove-zone`) and uv resolves
gove-zone's own dependencies (crypto/yaml/mcp) automatically — no extras needed.
Only the **root workspace** `uv run --package gove-zone …` form omits them, and
then 15 tests fail on missing optional deps (Ed25519 signing → `crypto`, YAML
policy → `yaml`, MCP demos → `mcp`). The README "Development checks" command was
updated to the in-package form in this pass; `make review` uses it too.

## Constitutional-hash check needs submodules (reviewer trap #2)

```bash
python3 scripts/verify_constitutional_hashes.py   # exits 1 on a bare clone
```

All 221 pinned markers live inside submodules, so on a clone without submodule
initialization this check **fails closed** (exit 1). This is correct fail-closed
behavior but is not a code defect a reviewer should chase. To run it, initialize
the public submodules first (see below). Full characterization in
`docs/HASH_VERIFICATION_REPORT.md`.

The constitutional hash verification requires the complete source tree,
including required submodule contents. The core governance kernel remains
independently reproducible without optional research references — everything in
the "minimal anonymous path" above runs on a bare clone.

## Submodules — classification

| Submodule | Class | Needed for core invariant? | Public clone works? |
|---|---|---|---|
| `packages/acgs-lite` | dislovelhl library (PyPI) | No (only for acgs-lite examples) | Yes (public) |
| `packages/Acgs-Swarm` | dislovelhl research | No | Yes (public) |
| `packages/ACGS-agency-agents` | dislovelhl | No | Yes (public) |
| `packages/clinicalguard` | dislovelhl | No | **May require access** (may be private) |
| `external/UI-TARS-desktop` | bytedance (third-party) | **No — nothing imports it** | Yes but unrelated |
| `external/openswarm` | VRSEN (third-party) | **No** | Yes but unrelated |
| `external/everything-claude-code` | affaan-m (third-party) | **No** | Yes but unrelated |
| `external/natural_language_autoencoders` | kitft (third-party) | **No** | Yes but unrelated |

```bash
# Optional — public submodules only (skips clinicalguard if inaccessible):
git submodule update --init packages/acgs-lite packages/Acgs-Swarm packages/ACGS-agency-agents
```

### `external/*` — removed as submodules (done)

The four `external/*` submodules were third-party projects that nothing in the
tree imports. Embedding them made `git clone --recurse-submodules` pull megabytes
of unrelated upstream code and risk failing on a vanished remote. **They have
been removed from `.gitmodules`** and replaced with a pinned reference list in
[`external/README.md`](../external/README.md) (project, purpose, upstream URL,
pinned commit, license). A plain `git clone` — with or without `--recursive` —
now succeeds for any reviewer. Only the 4 first-party dislovelhl submodules
remain in `.gitmodules`.

## Reproducibility verdict

- **Core invariant: fully reproducible on an anonymous clone** with no
  submodules and one `crypto` extra. ✅
- **Blockers for a smooth reviewer experience:** the two documented traps above
  (test extras, hash-check submodule dependency) and the noisy `external/*`
  submodules. All three are documentation / hygiene fixes, not code defects.
