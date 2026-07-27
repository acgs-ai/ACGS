# Document Reference Policy

How one file in this repository may point at another. The rule exists because
markdown link checking catches the cheap failures and misses the expensive ones.

## The failure this prevents

`make lint-docs` verifies that relative markdown links resolve. It does not — and
cannot — verify:

- a **line-number citation** (`FILE.md:30`), which any edit above line 30 silently
  invalidates;
- a **section-number citation** (`doc-00 §3`), which renumbering or removing a
  section silently invalidates;
- a **prose reference** ("SWOT recommendation 5", "W6"), which survives as text
  after the document it names is gone;
- a **docstring reference** from `.py` to a document, which no doc tool inspects.

All four classes were found live in this repository during the 2026-07-26 exposure
audits. Every one of them read as correct, and none of them was.

## Rules

**1. Cite by stable anchor, never by line number.**

```markdown
<!-- no  -->  See `docs/VERSIONING.md:64`.
<!-- yes -->  See [`docs/VERSIONING.md`](VERSIONING.md), section "Drift 1".
<!-- yes -->  In `docs/VERSIONING.md`, search for the literal string `v2.10.0`.
```

A grep target is a legitimate anchor: it survives edits that move the line.

**2. Cite by heading text, not by section number**, unless the number is part of
the heading itself and the document commits to numbering stability.

**3. A document that will outlive its source must restate what it needs.** If
`B.md` cannot be understood without `A.md`, and `A.md` may become private or be
retired, inline the necessary premise into `B.md`. `06-DECISION-RECORD.md` is the
worked example: it now restates each decision rather than resolving "the five open
decisions in §7" of a document a reader may not have.

**4. Code may reference a document only for provenance, never for a contract.**
A docstring may say *why* a module exists. It must not make a document the source
of truth for a schema or an interface the module itself defines — that reference
breaks the moment the document moves, and nothing tests it.

```python
# no  — the doc owns the schema, and the doc can move
"""...writes the verdict in the shape ``docs/codex-goals/phase1-week2-paper-gate.md`` specifies."""

# yes — the module owns the schema
"""...writes the verdict in the shape this module's ``build_gate_record()`` defines."""
```

**5. Before moving or removing any document, sweep for all five reference classes** —
not just markdown links:

```bash
BASE=path/to/doc            # e.g. docs/reconstruction/00-EXECUTIVE-SUMMARY
STEM=$(basename "$BASE")

git grep -n "$STEM" -- ':!node_modules'          # links + line-number cites
git grep -nE "doc[- ]?00|§[0-9]" -- ':!node_modules'   # section cites (tune per doc)
git grep -n "$STEM" -- '*.py' '*.ts' '*.js'      # code-level pins
```

Zero markdown hits does **not** mean zero references. Check the code sweep
separately — it is the one people skip.

**6. Do not assert that a document is pinned without running the sweep.** The
retired `docs/internal/README.md` claimed `docs/strategy/` was "pinned by
tests/scripts/lint." It was not pinned by anything. That single unverified sentence
kept commercially sensitive material in a public repository for months, because
each subsequent reader treated it as an established constraint rather than a claim.
An unverified blocker is more expensive than a real one.

## Scope

Applies to everything under `docs/`, to package-local docs, and to any `.py`/`.ts`
docstring or comment that names a document path.

There is currently **no automated gate** for these rules. `make lint-docs` covers
relative-link resolution inside `packages/ai-governance-research` only. Until a
repo-wide checker exists, rule 5 is a manual pre-move step and rule 6 is a review
question.
