# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Constitutional governance

### Constitution
The versioned ruleset a governance engine enforces on every request — the source of truth for which actions are allowed, denied, escalated, or sent for review. A default Constitution has a canonical content hash used as provenance (see Constitutional hash).

### Constitutional hash
A content hash of a Constitution's data, stamped into files and artifacts as provenance of which ruleset they were produced under. It identifies the governing ruleset, not the bytes of the file it appears in — two otherwise-unrelated files governed by the same Constitution carry the same hash, so it is not a per-file content lock.

A file carrying a constitutional-hash marker is Sealed: when its governed content changes, the hash must be recomputed rather than left stale, and that recomputation is verified rather than trusted.

### Sealed
A status applied to files or surfaces that must not be hand-edited because their integrity is guaranteed elsewhere — generated outputs, lock files, and files stamped with a Constitutional hash. A sealed file changes only by re-running its generator or recomputing its hash, never by a direct edit; an automated loop or agent operating under a clean-files-only scope treats the sealed set as off-limits.
