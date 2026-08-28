# Second Brain v0.1 invariants

These invariants define the acceptance boundary. An invariant is complete only
when its database/API/worker wiring and negative-path tests pass.

## Ownership and scope

1. Every persistent object belongs to an owner and workspace.
2. PostgreSQL RLS and composite keys enforce scope; UI filtering is never the security boundary.
3. Development/test identity is enabled only by explicit configuration and only
   on loopback listeners. It is rejected on non-loopback binds.
4. Production has no client-trusted principal mode. Startup fails unless a
   configured trusted identity verifier validates the server-side session.
5. The browser receives an opaque `Secure`, `HttpOnly`, `SameSite=Lax` session
   cookie. State-changing requests require same-origin checks plus a CSRF token;
   bearer or principal headers supplied by the browser are never authoritative.
6. Every scoped database transaction executes `SET LOCAL app.owner_id` and
   `SET LOCAL app.workspace_id` from the verified principal before data access.
   Missing or malformed settings fail closed and are cleared at transaction end.
7. Spoofed principal/workspace headers, cookie tampering, missing CSRF, verifier
   outage, and production dev-auth configuration are negative tests.
8. A policy integration may add a veto but cannot grant access or bypass scope.

Configuration boundary invariant: the API receives only the restricted
application-role database URL. The worker receives that content URL plus the
separately permissioned `second_brain_worker` dispatcher URL; it does not load
the API `.env`. Database-owner/bootstrap credentials and Compose port overrides
exist only in local inline Compose defaults or an explicitly passed untracked
`.env.compose.local`. That file is never sourced, exported, or loaded by the
service processes, and `make check` fails before later surface checks when Git
does not ignore it.

## Source and processing lineage

9. Sources and source versions are immutable once accepted.
10. Non-URL originals use server-generated object keys and exact-byte SHA-256;
    filenames are display metadata only. A URL source may initially have no
    byte hash or object. Its normalized-URI hash supplies scoped capture
    idempotency; after processing, the fetched bytes, exact hash, object key,
    final URI, redirects, and peer binding are authoritative on append-only
    source-version and URL-fetch provenance.
11. Parser or chunker upgrades create a new processing version.
12. Ingestion deduplicates by owner and workspace plus a source-type-specific
    normalized hash: canonical content for notes/uploads and normalized URI for
    URL capture. A normalized URI hash is never treated as an exact-byte hash.
13. Jobs are durable, leased, retry-safe, idempotent, restart-resumable, and visibly stateful.
14. Every chunk has a stable ID, chunker version, character offsets, and available page/section/paragraph metadata.

## Mandatory relations and independent database gates

The empty-database migration test must assert each relation exists, each scoped
relation has owner/workspace columns or a composite foreign-key path to them,
each scoped relation has `ENABLE` and `FORCE ROW LEVEL SECURITY` plus select and
mutation policies, and every append-only relation rejects update/delete through
the application role.

| Relation | Scope and composite constraint | Mutation contract |
|---|---|---|
| `users` | stable user ID; self policy | identity-managed, no content fields |
| `workspaces` | owner ID; unique `(id, owner_id)` | mutable metadata, scoped |
| `workspace_memberships` | composite workspace+user membership | append/revoke events, no cross-workspace FK |
| `projects` | owner+workspace composite FK | scoped mutable metadata |
| `sources` | owner+workspace; scoped dedup pointer | immutable provenance; lifecycle state only |
| `source_versions` | owner+workspace+source composite FK | append-only |
| `ingestion_jobs` | owner+workspace+source/version composite FK | append-oriented attempts/state history |
| `documents` | owner+workspace+source version | append-only extracted document |
| `chunks` | owner+workspace+document/version | append-only versioned units |
| `embeddings` | owner+workspace+chunk+provider profile | append-only; purgeable |
| `tags` | owner+workspace | scoped mutable metadata |
| `source_tags` | composite source+tag scope | scoped association |
| `conversations` | owner+workspace | scoped metadata |
| `messages` | owner+workspace+conversation | append-only |
| `retrieval_runs` | owner+workspace+conversation/query | append-only |
| `retrieval_results` | owner+workspace+run+chunk | append-only ranked evidence |
| `answers` | owner+workspace+run | append-only final status |
| `citations` | owner+workspace+answer+retrieved result | append-only validated citation |
| `memory_proposals` | owner+workspace+evidence lineage | inactive append-only proposal/decision events |
| `approved_memories` | owner+workspace+proposal origin | stable identity and status |
| `memory_revisions` | owner+workspace+approved memory | append-only meaning history |
| `purge_records` | owner+workspace+target tombstone | append-only audit without source content |

## Retrieval and answers

15. Retrieval is scoped in the database before ranking.
16. Lexical search remains available when model providers are unavailable.
17. Hybrid ranking uses lexical and semantic top 50, RRF `k=60`, and chunk-ID tie-breaking.
18. Retrieved content is untrusted data and cannot change authorization, tools, citation rules, or output schema.
19. Ask sends at most eight chunks and 12,000 evidence characters by default.
20. Every evidence-supported statement has a non-empty validated citation set;
    system commentary is separate and cannot contain source-factual claims.
21. Citations must be retrieved, currently accessible, and resolvable to source context.
22. `validation_failed` suppresses generated text. A fallback may contain only
    bounded extractive passages with independently validated citations.
23. Inadequate evidence produces `insufficient_evidence`.
24. Query, configuration, ranks, model, prompt version, answer, status, and citations persist together.
25. Semantic-only evidence is adequate only when its finite similarity meets a
    calibrated threshold stored with an exactly matching provider, model,
    dimensions, and embedding profile version. `NULL`, drift, or a score below
    threshold abstains before generation. A changed threshold requires a new
    append-only profile version and re-ingestion; it is never mutated in place.

## Deliberate memory

26. Proposed memory is inactive.
27. Approval, rejection, edit-and-approve, supersession, archive, and deletion are explicit actions.
28. Approval preserves evidence references.
29. Approved edits create revisions; historical meaning is never overwritten.
30. A model or policy adapter cannot activate memory.

## Security, privacy, and deletion

31. Upload, extraction, chunks, redirects, response bytes, evidence, and processing time are bounded.
32. URL ingestion rejects unsafe protocols, local/private/link-local/metadata targets, redirects, and rebinding.
33. Logs contain safe metadata, never raw source content or provider secrets.
34. Provider egress sends only the bounded evidence required for the current
    operation, never originals, unrelated chunks, credentials, or hidden scope
    metadata; fake/local mode performs zero network egress.
35. Purge transactionally excludes retrieval, then removes originals, text, chunks, and embeddings.
36. Security failures remain visible and never fall back to unrestricted behavior.
37. Original, extracted, generated, proposed, approved, and system metadata remain distinguishable.
38. Browser acceptance uses real PostgreSQL, pgvector, worker, and local object storage.
39. Secure, grounded, complete, and production-ready claims require their acceptance evidence.

## Future local ACGS policy seam

40. The optional interface is `evaluate(context) -> pass|veto|unavailable`.
41. Context is bounded metadata only: request/action IDs, actor/workspace IDs,
    resource type/ID, source type/MIME, numeric byte/chunk/result/citation counts,
    memory category, native-check status, and UTC timestamp. It contains no raw
    source, extracted text, chunks, answer text, memory statement, prompt, cookie,
    credential, object path, or provider payload.
42. Disabled or absent integration means no additional veto; every native
    ownership, citation, purge, and memory-activation check still runs.
43. Enabled integration returning `unavailable`, timing out, or raising fails
    closed with a visible policy-unavailable state and no protected mutation.
44. `pass` is never authority. It cannot grant access, validate a citation,
    authorize purge, or activate memory when a native check fails.
45. Results include bounded `reason_code`, `policy_id`, `policy_version`,
    `audit_id`, and `evaluated_at`; no second policy engine is implemented in v0.1.

## Migration harness safety

46. Migration downgrade/up proof runs only in a harness-created database whose
    name begins `second_brain_test_`, host is a known loopback address, and
    lifecycle is create → migrate → assert → downgrade/up → assert → drop.
47. The harness refuses the configured application database, non-loopback hosts,
    unexpected database names, and cleanup ambiguity before destructive DDL.
