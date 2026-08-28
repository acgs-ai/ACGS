# Second Brain v0.1 task list

- [x] 1. Create local operating boundary.
- [x] 2. Record architecture, invariants, API trust contract, and threat model; independently approved.
- [x] 3. Wire uv/pnpm workspaces and local PostgreSQL+pgvector. Independently
  approved, including root pnpm and path-filtered CI registration.
- [x] 4. Bootstrap FastAPI service and safe readiness. Independently approved.
- [x] 5. Create identity/source/job lineage migration. Independently approved.
- [x] 6. Create retrieval/answer/memory migration and constraints. Independently approved.
- [x] 7. Enforce principal scope with PostgreSQL RLS. Independently approved.
- [x] Checkpoint A: empty DB and cross-scope gates pass. Final independent
  `APPROVE`; `P0=0`, `P1=0`, `P2=0`, `P3=0`.
- [x] 8. Implement object storage and hashing contracts. Independently approved.
- [x] 9. Implement capture API and visible jobs. Independently approved.
- [x] 10. Implement TXT/Markdown/PDF/DOCX parsers. Independently approved.
- [x] 11. Implement fail-closed URL ingestion. Independently approved.
- [x] 12. Implement deterministic chunking and durable claims. Independently approved.
- [x] 13. Implement fake and OpenAI-compatible providers. Independently approved.
- [x] 14. Implement restart-resumable ingestion worker. Independently approved.
- [x] Checkpoint B: one source is durable, searchable-ready, and restart-safe.
  Final independent `APPROVE`; `P0=0`, `P1=0`, `P2=0`, `P3=0`.
- [x] 15. Implement scoped lexical/vector/RRF retrieval. Independently approved.
- [x] 16. Implement source detail and citation context. Independently approved.
- [x] 17. Implement bounded evidence and persisted retrieval runs. Independently approved.
- [x] 18. Implement citation validation, abstention, and fallback. Independently approved.
- [x] Checkpoint C: injection and fabricated citations fail closed. Final
  independent `APPROVE`; `P0=0`, `P1=0`, `P2=0`, `P3=0`.
- [x] 19. Implement proposals and explicit memory approval. Independently approved.
- [x] 20. Implement revisions, supersession, archive, and purge. Independently approved.
- [x] 21. Implement projects, tags, filters, and Today. Independently approved.
- [x] 22. Implement veto-only policy port and safe logging. Independently approved.
- [x] Checkpoint D: memory/purge/logging trust gates pass. Final independent
  `APPROVE`; `P0=0`, `P1=0`, `P2=0`, `P3=0`.
- [x] 23. Bootstrap isolated Next.js application shell. Independently approved.
- [x] 24. Implement web API/session boundary. Independently approved; its
  earlier nonblocking `P2` citation-contract dependency was closed by completed
  Task 17.
- [x] 25. Build Inbox and Library. Independently approved.
- [x] 26. Build source detail and Search. Independently approved.
- [x] 27. Build Ask and Memory Review. Independently approved.
- [x] 28. Build Today and Settings. Independently approved.
- [x] 29. Prove primary journey with real persistence in Playwright.
  Independently approved.
- [x] Checkpoint E: desktop/mobile keyboard journey passes without mocked
  persistence. Final independent approval.
- [x] 30. Add path-filtered CI and full local gate. Independently approved.
- [x] 31. Complete product/trust documentation. Independently approved.
- [x] 32. Complete operations, limitations, and ACGS boundary docs.
  Independently approved.
- [x] 33. Run independent final verification and evidence-backed handoff.
  Completed with an overall `PARTIAL` verdict; package verification passed and
  root-workspace blockers are recorded in the implementation log.
