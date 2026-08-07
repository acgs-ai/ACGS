# Version Boundary Record (Phase 1.1)

Authoritative statement of which Claude Code transcript versions the ingestion
foundation accepts. Enforced in `acgs_trajectory/adapter.py`
(`SUPPORTED_VERSION_PREFIXES`) and gated at ingestion (`ingest.py`). **Schema
drift is never silently accepted.**

## Supported

| Claude Code version | Verification basis |
|---|---|
| **2.1.170** | Directly inspected at block level; all format facts (ADR 0002 D1–D7) confirmed against a live session. |
| `2.x` (prefix) | Accepted by prefix compatibility with 2.1.170. **Not individually block-verified** — treated as supported pending a per-version golden fixture (risk R1/R9). |

## Unknown / unsupported versions

Any transcript whose `version` is absent, or does not match a supported prefix
(e.g. a future `3.x`, or the test `9.9.9`):

1. **Quarantine.** `integrity.status = quarantined`, reason
   `V6:unsupported_version:<v>`. The raw is retained in the restricted
   quarantine store — never dropped, never redacted.
2. **Require adapter review.** A human must inspect the new version's block
   layout, extend `SUPPORTED_VERSION_PREFIXES` and, per ADR 0002, add a pinned
   golden fixture before the version is promoted to Supported.
3. **No silent acceptance.** There is no permissive fallback path. Unknown
   record `type`s inside an otherwise-supported version are likewise quarantined
   (`V6:unknown_record_type:<t>`).

## Change procedure

To add a version:

1. Capture a real session on the new version.
2. Diff its block shapes against ADR 0002 D1–D7; record deltas as a new ADR.
3. Add a golden fixture under `tests/fixtures/`.
4. Extend `SUPPORTED_VERSION_PREFIXES` (or add a version-specific parser branch).
5. Re-run the full suite + evidence freeze; only then is the version Supported.
