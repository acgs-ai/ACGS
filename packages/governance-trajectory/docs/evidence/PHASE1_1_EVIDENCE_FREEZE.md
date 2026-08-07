# Phase 1.1 Evidence Freeze Report

**Verdict: PASS**

- Commit SHA: `913147852d9859c4a764cb8529805ada08bc6d96`
- Branch: `master`  |  Dirty: `False`
- Schema: `4a61b5d2a6b8b25fb72c161cf599cd8f57dcaa60b9bbd9b41a11edaad0b2e2dd` (`acgs_trajectory/schemas/governance_trajectory_v2.schema.json`)
- Manifest SHA-256: `c55ac63bbf4a56977cad015ccbdd8025b6f1ae7e4ffd6db1c0caa09e04e5cbe2`

## Test results
- pytest: **38 passed**

## Deterministic replay
- fixture: `tests/fixtures/complete_session.jsonl` (status `complete`)
- canonical SHA-256: `9e9d2530132a3d5e99c163846846ab82a583a4c2bbcfe404a1a034bffc2e3a56`
- normalized SHA-256: `bcc589d875db31a375bdbdb098e3b3b4100dad7c52fff9d4edd2fc879fc71c0d`
- trajectory_id: `f91157f59536ce6471bf10c94539a771370e039b48bd12eb8fc198485dadccfa`
- byte-identical across 2 runs: **True**
- source fixture unmutated: **True**

## Schema + provenance
- schema is Draft 2020-12: True
- sample artifact valid: True
- manifest hash-chain verified: True

## Validation coverage (V1–V6)
- **V1 causal integrity** — validate.v1_causal_graph — tests: test_v1_clean_on_complete, test_v1_orphan_detected, test_v1_sidechain_linked, test_subagent_relationship_and_edges
- **V2 block/tool linkage** — adapter.SourceAdapter.parse (tool join) + validate.v2_block_integrity — tests: test_tool_use_result_linkage, test_v1_broken_tool_ref, test_v2_block_integrity_clean, test_block_separation_thinking_text_tooluse
- **V3 tamper detection** — validate.v4_tamper + raw_store.verify_raw + raw_store.verify_chain — tests: test_tamper_detection_v4, test_verify_raw_detects_tamper, test_manifest_chain_detects_modification
- **V4 provenance completeness** — validate.v3_provenance — tests: test_missing_git_head_is_incomplete_not_complete, test_environment_and_leaf
- **V5 secret boundary** — secrets_scan.scan_text + ingest quarantine routing — tests: test_v5_secret_detection, test_v5_git_sha_whitelisted, test_secret_session_quarantined_and_not_in_shared_archive
- **V6 unsupported input handling** — adapter version boundary + ingest quarantine + validate.v6_schema — tests: test_unsupported_version_quarantined, test_unknown_record_type_quarantined_but_retained, test_malformed_line_raises, test_v6_rejects_derived_values

## Acceptance mapping (A1–A9)
- **A1 schema contract valid** — jsonschema check_schema + sample validates (test_v6_schema_loads_and_is_draft2020)
- **A2 golden round-trip** — replay byte-identical (test_replay_byte_identical_across_runs)
- **A3 orphan=0 on golden** — test_v1_clean_on_complete
- **A4 tamper detection** — test_tamper_detection_v4 + test_verify_raw_detects_tamper
- **A5 missing-field fail-closed** — test_missing_git_head_is_incomplete_not_complete
- **A6 unknown-type quarantine** — test_unknown_record_type_quarantined_but_retained
- **A7 secret boundary** — test_secret_session_quarantined_and_not_in_shared_archive
- **A8 raw immutability** — test_content_addressed_worm + test_manifest_hash_chain
- **A9 determinism** — test_determinism_identical_input_identical_output + test_replay_byte_identical_across_runs

## Supported versions
- exact: 2.1.170  |  prefixes: 2.
- unknown → quarantine + adapter review (no silent schema drift)

## Remaining risks
- R1/R9 version drift: only 2.1.170 block-verified; other 2.x by prefix.
- R2 secret-scanner precision: fail-closed over-quarantine (noisy on high-entropy tokens).
- R4 git-join fidelity bounded by capture; diff not yet auto-captured.
- Fixture corpus small (synthetic + shapes); expand before production.

_Known limitations: docs/phase1/implementation-summary.md#6-known-limitations._
