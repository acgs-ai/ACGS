# Evidence-Backed Authority Verification

This directory is the self-contained source and evidence closure for the
single-host authority-verification case study.

**Recomputed verdict: `BLOCKED_ROOT_EQUIVALENCE`.** The shipped evidence
contains a classified rootful-Docker path. This is a local artifact result, not
a population claim, formal verification result, or authorization to modify a
host.

## Safe reproduction

Pure replay is the default verification path. It reads only files in this
directory and does not inspect the current host or invoke Docker.

```bash
python3 artifact_replay.py --verify-shipped
python3 table16_metrics.py --verify
python3 release_manifest.py --verify
python3 -m pytest tests -q
python3 render_pdf.py
sha256sum -c "Evidence-Backed Authority Verification.sha256"
```

`artifact_replay.py` recomputes the classification sets, successful surface
coverage, credential binding, privilege-graph closure, conditions, evidence
digest, and verdict. `REPLAY_RESULT.json` is the shipped expected result.
The canonical PDF is generated from `paper.md` by `render_pdf.py`. The
renderer uses only relative paths and refuses versions other than those sealed
in `RENDERER.lock.json`. It intentionally creates a new canonical artifact;
it does not claim to reproduce the earlier `fa34430...` PDF.

## Active Docker probe

The Docker experiment is an **active mutation probe** and is never run by
artifact replay or the default `docker_rootful()` API. It requires both flags:

```bash
python3 root_equivalence.py \
  --active-docker-probe \
  --ack-disposable-host
```

Run it only on a disposable host. The probe bind-mounts a temporary host
directory and changes file content, ownership, and mode. Newly executed probes
record the exact mutation and cleanup paths, operations, return codes, outcomes,
and removal status. The shipped registry contains a
historical active result that predates this metadata and is explicitly labeled
`HISTORICAL_RESULT`; it does not claim recorded per-command active evidence.
Without both flags, Docker execution is unavailable and cannot satisfy surface
coverage.

## Integrity contracts

- `EXPECTED_CREDENTIAL.json` seals all Linux UID/GID tuples,
  supplementary groups, five capability sets, `NoNewPrivs`, seccomp state,
  uid/gid maps, and user-namespace identity. Consumers recompute this structure
  from raw inventory fields; `host_representative` is never trusted.
- `SURFACE_REGISTRY.json` defines required discovery surfaces. A surface is
  covered only by a first-class result with `status=SUCCESS` and
  `completed=true`; missing, error, or unavailable results enter *U*.
- *R*, *Q*, and *U* are derived from each mechanism/path classification.
  Published summary arrays are checked for exact agreement and a mismatch
  fails closed.
- Both inventories must bind to the same sealed credential digest.
- `REPLAY_RESULT.json` binds the recomputed summaries, coverage, closure,
  conditions, artifact hashes, digest, and verdict.
- `SHA256SUMS` binds every shipped source, evidence, replay, renderer, test,
  PDF, and sidecar file. The manifest excludes only itself to avoid a circular
  digest; `release_manifest.py --verify` also rejects missing or extra files.

## Evidence and source

The closure intentionally excludes caches, `.omc` state, internal review
drafts, and obsolete manifests. Primary files are:

- `paper.md`, `references.bib`, generated PDF and SHA-256 file
- `artifact_replay.py`, `exclusivity_model.py`,
  `privilege_context.py`, and privilege graph/topology sources
- `EXPECTED_CREDENTIAL.json`, `SURFACE_REGISTRY.json`,
  `REPLAY_RESULT.json`
- the shipped JSON evidence consumed by replay
- `tests/` adversarial and regression coverage

The claim boundary remains `BLOCKED_ROOT_EQUIVALENCE`. No cutover, privilege
removal, Docker probe, or host mutation is performed by the safe replay path.
