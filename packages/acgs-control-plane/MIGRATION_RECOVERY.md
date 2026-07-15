# Local disposable migration recovery drill

This package includes a deliberately narrow recovery command for testing a
forward-only control-plane migration against a **distinct, empty, disposable
PostgreSQL database**:

```bash
python -m acgs_control_plane.migration_recovery --help
```

The command labels every bundle `local_disposable_recovery_drill`. It is local
engineering evidence, not production disaster-recovery evidence.

## Safety boundary

The drill:

- reads database URLs only from explicitly named environment variables;
- builds a minimal child-process environment from the parsed URL, excluding
  ambient libpq controls and unrelated secrets, and uses a temporary `0600`
  passfile rather than placing a password in command arguments;
- accepts only the exact known Alembic head schema;
- creates a PostgreSQL custom-format archive from an exported repeatable-read,
  read-only snapshot with `--no-owner` and `--no-acl`;
- freezes each existing audit chain with its append sidecar lock, verifies it
  against the database anchor, and copies it while locked;
- rejects any difference between before, exported-snapshot, and after database
  fingerprints;
- writes staging directories as `0700` and bundle files as `0600`; PostgreSQL
  passfiles are created atomically with owner-only permissions and, where
  descriptor chmod is available, normalized to exact `0600` before use;
- publishes a completed bundle by a same-parent atomic rename;
- fsyncs the dump, manifest, and copied audit files before success, and also
  fsyncs audit/staging directories and the output parent on platforms exposing
  POSIX directory-fsync support;
- verifies canonical manifest shape, path containment, artifact hashes, audit
  chains, and `pg_restore --list` readability before inspecting or mutating a
  restore target;
- bounds each database fingerprint capture to 100,000 rows per table, 1 MiB of
  canonical bytes per row, 64 MiB of canonical bytes per table, and 128 MiB of
  canonical bytes across the capture; rows are requested from SQLAlchemy in
  fixed batches of 128 and the limits cannot be raised by CLI or configuration;
- restores only to a separately and explicitly named empty PostgreSQL database
  and an absent or empty audit directory;
- holds the same PostgreSQL advisory-lock identity used by canonical migrations,
  repeats the empty-target check immediately before restore, and retains the
  session lock through post-restore verification;
- invokes `pg_restore` with `--single-transaction`, `--exit-on-error`,
  `--no-owner`, and `--no-acl`; and
- compares post-restore schema, table, organization/audit identity, and anchor
  fingerprints before publishing restored audit files.

Unknown schemas, unexpected files, symlinks, traversal, unsafe organization
identifiers, missing audit locks, corrupt chains, source drift, non-empty
targets, archive errors, and post-restore differences fail closed.

The canonical manifest includes schema, table, artifact, and audit-chain
fingerprints. It does **not** include a database URL, password, raw database
row, or audit payload. The database dump and audit files necessarily contain
the backed-up application data; protect the whole bundle accordingly.

Because the manifest is unkeyed, a bundle from an untrusted path is prohibited.
Restore requires an explicit acknowledgement that the bundle came from an
operator-controlled local path. That acknowledgement is not authentication and
must never be used to bless a downloaded or otherwise untrusted bundle.

## Create and verify

Use a maintenance window. Drift detection is a refusal mechanism, not a writer
lock:

```bash
export ACP_RECOVERY_SOURCE_URL='postgresql+psycopg://...'
mkdir -m 0700 ./recovery-output

python -m acgs_control_plane.migration_recovery create \
  --source-url-env ACP_RECOVERY_SOURCE_URL \
  --audit-dir ./acp-audit \
  --output ./recovery-output/pre-migration

python -m acgs_control_plane.migration_recovery verify \
  --bundle ./recovery-output/pre-migration
```

The output path must not exist. Its parent and the audit source must be real
directories, not symlinks. A successful create prints the assurance label and
operation. A refusal exits with status 2 and suppresses subprocess output so a
connection string or database payload is not echoed.

## Restore rehearsal

Create a separate empty database first. Its explicit name must equal the name
in the URL and must differ from the source database name recorded in the
manifest:

```bash
export ACP_RECOVERY_TARGET_URL='postgresql+psycopg://.../acgs_recovery_drill'

python -m acgs_control_plane.migration_recovery restore \
  --bundle ./recovery-output/pre-migration \
  --target-url-env ACP_RECOVERY_TARGET_URL \
  --target-database-name acgs_recovery_drill \
  --target-audit-dir ./recovered-audit \
  --acknowledge-operator-controlled-bundle
```

Do not point the command at an application database. The target PostgreSQL
`public` schema must be empty, and the target audit path must be absent or an
empty directory. The drill never runs an Alembic downgrade and never performs
a production cutover. Isolate and quiesce the disposable target before starting.
The advisory lock coordinates with ACGS migration/recovery commands; arbitrary
writers that ignore that lock are outside this drill's trust boundary.

After a successful rehearsal, separately run the package migration and
application validation appropriate to the candidate release. Delete the
disposable target only through the operator-approved database lifecycle.

## Honest limitations

- The exported PostgreSQL snapshot and locked filesystem audit snapshot are
  **not atomic with each other**. The before/snapshot/after and anchor checks
  detect observed drift; they cannot manufacture a cross-store transaction.
- The unkeyed SHA-256 manifest provides integrity checking, not authenticity.
  A writer able to replace both artifacts and manifest can recompute it.
- The bundle is not encrypted. File modes reduce local exposure but are not an
  encryption or key-management system.
- Platforms without descriptor-level chmod retain the atomic owner-only
  passfile creation request, but platform umask and permission semantics may
  further restrict the resulting mode.
- Directory fsync is required on supported POSIX platforms. Platforms without
  `os.O_DIRECTORY` skip directory fsync because Python exposes no equivalent
  primitive there; this drill remains local evidence, not a durability claim.
- This is not PITR, continuous backup, object retention, independent witnessing,
  a backup scheduler, production restore automation, or production DR proof.
- Table fingerprints are computed by reading and sorting canonicalized rows in
  memory inside the fixed envelope above. A database driver must materialize
  one raw row before its canonical 1 MiB limit can be checked; no raw rows are
  spilled to disk, but a single oversized source value can temporarily exceed
  that canonical bound. This is a bounded beta-scale drill, not an
  unbounded-memory production backup path.
- PostgreSQL archive portability still depends on supported `pg_dump` and
  `pg_restore` versions and extensions outside this package's scope.
- Database restoration is transactional, but database restore and audit
  directory publication are not one atomic operation. If audit publication
  fails after a successful database restore, discard the disposable target and
  repeat the drill; do not cut it over.
- A post-restore fingerprint or audit-equivalence failure means the disposable
  target is contaminated. It publishes no audit directory or success result,
  but it cannot roll back a restore process that already committed. Discard and
  recreate the isolated target before retrying.
- Publication uses an exclusive sidecar to prevent two cooperating drill
  processes from replacing the same output. Python has no portable atomic
  rename-no-replace operation for directories; a malicious same-user process
  that ignores the sidecar can still race the final existence check. Use a
  private `0700` output parent controlled by the operator.
- No Alembic downgrade, production deployment, backup retention, external
  witness, RPO, RTO, or customer recovery claim is established here.

These limitations must remain attached to any evidence produced by this drill.
