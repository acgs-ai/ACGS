# agent-bus-analyzer

Observer-only analysis layer for the `EnhancedAgentBus` + `gove-zone` audit
chain. Captures dispatch / response events, persists hash-chained traces in
append-only JSONL, surfaces wiring defects and tampering through a privileged
console view.

- **Spec**: `specs/001-enhanced-agent-bus-analysis/spec.md`
- **Plan**: `specs/001-enhanced-agent-bus-analysis/plan.md`
- **Tasks**: `specs/001-enhanced-agent-bus-analysis/tasks.md`

The package is read-only on the bus and the gove-zone audit chain. It is
never on the authorization path.

## Local receipt-proof smoke

Backfill a canonical `gove-zone` audit JSONL into the analyzer store, then run
the API against that store:

```bash
agent-bus-analyzer import-audit \
  --audit-file .gove-zone/audit.jsonl \
  --store-dir .agent-bus-analyzer \
  --constitutional-hash 608508a9bd224290

agent-bus-analyzer serve \
  --host 127.0.0.1 \
  --port 8042 \
  --store-dir .agent-bus-analyzer
```

`import-audit` is a one-shot deploy/backfill helper. The long-running
`observer` subcommand tails the same audit file continuously. Both project
live `gove-zone` `DecisionRecord` fields (`tool`, `argument_hash`,
`timestamp_iso`, `event_hash`) into the bus analyzer's hash-chained trace
store so `/api/bus/receipts/{receipt_id}` can return a console-ready proof.

## Phoenix / OpenTelemetry cross-links

Receipt proofs can carry optional Phoenix/OpenTelemetry drill-through ids
without making Phoenix the evidence source of truth. The observer extracts:

- `phoenix_trace_id` from W3C `traceparent`, `trace_id`,
  `otel_trace_id`, or `phoenix_trace_id`.
- `phoenix_span_id` from explicit `span_id`, `otel_span_id`, or
  `phoenix_span_id`.
- `phoenix_parent_span_id` from `traceparent` parent-id or explicit parent
  span fields.

The ids are stored on each chain-hashed `Event`, summarized on
`TraceListItem`, copied onto `ReceiptProof`, and included in the signed
evidence packet when present. Hash-chained ACGS receipts remain authoritative;
Phoenix traces are an adjunct debugging lens that may expire independently.

## Evidence export signing

Receipt proof exports always include an `export_signature` block inside
`signed_evidence_packet`.

- Local/dev without signing material emits an explicit
  `status: "unsigned-local-digest"` SHA-256 canonical JSON digest.
- Deployment signing uses stdlib HMAC-SHA256 over the canonical packet
  excluding `export_signature` itself:

```bash
export ACGS_EVIDENCE_SIGNING_KEY_ID="bus-signer-v1"
export ACGS_EVIDENCE_SIGNING_SECRET="..."
export ACGS_EVIDENCE_SIGNING_REQUIRED="true"
```

If `ACGS_EVIDENCE_SIGNING_REQUIRED` is true, missing or partial signing
material fails closed instead of silently downgrading to a local digest. The
secret must come from the deployment secret manager; never commit it.

## Deployment contract

Package-local deployment artifacts live under `deploy/`:

- `deploy/Dockerfile` builds a non-root Python image and starts
  `agent-bus-analyzer serve --store-dir /var/lib/agent-bus-analyzer`.
- `deploy/cloudrun/service.yaml` is a Cloud Run service template that keeps
  the analyzer API internal/load-balancer reachable, probes
  `/api/bus/healthz`, sets `ACGS_EVIDENCE_SIGNING_REQUIRED=true`, reads
  `ACGS_EVIDENCE_SIGNING_SECRET` from Secret Manager through
  `valueFrom.secretKeyRef`, and mounts `REPLACE_ANALYZER_TRACE_BUCKET` at
  `/var/lib/agent-bus-analyzer` via Cloud Storage FUSE so the file-backed
  trace store survives container restarts.
- The template keeps `maxScale=1` because the current `TraceStore` is a
  SQLite + JSONL file store. Scale-out requires an object-store/native-index
  backend or per-writer trace-store partitioning before multiple serving
  instances write to the same mounted bucket path.
- `deploy/cloudrun/import-audit-job.yaml` is a single-task Cloud Run Job
  template for post-deploy backfill. It reads
  `/var/lib/agent-bus-analyzer/imports/gove-zone-audit.jsonl` from the same
  mounted bucket, runs `agent-bus-analyzer import-audit`, writes into
  `/var/lib/agent-bus-analyzer`, and disables automatic retries so a partial
  append-only import is reviewed before manual re-run.
- `agent-bus-analyzer postdeploy-smoke --base-url ... --receipt-id ...` is
  the read-only deployed smoke check. It verifies `/api/bus/healthz`, fetches
  the receipt proof with `ANALYZER_REVIEWER_TOKEN` or `--token`, requires
  `hash_chain_verified=true`, and fails closed unless the exported packet is
  deployment-signed. Use `--allow-unsigned-local` only for local smoke tests.

The template intentionally pins the secret version (`key: "1"`) rather than
using `latest`, because environment-variable secrets are resolved at instance
startup. Rotate by creating a new secret version, updating the key id and
version in the rendered deploy manifest, then rolling a new revision.

This template is local deployment readiness, not live production proof. A
production rollout still needs an image build, a rendered project number and
service account, a real Secret Manager secret, a real trace bucket plus IAM on
the runtime service account, an uploaded canonical audit JSONL, execution of
the rendered import job, and post-deploy API/header/proof checks from the
deployed revision.
