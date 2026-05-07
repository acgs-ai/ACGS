# ACGS × Arize Phoenix

Self-hosted Arize Phoenix as an observability adjunct to the ACGS chain-hashed
audit trail. Phoenix does not replace ACGS evidence — it cross-links into it.

See `../../docs/design/acgs-phoenix-observability.md` for the full design and
ADR-style decision record (authoritativeness, retention asymmetry, fail-closed
posture, EU AI Act Article 12/15 coverage implications).

## Quick start

```bash
cd hermes_acgs_bundle/phoenix
docker compose up -d
docker compose logs -f phoenix   # wait for "Phoenix is running"
xdg-open http://127.0.0.1:6006   # UI
```

OTLP endpoints for instrumented applications:

| Transport | Endpoint                            |
|-----------|-------------------------------------|
| gRPC      | `http://127.0.0.1:4317`             |
| HTTP      | `http://127.0.0.1:6006/v1/traces`   |

Note: port 4318 is NOT available for HTTP OTLP in Phoenix 15.x — it is gRPC-only
(verified against Phoenix 15.4.0 startup logs). Use `:6006/v1/traces` for HTTP.

Tail logs: `docker compose logs --tail=200 phoenix`.

Tear down (retains data volume):

```bash
docker compose down
```

Full wipe (drops traces, evals, datasets):

```bash
docker compose down -v
```

## Minimal Python client instrumentation

Install on the application side — do **not** add Phoenix/OpenInference to the
core governance package. They belong in the instrumented edge (Hermes itself,
or the calling app), not in the ACGS evaluator.

```bash
pip install arize-phoenix-otel openinference-instrumentation-openai
```

```python
from phoenix.otel import register

tracer_provider = register(
    project_name="acgs-governed-hermes",
    endpoint="http://127.0.0.1:6006/v1/traces",
    set_global_tracer_provider=True,
)
```

Any OpenAI/Anthropic/LiteLLM call made after `register()` will emit
OpenInference spans to Phoenix. When `HermesACGSMiddleware._audit()` runs
inside that span, the emitted ACGS evidence row will carry `trace_id` and
`span_id` in `metadata`, and the span will carry `acgs.event_hash` and
`acgs.decision` attributes.

## Operational posture

- **Loopback by default.** The compose file binds `127.0.0.1`. To expose the UI
  remotely, front Phoenix with a reverse proxy that terminates TLS and enforces
  auth — Phoenix's built-in auth works but should not be the only layer.
- **Telemetry opt-out baked in.** `PHOENIX_TELEMETRY_ENABLED=false` disables
  anonymous web analytics. Trace data itself is never sent to Arize.
- **Version pinned.** Never `:latest`. Bump the tag explicitly, re-run the
  cross-link tests, then promote.
- **Retention asymmetry.** Phoenix traces are typically retained 7–90 days.
  The ACGS chain is forever. A missing Phoenix trace is **not** destroyed
  evidence — the binding data (`event_hash`, `input_hash`, Merkle root) all
  live in the ACGS JSONL chain.
- **Air-gap friendly.** `PHOENIX_TELEMETRY_ENABLED=false` plus
  `PHOENIX_ALLOWLIST_ONLY_OUTBOUND=true` covers the SSRF surfaces introduced
  by the PXI/playground features in 15.x.

## Nonroot variant

The compose file runs as root for first-boot ergonomics. To switch to the
hardened nonroot image:

```bash
docker compose down
sudo chown -R 1000:1000 /var/lib/docker/volumes/acgs-phoenix-data/_data
# then uncomment the `image: …-nonroot` and `user: "1000:1000"` lines and re-up.
docker compose up -d
```

## What this does NOT do

- It does not send anything to Arize's hosted service.
- It does not alter ACGS evidence schema, hashing, or chain verification.
- It does not replace the ACGS audit trail. Phoenix is ephemeral; the chain is
  the authoritative record.
- It does not make Phoenix a hard dependency of ACGS gates. If Phoenix is
  unreachable, ACGS continues to gate and audit unaffected (spans simply do
  not link back). Evals-as-governance (Deliverable D3) is a separate build
  with an explicit policy decision required before it lands.
