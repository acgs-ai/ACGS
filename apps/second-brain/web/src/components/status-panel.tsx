import type { ServiceStatus } from "@/lib/server-api";

export function StatusPanel({ status }: { status: ServiceStatus }) {
  if (status.kind === "unavailable") {
    return (
      <section className="state-panel" aria-labelledby="service-status-heading">
        <p className="status-label">Unavailable</p>
        <h2 id="service-status-heading">Service unavailable</h2>
        <p>
          Capture, retrieval, Ask, and memory actions remain unavailable until the service recovers.
        </p>
      </section>
    );
  }

  return (
    <section className="status-section" aria-labelledby="service-status-heading">
      <div>
        <p className="status-label">Available</p>
        <h2 id="service-status-heading">Service ready</h2>
      </div>
      <dl className="status-grid">
        <div>
          <dt>Database</dt>
          <dd>{status.database}</dd>
        </div>
        <div>
          <dt>Object storage</dt>
          <dd>{status.storage}</dd>
        </div>
        <div>
          <dt>Model transport</dt>
          <dd>{status.modelProvider}</dd>
        </div>
        <div>
          <dt>Embedding adapter</dt>
          <dd>{status.embeddingProviderStatus}</dd>
        </div>
        <div>
          <dt>Generation adapter</dt>
          <dd>{status.generationProviderStatus}</dd>
        </div>
        <div>
          <dt>Upload limit</dt>
          <dd>{status.maxUploadBytes.toLocaleString()} bytes</dd>
        </div>
        <div>
          <dt>Extracted text limit</dt>
          <dd>{status.maxExtractedChars.toLocaleString()} characters</dd>
        </div>
        <div>
          <dt>Chunk limit</dt>
          <dd>{status.maxChunks.toLocaleString()} per source</dd>
        </div>
        <div>
          <dt>Processing limit</dt>
          <dd>{status.maxProcessingSeconds.toLocaleString()} seconds</dd>
        </div>
      </dl>
      <p className="helper-text">
        Provider availability reports local adapter state, not remote health.
      </p>
    </section>
  );
}
