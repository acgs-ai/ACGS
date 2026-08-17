// Constraints + indexes for the govern-zone knowledge graph.
// Every node carries a unique `key`; File.key is the repo-relative POSIX path
// and is the join spine every ingest layer keys on.

CREATE CONSTRAINT file_key IF NOT EXISTS FOR (n:File) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT symbol_key IF NOT EXISTS FOR (n:Symbol) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT endpoint_key IF NOT EXISTS FOR (n:Endpoint) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT package_key IF NOT EXISTS FOR (n:Package) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT layer_key IF NOT EXISTS FOR (n:Layer) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT tourstep_key IF NOT EXISTS FOR (n:TourStep) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT commit_key IF NOT EXISTS FOR (n:Commit) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT author_key IF NOT EXISTS FOR (n:Author) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT workflow_key IF NOT EXISTS FOR (n:Workflow) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT adr_key IF NOT EXISTS FOR (n:ADR) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT control_key IF NOT EXISTS FOR (n:Control) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT policy_key IF NOT EXISTS FOR (n:Policy) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT hash_key IF NOT EXISTS FOR (n:Hash) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT snapshot_key IF NOT EXISTS FOR (n:Snapshot) REQUIRE n.key IS UNIQUE;

CREATE INDEX file_package IF NOT EXISTS FOR (n:File) ON (n.package);
CREATE INDEX file_language IF NOT EXISTS FOR (n:File) ON (n.language);
CREATE INDEX file_sealed IF NOT EXISTS FOR (n:File) ON (n.sealed);
CREATE INDEX file_hotspot IF NOT EXISTS FOR (n:File) ON (n.hotspot);
CREATE INDEX file_is_test IF NOT EXISTS FOR (n:File) ON (n.is_test);
CREATE INDEX symbol_path IF NOT EXISTS FOR (n:Symbol) ON (n.path);
CREATE INDEX control_framework IF NOT EXISTS FOR (n:Control) ON (n.framework);
CREATE INDEX adr_status IF NOT EXISTS FOR (n:ADR) ON (n.status);
CREATE FULLTEXT INDEX summary_search IF NOT EXISTS
  FOR (n:File|Symbol) ON EACH [n.name, n.summary];
