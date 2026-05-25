"""Static deployment contract tests for the analyzer API service.

These tests intentionally inspect committed deploy artifacts instead of
provider state. They prove that a future Cloud Run rollout has a
store-backed API entrypoint and deployment-managed signing secret wiring.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (PACKAGE_ROOT / relative_path).read_text(encoding="utf-8")


def test_cloud_run_manifest_wires_secret_manager_signing_material() -> None:
    manifest = _read("deploy/cloudrun/service.yaml")

    assert "run.googleapis.com/secrets" in manifest
    assert "ACGS_EVIDENCE_SIGNING_REQUIRED" in manifest
    assert 'value: "true"' in manifest
    assert "ACGS_EVIDENCE_SIGNING_KEY_ID" in manifest
    assert "ACGS_EVIDENCE_SIGNING_SECRET" in manifest
    assert "valueFrom:" in manifest
    assert "secretKeyRef:" in manifest
    assert "name: evidence-signing-secret" in manifest
    assert 'key: "1"' in manifest
    assert "key: latest" not in manifest


def test_cloud_run_manifest_runs_store_backed_server() -> None:
    manifest = _read("deploy/cloudrun/service.yaml")

    assert "agent-bus-analyzer" in manifest
    assert "serve" in manifest
    assert "--host" in manifest
    assert "0.0.0.0" in manifest
    assert "--store-dir" in manifest
    assert "AGENT_BUS_ANALYZER_STORE_DIR" in manifest
    assert "/var/lib/agent-bus-analyzer" in manifest


def test_dockerfile_uses_non_root_store_backed_server_entrypoint() -> None:
    dockerfile = _read("deploy/Dockerfile")

    assert "FROM python:" in dockerfile
    assert "pip install --no-cache-dir ." in dockerfile
    assert "USER ${ANALYZER_UID}:${ANALYZER_GID}" in dockerfile
    assert "agent-bus-analyzer" in dockerfile
    assert "serve" in dockerfile
    assert "--store-dir" in dockerfile


def test_cloud_run_manifest_mounts_persistent_trace_store() -> None:
    manifest = _read("deploy/cloudrun/service.yaml")

    assert "volumeMounts:" in manifest
    assert "name: analyzer-trace-store" in manifest
    assert "mountPath: /var/lib/agent-bus-analyzer" in manifest
    assert "volumes:" in manifest
    assert "driver: gcsfuse.run.googleapis.com" in manifest
    assert "readOnly: false" in manifest
    assert "bucketName: REPLACE_ANALYZER_TRACE_BUCKET" in manifest
    assert "mountOptions:" in manifest
    assert "implicit-dirs" in manifest
    assert "uid=10001" in manifest
    assert "gid=10001" in manifest


def test_cloud_run_manifest_limits_file_store_to_single_writer_instance() -> None:
    manifest = _read("deploy/cloudrun/service.yaml")

    assert 'autoscaling.knative.dev/maxScale: "1"' in manifest


def test_dockerfile_uses_stable_non_root_uid_for_mounted_trace_store() -> None:
    dockerfile = _read("deploy/Dockerfile")

    assert "ANALYZER_UID=10001" in dockerfile
    assert "ANALYZER_GID=10001" in dockerfile
    assert "--uid ${ANALYZER_UID}" in dockerfile
    assert "--gid ${ANALYZER_GID}" in dockerfile
    assert "USER ${ANALYZER_UID}:${ANALYZER_GID}" in dockerfile


def test_cloud_run_import_audit_job_writes_mounted_trace_store_once() -> None:
    manifest = _read("deploy/cloudrun/import-audit-job.yaml")

    assert "apiVersion: run.googleapis.com/v1" in manifest
    assert "kind: Job" in manifest
    assert "name: agent-bus-analyzer-import-audit" in manifest
    assert "parallelism: 1" in manifest
    assert "taskCount: 1" in manifest
    assert "maxRetries: 0" in manifest
    assert "serviceAccountName: REPLACE_ANALYZER_RUNTIME_SERVICE_ACCOUNT" in manifest
    assert "command:" in manifest
    assert "agent-bus-analyzer" in manifest
    assert "args:" in manifest
    assert "import-audit" in manifest
    assert "--audit-file" in manifest
    assert "/var/lib/agent-bus-analyzer/imports/gove-zone-audit.jsonl" in manifest
    assert "--store-dir" in manifest
    assert "/var/lib/agent-bus-analyzer" in manifest
    assert "--constitutional-hash" in manifest
    assert "REPLACE_CONSTITUTIONAL_HASH" in manifest
    assert "volumeMounts:" in manifest
    assert "name: analyzer-trace-store" in manifest
    assert "mountPath: /var/lib/agent-bus-analyzer" in manifest
    assert "driver: gcsfuse.run.googleapis.com" in manifest
    assert "readOnly: false" in manifest
    assert "bucketName: REPLACE_ANALYZER_TRACE_BUCKET" in manifest
    assert "mountOptions: implicit-dirs,uid=10001,gid=10001" in manifest
