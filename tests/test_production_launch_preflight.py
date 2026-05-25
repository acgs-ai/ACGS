"""Tests for scripts/production_launch_preflight.py."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import build_release_evidence as bre
import production_launch_preflight as plp

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "production_launch_preflight.py"


def test_current_manifest_preflight_stays_blocked_until_external_proof_is_attached():
    manifest = bre.build_manifest(ROOT)
    preflight = plp.build_preflight(manifest, manifest_path="dist-release-evidence/manifest.json")

    assert preflight["artifactKind"] == "production-launch-preflight"
    assert preflight["status"] == "blocked"
    assert "not production deployment proof" in preflight["claimBoundary"]
    assert "hosted-storybook-buyer-evidence" in preflight["pendingItemIds"]
    assert "hosted-storybook-buyer-evidence" in preflight["externalBlockerIds"]
    assert preflight["productionEvidenceChain"]["status"] in {"consistent", "needs-refresh"}
    action_ids = {action["id"] for action in preflight["requiredActions"]}
    assert "clear-local-readiness-pending-items" in action_ids
    assert "replace-external-blockers-with-proof" in action_ids


def test_ready_manifest_requires_no_pending_live_chain_validation_or_external_blockers():
    manifest = bre.build_manifest(ROOT)
    ready_manifest = copy.deepcopy(manifest)
    ready_manifest["readiness"]["summary"] = {"fail": 0, "pass": 1, "pending": 0, "total": 1}
    ready_manifest["readiness"]["pendingItemIds"] = []
    ready_manifest["readiness"]["failingItemIds"] = []
    ready_manifest["externalBlockers"] = []
    artifacts = ready_manifest["evidenceArtifacts"]
    artifacts["productionLiveVerifier"]["latestOutputSnapshot"].update(
        {"present": True, "status": "pass", "blockers": []}
    )
    artifacts["productionEvidenceChain"]["latestChainSnapshot"].update(
        {"status": "consistent", "issues": []}
    )
    artifacts["productionEvidenceValidation"]["latestValidationSnapshot"].update(
        {"present": True, "status": "pass", "failingCheckIds": []}
    )

    preflight = plp.build_preflight(ready_manifest, manifest_path="ready-manifest.json")

    assert preflight["status"] == "ready"
    assert preflight["requiredActions"] == []
    assert preflight["externalBlockerIds"] == []


def test_cli_outputs_json_and_require_ready_fails_for_blocked_manifest(tmp_path: Path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(bre.build_manifest(ROOT)), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--manifest", str(manifest_path), "--json"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["requiredActions"]

    require_ready = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--manifest",
            str(manifest_path),
            "--json",
            "--require-ready",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    assert require_ready.returncode == 1
    assert json.loads(require_ready.stdout)["status"] == "blocked"
