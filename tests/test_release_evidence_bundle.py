"""Tests for scripts/build_release_evidence.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import build_release_evidence as bre

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_release_evidence.py"


def test_manifest_is_conservative_and_tracks_readiness():
    manifest = bre.build_manifest(ROOT)

    assert manifest["artifactKind"] == "local-release-evidence-bundle"
    assert "not production deployment proof" in manifest["claimBoundary"]
    assert "not legal signoff" in manifest["claimBoundary"]
    assert manifest["readiness"]["summary"]["fail"] == 0
    assert "hosted-storybook-buyer-evidence" in manifest["readiness"]["pendingItemIds"]
    blocker_ids = {blocker["blockerId"] for blocker in manifest["externalBlockers"]}
    assert "production-deployment" in blocker_ids
    assert "frontend-production-auth" in blocker_ids
    assert "hosted-storybook-buyer-evidence" in blocker_ids
    assert "make verify-js-node24" in manifest["verificationCommands"]
    assert "make platform-readiness" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:all" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:cloudrun-renderer" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:production-deploy-contract" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:production-launch-handoff" in manifest["verificationCommands"]
    assert (
        "pnpm -F acgi-ai run test:production-authority-packet" in manifest["verificationCommands"]
    )
    assert (
        "pnpm -F acgi-ai run test:production-evidence-template" in manifest["verificationCommands"]
    )
    assert "pnpm -F acgi-ai run test:production-live-verifier" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:production-blocker-report" in manifest["verificationCommands"]
    assert (
        "pnpm -F acgi-ai run test:production-evidence-validator" in manifest["verificationCommands"]
    )
    assert "pnpm -F acgi-ai run test:production-cutover-plan" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:production-evidence-draft" in manifest["verificationCommands"]
    bridge_command = (
        "uv run --package gove-zone python -m pytest "
        "packages/gove-zone/tests/test_integration_hook.py --import-mode=importlib -q"
    )
    assert bridge_command in manifest["verificationCommands"]
    policy_gate_command = (
        "uv run --package gove-zone python -m pytest "
        "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q"
    )
    assert policy_gate_command in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:storybook-publication" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:storybook-runtime-plan" in manifest["verificationCommands"]
    assert "pnpm -F acgi-ai run test:hosted-storybook-handoff" in manifest["verificationCommands"]
    assert "make production-launch-preflight" in manifest["verificationCommands"]


def test_manifest_exposes_buyer_gallery_ci_artifact():
    manifest = bre.build_manifest(ROOT)
    renderer = manifest["evidenceArtifacts"]["cloudRunRenderer"]
    production_deploy = manifest["evidenceArtifacts"]["productionDeployContract"]
    production_launch = manifest["evidenceArtifacts"]["productionLaunchHandoff"]
    production_launch_preflight = manifest["evidenceArtifacts"]["productionLaunchPreflight"]
    production_authority = manifest["evidenceArtifacts"]["productionAuthorityPacket"]
    production_evidence = manifest["evidenceArtifacts"]["productionEvidenceTemplate"]
    production_live = manifest["evidenceArtifacts"]["productionLiveVerifier"]
    production_blockers = manifest["evidenceArtifacts"]["productionBlockerReport"]
    production_cutover = manifest["evidenceArtifacts"]["productionCutoverPlan"]
    production_evidence_draft = manifest["evidenceArtifacts"]["productionEvidenceDraft"]
    production_validator = manifest["evidenceArtifacts"]["productionEvidenceValidator"]
    production_validation = manifest["evidenceArtifacts"]["productionEvidenceValidation"]
    production_chain = manifest["evidenceArtifacts"]["productionEvidenceChain"]
    fixture_fallback = manifest["evidenceArtifacts"]["fixtureFallbackBoundary"]
    runtime_bridge = manifest["evidenceArtifacts"]["runtimeFrameworkBridge"]
    runtime_policy_gate = manifest["evidenceArtifacts"]["runtimePolicyGate"]
    storybook_runtime = manifest["evidenceArtifacts"]["storybookRuntimePlan"]
    publication = manifest["evidenceArtifacts"]["storybookPublication"]
    hosted_storybook = manifest["evidenceArtifacts"]["hostedStorybookHandoff"]
    buyer = manifest["evidenceArtifacts"]["buyerEvidenceGallery"]

    assert renderer["script"] == "acgi-ai/scripts/render-cloudrun-service.mjs"
    assert renderer["proofCommand"] == "pnpm -F acgi-ai run test:cloudrun-renderer"
    assert (
        production_deploy["proofCommand"] == "pnpm -F acgi-ai run test:production-deploy-contract"
    )
    assert production_deploy["marketingWorkflow"] == ".github/workflows/marketing.yml"
    assert production_deploy["consoleWorkflow"] == ".github/workflows/console.yml"
    assert "not live production deployment proof" in production_deploy["claimBoundary"]
    assert production_launch["handoff"] == "acgi-ai/PRODUCTION-LAUNCH.md"
    assert production_launch["proofCommand"] == "pnpm -F acgi-ai run test:production-launch-handoff"
    assert "not live production deployment proof" in production_launch["claimBoundary"]
    assert production_launch_preflight["script"] == "scripts/production_launch_preflight.py"
    assert production_launch_preflight["proofCommand"] == "make production-launch-preflight"
    assert "--require-ready" in production_launch_preflight["operatorCommand"]
    assert "requiredActions" in production_launch_preflight["outputFields"]
    assert "repository" in production_launch_preflight["outputFields"]
    assert "externalBlockerIds" in production_launch_preflight["outputFields"]
    assert "current clean commit" in production_launch_preflight["claimBoundary"]
    assert "does not deploy" in production_launch_preflight["claimBoundary"]
    assert production_authority["templatePath"] == "acgi-ai/production-authority.example.json"
    assert (
        production_authority["proofCommand"]
        == "pnpm -F acgi-ai run test:production-authority-packet"
    )
    assert production_authority["templatePresent"] is True
    assert production_authority["templateStatus"] == "pending-external-authority"
    assert "deploy-owner-approval" in production_authority["requiredApprovalIds"]
    assert "pending-external:deploy-owner-approval" in json.dumps(manifest)
    assert "not production deployment proof" in production_authority["claimBoundary"]
    assert production_evidence["templatePath"] == "acgi-ai/production-evidence.example.json"
    assert (
        production_evidence["proofCommand"]
        == "pnpm -F acgi-ai run test:production-evidence-template"
    )
    assert production_evidence["templatePresent"] is True
    assert production_evidence["templateStatus"] == "template-only"
    assert "not live production proof" in production_evidence["claimBoundary"]
    assert "pending-external" in production_evidence["claimBoundary"]
    assert production_live["script"] == "acgi-ai/scripts/verify-production-live.mjs"
    assert production_live["proofCommand"] == "pnpm -F acgi-ai run test:production-live-verifier"
    assert (
        production_live["liveProofCommand"]
        == "pnpm -F acgi-ai run verify:production-live -- --json"
    )
    assert (
        production_live["savedOutputCommand"]
        == "pnpm -F acgi-ai run verify:production-live -- --json --out "
        "../dist-release-evidence/production-live-verification.json"
    )
    assert "https://console.acgs.ai" in production_live["targets"]
    assert "blockers" in production_live["outputFields"]
    assert "blockedUntil" in production_live["outputFields"]
    assert (
        production_live["latestOutputSnapshot"]["path"]
        == "dist-release-evidence/production-live-verification.json"
    )
    assert "not live production proof" in production_live["latestOutputSnapshot"]["claimBoundary"]
    assert "not live production proof" in production_live["claimBoundary"]
    assert "productionLiveBlockers" in production_live["claimBoundary"]
    assert production_blockers["script"] == "acgi-ai/scripts/build-production-blocker-report.mjs"
    assert (
        production_blockers["proofCommand"] == "pnpm -F acgi-ai run test:production-blocker-report"
    )
    assert "build:production-blocker-report" in production_blockers["operatorCommand"]
    assert "copyIntoProductionEvidence" in production_blockers["outputFields"]
    assert (
        production_blockers["latestReportSnapshot"]["path"]
        == "dist-release-evidence/production-blocker-report.json"
    )
    assert (
        "not live production proof" in production_blockers["latestReportSnapshot"]["claimBoundary"]
    )
    assert "not live production proof" in production_blockers["claimBoundary"]
    assert production_cutover["script"] == "acgi-ai/scripts/build-production-cutover-plan.mjs"
    assert production_cutover["proofCommand"] == "pnpm -F acgi-ai run test:production-cutover-plan"
    assert "build:production-cutover-plan" in production_cutover["operatorCommand"]
    assert "dnsCutover" in production_cutover["outputFields"]
    assert "copyIntoProductionEvidence" in production_cutover["outputFields"]
    assert (
        production_cutover["latestPlanSnapshot"]["path"]
        == "dist-release-evidence/production-cutover-plan.json"
    )
    assert "not live production proof" in production_cutover["latestPlanSnapshot"]["claimBoundary"]
    assert "not live production proof" in production_cutover["claimBoundary"]
    assert (
        production_evidence_draft["script"] == "acgi-ai/scripts/build-production-evidence-draft.mjs"
    )
    assert (
        production_evidence_draft["proofCommand"]
        == "pnpm -F acgi-ai run test:production-evidence-draft"
    )
    assert "build:production-evidence-draft" in production_evidence_draft["operatorCommand"]
    assert "productionBlockerReport" in production_evidence_draft["outputFields"]
    assert "productionCutoverPlan" in production_evidence_draft["outputFields"]
    assert (
        production_evidence_draft["latestDraftSnapshot"]["path"]
        == "dist-release-evidence/production-evidence.deployment-blocked.json"
    )
    assert "not live production proof" in production_evidence_draft["claimBoundary"]
    assert "pending-external" in production_evidence_draft["outputFields"]
    assert production_validator["script"] == "acgi-ai/scripts/validate-production-evidence.mjs"
    assert (
        production_validator["proofCommand"]
        == "pnpm -F acgi-ai run test:production-evidence-validator"
    )
    assert "validate:production-evidence" in production_validator["operatorCommand"]
    assert "productionLiveStatus" in production_validator["templateFields"]
    assert "productionLiveBlockers" in production_validator["templateFields"]
    assert "validatedProductionEvidence" in production_validator["templateFields"]
    assert "not legal" in production_validator["claimBoundary"]
    assert (
        production_validation["latestValidationSnapshot"]["path"]
        == "dist-release-evidence/production-evidence-validation.deployment-blocked.json"
    )
    assert "not live production proof" in production_validation["claimBoundary"]
    assert production_chain["proofCommand"] == "make release-evidence"
    assert production_chain["latestChainSnapshot"]["status"] in {"consistent", "needs-refresh"}
    assert "productionEvidenceValidation" in production_chain["latestChainSnapshot"]["artifacts"]
    assert "not live production proof" in production_chain["claimBoundary"]
    assert fixture_fallback["module"] == "acgi-ai/src/api/hooks.ts"
    assert "pnpm -F acgi-ai run test:security" in fixture_fallback["proofCommands"]
    assert "pnpm -F acgi-ai run test:mvp" in fixture_fallback["proofCommands"]
    assert (
        "import.meta.env.PROD disables fixture fallback" in fixture_fallback["productionBehavior"]
    )
    assert "network-unavailable TypeError" in fixture_fallback["mockModeBehavior"]
    assert "not proof that the live governed bus is deployed" in fixture_fallback["claimBoundary"]
    assert runtime_bridge["module"] == "packages/gove-zone/src/gove_zone/integration.py"
    assert runtime_bridge["publicHelper"] == "tool_call_from_hook_payload"
    assert "test_integration_hook.py" in runtime_bridge["proofCommand"]
    assert "test_setup.py" in runtime_bridge["cliProofCommand"]
    assert "MCP-style" in runtime_bridge["supportedLocalShapes"][1]
    assert "tool_calls" in runtime_bridge["supportedLocalShapes"][3]
    assert "OpenAI Chat" in runtime_bridge["supportedLocalShapes"][3]
    assert "tool_calls" in runtime_bridge["supportedLocalShapes"][4]
    assert "LangChain-style" in runtime_bridge["supportedLocalShapes"][4]
    assert "not a claim" in runtime_bridge["claimBoundary"]
    assert "gove-zone gate --policy-bundle" in runtime_policy_gate["cli"]
    assert runtime_policy_gate["policyType"] == "RuleSetPolicy"
    assert "deny" in runtime_policy_gate["blockingDecisions"]
    assert "escalate" in runtime_policy_gate["blockingDecisions"]
    assert "OpenAI Chat" in runtime_policy_gate["coveredPayloadShapes"][0]
    assert "LangChain-style" in runtime_policy_gate["coveredPayloadShapes"][1]
    assert "not live third-party deployment proof" in runtime_policy_gate["claimBoundary"]
    assert storybook_runtime["planPath"] == "acgi-ai/storybook-runtime.plan.json"
    assert storybook_runtime["proofCommand"] == "pnpm -F acgi-ai run test:storybook-runtime-plan"
    assert storybook_runtime["status"] == "pending-dependency-authority"
    assert "dependency-owner-approval" in storybook_runtime["requiredApprovalIds"]
    assert storybook_runtime["proposedRuntime"]["frameworkPackage"] == "@storybook/react-vite"
    assert storybook_runtime["proposedRuntime"]["initCommand"] == "npx storybook@latest init"
    assert "not official Storybook runtime proof" in storybook_runtime["claimBoundary"]
    assert "pending-external" in storybook_runtime["claimBoundary"]
    assert "pending-external:dependency-owner-approval" in json.dumps(storybook_runtime)
    assert publication["workflow"] == ".github/workflows/storybook.yml"
    assert publication["target"] == "https://storybook.acgs.ai"
    assert publication["proofCommand"] == "pnpm -F acgi-ai run test:storybook-publication"
    assert publication["deploymentGate"] == "vars.STORYBOOK_PAGES_ENABLED == 'true'"
    assert hosted_storybook["script"] == "acgi-ai/scripts/build-hosted-storybook-handoff.mjs"
    assert hosted_storybook["proofCommand"] == "pnpm -F acgi-ai run test:hosted-storybook-handoff"
    assert "build:hosted-storybook-handoff" in hosted_storybook["operatorCommand"]
    assert "storybook-manifest-live" in hosted_storybook["outputFields"]
    assert "pending-external" in hosted_storybook["outputFields"]
    assert "copyIntoProductionEvidence.hostedStorybook" in hosted_storybook["outputFields"]
    assert (
        hosted_storybook["latestHandoffSnapshot"]["path"]
        == "dist-release-evidence/hosted-storybook-handoff.json"
    )
    assert "not live production proof" in hosted_storybook["claimBoundary"]
    assert buyer["expectedPath"] == "acgi-ai/dist-buyer-evidence/"
    assert buyer["ciArtifactName"] == "buyer-evidence-gallery"


def test_write_bundle_outputs_machine_and_human_artifacts(tmp_path: Path):
    out_dir = tmp_path / "release-evidence"
    manifest = bre.write_bundle(out_dir=out_dir, repo_root=ROOT)

    manifest_path = out_dir / "manifest.json"
    readiness_path = out_dir / "platform-readiness.json"
    readme_path = out_dir / "README.md"

    assert manifest_path.is_file()
    assert readiness_path.is_file()
    assert readme_path.is_file()
    assert json.loads(manifest_path.read_text())["artifactKind"] == manifest["artifactKind"]
    assert json.loads(readiness_path.read_text())["summary"]["fail"] == 0
    readme = readme_path.read_text()
    assert "Local release-readiness evidence bundle" in readme
    assert "not live production proof" in readme or "not production deployment proof" in readme
    assert "production-evidence.example.json" in readme
    assert "verify-production-live.mjs" in readme
    assert "test:production-live-verifier" in readme
    assert "build-production-blocker-report.mjs" in readme
    assert "test:production-blocker-report" in readme
    assert "Saved live-evidence snapshots" in readme
    assert "production-live-verification.json" in readme
    assert "production-blocker-report.json" in readme
    assert "production-cutover-plan.json" in readme
    assert "test:production-cutover-plan" in readme
    assert "build-production-evidence-draft.mjs" in readme
    assert "production-evidence.deployment-blocked.json" in readme
    assert "production-evidence-validation.deployment-blocked.json" in readme
    assert "production evidence chain" in readme
    assert "production_launch_preflight.py" in readme
    assert "make production-launch-preflight" in readme
    assert "--require-ready" in readme
    assert "test:production-evidence-draft" in readme
    assert "build-hosted-storybook-handoff.mjs" in readme
    assert "hosted-storybook-handoff.json" in readme
    assert "test:hosted-storybook-handoff" in readme
    assert "pending-external:storybook-pages-proof" in readme
    assert "productionLiveBlockers" in readme
    assert "copyIntoProductionEvidence" in readme
    assert "network-unavailable `TypeError`" in readme
    assert "tool_call_from_hook_payload" in readme
    assert "gove-zone gate --policy-bundle" in readme
    assert "pending-external" in readme


def test_cli_writes_bundle_and_exits_zero_with_pending_items(tmp_path: Path):
    out_dir = tmp_path / "bundle"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--out-dir", str(out_dir)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Release evidence bundle written" in result.stdout
    assert (out_dir / "manifest.json").is_file()


def test_optional_live_snapshot_helpers_are_claim_safe(tmp_path: Path):
    evidence_dir = tmp_path / "dist-release-evidence"
    evidence_dir.mkdir()
    (evidence_dir / "production-live-verification.json").write_text(
        json.dumps(
            {
                "artifactKind": "production-live-verification",
                "generatedAt": "2026-05-25T00:00:00Z",
                "status": "fail",
                "blockedUntil": "Fix DNS",
                "claimBoundary": "source boundary",
                "targets": {"consoleUrl": "https://console.acgs.ai"},
                "checks": [
                    {"id": "console-dns-live", "status": "fail", "error": "ENOTFOUND"},
                    {"id": "storybook-dns-live", "status": "fail", "error": "ENOTFOUND"},
                    {"id": "marketing-dns-live", "status": "pass"},
                ],
                "blockers": [
                    {"blockerId": "live-console-dns"},
                    {"blockerId": "live-console-healthz"},
                    {"blockerId": "live-storybook-dns"},
                ],
            }
        )
        + "\n"
    )
    (evidence_dir / "production-blocker-report.json").write_text(
        json.dumps(
            {
                "artifactKind": "production-blocker-report",
                "generatedAt": "2026-05-25T00:00:01Z",
                "status": "blocked",
                "productionLiveStatus": "fail",
                "productionLiveBlockers": [
                    "live-console-dns",
                    "live-console-healthz",
                    "live-storybook-dns",
                ],
                "failedCheckIds": ["console-dns-live"],
                "blockedUntil": "Fix DNS",
                "claimBoundary": "source blocker boundary",
            }
        )
        + "\n"
    )
    (evidence_dir / "production-cutover-plan.json").write_text(
        json.dumps(
            {
                "artifactKind": "production-cutover-plan",
                "generatedAt": "2026-05-25T00:00:02Z",
                "status": "blocked",
                "productionLiveBlockers": [
                    "live-console-dns",
                    "live-console-healthz",
                    "live-storybook-dns",
                ],
                "failedCheckIds": ["console-dns-live"],
                "blockedUntil": "Fix DNS",
                "claimBoundary": "source cutover boundary",
            }
        )
        + "\n"
    )
    (evidence_dir / "production-evidence.deployment-blocked.json").write_text(
        json.dumps(
            {
                "artifactKind": "production-evidence",
                "generatedAt": "2026-05-25T00:00:03Z",
                "status": "deployment-blocked",
                "claimBoundary": "source draft boundary",
                "verification": {
                    "productionLiveStatus": "fail",
                    "productionLiveBlockers": [
                        "live-console-dns",
                        "live-console-healthz",
                        "live-storybook-dns",
                    ],
                },
                "artifacts": {
                    "productionBlockerReport": (
                        "dist-release-evidence/production-blocker-report.json"
                    ),
                    "productionCutoverPlan": "dist-release-evidence/production-cutover-plan.json",
                },
                "sourceArtifacts": {
                    "liveOutputPath": "dist-release-evidence/production-live-verification.json"
                },
                "blockedUntil": "Fix DNS",
            }
        )
        + "\n"
    )
    (evidence_dir / "production-evidence-validation.deployment-blocked.json").write_text(
        json.dumps(
            {
                "artifactKind": "production-evidence-validation",
                "generatedAt": "2026-05-25T00:00:04Z",
                "status": "pass",
                "claimBoundary": "source validation boundary",
                "manifestPath": (
                    "../dist-release-evidence/production-evidence.deployment-blocked.json"
                ),
                "liveOutputPath": "../dist-release-evidence/production-live-verification.json",
                "checks": [
                    {"id": "schema-version", "status": "pass"},
                    {"id": "production-live-blockers-field", "status": "pass"},
                ],
            }
        )
        + "\n"
    )
    (evidence_dir / "hosted-storybook-handoff.json").write_text(
        json.dumps(
            {
                "artifactKind": "hosted-storybook-handoff",
                "generatedAt": "2026-05-25T00:00:05Z",
                "status": "blocked",
                "claimBoundary": "source hosted Storybook boundary",
                "target": {
                    "url": "https://storybook.acgs.ai",
                    "manifestUrl": "https://storybook.acgs.ai/manifest.json",
                },
                "localPublication": {"publishTargetReady": True},
                "liveVerification": {
                    "productionLiveStatus": "fail",
                    "storybookBlockers": [{"blockerId": "live-storybook-dns"}],
                },
                "copyIntoProductionEvidence": {
                    "hostedStorybook": {"status": "pending"},
                    "remainingBlocker": "hosted-storybook-buyer-evidence",
                },
            }
        )
        + "\n"
    )

    live = bre.production_live_snapshot(tmp_path)
    blockers = bre.production_blocker_report_snapshot(tmp_path)
    cutover = bre.production_cutover_plan_snapshot(tmp_path)
    draft = bre.production_evidence_draft_snapshot(tmp_path)
    validation = bre.production_evidence_validation_snapshot(tmp_path)
    chain = bre.production_evidence_chain_snapshot(tmp_path)
    hosted_storybook = bre.hosted_storybook_handoff_snapshot(tmp_path)

    assert live["present"] is True
    assert live["status"] == "fail"
    assert live["blockers"] == [
        "live-console-dns",
        "live-console-healthz",
        "live-storybook-dns",
    ]
    assert live["checkStatuses"][0] == {
        "id": "console-dns-live",
        "status": "fail",
        "error": "ENOTFOUND",
    }
    assert "not live production proof" in live["claimBoundary"]
    assert blockers["present"] is True
    assert blockers["status"] == "blocked"
    assert blockers["productionLiveBlockers"] == [
        "live-console-dns",
        "live-console-healthz",
        "live-storybook-dns",
    ]
    assert "not live production proof" in blockers["claimBoundary"]
    assert cutover["present"] is True
    assert cutover["status"] == "blocked"
    assert cutover["productionLiveBlockers"] == [
        "live-console-dns",
        "live-console-healthz",
        "live-storybook-dns",
    ]
    assert "not live production proof" in cutover["claimBoundary"]
    assert draft["present"] is True
    assert draft["status"] == "deployment-blocked"
    assert draft["productionLiveStatus"] == "fail"
    assert draft["productionLiveBlockers"] == [
        "live-console-dns",
        "live-console-healthz",
        "live-storybook-dns",
    ]
    assert "not live production proof" in draft["claimBoundary"]
    assert validation["present"] is True
    assert validation["status"] == "pass"
    assert validation["checkCount"] == 2
    assert validation["failingCheckIds"] == []
    assert "not live production proof" in validation["claimBoundary"]
    assert chain["status"] == "consistent"
    assert chain["blockerSets"]["productionLiveVerifier"] == [
        "live-console-dns",
        "live-console-healthz",
        "live-storybook-dns",
    ]
    assert chain["issues"] == []
    assert "not live production proof" in chain["claimBoundary"]
    assert hosted_storybook["present"] is True
    assert hosted_storybook["status"] == "blocked"
    assert hosted_storybook["targetUrl"] == "https://storybook.acgs.ai"
    assert hosted_storybook["storybookBlockers"] == ["live-storybook-dns"]
    assert "not live production proof" in hosted_storybook["claimBoundary"]
    assert bre.production_live_snapshot(tmp_path / "missing")["present"] is False
    assert bre.production_evidence_draft_snapshot(tmp_path / "missing")["present"] is False
    assert bre.production_evidence_validation_snapshot(tmp_path / "missing")["present"] is False
    assert bre.production_evidence_chain_snapshot(tmp_path / "missing")["status"] == "needs-refresh"
    assert bre.hosted_storybook_handoff_snapshot(tmp_path / "missing")["present"] is False
