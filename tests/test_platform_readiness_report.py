"""Tests for scripts/platform_readiness_report.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import platform_readiness_report as pr

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "platform_readiness_report.py"


def test_build_items_tracks_local_passes_and_pending_hosted_storybook():
    items = pr.build_items(ROOT)
    by_id = {item.item_id: item for item in items}

    assert by_id["local-evidence-spine"].status == "pass"
    assert by_id["bus-contract-regeneration"].status == "pass"
    assert by_id["deploy-contracts-local"].status == "pass"
    assert by_id["console-auth-forward-gate"].status == "pass"
    assert "/auth/status" in by_id["console-auth-forward-gate"].evidence
    assert "hasProductionSession" in by_id["console-auth-forward-gate"].evidence
    assert by_id["cloudrun-renderer-local"].status == "pass"
    assert by_id["production-deploy-fail-closed-local"].status == "pass"
    assert by_id["production-launch-handoff-local"].status == "pass"
    assert by_id["production-authority-packet-local"].status == "pass"
    authority_item = by_id["production-authority-packet-local"]
    authority_template = pr._maybe_read(ROOT, "acgi-ai/production-authority.example.json")
    assert "production-authority.example.json" in authority_item.evidence
    assert "pending-external" in authority_item.evidence
    assert "pending-external:deploy-owner-approval" in authority_template
    assert "not production deployment proof" in authority_template
    assert by_id["production-evidence-template-local"].status == "pass"
    assert "pending-external" in by_id["production-evidence-template-local"].evidence
    assert (
        "verified assurance detail fields" in by_id["production-evidence-template-local"].evidence
    )
    assert by_id["production-live-verifier-local"].status == "pass"
    assert "verify:production-live" in by_id["production-live-verifier-local"].evidence
    assert "blocker ids" in by_id["production-live-verifier-local"].evidence
    assert by_id["production-blocker-report-local"].status == "pass"
    assert "copyIntoProductionEvidence" in by_id["production-blocker-report-local"].evidence
    assert by_id["production-evidence-validator-local"].status == "pass"
    assert "validate:production-evidence" in by_id["production-evidence-validator-local"].evidence
    assert "blocker ids" in by_id["production-evidence-validator-local"].evidence
    assert "manual WCAG" in by_id["production-evidence-validator-local"].evidence
    assert "pending-external refs" in by_id["production-evidence-validator-local"].evidence
    assert by_id["production-cutover-plan-local"].status == "pass"
    assert "DNS cutover" in by_id["production-cutover-plan-local"].evidence
    assert "liveCheckSummary" in by_id["production-cutover-plan-local"].evidence
    assert "cutoverDelta" in by_id["production-cutover-plan-local"].evidence
    assert "copyIntoProductionEvidence" in by_id["production-cutover-plan-local"].evidence
    assert by_id["production-evidence-draft-local"].status == "pass"
    assert "deployment-blocked" in by_id["production-evidence-draft-local"].evidence
    assert "pending-external" in by_id["production-evidence-draft-local"].evidence
    assert by_id["production-evidence-chain-local"].status == "pass"
    assert "blocker drift" in by_id["production-evidence-chain-local"].evidence
    assert "not live production proof" in by_id["production-evidence-chain-local"].evidence
    assert by_id["production-blocker-evidence-runbook-local"].status == "pass"
    assert (
        "build_production_blocker_evidence.py"
        in by_id["production-blocker-evidence-runbook-local"].command
    )
    assert (
        "tests/test_production_blocker_evidence.py"
        in by_id["production-blocker-evidence-runbook-local"].command
    )
    blocker_evidence = by_id["production-blocker-evidence-runbook-local"].evidence
    assert "exact Node 24 gate" in blocker_evidence
    assert "non-deploying dry-run plan" in blocker_evidence
    assert "transcript canonicalization" in blocker_evidence
    assert "preflight JSON" in blocker_evidence
    assert by_id["production-launch-preflight-local"].status == "pass"
    assert "ready/blocked" in by_id["production-launch-preflight-local"].evidence
    assert "clean commit" in by_id["production-launch-preflight-local"].evidence
    assert "proof-intake artifacts" in by_id["production-launch-preflight-local"].evidence
    assert "not production deployment proof" in by_id["production-launch-preflight-local"].evidence
    assert by_id["fixture-fallback-fail-closed-local"].status == "pass"
    assert "network-unavailable" in by_id["fixture-fallback-fail-closed-local"].evidence
    assert by_id["claim-safety"].status == "pass"
    assert by_id["platform-blueprint-ui-local"].status == "pass"
    assert "same-style marketing workbench" in by_id["platform-blueprint-ui-local"].evidence
    assert "console workbench" in by_id["platform-blueprint-ui-local"].evidence
    assert "one workbench content contract" in by_id["platform-blueprint-ui-local"].evidence
    assert "service-design/accessibility anchors" in by_id["platform-blueprint-ui-local"].evidence
    assert "guided review path" in by_id["platform-blueprint-ui-local"].evidence
    assert "operator decision rail" in by_id["platform-blueprint-ui-local"].evidence
    assert "framework integration rail" in by_id["platform-blueprint-ui-local"].evidence
    assert "agent framework starter kits" in by_id["platform-blueprint-ui-local"].evidence
    assert "launch proof ladder" in by_id["platform-blueprint-ui-local"].evidence
    assert "live verifier blocker map" in by_id["platform-blueprint-ui-local"].evidence
    assert "release blocker queue" in by_id["platform-blueprint-ui-local"].evidence
    assert "production command rail" in by_id["platform-blueprint-ui-local"].evidence
    assert "hosted Storybook runway" in by_id["platform-blueprint-ui-local"].evidence
    assert "assurance proof intake" in by_id["platform-blueprint-ui-local"].evidence
    assert "35/36 local readiness copy" in by_id["platform-blueprint-ui-local"].evidence
    assert "test:platform-blueprint" in by_id["platform-blueprint-ui-local"].command
    assert by_id["local-verification-fanout"].status == "pass"
    assert "configured pyproject mypy fan-out" in by_id["local-verification-fanout"].evidence
    assert by_id["release-evidence-bundle"].status == "pass"
    assert by_id["node24-local-toolchain"].status == "pass"
    assert by_id["buyer-evidence-gallery-local"].status == "pass"
    assert "visual workbench story" in by_id["buyer-evidence-gallery-local"].evidence
    assert "agent framework starter kits" in by_id["buyer-evidence-gallery-local"].evidence
    assert "operator decision rail story" in by_id["buyer-evidence-gallery-local"].evidence
    assert "launch proof ladder story" in by_id["buyer-evidence-gallery-local"].evidence
    assert "hosted Storybook runway proof points" in by_id["buyer-evidence-gallery-local"].evidence
    assert by_id["browser-workbench-evidence-local"].status == "pass"
    assert (
        "Chrome/Chromium screenshot command" in by_id["browser-workbench-evidence-local"].evidence
    )
    assert "target-visible hash guard" in by_id["browser-workbench-evidence-local"].evidence
    assert "operator decision rail" in by_id["browser-workbench-evidence-local"].evidence
    assert "guided review path" in by_id["browser-workbench-evidence-local"].evidence
    assert "framework integration rail" in by_id["browser-workbench-evidence-local"].evidence
    assert "agent framework starter kits" in by_id["browser-workbench-evidence-local"].evidence
    assert "live verifier blocker map" in by_id["browser-workbench-evidence-local"].evidence
    assert "release blocker queue" in by_id["browser-workbench-evidence-local"].evidence
    assert "production command rail" in by_id["browser-workbench-evidence-local"].evidence
    assert "hosted Storybook runway" in by_id["browser-workbench-evidence-local"].evidence
    assert "assurance proof intake" in by_id["browser-workbench-evidence-local"].evidence
    assert "five visual baseline viewports" in by_id["browser-workbench-evidence-local"].evidence
    assert "test:browser-evidence" in by_id["browser-workbench-evidence-local"].command
    assert "evidence:browser-workbench" in by_id["browser-workbench-evidence-local"].command
    assert by_id["runtime-framework-bridge-local"].status == "pass"
    assert "MCP" in by_id["runtime-framework-bridge-local"].evidence
    assert "OpenAI Responses" in by_id["runtime-framework-bridge-local"].evidence
    assert "batched tool-call" in by_id["runtime-framework-bridge-local"].evidence
    assert "malformed recognized batch" in by_id["runtime-framework-bridge-local"].evidence
    assert "/products/gove-zone" in by_id["runtime-framework-bridge-local"].evidence
    assert by_id["runtime-policy-gate-local"].status == "pass"
    assert "RuleSetPolicy" in by_id["runtime-policy-gate-local"].evidence
    assert "OpenAI Responses" in by_id["runtime-policy-gate-local"].evidence
    assert "batched event" in by_id["runtime-policy-gate-local"].evidence
    assert "malformed recognized" in by_id["runtime-policy-gate-local"].evidence
    assert by_id["gove-zone-smoke-local"].status == "pass"
    assert "allow/deny/audit-chain" in by_id["gove-zone-smoke-local"].evidence
    assert "gove-zone smoke" in by_id["gove-zone-smoke-local"].command
    assert by_id["buyer-evidence-ci-artifact"].status == "pass"
    assert by_id["storybook-runtime-plan-local"].status == "pass"
    assert "pending-external" in by_id["storybook-runtime-plan-local"].evidence
    storybook_runtime_plan = pr._maybe_read(ROOT, "acgi-ai/storybook-runtime.plan.json")
    assert "pending-external:dependency-owner-approval" in storybook_runtime_plan
    assert "not official Storybook runtime proof" in storybook_runtime_plan
    assert "storybook build --output-dir storybook-static" in storybook_runtime_plan
    assert "visual-governance-workbench" in storybook_runtime_plan
    assert "operator-decision-rail" in storybook_runtime_plan
    assert "guided-review-path" in storybook_runtime_plan
    assert "launch-proof-ladder" in storybook_runtime_plan
    assert by_id["storybook-publication-workflow-local"].status == "pass"
    assert (
        "hosted handoff/proof-template checks"
        in by_id["storybook-publication-workflow-local"].evidence
    )
    assert by_id["hosted-storybook-handoff-local"].status == "pass"
    assert "pending-external" in by_id["hosted-storybook-handoff-local"].evidence
    assert "copyIntoProductionEvidence" in by_id["hosted-storybook-handoff-local"].evidence
    assert by_id["hosted-storybook-proof-intake-local"].status == "pass"
    assert (
        "hosted-storybook-proof.example.json"
        in by_id["hosted-storybook-proof-intake-local"].evidence
    )
    assert (
        "test:hosted-storybook-proof-template"
        in by_id["hosted-storybook-proof-intake-local"].command
    )
    assert (
        "test:hosted-storybook-proof-gap-report"
        in by_id["hosted-storybook-proof-intake-local"].command
    )
    assert (
        "build:hosted-storybook-proof-gap-report"
        in by_id["hosted-storybook-proof-intake-local"].command
    )
    assert "validate:hosted-storybook-proof" in by_id["hosted-storybook-proof-intake-local"].command
    assert (
        "../dist-release-evidence/hosted-storybook-proof-validation.json"
        in by_id["hosted-storybook-proof-intake-local"].command
    )
    assert "gap checklist" in by_id["hosted-storybook-proof-intake-local"].evidence
    assert "completed-proof checks" in by_id["hosted-storybook-proof-intake-local"].evidence
    assert (
        "hosted-storybook-proof-validation.json"
        in by_id["hosted-storybook-proof-intake-local"].evidence
    )
    assert (
        "hosted-storybook-proof-gap-report.json"
        in by_id["hosted-storybook-proof-intake-local"].command
    )
    assert "visual-diff evidence" in by_id["hosted-storybook-proof-intake-local"].evidence
    assert (
        "all eight buyer-evidence stories" in by_id["hosted-storybook-proof-intake-local"].evidence
    )
    assert by_id["external-blockers-documented"].status == "pass"
    assert by_id["hosted-storybook-buyer-evidence"].status == "pending"
    assert (
        "storybook.acgs.ai publication workflow exists"
        in by_id["hosted-storybook-buyer-evidence"].evidence
    )


def test_bus_contract_item_locks_root_openapi_wiring():
    item = next(i for i in pr.build_items(ROOT) if i.item_id == "bus-contract-regeneration")
    assert item.status == "pass"
    assert "make openapi" in item.command
    assert "test:bus-schema" in item.command


def test_summary_counts_pending_without_failing():
    items = pr.build_items(ROOT)
    summary = pr.summarize(items)

    assert summary["fail"] == 0
    assert summary["pending"] >= 1
    assert summary["pass"] + summary["pending"] == summary["total"]


def test_render_markdown_keeps_deployment_claim_conservative():
    report = pr.render_markdown(pr.build_items(ROOT))

    assert "Platform readiness report" in report
    assert "Production deployment remains unproven" in report
    assert "release-evidence-bundle" in report
    assert "console-auth-forward-gate" in report
    assert "cloudrun-renderer-local" in report
    assert "production-deploy-fail-closed-local" in report
    assert "production-launch-handoff-local" in report
    assert "production-authority-packet-local" in report
    assert "test:production-authority-packet" in report
    assert "production-evidence-template-local" in report
    assert "production-live-verifier-local" in report
    assert "production-blocker-report-local" in report
    assert "production-evidence-validator-local" in report
    assert "production-cutover-plan-local" in report
    assert "production-evidence-draft-local" in report
    assert "production-evidence-chain-local" in report
    assert "production-blocker-evidence-runbook-local" in report
    assert "production-launch-preflight-local" in report
    assert "fixture-fallback-fail-closed-local" in report
    assert "platform-blueprint-ui-local" in report
    assert "node24-local-toolchain" in report
    assert "buyer-evidence-gallery-local" in report
    assert "browser-workbench-evidence-local" in report
    assert "runtime-framework-bridge-local" in report
    assert "runtime-policy-gate-local" in report
    assert "gove-zone-smoke-local" in report
    assert "buyer-evidence-ci-artifact" in report
    assert "storybook-runtime-plan-local" in report
    assert "test:storybook-runtime-plan" in report
    assert "storybook-publication-workflow-local" in report
    assert "hosted-storybook-handoff-local" in report
    assert "hosted-storybook-proof-intake-local" in report
    assert "test:hosted-storybook-proof-gap-report" in report
    assert "hosted-storybook-buyer-evidence" in report
    assert "pending" in report


def test_cli_json_exits_zero_with_pending_items():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["summary"]["fail"] == 0
    assert payload["summary"]["pending"] >= 1
