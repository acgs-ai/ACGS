#!/usr/bin/env python3
"""Build a local release-readiness evidence bundle.

The bundle is deliberately conservative: it captures current repo-local
readiness evidence and explicit external blockers, but it is not a production
release, hosted deploy, legal signoff, or compliance attestation.

Usage:
    python scripts/build_release_evidence.py
    python scripts/build_release_evidence.py --out-dir dist-release-evidence
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

import platform_readiness_report as readiness

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "dist-release-evidence"

CLAIM_BOUNDARY = (
    "Local release-readiness evidence bundle only; not production deployment "
    "proof, not hosted Storybook proof, not legal signoff, not pentest evidence, "
    "and not a regulatory or compliance attestation."
)

PRODUCTION_LIVE_SNAPSHOT = Path("dist-release-evidence/production-live-verification.json")
PRODUCTION_BLOCKER_REPORT_SNAPSHOT = Path("dist-release-evidence/production-blocker-report.json")
PRODUCTION_CUTOVER_PLAN_SNAPSHOT = Path("dist-release-evidence/production-cutover-plan.json")
PRODUCTION_EVIDENCE_DRAFT_SNAPSHOT = Path(
    "dist-release-evidence/production-evidence.deployment-blocked.json"
)
PRODUCTION_EVIDENCE_VALIDATION_SNAPSHOT = Path(
    "dist-release-evidence/production-evidence-validation.deployment-blocked.json"
)
HOSTED_STORYBOOK_HANDOFF_SNAPSHOT = Path("dist-release-evidence/hosted-storybook-handoff.json")

REQUIRED_VERIFICATION_COMMANDS = [
    "make verify",
    "make verify-js-node24",
    "make platform-readiness",
    "pnpm -F acgi-ai run test:all",
    "pnpm -F acgi-ai run test:cloudrun-renderer",
    "pnpm -F acgi-ai run test:production-deploy-contract",
    "pnpm -F acgi-ai run test:production-launch-handoff",
    "pnpm -F acgi-ai run test:production-authority-packet",
    "pnpm -F acgi-ai run test:production-evidence-template",
    "pnpm -F acgi-ai run test:production-live-verifier",
    "pnpm -F acgi-ai run test:production-blocker-report",
    "pnpm -F acgi-ai run test:production-evidence-validator",
    "pnpm -F acgi-ai run test:production-cutover-plan",
    "pnpm -F acgi-ai run test:production-evidence-draft",
    (
        "uv run --package gove-zone python -m pytest "
        "packages/gove-zone/tests/test_integration_hook.py --import-mode=importlib -q"
    ),
    (
        "uv run --package gove-zone python -m pytest "
        "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q"
    ),
    "pnpm -F acgi-ai run evidence:build",
    "pnpm -F acgi-ai run test:buyer-evidence",
    "pnpm -F acgi-ai run test:storybook-runtime-plan",
    "pnpm -F acgi-ai run test:storybook-publication",
    "pnpm -F acgi-ai run test:hosted-storybook-handoff",
    "pnpm -F acgi-ai run test:ci-gates",
    "make production-launch-preflight",
]


def _git(args: list[str], repo_root: Path = REPO_ROOT) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _read_json_if_present(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _compact_check_statuses(data: dict[str, Any]) -> list[dict[str, Any]]:
    checks = data.get("checks")
    if not isinstance(checks, list):
        return []
    compacted = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        compacted.append(
            {
                "id": check.get("id"),
                "status": check.get("status"),
                "error": check.get("error"),
            }
        )
    return compacted


def _compact_live_blockers(data: dict[str, Any]) -> list[str]:
    blockers = data.get("blockers")
    if not isinstance(blockers, list):
        return []
    blocker_ids = []
    for blocker in blockers:
        if isinstance(blocker, dict) and blocker.get("blockerId"):
            blocker_ids.append(str(blocker["blockerId"]))
        elif isinstance(blocker, str):
            blocker_ids.append(blocker)
    return blocker_ids


def _unique_strings(values: list[Any]) -> list[str]:
    """Return stable unique non-empty strings."""

    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip() or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def production_live_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a compact optional snapshot of saved live-verifier output."""

    data = _read_json_if_present(repo_root / PRODUCTION_LIVE_SNAPSHOT)
    snapshot: dict[str, Any] = {
        "path": PRODUCTION_LIVE_SNAPSHOT.as_posix(),
        "present": data is not None,
        "claimBoundary": (
            "Saved verify:production-live output is not live production proof unless "
            "status is pass and every required live check passes; failures remain "
            "deployment blockers."
        ),
    }
    if data is None:
        return snapshot

    snapshot.update(
        {
            "artifactKind": data.get("artifactKind"),
            "generatedAt": data.get("generatedAt"),
            "status": data.get("status"),
            "blockedUntil": data.get("blockedUntil"),
            "targets": data.get("targets"),
            "checkStatuses": _compact_check_statuses(data),
            "blockers": _compact_live_blockers(data),
            "sourceClaimBoundary": data.get("claimBoundary"),
        }
    )
    return snapshot


def production_blocker_report_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a compact optional snapshot of a saved blocker-report artifact."""

    data = _read_json_if_present(repo_root / PRODUCTION_BLOCKER_REPORT_SNAPSHOT)
    snapshot: dict[str, Any] = {
        "path": PRODUCTION_BLOCKER_REPORT_SNAPSHOT.as_posix(),
        "present": data is not None,
        "claimBoundary": (
            "Saved production-blocker-report output summarizes local live-verifier "
            "JSON and is not live production proof; status blocked means deployment "
            "claims remain blocked."
        ),
    }
    if data is None:
        return snapshot

    snapshot.update(
        {
            "artifactKind": data.get("artifactKind"),
            "generatedAt": data.get("generatedAt"),
            "status": data.get("status"),
            "productionLiveStatus": data.get("productionLiveStatus"),
            "productionLiveBlockers": data.get("productionLiveBlockers")
            if isinstance(data.get("productionLiveBlockers"), list)
            else [],
            "failedCheckIds": data.get("failedCheckIds")
            if isinstance(data.get("failedCheckIds"), list)
            else [],
            "blockedUntil": data.get("blockedUntil"),
            "sourceClaimBoundary": data.get("claimBoundary"),
        }
    )
    return snapshot


def production_cutover_plan_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a compact optional snapshot of a saved cutover-plan artifact."""

    data = _read_json_if_present(repo_root / PRODUCTION_CUTOVER_PLAN_SNAPSHOT)
    snapshot: dict[str, Any] = {
        "path": PRODUCTION_CUTOVER_PLAN_SNAPSHOT.as_posix(),
        "present": data is not None,
        "claimBoundary": (
            "Saved production-cutover-plan output is an operator handoff only "
            "and is not live production proof; status blocked means DNS/deploy "
            "cutover claims remain blocked."
        ),
    }
    if data is None:
        return snapshot

    snapshot.update(
        {
            "artifactKind": data.get("artifactKind"),
            "generatedAt": data.get("generatedAt"),
            "status": data.get("status"),
            "productionLiveBlockers": data.get("productionLiveBlockers")
            if isinstance(data.get("productionLiveBlockers"), list)
            else [],
            "failedCheckIds": data.get("failedCheckIds")
            if isinstance(data.get("failedCheckIds"), list)
            else [],
            "blockedUntil": data.get("blockedUntil"),
            "sourceClaimBoundary": data.get("claimBoundary"),
        }
    )
    return snapshot


def production_evidence_draft_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a compact optional snapshot of a saved deployment-blocked evidence draft."""

    data = _read_json_if_present(repo_root / PRODUCTION_EVIDENCE_DRAFT_SNAPSHOT)
    snapshot: dict[str, Any] = {
        "path": PRODUCTION_EVIDENCE_DRAFT_SNAPSHOT.as_posix(),
        "present": data is not None,
        "claimBoundary": (
            "Saved production-evidence draft is a deployment-blocked operator handoff "
            "only and is not live production proof; pending-external refs mean "
            "external deploy proof is still missing."
        ),
    }
    if data is None:
        return snapshot

    verification = data.get("verification") if isinstance(data.get("verification"), dict) else {}
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
    snapshot.update(
        {
            "artifactKind": data.get("artifactKind"),
            "generatedAt": data.get("generatedAt"),
            "status": data.get("status"),
            "productionLiveStatus": verification.get("productionLiveStatus"),
            "productionLiveBlockers": verification.get("productionLiveBlockers")
            if isinstance(verification.get("productionLiveBlockers"), list)
            else [],
            "sourceArtifacts": data.get("sourceArtifacts"),
            "productionBlockerReport": artifacts.get("productionBlockerReport"),
            "productionCutoverPlan": artifacts.get("productionCutoverPlan"),
            "blockedUntil": data.get("blockedUntil"),
            "sourceClaimBoundary": data.get("claimBoundary"),
        }
    )
    return snapshot


def production_evidence_validation_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a compact optional snapshot of saved production-evidence validation output."""

    data = _read_json_if_present(repo_root / PRODUCTION_EVIDENCE_VALIDATION_SNAPSHOT)
    snapshot: dict[str, Any] = {
        "path": PRODUCTION_EVIDENCE_VALIDATION_SNAPSHOT.as_posix(),
        "present": data is not None,
        "claimBoundary": (
            "Saved production-evidence-validation output only proves local "
            "manifest/live-output consistency; it is not live production proof, "
            "legal signoff, SOC2 proof, WCAG conformance evidence, pentest "
            "completion, or regulatory compliance proof."
        ),
    }
    if data is None:
        return snapshot

    checks = data.get("checks") if isinstance(data.get("checks"), list) else []
    failing_check_ids = [
        check.get("id")
        for check in checks
        if isinstance(check, dict) and check.get("status") != "pass" and check.get("id")
    ]
    snapshot.update(
        {
            "artifactKind": data.get("artifactKind"),
            "generatedAt": data.get("generatedAt"),
            "status": data.get("status"),
            "manifestPath": data.get("manifestPath"),
            "liveOutputPath": data.get("liveOutputPath"),
            "checkCount": len(checks),
            "failingCheckIds": failing_check_ids,
            "sourceClaimBoundary": data.get("claimBoundary"),
        }
    )
    return snapshot


def hosted_storybook_handoff_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a compact optional snapshot of a saved hosted Storybook handoff."""

    data = _read_json_if_present(repo_root / HOSTED_STORYBOOK_HANDOFF_SNAPSHOT)
    snapshot: dict[str, Any] = {
        "path": HOSTED_STORYBOOK_HANDOFF_SNAPSHOT.as_posix(),
        "present": data is not None,
        "claimBoundary": (
            "Saved hosted-storybook-handoff output is an operator handoff only "
            "and is not live production proof; pending-external refs mean "
            "Storybook Pages proof is still missing."
        ),
    }
    if data is None:
        return snapshot

    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    local_publication = (
        data.get("localPublication") if isinstance(data.get("localPublication"), dict) else {}
    )
    live_verification = (
        data.get("liveVerification") if isinstance(data.get("liveVerification"), dict) else {}
    )
    blockers = live_verification.get("storybookBlockers")
    blocker_ids = [
        blocker.get("blockerId")
        for blocker in blockers
        if isinstance(blocker, dict) and blocker.get("blockerId")
    ] if isinstance(blockers, list) else []
    snapshot.update(
        {
            "artifactKind": data.get("artifactKind"),
            "generatedAt": data.get("generatedAt"),
            "status": data.get("status"),
            "targetUrl": target.get("url"),
            "manifestUrl": target.get("manifestUrl"),
            "publishTargetReady": local_publication.get("publishTargetReady"),
            "productionLiveStatus": live_verification.get("productionLiveStatus"),
            "storybookBlockers": blocker_ids,
            "copyIntoProductionEvidence": data.get("copyIntoProductionEvidence"),
            "sourceClaimBoundary": data.get("claimBoundary"),
        }
    )
    return snapshot


def production_evidence_chain_snapshot(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Summarize whether saved production handoff artifacts agree with each other."""

    live = production_live_snapshot(repo_root)
    blocker_report = production_blocker_report_snapshot(repo_root)
    cutover_plan = production_cutover_plan_snapshot(repo_root)
    evidence_draft = production_evidence_draft_snapshot(repo_root)
    validation = production_evidence_validation_snapshot(repo_root)
    hosted_storybook = hosted_storybook_handoff_snapshot(repo_root)

    missing_artifacts = [
        artifact["path"]
        for artifact in [
            live,
            blocker_report,
            cutover_plan,
            evidence_draft,
            validation,
            hosted_storybook,
        ]
        if artifact.get("present") is not True
    ]

    live_blockers = _unique_strings(live.get("blockers", []))
    blocker_report_blockers = _unique_strings(blocker_report.get("productionLiveBlockers", []))
    cutover_blockers = _unique_strings(cutover_plan.get("productionLiveBlockers", []))
    draft_blockers = _unique_strings(evidence_draft.get("productionLiveBlockers", []))
    hosted_storybook_blockers = _unique_strings(hosted_storybook.get("storybookBlockers", []))

    blocker_sets = {
        "productionLiveVerifier": live_blockers,
        "productionBlockerReport": blocker_report_blockers,
        "productionCutoverPlan": cutover_blockers,
        "productionEvidenceDraft": draft_blockers,
    }
    reference_blockers = live_blockers
    drift = [
        {"artifact": name, "blockers": blockers}
        for name, blockers in blocker_sets.items()
        if blockers != reference_blockers
    ]
    hosted_storybook_extra = [
        blocker for blocker in hosted_storybook_blockers if blocker not in reference_blockers
    ]

    issues: list[str] = []
    if missing_artifacts:
        issues.append("missing-artifacts")
    if drift:
        issues.append("production-live-blocker-drift")
    if hosted_storybook_extra:
        issues.append("hosted-storybook-blocker-not-in-live-output")
    if validation.get("present") is True and validation.get("status") != "pass":
        issues.append("production-evidence-validation-not-passing")
    if validation.get("present") is True:
        manifest_path = str(validation.get("manifestPath") or "")
        live_output_path = str(validation.get("liveOutputPath") or "")
        if "production-evidence.deployment-blocked.json" not in manifest_path:
            issues.append("validation-manifest-path-mismatch")
        if "production-live-verification.json" not in live_output_path:
            issues.append("validation-live-output-path-mismatch")

    return {
        "status": "consistent" if not issues else "needs-refresh",
        "claimBoundary": (
            "Production evidence chain consistency only compares saved local "
            "handoff artifacts; it does not deploy, fetch live origins, mutate "
            "DNS, validate legal/SOC2/WCAG/pentest/regulatory claims, or create "
            "live production proof; it is not live production proof."
        ),
        "artifacts": {
            "productionLiveVerifier": live["path"],
            "productionBlockerReport": blocker_report["path"],
            "productionCutoverPlan": cutover_plan["path"],
            "productionEvidenceDraft": evidence_draft["path"],
            "productionEvidenceValidation": validation["path"],
            "hostedStorybookHandoff": hosted_storybook["path"],
        },
        "missingArtifacts": missing_artifacts,
        "blockerSets": blocker_sets,
        "hostedStorybookBlockers": hosted_storybook_blockers,
        "issues": issues,
        "validation": {
            "status": validation.get("status"),
            "failingCheckIds": validation.get("failingCheckIds", []),
            "manifestPath": validation.get("manifestPath"),
            "liveOutputPath": validation.get("liveOutputPath"),
        },
    }


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def extract_valid_deferrals(repo_root: Path = REPO_ROOT) -> list[dict[str, str]]:
    """Extract the deploy-blocking deferral table from the readiness map."""

    path = repo_root / "docs" / "integration-readiness-task-map.md"
    if not path.is_file():
        return []

    blockers: list[dict[str, str]] = []
    in_section = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## Valid deferrals / external blockers"):
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if not in_section or not line.startswith("|"):
            continue
        parts = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(parts) < 3 or parts[0] in {"Area", "---"} or set(parts[0]) == {"-"}:
            continue
        blockers.append(
            {
                "blockerId": _slugify(parts[0]),
                "area": parts[0],
                "deferredWork": parts[1],
                "reason": parts[2],
                "source": "docs/integration-readiness-task-map.md",
            }
        )
    return blockers


def build_manifest(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Return a release-readiness manifest from current repo-local evidence."""

    items = readiness.build_items(repo_root)
    summary = readiness.summarize(items)
    pending_items = [item for item in items if item.status == "pending"]
    failing_items = [item for item in items if item.status == "fail"]
    external_blockers = extract_valid_deferrals(repo_root)
    external_blocker_ids = {blocker["blockerId"] for blocker in external_blockers}
    for item in pending_items:
        blocker_id = _slugify(item.item_id)
        if blocker_id in external_blocker_ids:
            continue
        external_blockers.append(
            {
                "blockerId": blocker_id,
                "area": item.title,
                "deferredWork": item.command,
                "reason": item.evidence,
                "source": "scripts/platform_readiness_report.py",
            }
        )

    status_lines = (_git(["status", "--short"], repo_root) or "").splitlines()

    buyer_manifest = _read_json_if_present(
        repo_root / "acgi-ai" / "dist-buyer-evidence" / "manifest.json"
    )
    production_evidence_template = _read_json_if_present(
        repo_root / "acgi-ai" / "production-evidence.example.json"
    )
    production_authority_packet = _read_json_if_present(
        repo_root / "acgi-ai" / "production-authority.example.json"
    )

    package_json = json.loads((repo_root / "acgi-ai" / "package.json").read_text())

    return {
        "schemaVersion": 1,
        "artifactKind": "local-release-evidence-bundle",
        "generatedAt": dt.datetime.now(dt.UTC).isoformat(),
        "claimBoundary": CLAIM_BOUNDARY,
        "repository": {
            "path": str(repo_root),
            "branch": _git(["branch", "--show-current"], repo_root),
            "commit": _git(["rev-parse", "HEAD"], repo_root),
            "dirty": bool(status_lines),
            "dirtyEntryCount": len(status_lines),
        },
        "toolchain": {
            "acgiPackageManager": package_json.get("packageManager"),
            "acgiNodeEngine": package_json.get("engines", {}).get("node"),
        },
        "readiness": {
            "summary": summary,
            "items": [asdict(item) for item in items],
            "pendingItemIds": [item.item_id for item in pending_items],
            "failingItemIds": [item.item_id for item in failing_items],
        },
        "evidenceArtifacts": {
            "cloudRunRenderer": {
                "script": "acgi-ai/scripts/render-cloudrun-service.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:cloudrun-renderer",
            },
            "productionDeployContract": {
                "proofCommand": "pnpm -F acgi-ai run test:production-deploy-contract",
                "marketingWorkflow": ".github/workflows/marketing.yml",
                "consoleWorkflow": ".github/workflows/console.yml",
                "claimBoundary": (
                    "local production deploy fail-closed contract only; "
                    "not live production deployment proof"
                ),
            },
            "productionLaunchHandoff": {
                "handoff": "acgi-ai/PRODUCTION-LAUNCH.md",
                "proofCommand": "pnpm -F acgi-ai run test:production-launch-handoff",
                "claimBoundary": (
                    "operator production launch handoff only; not live production deployment proof"
                ),
            },
            "productionLaunchPreflight": {
                "script": "scripts/production_launch_preflight.py",
                "proofCommand": "make production-launch-preflight",
                "operatorCommand": (
                    "uv run python scripts/production_launch_preflight.py "
                    "--manifest dist-release-evidence/manifest.json --require-ready"
                ),
                "outputFields": [
                    "status",
                    "requiredActions",
                    "repository",
                    "pendingItemIds",
                    "productionLive",
                    "productionEvidenceChain",
                    "externalBlockerIds",
                ],
                "claimBoundary": (
                    "local release-evidence preflight only; reports ready/blocked "
                    "state and requires a current clean commit evidence snapshot, "
                    "but does not deploy, mutate DNS, approve release authority, "
                    "or create live production proof"
                ),
            },
            # Production authority packet remains not production deployment proof.
            "productionAuthorityPacket": {
                "templatePath": "acgi-ai/production-authority.example.json",
                "proofCommand": "pnpm -F acgi-ai run test:production-authority-packet",
                "templatePresent": production_authority_packet is not None,
                "templateStatus": (production_authority_packet or {}).get("status"),
                "requiredApprovalIds": [
                    approval.get("id")
                    for approval in (production_authority_packet or {}).get(
                        "requiredApprovals", []
                    )
                    if isinstance(approval, dict)
                ],
                "claimBoundary": (
                    "template-only deploy/DNS/auth/claim authority packet; not "
                    "production deployment proof, not deploy approval, and not live proof "
                    "until pending-external refs are replaced by signed operator evidence"
                ),
            },
            "productionEvidenceTemplate": {
                "templatePath": "acgi-ai/production-evidence.example.json",
                "proofCommand": "pnpm -F acgi-ai run test:production-evidence-template",
                "claimBoundary": (
                    "template-only live evidence intake; not live production proof; "
                    "assurance fields remain pending-external until external proof is attached"
                ),
                "templatePresent": production_evidence_template is not None,
                "templateStatus": (production_evidence_template or {}).get("status"),
                "template": production_evidence_template,
            },
            "productionLiveVerifier": {
                "script": "acgi-ai/scripts/verify-production-live.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:production-live-verifier",
                "liveProofCommand": "pnpm -F acgi-ai run verify:production-live -- --json",
                "latestOutputSnapshot": production_live_snapshot(repo_root),
                "targets": [
                    "https://acgs.ai",
                    "https://console.acgs.ai",
                    "https://storybook.acgs.ai",
                    "https://storybook.acgs.ai/manifest.json",
                ],
                "liveCheckIds": [
                    "marketing-dns-live",
                    "console-dns-live",
                    "storybook-dns-live",
                    "marketing-https-live",
                    "console-healthz-live",
                    "console-security-headers-live",
                    "storybook-https-live",
                    "storybook-manifest-live",
                ],
                "outputFields": [
                    "status",
                    "blockedUntil",
                    "blockers",
                    "checks",
                ],
                "claimBoundary": (
                    "local proofCommand only verifies wiring; liveProofCommand output is not live "
                    "production proof unless all required live checks pass; "
                    "failures remain blockers and are copied into productionLiveBlockers"
                ),
            },
            "productionBlockerReport": {
                "script": "acgi-ai/scripts/build-production-blocker-report.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:production-blocker-report",
                "latestReportSnapshot": production_blocker_report_snapshot(repo_root),
                "operatorCommand": (
                    "pnpm -F acgi-ai run build:production-blocker-report -- --live-output "
                    "<verify-production-live.json> --out <production-blocker-report.json>"
                ),
                "outputFields": [
                    "status",
                    "productionLiveStatus",
                    "productionLiveBlockers",
                    "blockedUntil",
                    "copyIntoProductionEvidence",
                ],
                "claimBoundary": (
                    "local proofCommand verifies report behavior only; operatorCommand "
                    "summarizes attached verify:production-live JSON into a "
                    "production-blocker-report, does not deploy or fetch live origins, "
                    "and is not live production proof"
                ),
            },
            "productionCutoverPlan": {
                "script": "acgi-ai/scripts/build-production-cutover-plan.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:production-cutover-plan",
                "latestPlanSnapshot": production_cutover_plan_snapshot(repo_root),
                "operatorCommand": (
                    "pnpm -F acgi-ai run build:production-cutover-plan -- --live-output "
                    "<verify-production-live.json> --blocker-report "
                    "<production-blocker-report.json> --out <production-cutover-plan.json>"
                ),
                "outputFields": [
                    "status",
                    "requiredGitHubSecrets",
                    "dnsCutover",
                    "productionLiveBlockers",
                    "copyIntoProductionEvidence",
                ],
                "claimBoundary": (
                    "local proofCommand verifies cutover-plan behavior only; operatorCommand "
                    "summarizes saved live evidence into a production-cutover-plan, "
                    "does not deploy or mutate DNS, and is not live production proof"
                ),
            },
            "productionEvidenceDraft": {
                "script": "acgi-ai/scripts/build-production-evidence-draft.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:production-evidence-draft",
                "latestDraftSnapshot": production_evidence_draft_snapshot(repo_root),
                "operatorCommand": (
                    "pnpm -F acgi-ai run build:production-evidence-draft -- --live-output "
                    "<verify-production-live.json> --blocker-report "
                    "<production-blocker-report.json> --cutover-plan "
                    "<production-cutover-plan.json> --out "
                    "<production-evidence.deployment-blocked.json>"
                ),
                "outputFields": [
                    "status",
                    "productionLiveStatus",
                    "productionLiveBlockers",
                    "productionEvidenceValidationCommand",
                    "productionBlockerReport",
                    "productionCutoverPlan",
                    "pending-external",
                ],
                "claimBoundary": (
                    "local proofCommand verifies draft behavior only; operatorCommand "
                    "summarizes saved blocked live evidence into a deployment-blocked "
                    "production-evidence draft, does not deploy or fetch live origins, "
                    "and is not live production proof"
                ),
            },
            "productionEvidenceValidator": {
                "script": "acgi-ai/scripts/validate-production-evidence.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:production-evidence-validator",
                "operatorCommand": (
                    "pnpm -F acgi-ai run validate:production-evidence -- --manifest "
                    "<completed-production-evidence.json> --live-output "
                    "<verify-production-live.json>"
                ),
                "templateFields": [
                    "productionLiveStatus",
                    "productionLiveBlockers",
                    "productionEvidenceValidationCommand",
                    "productionEvidenceValidationOutputRef",
                    "validatedProductionEvidence",
                ],
                "claimBoundary": (
                    "local proofCommand only verifies validator behavior; operatorCommand "
                    "validates completed production evidence and live verifier JSON but is "
                    "not legal, SOC2, WCAG, pentest, regulatory, or live deployment proof "
                    "by itself"
                ),
            },
            "productionEvidenceValidation": {
                "latestValidationSnapshot": production_evidence_validation_snapshot(repo_root),
                "claimBoundary": (
                    "saved validator output only proves local production-evidence "
                    "manifest consistency against an attached live-verifier JSON; "
                    "it is not live production proof or external assurance proof"
                ),
            },
            "productionEvidenceChain": {
                "proofCommand": "make release-evidence",
                "latestChainSnapshot": production_evidence_chain_snapshot(repo_root),
                "claimBoundary": (
                    "local saved-artifact chain consistency only; not live production "
                    "proof, not DNS proof, not hosted Storybook proof, and not legal, "
                    "SOC2, WCAG, pentest, or regulatory proof"
                ),
            },
            "fixtureFallbackBoundary": {
                "module": "acgi-ai/src/api/hooks.ts",
                "proofCommands": [
                    "pnpm -F acgi-ai run test:security",
                    "pnpm -F acgi-ai run test:mvp",
                ],
                "productionBehavior": (
                    "import.meta.env.PROD disables fixture fallback and production "
                    "bundles are scanned for fixture sentinels"
                ),
                "mockModeBehavior": (
                    "withFixtureFallback rethrows ApiError and non-network errors; "
                    "fixture data is only used for network-unavailable TypeError cases"
                ),
                "claimBoundary": (
                    "local frontend fail-closed guard only; not proof that the live "
                    "governed bus is deployed or reachable"
                ),
            },
            "runtimeFrameworkBridge": {
                "module": "packages/gove-zone/src/gove_zone/integration.py",
                "publicHelper": "tool_call_from_hook_payload",
                "proofCommand": (
                    "uv run --package gove-zone python -m pytest "
                    "packages/gove-zone/tests/test_integration_hook.py "
                    "--import-mode=importlib -q"
                ),
                "supportedLocalShapes": [
                    "Claude/Codex-style {tool_name, tool_input}",
                    "MCP-style {method: tools/call, params: {name, arguments}}",
                    "function-call-style {type: function_call, name, arguments}",
                    "OpenAI Chat tool_calls [{function: {name, arguments}}]",
                    "LangChain-style tool_calls [{name, args}]",
                    "generic {name, arguments|args|input}",
                ],
                "cliProofCommand": (
                    "uv run --package gove-zone python -m pytest "
                    "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q"
                ),
                "claimBoundary": (
                    "dependency-free local adapter normalization only; not a claim "
                    "that every third-party agent framework integration has been "
                    "certified or production deployed"
                ),
            },
            "runtimePolicyGate": {
                "cli": "gove-zone gate --policy-bundle <policy.bundle.json> < event.json",
                "module": "packages/gove-zone/src/gove_zone/cli.py",
                "policyType": "RuleSetPolicy",
                "proofCommand": (
                    "uv run --package gove-zone python -m pytest "
                    "packages/gove-zone/tests/test_setup.py --import-mode=importlib -q"
                ),
                "blockingDecisions": ["deny", "escalate"],
                "coveredPayloadShapes": [
                    "OpenAI Chat tool_calls [{function: {name, arguments}}]",
                    "LangChain-style tool_calls [{name, args}]",
                ],
                "claimBoundary": (
                    "local CLI hook-gate contract only; policy effectiveness depends "
                    "on the reviewed bundle supplied by the operator and does not "
                    "prove live framework deployment; not live third-party deployment proof"
                ),
            },
            "storybookRuntimePlan": {
                "planPath": "acgi-ai/storybook-runtime.plan.json",
                "proofCommand": "pnpm -F acgi-ai run test:storybook-runtime-plan",
                "status": "pending-dependency-authority",
                "requiredApprovalIds": [
                    "dependency-owner-approval",
                    "release-owner-approval",
                ],
                "proofRefs": {
                    "dependencyApproval": "pending-external:dependency-owner-approval",
                    "versionPins": "pending-external:storybook-version-pins",
                    "runtimeBuildOutput": "pending-external:official-storybook-build-output",
                    "liveStorybookManifest": "pending-external:storybook-pages-proof",
                },
                "proposedRuntime": {
                    "initCommand": "npx storybook@latest init",
                    "frameworkPackage": "@storybook/react-vite",
                    "corePackage": "storybook",
                },
                "claimBoundary": (
                    "local plan only; not official Storybook runtime proof, not hosted "
                    "Storybook proof, not production deployment proof, and no "
                    "dependencies are installed until pending-external dependency "
                    "approval is replaced by signed evidence"
                ),
            },
            "storybookPublication": {
                "workflow": ".github/workflows/storybook.yml",
                "target": "https://storybook.acgs.ai",
                "proofCommand": "pnpm -F acgi-ai run test:storybook-publication",
                "deploymentGate": "vars.STORYBOOK_PAGES_ENABLED == 'true'",
            },
            "hostedStorybookHandoff": {
                "script": "acgi-ai/scripts/build-hosted-storybook-handoff.mjs",
                "proofCommand": "pnpm -F acgi-ai run test:hosted-storybook-handoff",
                "latestHandoffSnapshot": hosted_storybook_handoff_snapshot(repo_root),
                "operatorCommand": (
                    "pnpm -F acgi-ai run build:hosted-storybook-handoff -- "
                    "--buyer-evidence-manifest <dist-buyer-evidence/manifest.json> "
                    "--live-output <verify-production-live.json> --out "
                    "<hosted-storybook-handoff.json>"
                ),
                "outputFields": [
                    "status",
                    "target",
                    "localPublication",
                    "liveVerification",
                    "storybook-manifest-live",
                    "pending-external",
                    "copyIntoProductionEvidence.hostedStorybook",
                ],
                "claimBoundary": (
                    "local proofCommand verifies handoff behavior only; operatorCommand "
                    "summarizes saved buyer-evidence and live verifier JSON into a "
                    "hosted-storybook-handoff, does not deploy, mutate DNS, fetch live "
                    "origins, install the official Storybook runtime, or create live "
                    "production proof; not live production proof"
                ),
            },
            "buyerEvidenceGallery": {
                "expectedPath": "acgi-ai/dist-buyer-evidence/",
                "ciArtifactName": "buyer-evidence-gallery",
                "manifestPresent": buyer_manifest is not None,
                "manifest": buyer_manifest,
            },
            "platformReadinessJson": "platform-readiness.json",
        },
        "verificationCommands": REQUIRED_VERIFICATION_COMMANDS,
        "externalBlockers": external_blockers,
    }


def render_readme(manifest: dict[str, Any]) -> str:
    summary = manifest["readiness"]["summary"]
    blockers = manifest["externalBlockers"]
    blocker_lines = "\n".join(
        (
            f"- `{blocker['blockerId']}` — {blocker['area']}: "
            f"{blocker['deferredWork']} ({blocker['reason']})"
        )
        for blocker in blockers
    ) or (
        "- None recorded in local readiness; verify live production evidence "
        "before stronger claims."
    )
    commands = "\n".join(f"- `{command}`" for command in manifest["verificationCommands"])
    production_live = manifest["evidenceArtifacts"]["productionLiveVerifier"][
        "latestOutputSnapshot"
    ]
    production_blockers = manifest["evidenceArtifacts"]["productionBlockerReport"][
        "latestReportSnapshot"
    ]
    production_cutover = manifest["evidenceArtifacts"]["productionCutoverPlan"][
        "latestPlanSnapshot"
    ]
    production_evidence_draft = manifest["evidenceArtifacts"]["productionEvidenceDraft"][
        "latestDraftSnapshot"
    ]
    production_evidence_validation = manifest["evidenceArtifacts"]["productionEvidenceValidation"][
        "latestValidationSnapshot"
    ]
    production_evidence_chain = manifest["evidenceArtifacts"]["productionEvidenceChain"][
        "latestChainSnapshot"
    ]
    hosted_storybook_handoff = manifest["evidenceArtifacts"]["hostedStorybookHandoff"][
        "latestHandoffSnapshot"
    ]
    live_snapshot_line = (
        f"- `{production_live['path']}` captured status "
        f"`{production_live.get('status')}` with blockers "
        f"`{', '.join(production_live.get('blockers', [])) or 'none'}`."
        if production_live["present"]
        else f"- `{production_live['path']}` is not present in this bundle."
    )
    blocker_snapshot_line = (
        f"- `{production_blockers['path']}` captured status "
        f"`{production_blockers.get('status')}` for live status "
        f"`{production_blockers.get('productionLiveStatus')}`."
        if production_blockers["present"]
        else f"- `{production_blockers['path']}` is not present in this bundle."
    )
    cutover_snapshot_line = (
        f"- `{production_cutover['path']}` captured status "
        f"`{production_cutover.get('status')}` with blockers "
        f"`{', '.join(production_cutover.get('productionLiveBlockers', [])) or 'none'}`."
        if production_cutover["present"]
        else f"- `{production_cutover['path']}` is not present in this bundle."
    )
    evidence_draft_snapshot_line = (
        f"- `{production_evidence_draft['path']}` captured status "
        f"`{production_evidence_draft.get('status')}` with live status "
        f"`{production_evidence_draft.get('productionLiveStatus')}`."
        if production_evidence_draft["present"]
        else f"- `{production_evidence_draft['path']}` is not present in this bundle."
    )
    validation_snapshot_line = (
        f"- `{production_evidence_validation['path']}` captured status "
        f"`{production_evidence_validation.get('status')}` with "
        f"`{production_evidence_validation.get('checkCount')}` checks."
        if production_evidence_validation["present"]
        else f"- `{production_evidence_validation['path']}` is not present in this bundle."
    )
    chain_snapshot_line = (
        f"- Production evidence chain status: `{production_evidence_chain['status']}` "
        f"with issues `{', '.join(production_evidence_chain.get('issues', [])) or 'none'}`."
    )
    hosted_storybook_snapshot_line = (
        f"- `{hosted_storybook_handoff['path']}` captured status "
        f"`{hosted_storybook_handoff.get('status')}` with blockers "
        f"`{', '.join(hosted_storybook_handoff.get('storybookBlockers', [])) or 'none'}`."
        if hosted_storybook_handoff["present"]
        else f"- `{hosted_storybook_handoff['path']}` is not present in this bundle."
    )

    return f"""# Local release-readiness evidence bundle

{manifest["claimBoundary"]}

## Readiness summary

- Pass: {summary["pass"]}
- Fail: {summary["fail"]}
- Pending: {summary["pending"]}
- Total: {summary["total"]}

## Required verification commands

{commands}

## External blockers

{blocker_lines}

## Saved live-evidence snapshots

{live_snapshot_line}
{blocker_snapshot_line}
{cutover_snapshot_line}
{evidence_draft_snapshot_line}
{validation_snapshot_line}
{chain_snapshot_line}
{hosted_storybook_snapshot_line}

These snapshots are operator handoff evidence only. They are not live production
proof unless the saved live verifier status is `pass` and every required live
check passed. The production evidence chain check only compares saved local
handoff artifacts for drift; it does not deploy, fetch live origins, or create
live production proof.

## Artifact notes

- `manifest.json` is the machine-readable bundle manifest.
- `platform-readiness.json` is the readiness item snapshot used to build this bundle.
- `acgi-ai/scripts/render-cloudrun-service.mjs` is the shared fail-closed Cloud Run renderer.
- `acgi-ai/scripts/check-production-deploy-contract.mjs` is the production
  deploy fail-closed verifier for marketing Vercel and console Cloud Run workflow
  contracts.
- `acgi-ai/PRODUCTION-LAUNCH.md` is the production launch handoff for required
  secrets, preflight commands, live proof artifacts, rollback triggers, and claim
  boundaries.
- `scripts/production_launch_preflight.py` reads `dist-release-evidence/manifest.json`
  and emits a conservative ready/blocked production launch preflight. `make
  production-launch-preflight` refreshes the release evidence first and reports
  the current blocked state without deploying, mutating DNS, or creating live
  production proof. Use `--require-ready` only after external deploy, authority,
  hosted Storybook, and assurance evidence is attached.
- `acgi-ai/production-authority.example.json` is the template-only authority
  packet for deploy-owner, DNS-owner, auth-owner, claim/legal-owner, and rollback
  approvals. `pnpm -F acgi-ai run test:production-authority-packet` verifies it
  remains `pending-external:deploy-owner-approval` style evidence and is not
  production deployment proof, deploy approval, DNS proof, or hosted Storybook
  proof by itself.
- `acgi-ai/production-evidence.example.json` is the template-only live proof
  intake manifest. It is not live production proof; legal, pentest, WCAG/manual,
  browser, and hosted Storybook fields stay `pending-external` until external
  evidence is attached.
- `acgi-ai/scripts/verify-production-live.mjs` is the post-deploy live evidence
  command for DNS, HTTPS, `/healthz`, security headers, and Storybook proof,
  including `storybook-manifest-live` validation of `https://storybook.acgs.ai/manifest.json`.
  `pnpm -F acgi-ai run test:production-live-verifier` checks local wiring, while
  `pnpm -F acgi-ai run verify:production-live -- --json` is the credentialed
  live proof command that may fail until production DNS and hosted deploys exist.
  Its JSON includes `blockedUntil` and `blockers` so failed live checks can be
  copied into `productionLiveBlockers` in the completed production evidence
  manifest.
- `acgi-ai/scripts/build-production-blocker-report.mjs` converts a saved
  `verify:production-live` JSON file into a local `production-blocker-report`
  with `copyIntoProductionEvidence` fields for the operator handoff.
  `pnpm -F acgi-ai run test:production-blocker-report` verifies this behavior;
  the builder does not deploy, fetch live origins, or create live production
  proof.
- `acgi-ai/scripts/build-production-cutover-plan.mjs` combines saved live
  verifier and blocker-report JSON into a local `production-cutover-plan`
  listing required GitHub secrets, DNS cutover records, remaining
  `productionLiveBlockers`, and `copyIntoProductionEvidence` handoff fields.
  `pnpm -F acgi-ai run test:production-cutover-plan` verifies this behavior;
  the builder does not deploy, mutate DNS, fetch live origins, or create live
  production proof.
- `acgi-ai/scripts/build-production-evidence-draft.mjs` combines saved live
  verifier, `production-blocker-report`, and `production-cutover-plan` JSON into
  a local `production-evidence.deployment-blocked.json` draft with
  `productionLiveBlockers`, `productionEvidenceValidationCommand`,
  `productionBlockerReport`, `productionCutoverPlan`, and explicit
  `pending-external:` refs for unavailable external deploy proof.
  `pnpm -F acgi-ai run test:production-evidence-draft` verifies this behavior;
  the builder does not deploy, mutate DNS, fetch live origins, or create live
  production proof.
- `dist-release-evidence/production-evidence-validation.deployment-blocked.json`
  is the saved local validator output for the deployment-blocked production
  evidence draft. `productionEvidenceChain` in `manifest.json` compares the
  saved live-verifier, blocker-report, cutover-plan, draft, validator, and
  hosted Storybook handoff snapshots so stale blocker copying is visible before
  an operator attaches external proof.
- `acgi-ai/scripts/build-hosted-storybook-handoff.mjs` combines a Pages-ready
  buyer-evidence manifest and saved `verify:production-live` JSON into a local
  `hosted-storybook-handoff.json` with `storybook-manifest-live`,
  `pending-external:storybook-pages-proof`, and
  `copyIntoProductionEvidence.hostedStorybook` fields.
  `pnpm -F acgi-ai run test:hosted-storybook-handoff` verifies this behavior;
  the builder does not deploy, mutate DNS, fetch live origins, install the
  official Storybook runtime, or create live production proof.
- `acgi-ai/storybook-runtime.plan.json` is the pending official Storybook
  runtime dependency plan. `pnpm -F acgi-ai run test:storybook-runtime-plan`
  verifies the `pending-external:dependency-owner-approval` boundary, the
  `@storybook/react-vite` / `npx storybook@latest init` operator plan, and that
  the plan remains not official Storybook runtime proof, not hosted Storybook
  proof, and not production deployment proof.
- `acgi-ai/src/api/hooks.ts` disables fixture fallback in production and limits
  non-production mock fallback to network-unavailable `TypeError` cases.
  `pnpm -F acgi-ai run test:security` and `pnpm -F acgi-ai run test:mvp`
  guard this boundary so API errors or contract drift cannot silently render
  fixture data.
- `packages/gove-zone/src/gove_zone/integration.py` exposes
  `tool_call_from_hook_payload` so agent-framework bridges can normalize
  Claude/Codex-style, MCP-style, function-call-style, and generic payloads
  before emitting governed receipts. This is local adapter evidence, not
  certification of every third-party framework integration.
- `gove-zone gate --policy-bundle <policy.bundle.json> < event.json` loads a
  reviewed `RuleSetPolicy`, emits a receipt, and exits non-zero for deny /
  escalate decisions so hook hosts can block the side effect before it runs.
  This is a local hook-gate contract, not live third-party deployment proof.
- `.github/workflows/storybook.yml` is the gated buyer-evidence Storybook
  publication scaffold for `storybook.acgs.ai`.
- `buyer-evidence-gallery` is the CI artifact name for the local buyer proof gallery.
- This bundle is a deploy handoff artifact, not live production proof.
"""


def write_bundle(out_dir: Path = DEFAULT_OUT_DIR, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    items = readiness.build_items(repo_root)
    manifest = build_manifest(repo_root)

    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "platform-readiness.json").write_text(
        json.dumps(
            {
                "summary": readiness.summarize(items),
                "items": [asdict(item) for item in items],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (out_dir / "README.md").write_text(render_readme(manifest), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    manifest = write_bundle(out_dir=out_dir)
    summary = manifest["readiness"]["summary"]
    print(
        "Release evidence bundle written to "
        f"{out_dir} ({summary['pass']}/{summary['total']} pass, "
        f"{summary['fail']} fail, {summary['pending']} pending)"
    )
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
